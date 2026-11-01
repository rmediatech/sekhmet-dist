use crate::self_learn::ThreatIntelRecord;
use crate::{now_unix, SekhmetStore, SekhmetStoreError, GENESIS_PREV_HASH};
use rusqlite::{params, Connection, OptionalExtension};
use sekhmet_crypto::{generate_random_hex, sha256_hex, SekhmetEd25519Signer};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelfHealReport {
    pub keystore_constraint_healed: bool,
    pub keystore_repaired: bool,
    pub graduated_retiring_key: bool,
    pub healed_merkle_links: usize,
    pub pruned_sessions: usize,
    pub pruned_threat_records: usize,
    pub merkle_verified: bool,
    pub merkle_entries: usize,
    pub merkle_head_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntelligenceSummary {
    pub active_quarantines: usize,
    pub total_learned_threats: usize,
    pub learned_user_baselines: usize,
    pub forensic_quarantine_events: usize,
    pub top_threats: Vec<ThreatIntelRecord>,
}

impl SekhmetStore {
    pub fn self_heal(&self, retiring_grace_ttl_secs: i64) -> Result<SelfHealReport, SekhmetStoreError> {
        let ts = now_unix();
        let conn = self.conn.lock().expect("db mutex poisoned");

        // 1. Heal legacy skm_keystore single-slot CHECK constraint if present
        let keystore_sql: Option<String> = conn
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name='skm_keystore'",
                [],
                |r| r.get(0),
            )
            .optional()
            .map_err(|_| SekhmetStoreError::DatabaseError)?;

        let mut keystore_constraint_healed = false;
        if let Some(sql_def) = keystore_sql {
            if !sql_def.contains("retiring_ed25519") {
                conn.execute_batch(
                    "CREATE TABLE skm_keystore_new (
                        key_slot TEXT PRIMARY KEY CHECK (key_slot IN ('root_ed25519', 'retiring_ed25519')),
                        seed_hex TEXT NOT NULL CHECK (length(seed_hex) = 64),
                        key_id   TEXT NOT NULL CHECK (length(key_id) BETWEEN 8 AND 64),
                        created_at INTEGER NOT NULL
                    );
                    INSERT INTO skm_keystore_new SELECT key_slot, seed_hex, key_id, created_at FROM skm_keystore;
                    DROP TABLE skm_keystore;
                    ALTER TABLE skm_keystore_new RENAME TO skm_keystore;",
                )
                .map_err(|_| SekhmetStoreError::DatabaseError)?;
                keystore_constraint_healed = true;
            }
        }

        // 2. Verify/Heal primary root_ed25519 key
        let root_seed: Option<String> = conn
            .query_row(
                "SELECT seed_hex FROM skm_keystore WHERE key_slot = 'root_ed25519'",
                [],
                |r| r.get(0),
            )
            .optional()
            .map_err(|_| SekhmetStoreError::DatabaseError)?;

        let mut keystore_repaired = false;
        let root_valid = root_seed
            .as_deref()
            .and_then(|s| SekhmetEd25519Signer::from_seed_hex(s).ok())
            .is_some();

        if !root_valid {
            let fresh_seed = generate_random_hex(32);
            let signer = SekhmetEd25519Signer::from_seed_hex(&fresh_seed)
                .map_err(|_| SekhmetStoreError::DatabaseError)?;
            conn.execute(
                "INSERT OR REPLACE INTO skm_keystore (key_slot, seed_hex, key_id, created_at) VALUES ('root_ed25519', ?1, ?2, ?3)",
                params![fresh_seed, signer.key_id(), ts],
            )
            .map_err(|_| SekhmetStoreError::DatabaseError)?;
            keystore_repaired = true;
        }

        // 3. Auto-Graduate expired retiring_ed25519 key once grace window elapses
        let mut graduated_retiring_key = false;
        if retiring_grace_ttl_secs > 0 {
            let cutoff = ts - retiring_grace_ttl_secs;
            let deleted = conn
                .execute(
                    "DELETE FROM skm_keystore WHERE key_slot = 'retiring_ed25519' AND created_at <= ?1",
                    params![cutoff],
                )
                .unwrap_or(0);
            if deleted > 0 {
                graduated_retiring_key = true;
            }
        }

        // 4. Merkle Audit Ledger Self-Healing & Forensic Quarantine
        let healed_merkle_links = self.heal_merkle_chain_locked(&conn, ts)?;

        // 5. Reap expired/revoked sessions & stale low-score threat records
        let pruned_sessions = conn
            .execute(
                "DELETE FROM skm_sessions WHERE expires_at < ?1 OR is_revoked = 1",
                params![ts],
            )
            .unwrap_or(0);

        let stale_threat_cutoff = ts - 604_800;
        let pruned_threat_records = conn
            .execute(
                "DELETE FROM skm_threat_memory WHERE quarantined_until < ?1 AND updated_at < ?2",
                params![ts, stale_threat_cutoff],
            )
            .unwrap_or(0);

        let _ = conn.execute_batch("PRAGMA wal_checkpoint(PASSIVE); PRAGMA optimize;");

        if keystore_constraint_healed || keystore_repaired || graduated_retiring_key || healed_merkle_links > 0 {
            let _ = self.append_audit_locked(
                &conn,
                "system",
                "self-heal",
                "SELF_HEAL_COMPLETED",
                &format!(
                    "constraint={} keystore={} graduated={} merkle_healed={}",
                    keystore_constraint_healed,
                    keystore_repaired,
                    graduated_retiring_key,
                    healed_merkle_links
                ),
            );
        }

        drop(conn);
        let (merkle_entries, merkle_head_hash) = self.verify_merkle_chain()?;

        Ok(SelfHealReport {
            keystore_constraint_healed,
            keystore_repaired,
            graduated_retiring_key,
            healed_merkle_links,
            pruned_sessions,
            pruned_threat_records,
            merkle_verified: true,
            merkle_entries,
            merkle_head_hash,
        })
    }

    fn heal_merkle_chain_locked(
        &self,
        conn: &Connection,
        ts: i64,
    ) -> Result<usize, SekhmetStoreError> {
        let mut stmt = conn
            .prepare(
                "SELECT seq, timestamp, tenant_id, actor_id, event_type, detail_sanitized, prev_hash, entry_hash
                 FROM skm_merkle_audit_log ORDER BY seq ASC",
            )
            .map_err(|_| SekhmetStoreError::DatabaseError)?;

        let rows: Vec<(i64, i64, String, String, String, String, String, String)> = stmt
            .query_map([], |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                    r.get(7)?,
                ))
            })
            .map_err(|_| SekhmetStoreError::DatabaseError)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| SekhmetStoreError::DatabaseError)?;

        let mut expected_prev = GENESIS_PREV_HASH.to_string();
        let mut healed_count = 0usize;

        for (seq, row_ts, tid, actor, ev, detail, prev_h, entry_h) in rows {
            let canonical_payload =
                format!("{}|{}|{}|{}|{}|{}", expected_prev, row_ts, tid, actor, ev, detail);
            let canonical_hash = sha256_hex(canonical_payload.as_bytes());

            if prev_h != expected_prev || entry_h != canonical_hash {
                let summary = format!(
                    "seq={} event={} prev_mismatch={} hash_mismatch={}",
                    seq,
                    ev,
                    prev_h != expected_prev,
                    entry_h != canonical_hash
                );
                conn.execute(
                    "INSERT INTO skm_forensic_quarantine (healed_at, corrupted_seq, corrupted_hash, forensic_summary)
                     VALUES (?1, ?2, ?3, ?4)",
                    params![ts, seq, entry_h, summary],
                )
                .map_err(|_| SekhmetStoreError::DatabaseError)?;

                conn.execute(
                    "UPDATE skm_merkle_audit_log SET prev_hash = ?1, entry_hash = ?2 WHERE seq = ?3",
                    params![expected_prev, canonical_hash, seq],
                )
                .map_err(|_| SekhmetStoreError::DatabaseError)?;
                healed_count += 1;
            }
            expected_prev = canonical_hash;
        }

        Ok(healed_count)
    }

    pub fn get_intelligence_summary(&self) -> Result<IntelligenceSummary, SekhmetStoreError> {
        let ts = now_unix();
        let conn = self.conn.lock().expect("db mutex poisoned");

        let active_quarantines: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM skm_threat_memory WHERE quarantined_until > ?1",
                params![ts],
                |r| r.get(0),
            )
            .unwrap_or(0);

        let total_learned_threats: i64 = conn
            .query_row("SELECT COUNT(*) FROM skm_threat_memory", [], |r| r.get(0))
            .unwrap_or(0);

        let learned_user_baselines: i64 = conn
            .query_row("SELECT COUNT(*) FROM skm_user_baselines", [], |r| r.get(0))
            .unwrap_or(0);

        let forensic_quarantine_events: i64 = conn
            .query_row("SELECT COUNT(*) FROM skm_forensic_quarantine", [], |r| r.get(0))
            .unwrap_or(0);

        let mut stmt = conn
            .prepare(
                "SELECT ip_or_cidr, strike_count, threat_score, quarantined_until, last_reason
                 FROM skm_threat_memory ORDER BY threat_score DESC, updated_at DESC LIMIT 10",
            )
            .map_err(|_| SekhmetStoreError::DatabaseError)?;

        let top_threats = stmt
            .query_map([], |r| {
                let ip_or_cidr: String = r.get(0)?;
                let is_subnet = ip_or_cidr.contains('/');
                Ok(ThreatIntelRecord {
                    ip_or_cidr,
                    strike_count: r.get(1)?,
                    threat_score: r.get(2)?,
                    quarantined_until: r.get(3)?,
                    last_reason: r.get(4)?,
                    subnet_herd_promoted: is_subnet,
                })
            })
            .map_err(|_| SekhmetStoreError::DatabaseError)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| SekhmetStoreError::DatabaseError)?;

        Ok(IntelligenceSummary {
            active_quarantines: active_quarantines as usize,
            total_learned_threats: total_learned_threats as usize,
            learned_user_baselines: learned_user_baselines as usize,
            forensic_quarantine_events: forensic_quarantine_events as usize,
            top_threats,
        })
    }
}
