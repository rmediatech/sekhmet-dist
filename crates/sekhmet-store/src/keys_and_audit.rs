use crate::{now_unix, SekhmetStore, SekhmetStoreError, GENESIS_PREV_HASH};
use rusqlite::{params, Connection, OptionalExtension};
use sekhmet_cidr::{
    check_domain_allowed, check_ip_allowed, validate_cidr_csv, validate_domain_csv,
};
use sekhmet_crypto::{
    compute_merkle_entry_hash, generate_random_hex, generate_sovereign_api_key, sha256_hex,
};
use sekhmet_sanitize::sanitize_boundary_text;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MintedApiKey {
    pub key_id: String,
    pub key_prefix: String,
    pub raw_key: String,
    pub label: String,
    pub allowed_cidrs: String,
    pub allowed_domains: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiedApiKeyContext {
    pub key_id: String,
    pub tenant_id: String,
    pub owner_user_id: String,
    pub subscription_tier: String,
}

impl SekhmetStore {
    pub fn create_session(
        &self,
        tenant_id: &str,
        user_id: &str,
        token_jti: &str,
        ttl_secs: i64,
        client_ip: &str,
    ) -> Result<String, SekhmetStoreError> {
        let session_id = format!("ses_{}", generate_random_hex(12));
        let ts = now_unix();
        let clean_ip = sanitize_boundary_text(client_ip, 64).unwrap_or_else(|_| "0.0.0.0".to_string());

        let conn = self.conn.lock().expect("db mutex poisoned");
        // Opportunistic expired session pruning to prevent unbounded table growth
        let _ = conn.execute("DELETE FROM skm_sessions WHERE expires_at <= ?1", params![ts]);
        conn.execute(
            "INSERT INTO skm_sessions (session_id, tenant_id, user_id, token_jti, issued_at, expires_at, is_revoked, client_ip)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, ?7)",
            params![session_id, tenant_id, user_id, token_jti, ts, ts + ttl_secs, clean_ip],
        )
        .map_err(|_| SekhmetStoreError::DatabaseError)?;
        Ok(session_id)
    }

    pub fn is_jti_active(&self, token_jti: &str) -> Result<bool, SekhmetStoreError> {
        let ts = now_unix();
        let conn = self.conn.lock().expect("db mutex poisoned");
        let row: Option<(i64, i64)> = conn
            .query_row(
                "SELECT is_revoked, expires_at FROM skm_sessions WHERE token_jti = ?1",
                params![token_jti],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(|_| SekhmetStoreError::DatabaseError)?;

        match row {
            Some((0, exp)) if exp > ts => Ok(true),
            _ => Ok(false),
        }
    }

    pub fn revoke_jti(&self, tenant_id: &str, token_jti: &str) -> Result<(), SekhmetStoreError> {
        let conn = self.conn.lock().expect("db mutex poisoned");
        conn.execute(
            "UPDATE skm_sessions SET is_revoked = 1 WHERE tenant_id = ?1 AND token_jti = ?2",
            params![tenant_id, token_jti],
        )
        .map_err(|_| SekhmetStoreError::DatabaseError)?;
        self.append_audit_locked(&conn, tenant_id, "session", "SESSION_REVOKED", token_jti)?;
        Ok(())
    }

    pub fn mint_api_key(
        &self,
        tenant_id: &str,
        user_id: &str,
        label: &str,
        allowed_cidrs_csv: &str,
        allowed_domains_csv: &str,
    ) -> Result<MintedApiKey, SekhmetStoreError> {
        let clean_label = sanitize_boundary_text(label, 128)
            .map_err(|e| SekhmetStoreError::Validation(e.to_string()))?;

        let conn = self.conn.lock().expect("db mutex poisoned");

        // 1. Verify user belongs to tenant and has verified email
        let is_verified: Option<i64> = conn
            .query_row(
                "SELECT is_email_verified FROM skm_users WHERE user_id = ?1 AND tenant_id = ?2 AND is_locked = 0",
                params![user_id, tenant_id],
                |r| r.get(0),
            )
            .optional()
            .map_err(|_| SekhmetStoreError::DatabaseError)?;

        match is_verified {
            Some(1) => {}
            Some(_) => return Err(SekhmetStoreError::EmailVerificationRequired),
            None => return Err(SekhmetStoreError::InvalidCredentials),
        }

        // 2. Check tenant subscription status and tier limits
        let tenant_row: Option<(String, String, i64)> = conn
            .query_row(
                "SELECT subscription_tier, subscription_status, max_api_keys FROM skm_tenants WHERE tenant_id = ?1",
                params![tenant_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()
            .map_err(|_| SekhmetStoreError::DatabaseError)?;

        let Some((tier, status, max_keys)) = tenant_row else {
            return Err(SekhmetStoreError::Validation("Tenant not found.".to_string()));
        };
        if status != "active" {
            return Err(SekhmetStoreError::SubscriptionInactive);
        }

        let active_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM skm_api_keys WHERE tenant_id = ?1 AND is_revoked = 0",
                params![tenant_id],
                |r| r.get(0),
            )
            .map_err(|_| SekhmetStoreError::DatabaseError)?;

        if active_count >= max_keys {
            return Err(SekhmetStoreError::KeyQuotaExceeded);
        }

        let tier_limits = self.get_tier_limits(&tier)?;
        let norm_cidrs = validate_cidr_csv(allowed_cidrs_csv, tier_limits.max_cidrs)
            .map_err(|e| SekhmetStoreError::Validation(e.to_string()))?;
        let norm_domains = validate_domain_csv(allowed_domains_csv, tier_limits.max_domains)
            .map_err(|e| SekhmetStoreError::Validation(e.to_string()))?;

        let (key_id, key_prefix, raw_key, secret_hash_hex) = generate_sovereign_api_key();
        let ts = now_unix();

        conn.execute(
            "INSERT INTO skm_api_keys (key_id, tenant_id, owner_user_id, key_prefix, secret_hash_hex, label, allowed_cidrs, allowed_domains, is_revoked, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 0, ?9)",
            params![
                key_id,
                tenant_id,
                user_id,
                key_prefix,
                secret_hash_hex,
                clean_label,
                norm_cidrs,
                norm_domains,
                ts
            ],
        )
        .map_err(|_| SekhmetStoreError::DatabaseError)?;

        self.append_audit_locked(&conn, tenant_id, user_id, "API_KEY_MINTED", &key_id)?;

        Ok(MintedApiKey {
            key_id,
            key_prefix,
            raw_key,
            label: clean_label,
            allowed_cidrs: norm_cidrs,
            allowed_domains: norm_domains,
        })
    }

    pub fn verify_api_key(
        &self,
        raw_key: &str,
        caller_ip: &str,
        caller_domain: &str,
    ) -> Result<VerifiedApiKeyContext, SekhmetStoreError> {
        let trimmed = raw_key.trim();
        if !trimmed.starts_with("skm_live_") || trimmed.len() > 128 {
            return Err(SekhmetStoreError::ApiKeyUnauthorized);
        }
        let secret_hash = sha256_hex(trimmed.as_bytes());
        let conn = self.conn.lock().expect("db mutex poisoned");

        let row: Option<(String, String, String, String, String, i64, String, String)> = conn
            .query_row(
                "SELECT k.key_id, k.tenant_id, k.owner_user_id, k.allowed_cidrs, k.allowed_domains, k.is_revoked,
                        t.subscription_tier, t.subscription_status
                 FROM skm_api_keys k
                 JOIN skm_tenants t ON t.tenant_id = k.tenant_id
                 WHERE k.secret_hash_hex = ?1",
                params![secret_hash],
                |r| {
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
                },
            )
            .optional()
            .map_err(|_| SekhmetStoreError::DatabaseError)?;

        let Some((
            key_id,
            tenant_id,
            owner_user_id,
            allowed_cidrs,
            allowed_domains,
            is_revoked,
            subscription_tier,
            subscription_status,
        )) = row
        else {
            return Err(SekhmetStoreError::ApiKeyUnauthorized);
        };

        if is_revoked != 0 || subscription_status != "active" {
            return Err(SekhmetStoreError::ApiKeyUnauthorized);
        }
        if !check_ip_allowed(&allowed_cidrs, caller_ip)
            || !check_domain_allowed(&allowed_domains, caller_domain)
        {
            self.append_audit_locked(
                &conn,
                &tenant_id,
                &key_id,
                "API_KEY_BOUNDARY_REJECTED",
                &format!("ip={} domain={}", caller_ip, caller_domain),
            )?;
            return Err(SekhmetStoreError::ApiKeyUnauthorized);
        }

        Ok(VerifiedApiKeyContext {
            key_id,
            tenant_id,
            owner_user_id,
            subscription_tier,
        })
    }

    pub fn revoke_api_key(
        &self,
        tenant_id: &str,
        actor_user_id: &str,
        key_id: &str,
    ) -> Result<(), SekhmetStoreError> {
        let conn = self.conn.lock().expect("db mutex poisoned");
        let updated = conn
            .execute(
                "UPDATE skm_api_keys SET is_revoked = 1 WHERE key_id = ?1 AND tenant_id = ?2",
                params![key_id, tenant_id],
            )
            .map_err(|_| SekhmetStoreError::DatabaseError)?;
        if updated == 0 {
            return Err(SekhmetStoreError::ApiKeyUnauthorized);
        }
        self.append_audit_locked(&conn, tenant_id, actor_user_id, "API_KEY_REVOKED", key_id)?;
        Ok(())
    }

    pub(crate) fn append_audit_locked(
        &self,
        conn: &Connection,
        tenant_id: &str,
        actor_id: &str,
        event_type: &str,
        detail: &str,
    ) -> Result<String, SekhmetStoreError> {
        let prev_hash: String = conn
            .query_row(
                "SELECT entry_hash FROM skm_merkle_audit_log ORDER BY seq DESC LIMIT 1",
                [],
                |r| r.get(0),
            )
            .optional()
            .map_err(|_| SekhmetStoreError::DatabaseError)?
            .unwrap_or_else(|| GENESIS_PREV_HASH.to_string());

        let clean_detail =
            sanitize_boundary_text(detail, 1024).unwrap_or_else(|_| "none".to_string());
        let ts = now_unix();
        let entry_hash = compute_merkle_entry_hash(
            &prev_hash,
            ts,
            tenant_id,
            actor_id,
            event_type,
            &clean_detail,
        );

        conn.execute(
            "INSERT INTO skm_merkle_audit_log (timestamp, tenant_id, actor_id, event_type, detail_sanitized, prev_hash, entry_hash)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![ts, tenant_id, actor_id, event_type, clean_detail, prev_hash, entry_hash],
        )
        .map_err(|_| SekhmetStoreError::DatabaseError)?;

        Ok(entry_hash)
    }

    /// Cryptographically verifies the entire linear SHA-256 Merkle audit chain from Genesis.
    pub fn verify_merkle_chain(&self) -> Result<(usize, String), SekhmetStoreError> {
        let conn = self.conn.lock().expect("db mutex poisoned");
        let mut stmt = conn
            .prepare(
                "SELECT seq, timestamp, tenant_id, actor_id, event_type, detail_sanitized, prev_hash, entry_hash
                 FROM skm_merkle_audit_log ORDER BY seq ASC",
            )
            .map_err(|_| SekhmetStoreError::DatabaseError)?;

        let mut rows = stmt
            .query([])
            .map_err(|_| SekhmetStoreError::DatabaseError)?;
        let mut expected_prev = GENESIS_PREV_HASH.to_string();
        let mut count = 0usize;

        while let Some(r) = rows.next().map_err(|_| SekhmetStoreError::DatabaseError)? {
            let seq: i64 = r.get(0).map_err(|_| SekhmetStoreError::DatabaseError)?;
            let ts: i64 = r.get(1).map_err(|_| SekhmetStoreError::DatabaseError)?;
            let tid: String = r.get(2).map_err(|_| SekhmetStoreError::DatabaseError)?;
            let actor: String = r.get(3).map_err(|_| SekhmetStoreError::DatabaseError)?;
            let ev: String = r.get(4).map_err(|_| SekhmetStoreError::DatabaseError)?;
            let detail: String = r.get(5).map_err(|_| SekhmetStoreError::DatabaseError)?;
            let prev: String = r.get(6).map_err(|_| SekhmetStoreError::DatabaseError)?;
            let entry: String = r.get(7).map_err(|_| SekhmetStoreError::DatabaseError)?;

            if prev != expected_prev {
                return Err(SekhmetStoreError::MerkleTamperDetected(seq));
            }
            let recomputed = compute_merkle_entry_hash(&prev, ts, &tid, &actor, &ev, &detail);
            if recomputed != entry {
                return Err(SekhmetStoreError::MerkleTamperDetected(seq));
            }
            expected_prev = entry;
            count += 1;
        }
        Ok((count, expected_prev))
    }
}
