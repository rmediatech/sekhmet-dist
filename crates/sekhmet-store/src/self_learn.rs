use crate::{now_unix, SekhmetStore, SekhmetStoreError};
use rusqlite::{params, OptionalExtension};
use sekhmet_sanitize::{sanitize_boundary_text, validate_and_normalize_email};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelRecord {
    pub ip_or_cidr: String,
    pub strike_count: i64,
    pub threat_score: i64,
    pub quarantined_until: i64,
    pub last_reason: String,
    pub subnet_herd_promoted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserBaselineVerdict {
    pub subnet_prefix: String,
    pub is_known_subnet: bool,
    pub unseen_subnet_anomaly: bool,
    pub hit_count: i64,
}

pub fn extract_subnet_prefix(ip_str: &str) -> String {
    if let Ok(ip) = ip_str.trim().parse::<IpAddr>() {
        match ip {
            IpAddr::V4(v4) => {
                let oct = v4.octets();
                format!("{}.{}.{}.0/24", oct[0], oct[1], oct[2])
            }
            IpAddr::V6(v6) => {
                let seg = v6.segments();
                format!("{:x}:{:x}:{:x}::/48", seg[0], seg[1], seg[2])
            }
        }
    } else {
        "unknown/0".to_string()
    }
}

impl SekhmetStore {
    pub fn check_threat_quarantine(
        &self,
        caller_ip: &str,
    ) -> Result<Option<ThreatIntelRecord>, SekhmetStoreError> {
        let clean_ip = caller_ip.trim();
        let subnet_cidr = extract_subnet_prefix(clean_ip);
        let ts = now_unix();
        let conn = self.conn.lock().expect("db mutex poisoned");

        let row: Option<(String, i64, i64, i64, String)> = conn
            .query_row(
                "SELECT ip_or_cidr, strike_count, threat_score, quarantined_until, last_reason
                 FROM skm_threat_memory
                 WHERE (ip_or_cidr = ?1 OR ip_or_cidr = ?2) AND quarantined_until > ?3
                 ORDER BY quarantined_until DESC LIMIT 1",
                params![clean_ip, subnet_cidr, ts],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .optional()
            .map_err(|_| SekhmetStoreError::DatabaseError)?;

        Ok(row.map(
            |(ip_or_cidr, strike_count, threat_score, quarantined_until, last_reason)| {
                let is_subnet = ip_or_cidr.contains('/');
                ThreatIntelRecord {
                    ip_or_cidr,
                    strike_count,
                    threat_score,
                    quarantined_until,
                    last_reason,
                    subnet_herd_promoted: is_subnet,
                }
            },
        ))
    }

    pub fn learn_threat_signal(
        &self,
        caller_ip: &str,
        weight: i64,
        reason: &str,
    ) -> Result<ThreatIntelRecord, SekhmetStoreError> {
        let clean_ip = sanitize_boundary_text(caller_ip.trim(), 64)
            .unwrap_or_else(|_| "0.0.0.0".to_string());
        let clean_reason =
            sanitize_boundary_text(reason, 128).unwrap_or_else(|_| "ADVERSARIAL_SIGNAL".to_string());
        let ts = now_unix();
        let w = weight.max(1);

        let conn = self.conn.lock().expect("db mutex poisoned");
        let existing: Option<(i64, i64, i64)> = conn
            .query_row(
                "SELECT strike_count, threat_score, quarantined_until FROM skm_threat_memory WHERE ip_or_cidr = ?1",
                params![clean_ip],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()
            .map_err(|_| SekhmetStoreError::DatabaseError)?;

        let (strikes, score, prev_q) = match existing {
            Some((s, sc, pq)) => (s + 1, sc + w, pq),
            None => (1, w, 0),
        };

        let quarantined_until = if score >= 10 {
            let backoff_secs = if strikes <= 2 {
                900
            } else if strikes <= 5 {
                3600
            } else if strikes <= 9 {
                21600
            } else {
                86400
            };
            (ts + backoff_secs).max(prev_q)
        } else {
            prev_q
        };

        conn.execute(
            "INSERT INTO skm_threat_memory (ip_or_cidr, strike_count, threat_score, quarantined_until, last_reason, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(ip_or_cidr) DO UPDATE SET
                strike_count = excluded.strike_count,
                threat_score = excluded.threat_score,
                quarantined_until = excluded.quarantined_until,
                last_reason = excluded.last_reason,
                updated_at = excluded.updated_at",
            params![clean_ip, strikes, score, quarantined_until, clean_reason, ts],
        )
        .map_err(|_| SekhmetStoreError::DatabaseError)?;

        let mut subnet_herd_promoted = false;
        let subnet_cidr = extract_subnet_prefix(&clean_ip);
        if let Some(octets_prefix) = subnet_cidr.strip_suffix("0/24") {
            let like_pattern = format!("{}%", octets_prefix);
            let quarantined_peers: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM skm_threat_memory WHERE ip_or_cidr LIKE ?1 AND ip_or_cidr NOT LIKE '%/%' AND quarantined_until > ?2",
                    params![like_pattern, ts],
                    |r| r.get(0),
                )
                .unwrap_or(0);

            if quarantined_peers >= 3 {
                let herd_until = ts + 7200;
                conn.execute(
                    "INSERT INTO skm_threat_memory (ip_or_cidr, strike_count, threat_score, quarantined_until, last_reason, updated_at)
                     VALUES (?1, ?2, 30, ?3, 'HERD_SUBNET_BOTNET_ESCALATION', ?4)
                     ON CONFLICT(ip_or_cidr) DO UPDATE SET
                        strike_count = strike_count + 1,
                        threat_score = threat_score + 10,
                        quarantined_until = MAX(quarantined_until, excluded.quarantined_until),
                        last_reason = excluded.last_reason,
                        updated_at = excluded.updated_at",
                    params![subnet_cidr, quarantined_peers, herd_until, ts],
                )
                .map_err(|_| SekhmetStoreError::DatabaseError)?;
                subnet_herd_promoted = true;
                let _ = self.append_audit_locked(
                    &conn,
                    "system",
                    "self-learn",
                    "SELF_LEARN_SUBNET_QUARANTINED",
                    &format!("subnet={} peers={}", subnet_cidr, quarantined_peers),
                );
            }
        }

        Ok(ThreatIntelRecord {
            ip_or_cidr: clean_ip,
            strike_count: strikes,
            threat_score: score,
            quarantined_until,
            last_reason: clean_reason,
            subnet_herd_promoted,
        })
    }

    pub fn is_trusted_user_subnet(&self, tenant_id: &str, email: &str, caller_ip: &str) -> bool {
        let Ok(norm_email) = validate_and_normalize_email(email) else {
            return false;
        };
        let subnet_prefix = extract_subnet_prefix(caller_ip);
        let conn = self.conn.lock().expect("db mutex poisoned");
        let hits: Option<i64> = conn
            .query_row(
                "SELECT b.hit_count FROM skm_user_baselines b
                 JOIN skm_users u ON u.user_id = b.user_id
                 WHERE u.tenant_id = ?1 AND u.email = ?2 AND b.subnet_prefix = ?3",
                params![tenant_id, norm_email, subnet_prefix],
                |r| r.get(0),
            )
            .optional()
            .unwrap_or(None);
        hits.unwrap_or(0) >= 2
    }

    pub fn learn_and_evaluate_user_baseline(
        &self,
        user_id: &str,
        tenant_id: &str,
        caller_ip: &str,
    ) -> Result<UserBaselineVerdict, SekhmetStoreError> {
        let subnet_prefix = extract_subnet_prefix(caller_ip);
        let ts = now_unix();
        let conn = self.conn.lock().expect("db mutex poisoned");

        let total_known_subnets: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM skm_user_baselines WHERE user_id = ?1",
                params![user_id],
                |r| r.get(0),
            )
            .unwrap_or(0);

        let existing_hits: Option<i64> = conn
            .query_row(
                "SELECT hit_count FROM skm_user_baselines WHERE user_id = ?1 AND subnet_prefix = ?2",
                params![user_id, subnet_prefix],
                |r| r.get(0),
            )
            .optional()
            .map_err(|_| SekhmetStoreError::DatabaseError)?;

        let is_known_subnet = existing_hits.is_some();
        let unseen_subnet_anomaly = total_known_subnets > 0 && !is_known_subnet;
        let new_hits = existing_hits.unwrap_or(0) + 1;

        conn.execute(
            "INSERT INTO skm_user_baselines (user_id, subnet_prefix, hit_count, first_seen, last_seen)
             VALUES (?1, ?2, ?3, ?4, ?4)
             ON CONFLICT(user_id, subnet_prefix) DO UPDATE SET
                hit_count = excluded.hit_count,
                last_seen = excluded.last_seen",
            params![user_id, subnet_prefix, new_hits, ts],
        )
        .map_err(|_| SekhmetStoreError::DatabaseError)?;

        if unseen_subnet_anomaly {
            let _ = self.append_audit_locked(
                &conn,
                tenant_id,
                user_id,
                "SELF_LEARN_UNSEEN_SUBNET",
                &format!("new_subnet={}", subnet_prefix),
            );
        }

        Ok(UserBaselineVerdict {
            subnet_prefix,
            is_known_subnet,
            unseen_subnet_anomaly,
            hit_count: new_hits,
        })
    }
}
