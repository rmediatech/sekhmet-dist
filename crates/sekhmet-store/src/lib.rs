pub mod keys_and_audit;
pub mod keystore_and_reset;
pub mod self_heal;
pub mod self_learn;

pub use rusqlite;
use rusqlite::{params, Connection, OptionalExtension};
use sekhmet_crypto::{
    generate_6digit_otp, generate_random_hex, hash_password, sha256_hex,
    verify_password_equalized, verify_totp_window,
};
use sekhmet_sanitize::{sanitize_boundary_text, validate_and_normalize_email};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

pub const PRISTINE_SCHEMA_SQL: &str = include_str!("../../../schema.sql");
pub const GENESIS_PREV_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Error)]
pub enum SekhmetStoreError {
    #[error("Input validation constraint violated: {0}")]
    Validation(String),
    #[error("Authentication failed: invalid credentials.")]
    InvalidCredentials,
    #[error("Two-factor TOTP verification code required or invalid.")]
    TotpRequiredOrInvalid,
    #[error("Email verification is required before performing this operation.")]
    EmailVerificationRequired,
    #[error("Tenant subscription is not active.")]
    SubscriptionInactive,
    #[error("Subscription tier API key quota reached.")]
    KeyQuotaExceeded,
    #[error("API key rejected: unauthorized IP, domain, or revoked key.")]
    ApiKeyUnauthorized,
    #[error("Merkle cryptographic audit chain integrity violation at seq {0}.")]
    MerkleTamperDetected(i64),
    #[error("Storage engine error.")]
    DatabaseError,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TierLimits {
    pub max_keys: i64,
    pub max_cidrs: usize,
    pub max_domains: usize,
}

pub fn default_tier_map() -> HashMap<String, TierLimits> {
    let mut m = HashMap::new();
    m.insert(
        "community".to_string(),
        TierLimits {
            max_keys: 1,
            max_cidrs: 1,
            max_domains: 1,
        },
    );
    m.insert(
        "starter".to_string(),
        TierLimits {
            max_keys: 5,
            max_cidrs: 3,
            max_domains: 3,
        },
    );
    m.insert(
        "business".to_string(),
        TierLimits {
            max_keys: 15,
            max_cidrs: 15,
            max_domains: 10,
        },
    );
    m.insert(
        "profleet".to_string(),
        TierLimits {
            max_keys: 50,
            max_cidrs: 100,
            max_domains: 50,
        },
    );
    m
}

pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisteredUser {
    pub user_id: String,
    pub tenant_id: String,
    pub email: String,
    pub display_name: String,
    pub otp_code: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatedUser {
    pub user_id: String,
    pub tenant_id: String,
    pub email: String,
    pub display_name: String,
    pub role: String,
    pub is_email_verified: bool,
}

pub struct SekhmetStore {
    pub(crate) conn: Mutex<Connection>,
    pub(crate) tier_limits: HashMap<String, TierLimits>,
}

impl SekhmetStore {
    pub fn open(db_path: &str) -> Result<Self, SekhmetStoreError> {
        Self::open_with_tiers(db_path, default_tier_map())
    }

    pub fn open_with_tiers(
        db_path: &str,
        tier_limits: HashMap<String, TierLimits>,
    ) -> Result<Self, SekhmetStoreError> {
        let conn = if db_path == ":memory:" {
            Connection::open_in_memory()
        } else {
            Connection::open(db_path)
        }
        .map_err(|_| SekhmetStoreError::DatabaseError)?;

        conn.execute_batch(PRISTINE_SCHEMA_SQL)
            .map_err(|_| SekhmetStoreError::DatabaseError)?;

        let store = Self {
            conn: Mutex::new(conn),
            tier_limits,
        };
        let _ = store.self_heal(0);
        Ok(store)
    }

    pub fn get_tier_limits(&self, tier: &str) -> Result<TierLimits, SekhmetStoreError> {
        self.tier_limits.get(tier).copied().ok_or_else(|| {
            SekhmetStoreError::Validation("Unsupported subscription tier.".to_string())
        })
    }

    pub fn create_tenant(
        &self,
        tenant_id: &str,
        display_name: &str,
        tier: &str,
    ) -> Result<String, SekhmetStoreError> {
        let clean_tid = sanitize_boundary_text(tenant_id, 64)
            .map_err(|e| SekhmetStoreError::Validation(e.to_string()))?;
        if clean_tid.starts_with('\'') || clean_tid.len() < 3 {
            return Err(SekhmetStoreError::Validation(
                "Invalid tenant_id.".to_string(),
            ));
        }
        let clean_name = sanitize_boundary_text(display_name, 128)
            .map_err(|e| SekhmetStoreError::Validation(e.to_string()))?;
        let limits = self.get_tier_limits(tier)?;
        let ts = now_unix();

        let conn = self.conn.lock().expect("db mutex poisoned");
        conn.execute(
            "INSERT INTO skm_tenants (tenant_id, display_name, subscription_tier, subscription_status, max_api_keys, created_at)
             VALUES (?1, ?2, ?3, 'active', ?4, ?5)",
            params![clean_tid, clean_name, tier, limits.max_keys, ts],
        )
        .map_err(|_| SekhmetStoreError::Validation("Tenant already exists or invalid.".to_string()))?;

        self.append_audit_locked(&conn, &clean_tid, "system", "TENANT_CREATED", &clean_name)?;
        Ok(clean_name)
    }

    pub fn update_tenant_subscription(
        &self,
        tenant_id: &str,
        tier: &str,
        status: &str,
    ) -> Result<(), SekhmetStoreError> {
        let limits = self.get_tier_limits(tier)?;
        if !matches!(status, "active" | "past_due" | "suspended" | "canceled") {
            return Err(SekhmetStoreError::Validation(
                "Invalid subscription status.".to_string(),
            ));
        }
        let conn = self.conn.lock().expect("db mutex poisoned");
        let updated = conn
            .execute(
                "UPDATE skm_tenants SET subscription_tier = ?1, subscription_status = ?2, max_api_keys = ?3 WHERE tenant_id = ?4",
                params![tier, status, limits.max_keys, tenant_id],
            )
            .map_err(|_| SekhmetStoreError::DatabaseError)?;
        if updated == 0 {
            return Err(SekhmetStoreError::Validation("Tenant not found.".to_string()));
        }
        self.append_audit_locked(
            &conn,
            tenant_id,
            "billing",
            "SUBSCRIPTION_UPDATED",
            &format!("tier={} status={}", tier, status),
        )?;
        Ok(())
    }

    pub fn register_user(
        &self,
        tenant_id: &str,
        email: &str,
        display_name: &str,
        password: &str,
        role: &str,
        totp_secret_hex: Option<&str>,
    ) -> Result<RegisteredUser, SekhmetStoreError> {
        let norm_email = validate_and_normalize_email(email)
            .map_err(|e| SekhmetStoreError::Validation(e.to_string()))?;
        let clean_name = sanitize_boundary_text(display_name, 128)
            .map_err(|e| SekhmetStoreError::Validation(e.to_string()))?;
        if !matches!(role, "owner" | "admin" | "member" | "service") {
            return Err(SekhmetStoreError::Validation("Invalid role.".to_string()));
        }
        let pw_hash = hash_password(password)
            .map_err(|_| SekhmetStoreError::Validation("Weak or oversized password.".to_string()))?;

        let otp_code = generate_6digit_otp();
        let otp_hash = sha256_hex(otp_code.as_bytes());
        let ts = now_unix();
        let user_id = format!("usr_{}", generate_random_hex(8));

        let conn = self.conn.lock().expect("db mutex poisoned");
        conn.execute(
            "INSERT INTO skm_users (user_id, tenant_id, email, display_name, password_hash, totp_secret_hex, is_email_verified, email_otp_hash, email_otp_expires, role, is_locked, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, ?7, ?8, ?9, 0, ?10)",
            params![
                user_id,
                tenant_id,
                norm_email,
                clean_name,
                pw_hash,
                totp_secret_hex,
                otp_hash,
                ts + 900,
                role,
                ts
            ],
        )
        .map_err(|_| SekhmetStoreError::Validation("User already registered or tenant invalid.".to_string()))?;

        self.append_audit_locked(&conn, tenant_id, &user_id, "USER_REGISTERED", &norm_email)?;
        Ok(RegisteredUser {
            user_id,
            tenant_id: tenant_id.to_string(),
            email: norm_email,
            display_name: clean_name,
            otp_code,
        })
    }

    pub fn verify_email_otp(
        &self,
        tenant_id: &str,
        email: &str,
        otp_code: &str,
    ) -> Result<(), SekhmetStoreError> {
        let norm_email = validate_and_normalize_email(email)
            .map_err(|_| SekhmetStoreError::InvalidCredentials)?;
        let candidate_hash = sha256_hex(otp_code.trim().as_bytes());
        let ts = now_unix();

        let conn = self.conn.lock().expect("db mutex poisoned");
        let row: Option<(String, Option<String>, Option<i64>)> = conn
            .query_row(
                "SELECT user_id, email_otp_hash, email_otp_expires FROM skm_users WHERE tenant_id = ?1 AND email = ?2",
                params![tenant_id, norm_email],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()
            .map_err(|_| SekhmetStoreError::DatabaseError)?;

        let Some((user_id, Some(stored_hash), Some(expires))) = row else {
            return Err(SekhmetStoreError::InvalidCredentials);
        };
        if ts > expires || stored_hash != candidate_hash {
            self.append_audit_locked(&conn, tenant_id, &user_id, "EMAIL_OTP_FAILED", &norm_email)?;
            return Err(SekhmetStoreError::InvalidCredentials);
        }

        conn.execute(
            "UPDATE skm_users SET is_email_verified = 1, email_otp_hash = NULL, email_otp_expires = NULL WHERE user_id = ?1",
            params![user_id],
        )
        .map_err(|_| SekhmetStoreError::DatabaseError)?;

        self.append_audit_locked(&conn, tenant_id, &user_id, "EMAIL_VERIFIED", &norm_email)?;
        Ok(())
    }

    pub fn authenticate_user(
        &self,
        tenant_id: &str,
        email: &str,
        password: &str,
        totp_code: Option<&str>,
    ) -> Result<AuthenticatedUser, SekhmetStoreError> {
        let norm_email = validate_and_normalize_email(email).unwrap_or_default();
        let conn = self.conn.lock().expect("db mutex poisoned");
        let row: Option<(String, String, String, Option<String>, i64, String, i64)> = conn
            .query_row(
                "SELECT user_id, display_name, password_hash, totp_secret_hex, is_email_verified, role, is_locked
                 FROM skm_users WHERE tenant_id = ?1 AND email = ?2",
                params![tenant_id, norm_email],
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                        r.get(6)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| SekhmetStoreError::DatabaseError)?;

        let stored_hash = row.as_ref().map(|r| r.2.as_str());
        let pw_ok = verify_password_equalized(stored_hash, password);

        let Some((user_id, display_name, _, totp_secret, is_verified, role, is_locked)) = row
        else {
            return Err(SekhmetStoreError::InvalidCredentials);
        };

        if !pw_ok || is_locked != 0 {
            self.append_audit_locked(&conn, tenant_id, &user_id, "AUTH_LOGIN_FAILED", &norm_email)?;
            return Err(SekhmetStoreError::InvalidCredentials);
        }

        if let Some(secret_hex) = totp_secret {
            let code = totp_code.ok_or(SekhmetStoreError::TotpRequiredOrInvalid)?;
            if !verify_totp_window(&secret_hex, code, now_unix() as u64) {
                self.append_audit_locked(&conn, tenant_id, &user_id, "AUTH_TOTP_FAILED", &norm_email)?;
                return Err(SekhmetStoreError::TotpRequiredOrInvalid);
            }
        }

        self.append_audit_locked(&conn, tenant_id, &user_id, "AUTH_LOGIN_SUCCESS", &norm_email)?;
        Ok(AuthenticatedUser {
            user_id,
            tenant_id: tenant_id.to_string(),
            email: norm_email,
            display_name,
            role,
            is_email_verified: is_verified != 0,
        })
    }
}
