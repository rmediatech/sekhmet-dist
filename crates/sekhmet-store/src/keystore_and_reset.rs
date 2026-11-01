use crate::{now_unix, SekhmetStore, SekhmetStoreError};
use rusqlite::{params, OptionalExtension};
use sekhmet_crypto::{
    generate_6digit_otp, generate_random_hex, hash_password, sha256_hex,
    validate_ed25519_seed_entropy, SekhmetEd25519Signer, SekhmetKeyRing,
};
use sekhmet_sanitize::validate_and_normalize_email;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyRingStatus {
    pub primary_kid: String,
    pub retiring_kid: Option<String>,
}

impl SekhmetStore {
    /// Loads the active + retiring Ed25519 Key Ring directly from SQLite WAL (`skm_keystore`),
    /// initializing and sealing a CSPRNG root keypair on first boot if none exists.
    pub fn load_or_init_keyring(
        &self,
        override_seed_hex: Option<&str>,
    ) -> Result<SekhmetKeyRing, SekhmetStoreError> {
        let conn = self.conn.lock().expect("db mutex poisoned");
        if let Some(seed) = override_seed_hex.filter(|s| !s.trim().is_empty()) {
            let primary = SekhmetEd25519Signer::from_seed_hex(seed).map_err(|_| {
                SekhmetStoreError::Validation(
                    "Invalid or low-entropy signing_key_seed_hex.".to_string(),
                )
            })?;
            let retiring = self.load_slot_signer_locked(&conn, "retiring_ed25519")?;
            return Ok(SekhmetKeyRing { primary, retiring });
        }

        let primary = match self.load_slot_signer_locked(&conn, "root_ed25519")? {
            Some(s) => s,
            None => {
                let new_seed_hex = generate_random_hex(32);
                let signer = SekhmetEd25519Signer::from_seed_hex(&new_seed_hex)
                    .map_err(|_| SekhmetStoreError::DatabaseError)?;
                let ts = now_unix();
                conn.execute(
                    "INSERT INTO skm_keystore (key_slot, seed_hex, key_id, created_at) VALUES ('root_ed25519', ?1, ?2, ?3)",
                    params![new_seed_hex, signer.key_id(), ts],
                )
                .map_err(|_| SekhmetStoreError::DatabaseError)?;

                self.append_audit_locked(
                    &conn,
                    "system",
                    "keystore",
                    "ROOT_ED25519_INITIALIZED",
                    signer.key_id(),
                )?;
                signer
            }
        };

        let retiring = self.load_slot_signer_locked(&conn, "retiring_ed25519")?;
        Ok(SekhmetKeyRing { primary, retiring })
    }

    fn load_slot_signer_locked(
        &self,
        conn: &rusqlite::Connection,
        slot: &str,
    ) -> Result<Option<SekhmetEd25519Signer>, SekhmetStoreError> {
        let seed_opt: Option<String> = conn
            .query_row(
                "SELECT seed_hex FROM skm_keystore WHERE key_slot = ?1",
                params![slot],
                |r| r.get(0),
            )
            .optional()
            .map_err(|_| SekhmetStoreError::DatabaseError)?;

        match seed_opt {
            Some(seed) => Ok(Some(
                SekhmetEd25519Signer::from_seed_hex(&seed)
                    .map_err(|_| SekhmetStoreError::DatabaseError)?,
            )),
            None => Ok(None),
        }
    }

    /// Rotates the root Ed25519 signing key to a newly generated CSPRNG seed.
    /// When `emergency == false` (Graceful), retains the previous key in `retiring_ed25519` for 0-downtime session upgrade.
    /// When `emergency == true`, purges `retiring_ed25519` and revokes all active sessions globally.
    pub fn rotate_root_key(&self, emergency: bool) -> Result<KeyRingStatus, SekhmetStoreError> {
        let new_seed_hex = generate_random_hex(32);
        self.apply_new_root_seed(&new_seed_hex, emergency, "ROTATED")
    }

    /// Imports a user-supplied BYOK 64-hex-char Ed25519 seed after validating cryptographic entropy.
    pub fn import_byok_key(
        &self,
        seed_hex: &str,
        emergency: bool,
    ) -> Result<KeyRingStatus, SekhmetStoreError> {
        let _ = validate_ed25519_seed_entropy(seed_hex).map_err(|_| {
            SekhmetStoreError::Validation(
                "BYOK seed rejected: must be 64 hex chars with high byte entropy.".to_string(),
            )
        })?;
        self.apply_new_root_seed(seed_hex.trim(), emergency, "IMPORTED_BYOK")
    }

    fn apply_new_root_seed(
        &self,
        new_seed_hex: &str,
        emergency: bool,
        reason_tag: &str,
    ) -> Result<KeyRingStatus, SekhmetStoreError> {
        let new_signer = SekhmetEd25519Signer::from_seed_hex(new_seed_hex)
            .map_err(|_| SekhmetStoreError::Validation("Invalid Ed25519 seed.".to_string()))?;
        let new_kid = new_signer.key_id().to_string();
        let ts = now_unix();

        let conn = self.conn.lock().expect("db mutex poisoned");
        let old_row: Option<(String, String)> = conn
            .query_row(
                "SELECT seed_hex, key_id FROM skm_keystore WHERE key_slot = 'root_ed25519'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(|_| SekhmetStoreError::DatabaseError)?;

        let mut retiring_kid = None;
        if emergency {
            conn.execute(
                "DELETE FROM skm_keystore WHERE key_slot = 'retiring_ed25519'",
                [],
            )
            .map_err(|_| SekhmetStoreError::DatabaseError)?;
            conn.execute("UPDATE skm_sessions SET is_revoked = 1", [])
                .map_err(|_| SekhmetStoreError::DatabaseError)?;
        } else if let Some((ref old_seed, ref old_kid)) = old_row {
            if old_kid != &new_kid {
                conn.execute(
                    "INSERT INTO skm_keystore (key_slot, seed_hex, key_id, created_at)
                     VALUES ('retiring_ed25519', ?1, ?2, ?3)
                     ON CONFLICT(key_slot) DO UPDATE SET seed_hex = excluded.seed_hex, key_id = excluded.key_id, created_at = excluded.created_at",
                    params![old_seed, old_kid, ts],
                )
                .map_err(|_| SekhmetStoreError::DatabaseError)?;
                retiring_kid = Some(old_kid.clone());
            }
        }

        conn.execute(
            "INSERT INTO skm_keystore (key_slot, seed_hex, key_id, created_at)
             VALUES ('root_ed25519', ?1, ?2, ?3)
             ON CONFLICT(key_slot) DO UPDATE SET seed_hex = excluded.seed_hex, key_id = excluded.key_id, created_at = excluded.created_at",
            params![new_seed_hex, new_kid, ts],
        )
        .map_err(|_| SekhmetStoreError::DatabaseError)?;

        let mode = if emergency { "EMERGENCY" } else { "GRACEFUL" };
        self.append_audit_locked(
            &conn,
            "system",
            "keystore",
            &format!("ROOT_ED25519_{}_{}", reason_tag, mode),
            &format!("primary={} retiring={:?}", new_kid, retiring_kid),
        )?;

        Ok(KeyRingStatus {
            primary_kid: new_kid,
            retiring_kid,
        })
    }

    pub fn request_password_reset(
        &self,
        tenant_id: &str,
        email: &str,
    ) -> Result<String, SekhmetStoreError> {
        let norm_email = validate_and_normalize_email(email)
            .map_err(|_| SekhmetStoreError::InvalidCredentials)?;
        let otp_code = generate_6digit_otp();
        let otp_hash = sha256_hex(otp_code.as_bytes());
        let ts = now_unix();

        let conn = self.conn.lock().expect("db mutex poisoned");
        let user_id: Option<String> = conn
            .query_row(
                "SELECT user_id FROM skm_users WHERE tenant_id = ?1 AND email = ?2 AND is_locked = 0",
                params![tenant_id, norm_email],
                |r| r.get(0),
            )
            .optional()
            .map_err(|_| SekhmetStoreError::DatabaseError)?;

        let Some(uid) = user_id else {
            return Err(SekhmetStoreError::InvalidCredentials);
        };

        conn.execute(
            "UPDATE skm_users SET email_otp_hash = ?1, email_otp_expires = ?2 WHERE user_id = ?3",
            params![otp_hash, ts + 900, uid],
        )
        .map_err(|_| SekhmetStoreError::DatabaseError)?;

        self.append_audit_locked(
            &conn,
            tenant_id,
            &uid,
            "PASSWORD_RESET_REQUESTED",
            &norm_email,
        )?;
        Ok(otp_code)
    }

    pub fn confirm_password_reset(
        &self,
        tenant_id: &str,
        email: &str,
        otp_code: &str,
        new_password: &str,
        min_password_len: usize,
    ) -> Result<(), SekhmetStoreError> {
        if new_password.len() < min_password_len {
            return Err(SekhmetStoreError::Validation(
                "Password shorter than policy minimum.".to_string(),
            ));
        }
        let norm_email = validate_and_normalize_email(email)
            .map_err(|_| SekhmetStoreError::InvalidCredentials)?;
        let candidate_hash = sha256_hex(otp_code.trim().as_bytes());
        let new_pw_hash = hash_password(new_password)
            .map_err(|_| SekhmetStoreError::Validation("Invalid password.".to_string()))?;
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
            self.append_audit_locked(
                &conn,
                tenant_id,
                &user_id,
                "PASSWORD_RESET_OTP_FAILED",
                &norm_email,
            )?;
            return Err(SekhmetStoreError::InvalidCredentials);
        }

        conn.execute(
            "UPDATE skm_users SET password_hash = ?1, is_email_verified = 1, email_otp_hash = NULL, email_otp_expires = NULL WHERE user_id = ?2",
            params![new_pw_hash, user_id],
        )
        .map_err(|_| SekhmetStoreError::DatabaseError)?;

        // Automatically revoke all prior sessions for this user upon password rotation
        conn.execute(
            "UPDATE skm_sessions SET is_revoked = 1 WHERE tenant_id = ?1 AND user_id = ?2",
            params![tenant_id, user_id],
        )
        .map_err(|_| SekhmetStoreError::DatabaseError)?;

        self.append_audit_locked(
            &conn,
            tenant_id,
            &user_id,
            "PASSWORD_RESET_COMPLETED",
            &norm_email,
        )?;
        Ok(())
    }

    /// Prunes expired or revoked sessions, verifies the SHA-256 Merkle chain, and checkpoints SQLite WAL.
    pub fn run_maintenance(&self) -> Result<(usize, usize, String), SekhmetStoreError> {
        let ts = now_unix();
        let pruned = {
            let conn = self.conn.lock().expect("db mutex poisoned");
            conn.execute(
                "DELETE FROM skm_sessions WHERE expires_at <= ?1 OR is_revoked = 1",
                params![ts],
            )
            .map_err(|_| SekhmetStoreError::DatabaseError)?
        };
        let (entries, head_hash) = self.verify_merkle_chain()?;
        {
            let conn = self.conn.lock().expect("db mutex poisoned");
            conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE); PRAGMA optimize;")
                .map_err(|_| SekhmetStoreError::DatabaseError)?;
        }
        Ok((pruned, entries, head_hash))
    }
}
