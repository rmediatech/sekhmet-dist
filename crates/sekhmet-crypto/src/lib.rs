use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::sync::OnceLock;
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SekhmetCryptoError {
    #[error("Password hashing or verification failed.")]
    PasswordError,
    #[error("Malformed or forged cryptographic token.")]
    InvalidToken,
    #[error("Cryptographic token has expired.")]
    ExpiredToken,
    #[error("Invalid or low-entropy hex key material.")]
    InvalidKeyMaterial,
}

static DUMMY_ARGON2_HASH: OnceLock<String> = OnceLock::new();

fn get_dummy_hash() -> &'static str {
    DUMMY_ARGON2_HASH.get_or_init(|| {
        let salt = SaltString::from_b64("c2VraG1ldHNvdmVyZWlnbg").expect("valid static salt");
        Argon2::default()
            .hash_password(b"sekhmet-dummy-equalizer-secret", &salt)
            .expect("valid dummy hash")
            .to_string()
    })
}

/// Validates a 32-byte (64-hex-char) Ed25519 seed for structural validity and minimum byte entropy.
/// Rejects all-zero, constant-byte, or low-diversity weak BYOK seeds.
pub fn validate_ed25519_seed_entropy(seed_hex: &str) -> Result<[u8; 32], SekhmetCryptoError> {
    let trimmed = seed_hex.trim();
    if trimmed.len() != 64 {
        return Err(SekhmetCryptoError::InvalidKeyMaterial);
    }
    let bytes = hex::decode(trimmed).map_err(|_| SekhmetCryptoError::InvalidKeyMaterial)?;
    let seed: [u8; 32] = bytes
        .try_into()
        .map_err(|_| SekhmetCryptoError::InvalidKeyMaterial)?;

    let unique_bytes: HashSet<u8> = seed.iter().copied().collect();
    if unique_bytes.len() < 8 {
        return Err(SekhmetCryptoError::InvalidKeyMaterial);
    }
    Ok(seed)
}

/// Hashes a plaintext password using RFC 9106 Argon2id.
pub fn hash_password(password: &str) -> Result<String, SekhmetCryptoError> {
    if password.len() < 8 || password.len() > 256 {
        return Err(SekhmetCryptoError::PasswordError);
    }
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|_| SekhmetCryptoError::PasswordError)
}

/// Verifies a password against an optional stored Argon2id hash.
/// When `stored_hash` is `None` (missing user), executes a full Argon2id cycle
/// against a static dummy hash to eliminate timing-based account enumeration.
pub fn verify_password_equalized(stored_hash: Option<&str>, candidate: &str) -> bool {
    let target_hash_str = stored_hash.unwrap_or_else(|| get_dummy_hash());
    let Ok(parsed_hash) = PasswordHash::new(target_hash_str) else {
        return false;
    };
    let ok = Argon2::default()
        .verify_password(candidate.as_bytes(), &parsed_hash)
        .is_ok();
    stored_hash.is_some() && ok
}

/// RFC 7519 JWT Header strictly pinned to EdDSA (RFC 8032 Ed25519).
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct JwtHeader {
    alg: String,
    typ: String,
    kid: String,
}

/// Standard + Sovereign RFC 7519 JWT Claims.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SekhmetClaims {
    pub iss: String,
    pub sub: String,
    pub tid: String,
    pub role: String,
    pub jti: String,
    pub iat: i64,
    pub exp: i64,
}

#[derive(Clone)]
pub struct SekhmetEd25519Signer {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
    key_id: String,
}

impl SekhmetEd25519Signer {
    pub fn generate() -> Self {
        let mut rng = OsRng;
        let signing_key = SigningKey::generate(&mut rng);
        let verifying_key = signing_key.verifying_key();
        let pub_hash = sha256_hex(verifying_key.as_bytes());
        let key_id = format!("skm-ed25519-{}", &pub_hash[..12]);
        Self {
            signing_key,
            verifying_key,
            key_id,
        }
    }

    pub fn from_seed_hex(seed_hex: &str) -> Result<Self, SekhmetCryptoError> {
        let seed = validate_ed25519_seed_entropy(seed_hex)?;
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();
        let pub_hash = sha256_hex(verifying_key.as_bytes());
        let key_id = format!("skm-ed25519-{}", &pub_hash[..12]);
        Ok(Self {
            signing_key,
            verifying_key,
            key_id,
        })
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    pub fn sign_jwt(&self, claims: &SekhmetClaims) -> Result<String, SekhmetCryptoError> {
        let header = JwtHeader {
            alg: "EdDSA".to_string(),
            typ: "JWT".to_string(),
            kid: self.key_id.clone(),
        };
        let h_b64 = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&header).map_err(|_| SekhmetCryptoError::InvalidToken)?,
        );
        let c_b64 = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(claims).map_err(|_| SekhmetCryptoError::InvalidToken)?,
        );
        let signing_input = format!("{}.{}", h_b64, c_b64);
        let sig: Signature = self.signing_key.sign(signing_input.as_bytes());
        let s_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());
        Ok(format!("{}.{}", signing_input, s_b64))
    }

    pub fn verify_jwt(
        &self,
        token: &str,
        now_unix: i64,
    ) -> Result<SekhmetClaims, SekhmetCryptoError> {
        if token.len() > 4096 {
            return Err(SekhmetCryptoError::InvalidToken);
        }
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(SekhmetCryptoError::InvalidToken);
        }
        let header_bytes = URL_SAFE_NO_PAD
            .decode(parts[0])
            .map_err(|_| SekhmetCryptoError::InvalidToken)?;
        let header: JwtHeader = serde_json::from_slice(&header_bytes)
            .map_err(|_| SekhmetCryptoError::InvalidToken)?;

        if header.alg != "EdDSA" || header.typ != "JWT" || header.kid != self.key_id {
            return Err(SekhmetCryptoError::InvalidToken);
        }

        let sig_bytes = URL_SAFE_NO_PAD
            .decode(parts[2])
            .map_err(|_| SekhmetCryptoError::InvalidToken)?;
        let sig = Signature::from_slice(&sig_bytes)
            .map_err(|_| SekhmetCryptoError::InvalidToken)?;
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        self.verifying_key
            .verify(signing_input.as_bytes(), &sig)
            .map_err(|_| SekhmetCryptoError::InvalidToken)?;

        let claims_bytes = URL_SAFE_NO_PAD
            .decode(parts[1])
            .map_err(|_| SekhmetCryptoError::InvalidToken)?;
        let claims: SekhmetClaims = serde_json::from_slice(&claims_bytes)
            .map_err(|_| SekhmetCryptoError::InvalidToken)?;

        if claims.exp <= now_unix {
            return Err(SekhmetCryptoError::ExpiredToken);
        }
        Ok(claims)
    }

    pub fn jwk_entry(&self) -> serde_json::Value {
        let x_b64 = URL_SAFE_NO_PAD.encode(self.verifying_key.as_bytes());
        serde_json::json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "alg": "EdDSA",
            "use": "sig",
            "kid": self.key_id,
            "x": x_b64
        })
    }

    pub fn jwks_json(&self) -> serde_json::Value {
        serde_json::json!({ "keys": [self.jwk_entry()] })
    }
}

/// Dual-Slot Ed25519 Key Ring supporting 0-downtime graceful key rollover and silent token re-signing.
#[derive(Clone)]
pub struct SekhmetKeyRing {
    pub primary: SekhmetEd25519Signer,
    pub retiring: Option<SekhmetEd25519Signer>,
}

impl SekhmetKeyRing {
    pub fn sign_jwt(&self, claims: &SekhmetClaims) -> Result<String, SekhmetCryptoError> {
        self.primary.sign_jwt(claims)
    }

    /// Verifies a JWT against the Primary key first, then falls back to the Retiring key.
    /// If verified via the Retiring key, automatically mints a fresh `replacement_token` signed by Primary!
    pub fn verify_jwt_with_upgrade(
        &self,
        token: &str,
        now_unix: i64,
    ) -> Result<(SekhmetClaims, Option<String>), SekhmetCryptoError> {
        match self.primary.verify_jwt(token, now_unix) {
            Ok(claims) => Ok((claims, None)),
            Err(SekhmetCryptoError::ExpiredToken) => Err(SekhmetCryptoError::ExpiredToken),
            Err(_) => {
                if let Some(ref retiring) = self.retiring {
                    let claims = retiring.verify_jwt(token, now_unix)?;
                    let replacement = self.primary.sign_jwt(&claims)?;
                    Ok((claims, Some(replacement)))
                } else {
                    Err(SekhmetCryptoError::InvalidToken)
                }
            }
        }
    }

    pub fn jwks_json(&self) -> serde_json::Value {
        let mut keys = vec![self.primary.jwk_entry()];
        if let Some(ref retiring) = self.retiring {
            if retiring.key_id() != self.primary.key_id() {
                keys.push(retiring.jwk_entry());
            }
        }
        serde_json::json!({ "keys": keys })
    }
}

/// Bare-metal RFC 6238 TOTP & RFC 4226 HOTP 6-digit code calculation (HMAC-SHA1 per RFC 6238 default).
pub fn rfc6238_totp_at(secret: &[u8], unix_seconds: u64, step_secs: u64) -> String {
    let counter = unix_seconds / step_secs.max(1);
    let counter_bytes = counter.to_be_bytes();
    let mut mac = Hmac::<Sha1>::new_from_slice(secret).expect("HMAC accepts any key size");
    mac.update(&counter_bytes);
    let result = mac.finalize().into_bytes();
    let offset = (result[19] & 0x0f) as usize;
    let binary = ((u32::from(result[offset] & 0x7f)) << 24)
        | ((u32::from(result[offset + 1])) << 16)
        | ((u32::from(result[offset + 2])) << 8)
        | u32::from(result[offset + 3]);
    let otp = binary % 1_000_000;
    format!("{:06}", otp)
}

pub fn verify_totp_window(secret_hex: &str, code: &str, now_unix: u64) -> bool {
    let Ok(secret) = hex::decode(secret_hex) else {
        return false;
    };
    let trimmed = code.trim();
    if trimmed.len() != 6 || !trimmed.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    for offset in [0i64, -30, 30] {
        let ts = (now_unix as i64 + offset).max(0) as u64;
        if rfc6238_totp_at(&secret, ts, 30) == trimmed {
            return true;
        }
    }
    false
}

pub fn generate_random_hex(byte_len: usize) -> String {
    let mut buf = vec![0u8; byte_len];
    OsRng.fill_bytes(&mut buf);
    hex::encode(buf)
}

pub fn generate_6digit_otp() -> String {
    let mut buf = [0u8; 4];
    OsRng.fill_bytes(&mut buf);
    let num = u32::from_be_bytes(buf) % 900_000 + 100_000;
    format!("{:06}", num)
}

pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

pub fn compute_merkle_entry_hash(
    prev_hash: &str,
    timestamp: i64,
    tenant_id: &str,
    actor_id: &str,
    event_type: &str,
    detail_sanitized: &str,
) -> String {
    let preimage = format!(
        "{}|{}|{}|{}|{}|{}",
        prev_hash, timestamp, tenant_id, actor_id, event_type, detail_sanitized
    );
    sha256_hex(preimage.as_bytes())
}

pub fn generate_sovereign_api_key() -> (String, String, String, String) {
    let id_suffix = generate_random_hex(6);
    let secret_part = generate_random_hex(24);
    let key_id = format!("key_{}", id_suffix);
    let prefix = format!("skm_live_{}", &secret_part[..8]);
    let raw_key = format!("skm_live_{}", secret_part);
    let secret_hash = sha256_hex(raw_key.as_bytes());
    (key_id, prefix, raw_key, secret_hash)
}
