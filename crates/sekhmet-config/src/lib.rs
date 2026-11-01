use sekhmet_sanitize::{sanitize_boundary_text, validate_safe_os_path};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

pub const MAX_CONFIG_BYTES: usize = 65_536;
pub const MAX_CONFIG_LINES: usize = 1_024;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SekhmetConfigError {
    #[error("Configuration file exceeds maximum size ({MAX_CONFIG_BYTES} bytes) or line count.")]
    PayloadTooLarge,
    #[error("Syntax error on line {line}: {reason}")]
    SyntaxError { line: usize, reason: String },
    #[error("Unknown configuration key '{section}.{key}' on line {line}.")]
    UnknownKey {
        line: usize,
        section: String,
        key: String,
    },
    #[error("Invalid value for '{key}': {reason}")]
    ValidationError { key: String, reason: String },
    #[error("Failed to read or write configuration file: {0}")]
    IoError(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TierQuotaConfig {
    pub max_keys: i64,
    pub max_cidrs: usize,
    pub max_domains: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SekhmetSstConfig {
    // [server]
    pub bind_addr: String,
    pub trust_forwarded_headers: bool,
    // [storage]
    pub db_path: String,
    pub signing_key_seed_hex: Option<String>,
    // [tokens]
    pub issuer: String,
    pub access_token_ttl_secs: i64,
    pub email_otp_ttl_secs: i64,
    // [policy]
    pub min_password_length: usize,
    pub require_totp_for_admins: bool,
    // [shield]
    pub honeypot_enabled: bool,
    pub ip_burst_capacity: f64,
    pub ip_refill_per_sec: f64,
    pub max_failed_logins_per_handle_per_min: u32,
    // [tiers]
    pub tiers: HashMap<String, TierQuotaConfig>,
}

impl Default for SekhmetSstConfig {
    fn default() -> Self {
        let mut tiers = HashMap::new();
        tiers.insert(
            "community".to_string(),
            TierQuotaConfig {
                max_keys: 1,
                max_cidrs: 1,
                max_domains: 1,
            },
        );
        tiers.insert(
            "starter".to_string(),
            TierQuotaConfig {
                max_keys: 5,
                max_cidrs: 3,
                max_domains: 3,
            },
        );
        tiers.insert(
            "business".to_string(),
            TierQuotaConfig {
                max_keys: 15,
                max_cidrs: 15,
                max_domains: 10,
            },
        );
        tiers.insert(
            "profleet".to_string(),
            TierQuotaConfig {
                max_keys: 50,
                max_cidrs: 100,
                max_domains: 50,
            },
        );

        Self {
            bind_addr: "127.0.0.1:4410".to_string(),
            trust_forwarded_headers: true,
            db_path: "./sekhmet.db".to_string(),
            signing_key_seed_hex: None,
            issuer: "sekhmet.rmediatech.sovereign".to_string(),
            access_token_ttl_secs: 3600,
            email_otp_ttl_secs: 900,
            min_password_length: 8,
            require_totp_for_admins: false,
            honeypot_enabled: true,
            ip_burst_capacity: 120.0,
            ip_refill_per_sec: 30.0,
            max_failed_logins_per_handle_per_min: 10,
            tiers,
        }
    }
}

impl SekhmetSstConfig {
    /// Generates a canonical, self-documenting SST YAML configuration file.
    pub fn render_canonical_yaml(&self) -> String {
        format!(
            "# ============================================================================\n\
             # SEKHMET (سخمت) — UNIVERSAL SINGLE-SOURCE-OF-TRUTH (SST) CONFIGURATION\n\
             # Standard: SOVEREIGN-RFC-BAREMETAL-01\n\
             # ============================================================================\n\
             \n\
             server:\n\
             \x20 bind_addr: \"{}\"\n\
             \x20 trust_forwarded_headers: {}\n\
             \n\
             storage:\n\
             \x20 db_path: \"{}\"\n\
             \x20 signing_key_seed_hex: \"{}\"\n\
             \n\
             tokens:\n\
             \x20 issuer: \"{}\"\n\
             \x20 access_token_ttl_secs: {}\n\
             \x20 email_otp_ttl_secs: {}\n\
             \n\
             policy:\n\
             \x20 min_password_length: {}\n\
             \x20 require_totp_for_admins: {}\n\
             \n\
             shield:\n\
             \x20 honeypot_enabled: {}\n\
             \x20 ip_burst_capacity: {:.1}\n\
             \x20 ip_refill_per_sec: {:.1}\n\
             \x20 max_failed_logins_per_handle_per_min: {}\n\
             \n\
             tiers:\n\
             \x20 community_max_keys: 1\n\
             \x20 community_max_cidrs: 1\n\
             \x20 community_max_domains: 1\n\
             \x20 starter_max_keys: 5\n\
             \x20 starter_max_cidrs: 3\n\
             \x20 starter_max_domains: 3\n\
             \x20 business_max_keys: 15\n\
             \x20 business_max_cidrs: 15\n\
             \x20 business_max_domains: 10\n\
             \x20 profleet_max_keys: 50\n\
             \x20 profleet_max_cidrs: 100\n\
             \x20 profleet_max_domains: 50\n",
            self.bind_addr,
            self.trust_forwarded_headers,
            self.db_path,
            self.signing_key_seed_hex.as_deref().unwrap_or(""),
            self.issuer,
            self.access_token_ttl_secs,
            self.email_otp_ttl_secs,
            self.min_password_length,
            self.require_totp_for_admins,
            self.honeypot_enabled,
            self.ip_burst_capacity,
            self.ip_refill_per_sec,
            self.max_failed_logins_per_handle_per_min
        )
    }

    /// Parses and strictly validates a bare-metal SST YAML configuration string.
    pub fn parse_yaml(raw: &str) -> Result<Self, SekhmetConfigError> {
        if raw.len() > MAX_CONFIG_BYTES {
            return Err(SekhmetConfigError::PayloadTooLarge);
        }
        let mut cfg = Self::default();
        let mut current_section = String::new();

        let lines: Vec<&str> = raw.lines().collect();
        if lines.len() > MAX_CONFIG_LINES {
            return Err(SekhmetConfigError::PayloadTooLarge);
        }

        for (idx, raw_line) in lines.into_iter().enumerate() {
            let line_num = idx + 1;
            let trimmed_comment = match raw_line.find('#') {
                Some(pos) => &raw_line[..pos],
                None => raw_line,
            };
            let trimmed = trimmed_comment.trim();
            if trimmed.is_empty() {
                continue;
            }

            let is_indented = raw_line.starts_with(' ') || raw_line.starts_with('\t');
            if !is_indented && trimmed.ends_with(':') {
                let sec = trimmed.trim_end_matches(':').trim();
                if !matches!(
                    sec,
                    "server" | "storage" | "tokens" | "policy" | "shield" | "tiers"
                ) {
                    return Err(SekhmetConfigError::SyntaxError {
                        line: line_num,
                        reason: format!("Unknown top-level section '{}'", sec),
                    });
                }
                current_section = sec.to_string();
                continue;
            }

            let Some((k_raw, v_raw)) = trimmed.split_once(':') else {
                return Err(SekhmetConfigError::SyntaxError {
                    line: line_num,
                    reason: "Expected 'key: value' pair".to_string(),
                });
            };
            let key = k_raw.trim();
            let val = unquote(v_raw.trim());

            match (current_section.as_str(), key) {
                ("server", "bind_addr") => cfg.bind_addr = val.to_string(),
                ("server", "trust_forwarded_headers") => {
                    cfg.trust_forwarded_headers = parse_bool(key, val)?
                }
                ("storage", "db_path") => cfg.db_path = val.to_string(),
                ("storage", "signing_key_seed_hex") => {
                    if val.is_empty() {
                        cfg.signing_key_seed_hex = None;
                    } else {
                        cfg.signing_key_seed_hex = Some(val.to_string());
                    }
                }
                ("tokens", "issuer") => cfg.issuer = val.to_string(),
                ("tokens", "access_token_ttl_secs") => {
                    cfg.access_token_ttl_secs = parse_i64(key, val)?
                }
                ("tokens", "email_otp_ttl_secs") => {
                    cfg.email_otp_ttl_secs = parse_i64(key, val)?
                }
                ("policy", "min_password_length") => {
                    cfg.min_password_length = parse_usize(key, val)?
                }
                ("policy", "require_totp_for_admins") => {
                    cfg.require_totp_for_admins = parse_bool(key, val)?
                }
                ("shield", "honeypot_enabled") => {
                    cfg.honeypot_enabled = parse_bool(key, val)?
                }
                ("shield", "ip_burst_capacity") => {
                    cfg.ip_burst_capacity = parse_f64(key, val)?
                }
                ("shield", "ip_refill_per_sec") => {
                    cfg.ip_refill_per_sec = parse_f64(key, val)?
                }
                ("shield", "max_failed_logins_per_handle_per_min") => {
                    cfg.max_failed_logins_per_handle_per_min = parse_u32(key, val)?
                }
                ("tiers", tier_key) => {
                    apply_tier_override(&mut cfg.tiers, tier_key, val, line_num)?
                }
                _ => {
                    return Err(SekhmetConfigError::UnknownKey {
                        line: line_num,
                        section: current_section.clone(),
                        key: key.to_string(),
                    })
                }
            }
        }

        cfg.validate()?;
        Ok(cfg)
    }

    pub fn load_from_file(path: &str) -> Result<Self, SekhmetConfigError> {
        validate_safe_os_path(path).map_err(|e| SekhmetConfigError::ValidationError {
            key: "config_path".to_string(),
            reason: e.to_string(),
        })?;
        let raw = std::fs::read_to_string(path).map_err(|e| SekhmetConfigError::IoError(e.to_string()))?;
        Self::parse_yaml(&raw)
    }

    pub fn validate(&self) -> Result<(), SekhmetConfigError> {
        if self.bind_addr.is_empty()
            || self.bind_addr.len() > 64
            || !self.bind_addr.contains(':')
            || self
                .bind_addr
                .bytes()
                .any(|b| !(b.is_ascii_alphanumeric() || matches!(b, b'.' | b':' | b'-' | b'[' | b']')))
        {
            return Err(SekhmetConfigError::ValidationError {
                key: "server.bind_addr".to_string(),
                reason: "Must be a valid host:port address.".to_string(),
            });
        }

        if self.db_path != ":memory:" {
            validate_safe_os_path(&self.db_path).map_err(|e| {
                SekhmetConfigError::ValidationError {
                    key: "storage.db_path".to_string(),
                    reason: e.to_string(),
                }
            })?;
        }

        if let Some(ref seed) = self.signing_key_seed_hex {
            if sekhmet_crypto::validate_ed25519_seed_entropy(seed).is_err() {
                return Err(SekhmetConfigError::ValidationError {
                    key: "storage.signing_key_seed_hex".to_string(),
                    reason: "Must be a high-entropy 64-hex-character (32-byte) RFC 8032 Ed25519 seed.".to_string(),
                });
            }
        }

        let clean_issuer = sanitize_boundary_text(&self.issuer, 128).map_err(|e| {
            SekhmetConfigError::ValidationError {
                key: "tokens.issuer".to_string(),
                reason: e.to_string(),
            }
        })?;
        if clean_issuer.starts_with('\'') || clean_issuer != self.issuer {
            return Err(SekhmetConfigError::ValidationError {
                key: "tokens.issuer".to_string(),
                reason: "Issuer contains forbidden formula or control characters.".to_string(),
            });
        }

        if !(60..=2_592_000).contains(&self.access_token_ttl_secs) {
            return Err(SekhmetConfigError::ValidationError {
                key: "tokens.access_token_ttl_secs".to_string(),
                reason: "Must be between 60 and 2592000 seconds.".to_string(),
            });
        }
        if !(60..=86_400).contains(&self.email_otp_ttl_secs) {
            return Err(SekhmetConfigError::ValidationError {
                key: "tokens.email_otp_ttl_secs".to_string(),
                reason: "Must be between 60 and 86400 seconds.".to_string(),
            });
        }
        if !(8..=128).contains(&self.min_password_length) {
            return Err(SekhmetConfigError::ValidationError {
                key: "policy.min_password_length".to_string(),
                reason: "Must be between 8 and 128 characters.".to_string(),
            });
        }
        if !(1.0..=100_000.0).contains(&self.ip_burst_capacity)
            || !(0.1..=100_000.0).contains(&self.ip_refill_per_sec)
        {
            return Err(SekhmetConfigError::ValidationError {
                key: "shield.rate_limit".to_string(),
                reason: "Rate limit capacity and refill must be positive bounded numbers.".to_string(),
            });
        }
        if !(1..=10_000).contains(&self.max_failed_logins_per_handle_per_min) {
            return Err(SekhmetConfigError::ValidationError {
                key: "shield.max_failed_logins_per_handle_per_min".to_string(),
                reason: "Must be between 1 and 10000.".to_string(),
            });
        }

        for (tier_name, quota) in &self.tiers {
            if !(0..=1000).contains(&quota.max_keys)
                || quota.max_cidrs > 500
                || quota.max_domains > 500
            {
                return Err(SekhmetConfigError::ValidationError {
                    key: format!("tiers.{}", tier_name),
                    reason: "Tier quota exceeds safe architectural bounds.".to_string(),
                });
            }
        }

        Ok(())
    }
}

fn unquote(s: &str) -> &str {
    if (s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')) {
        if s.len() >= 2 {
            return &s[1..s.len() - 1];
        }
    }
    s
}

fn parse_bool(key: &str, val: &str) -> Result<bool, SekhmetConfigError> {
    match val {
        "true" | "yes" => Ok(true),
        "false" | "no" => Ok(false),
        _ => Err(SekhmetConfigError::ValidationError {
            key: key.to_string(),
            reason: format!("Expected boolean, got '{}'", val),
        }),
    }
}

fn parse_i64(key: &str, val: &str) -> Result<i64, SekhmetConfigError> {
    val.parse::<i64>()
        .map_err(|_| SekhmetConfigError::ValidationError {
            key: key.to_string(),
            reason: format!("Expected integer, got '{}'", val),
        })
}

fn parse_usize(key: &str, val: &str) -> Result<usize, SekhmetConfigError> {
    val.parse::<usize>()
        .map_err(|_| SekhmetConfigError::ValidationError {
            key: key.to_string(),
            reason: format!("Expected positive integer, got '{}'", val),
        })
}

fn parse_u32(key: &str, val: &str) -> Result<u32, SekhmetConfigError> {
    val.parse::<u32>()
        .map_err(|_| SekhmetConfigError::ValidationError {
            key: key.to_string(),
            reason: format!("Expected u32, got '{}'", val),
        })
}

fn parse_f64(key: &str, val: &str) -> Result<f64, SekhmetConfigError> {
    let v = val
        .parse::<f64>()
        .map_err(|_| SekhmetConfigError::ValidationError {
            key: key.to_string(),
            reason: format!("Expected float, got '{}'", val),
        })?;
    if !v.is_finite() {
        return Err(SekhmetConfigError::ValidationError {
            key: key.to_string(),
            reason: "Float must be finite.".to_string(),
        });
    }
    Ok(v)
}

fn apply_tier_override(
    tiers: &mut HashMap<String, TierQuotaConfig>,
    key: &str,
    val: &str,
    line_num: usize,
) -> Result<(), SekhmetConfigError> {
    let Some((tier, field)) = key.split_once('_') else {
        return Err(SekhmetConfigError::UnknownKey {
            line: line_num,
            section: "tiers".to_string(),
            key: key.to_string(),
        });
    };
    let Some(entry) = tiers.get_mut(tier) else {
        return Err(SekhmetConfigError::UnknownKey {
            line: line_num,
            section: "tiers".to_string(),
            key: key.to_string(),
        });
    };
    match field {
        "max_keys" => entry.max_keys = parse_i64(key, val)?,
        "max_cidrs" => entry.max_cidrs = parse_usize(key, val)?,
        "max_domains" => entry.max_domains = parse_usize(key, val)?,
        _ => {
            return Err(SekhmetConfigError::UnknownKey {
                line: line_num,
                section: "tiers".to_string(),
                key: key.to_string(),
            })
        }
    }
    Ok(())
}
