use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SekhmetShieldError {
    #[error("Perimeter honeypot triggered; automated bot traffic rejected.")]
    HoneypotTriggered,
    #[error("Rate limit exceeded; please slow down.")]
    RateLimited,
    #[error("Cross-IP account velocity threshold exceeded; cool-down active.")]
    AccountVelocityExceeded,
}

#[derive(Debug, Clone)]
struct TokenBucket {
    tokens: f64,
    last_refill: Instant,
}

#[derive(Debug, Clone)]
struct HandleVelocityWindow {
    failures: u32,
    window_start: Instant,
}

pub struct SekhmetPerimeterShield {
    capacity: f64,
    refill_per_sec: f64,
    max_handle_failures_per_min: u32,
    ip_buckets: Mutex<HashMap<String, TokenBucket>>,
    handle_velocity: Mutex<HashMap<String, HandleVelocityWindow>>,
}

impl Default for SekhmetPerimeterShield {
    fn default() -> Self {
        Self::new(120.0, 30.0, 10)
    }
}

impl SekhmetPerimeterShield {
    pub fn new(capacity: f64, refill_per_sec: f64, max_handle_failures_per_min: u32) -> Self {
        Self {
            capacity,
            refill_per_sec,
            max_handle_failures_per_min,
            ip_buckets: Mutex::new(HashMap::new()),
            handle_velocity: Mutex::new(HashMap::new()),
        }
    }

    /// Checks structural honeypot fields (`website_url`, `company_fax`) in <5ns.
    #[inline]
    pub fn check_honeypot(
        website_url: Option<&str>,
        company_fax: Option<&str>,
    ) -> Result<(), SekhmetShieldError> {
        if website_url.map(|s| !s.is_empty()).unwrap_or(false)
            || company_fax.map(|s| !s.is_empty()).unwrap_or(false)
        {
            return Err(SekhmetShieldError::HoneypotTriggered);
        }
        Ok(())
    }

    /// Enforces sliding token-bucket rate limit per caller IP.
    pub fn check_ip_rate_limit(&self, ip: &str, cost: f64) -> Result<(), SekhmetShieldError> {
        let mut map = self.ip_buckets.lock().expect("shield mutex poisoned");
        if map.len() > 16_384 {
            map.clear();
        }
        let now = Instant::now();
        let bucket = map.entry(ip.to_string()).or_insert(TokenBucket {
            tokens: self.capacity,
            last_refill: now,
        });
        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.refill_per_sec).min(self.capacity);
        bucket.last_refill = now;

        if bucket.tokens < cost {
            return Err(SekhmetShieldError::RateLimited);
        }
        bucket.tokens -= cost;
        Ok(())
    }

    /// Tracks cross-IP velocity per account handle (`slow-shield` pattern) to defeat residential proxy credential stuffing.
    pub fn check_handle_velocity(&self, handle: &str) -> Result<(), SekhmetShieldError> {
        let key = handle.trim().to_ascii_lowercase();
        let mut map = self.handle_velocity.lock().expect("velocity mutex poisoned");
        let now = Instant::now();
        if let Some(entry) = map.get_mut(&key) {
            if now.duration_since(entry.window_start).as_secs() >= 60 {
                entry.failures = 0;
                entry.window_start = now;
            }
            if entry.failures >= self.max_handle_failures_per_min {
                return Err(SekhmetShieldError::AccountVelocityExceeded);
            }
        }
        Ok(())
    }

    pub fn record_handle_failure(&self, handle: &str) {
        let key = handle.trim().to_ascii_lowercase();
        let mut map = self.handle_velocity.lock().expect("velocity mutex poisoned");
        if map.len() > 16_384 {
            map.clear();
        }
        let now = Instant::now();
        let entry = map.entry(key).or_insert(HandleVelocityWindow {
            failures: 0,
            window_start: now,
        });
        if now.duration_since(entry.window_start).as_secs() >= 60 {
            entry.failures = 1;
            entry.window_start = now;
        } else {
            entry.failures = entry.failures.saturating_add(1);
        }
    }
}
