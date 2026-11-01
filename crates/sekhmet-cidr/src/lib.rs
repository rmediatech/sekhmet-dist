use std::net::IpAddr;
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SekhmetCidrError {
    #[error("Invalid CIDR or IP notation: {0}")]
    InvalidCidr(String),
    #[error("Invalid domain allowlist entry: {0}")]
    InvalidDomain(String),
    #[error("Maximum boundary list entries exceeded (max {0}).")]
    TooManyEntries(usize),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CidrBlock {
    V4 { network: u32, mask: u32 },
    V6 { network: u128, mask: u128 },
}

impl CidrBlock {
    pub fn parse(raw: &str) -> Result<Self, SekhmetCidrError> {
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.len() > 64 {
            return Err(SekhmetCidrError::InvalidCidr(raw.to_string()));
        }
        let (ip_part, prefix_opt) = match trimmed.split_once('/') {
            Some((ip, p)) => (ip, Some(p)),
            None => (trimmed, None),
        };
        let addr: IpAddr = ip_part
            .parse()
            .map_err(|_| SekhmetCidrError::InvalidCidr(raw.to_string()))?;

        match addr {
            IpAddr::V4(v4) => {
                let prefix: u8 = match prefix_opt {
                    Some(p) => p
                        .parse()
                        .map_err(|_| SekhmetCidrError::InvalidCidr(raw.to_string()))?,
                    None => 32,
                };
                if prefix > 32 {
                    return Err(SekhmetCidrError::InvalidCidr(raw.to_string()));
                }
                let mask = if prefix == 0 {
                    0
                } else {
                    !0u32 << (32 - prefix)
                };
                let ip_u32 = u32::from(v4);
                Ok(CidrBlock::V4 {
                    network: ip_u32 & mask,
                    mask,
                })
            }
            IpAddr::V6(v6) => {
                let prefix: u8 = match prefix_opt {
                    Some(p) => p
                        .parse()
                        .map_err(|_| SekhmetCidrError::InvalidCidr(raw.to_string()))?,
                    None => 128,
                };
                if prefix > 128 {
                    return Err(SekhmetCidrError::InvalidCidr(raw.to_string()));
                }
                let mask = if prefix == 0 {
                    0
                } else {
                    !0u128 << (128 - prefix)
                };
                let ip_u128 = u128::from(v6);
                Ok(CidrBlock::V6 {
                    network: ip_u128 & mask,
                    mask,
                })
            }
        }
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self, ip) {
            (CidrBlock::V4 { network, mask }, IpAddr::V4(v4)) => {
                (u32::from(v4) & mask) == *network
            }
            (CidrBlock::V6 { network, mask }, IpAddr::V6(v6)) => {
                (u128::from(v6) & mask) == *network
            }
            _ => false,
        }
    }
}

pub fn validate_cidr_csv(csv: &str, max_entries: usize) -> Result<String, SekhmetCidrError> {
    if csv.trim().is_empty() {
        return Ok(String::new());
    }
    let mut normalized = Vec::new();
    for entry in csv.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        if normalized.len() >= max_entries {
            return Err(SekhmetCidrError::TooManyEntries(max_entries));
        }
        let _ = CidrBlock::parse(entry)?;
        normalized.push(entry.to_string());
    }
    Ok(normalized.join(","))
}

pub fn check_ip_allowed(allowed_cidrs_csv: &str, caller_ip_str: &str) -> bool {
    if allowed_cidrs_csv.trim().is_empty() {
        return true;
    }
    let Ok(caller_ip) = caller_ip_str.trim().parse::<IpAddr>() else {
        return false;
    };
    for entry in allowed_cidrs_csv
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        if let Ok(block) = CidrBlock::parse(entry) {
            if block.contains(caller_ip) {
                return true;
            }
        }
    }
    false
}

pub fn validate_domain_csv(csv: &str, max_entries: usize) -> Result<String, SekhmetCidrError> {
    if csv.trim().is_empty() {
        return Ok(String::new());
    }
    let mut normalized = Vec::new();
    for raw in csv.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        if normalized.len() >= max_entries {
            return Err(SekhmetCidrError::TooManyEntries(max_entries));
        }
        let d = raw.to_ascii_lowercase();
        let check = d.strip_prefix("*.").unwrap_or(&d);
        if check.len() < 3
            || check.len() > 253
            || !check.contains('.')
            || check.starts_with('.')
            || check.ends_with('.')
            || check.bytes().any(|b| !(b.is_ascii_alphanumeric() || b == b'-' || b == b'.'))
        {
            return Err(SekhmetCidrError::InvalidDomain(raw.to_string()));
        }
        normalized.push(d);
    }
    Ok(normalized.join(","))
}

pub fn check_domain_allowed(allowed_domains_csv: &str, caller_domain: &str) -> bool {
    if allowed_domains_csv.trim().is_empty() {
        return true;
    }
    let host = caller_domain
        .trim()
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    if host.is_empty() {
        return false;
    }
    for pattern in allowed_domains_csv
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        if let Some(suffix) = pattern.strip_prefix("*.") {
            if host == suffix || host.ends_with(&format!(".{}", suffix)) {
                return true;
            }
        } else if host == pattern {
            return true;
        }
    }
    false
}
