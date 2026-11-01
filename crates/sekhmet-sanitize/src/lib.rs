use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SekhmetSanitizeError {
    #[error("Input exceeds maximum permitted byte length ({max} bytes).")]
    LengthExceeded { max: usize },
    #[error("Input cannot be empty.")]
    EmptyInput,
    #[error("Invalid RFC 5322 email address format.")]
    InvalidEmail,
    #[error("Path traversal or shell injection payload rejected.")]
    UnsafePath,
}

/// Scrubs raw ANSI CSI/OSC escape sequences and unprintable control bytes,
/// and neutralizes spreadsheet formula injection prefixes (`=`, `+`, `-`, `@`, `\t`, `\r`).
pub fn sanitize_boundary_text(input: &str, max_len: usize) -> Result<String, SekhmetSanitizeError> {
    if input.len() > max_len {
        return Err(SekhmetSanitizeError::LengthExceeded { max: max_len });
    }

    let mut clean = String::with_capacity(input.len() + 1);
    let bytes = input.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        let b = bytes[i];
        if b == 0x1B {
            // Skip ANSI CSI (\x1b[...letter) or OSC (\x1b]...BEL/ST)
            i += 1;
            if i < bytes.len() && bytes[i] == b'[' {
                i += 1;
                while i < bytes.len() && !(0x40..=0x7E).contains(&bytes[i]) {
                    i += 1;
                }
                if i < bytes.len() {
                    i += 1;
                }
            } else if i < bytes.len() && bytes[i] == b']' {
                i += 1;
                while i < bytes.len() && bytes[i] != 0x07 && bytes[i] != 0x1B {
                    i += 1;
                }
                if i < bytes.len() {
                    i += 1;
                }
            }
            continue;
        }
        // Strip null bytes and raw control characters
        if b < 0x20 || b == 0x7F {
            i += 1;
            continue;
        }
        clean.push(b as char);
        i += 1;
    }

    let trimmed = clean.trim();
    if trimmed.is_empty() {
        return Err(SekhmetSanitizeError::EmptyInput);
    }

    // Neutralize formula injection payloads even if original input started with \t or \r
    let first_raw = input.chars().next().unwrap_or(' ');
    let first_clean = trimmed.chars().next().unwrap_or(' ');
    let needs_quote = matches!(first_raw, '=' | '+' | '-' | '@' | '\t' | '\r')
        || matches!(first_clean, '=' | '+' | '-' | '@');

    let result = if needs_quote {
        format!("'{}", trimmed)
    } else {
        trimmed.to_string()
    };

    if result.len() > max_len {
        return Err(SekhmetSanitizeError::LengthExceeded { max: max_len });
    }
    Ok(result)
}

/// Validates and normalizes an email address per RFC 5321/5322 structural bounds.
pub fn validate_and_normalize_email(email: &str) -> Result<String, SekhmetSanitizeError> {
    let trimmed = email.trim();
    if trimmed.len() < 3 || trimmed.len() > 254 {
        return Err(SekhmetSanitizeError::InvalidEmail);
    }
    if trimmed.bytes().any(|b| b <= 0x20 || b >= 0x7F) {
        return Err(SekhmetSanitizeError::InvalidEmail);
    }
    let first = trimmed.as_bytes()[0];
    if matches!(first, b'=' | b'+' | b'-' | b'@' | b'.') {
        return Err(SekhmetSanitizeError::InvalidEmail);
    }
    let parts: Vec<&str> = trimmed.split('@').collect();
    if parts.len() != 2 {
        return Err(SekhmetSanitizeError::InvalidEmail);
    }
    let (local, domain) = (parts[0], parts[1]);
    if local.is_empty() || local.len() > 64 || domain.len() < 3 || !domain.contains('.') {
        return Err(SekhmetSanitizeError::InvalidEmail);
    }
    if domain.starts_with('.') || domain.ends_with('.') || domain.contains("..") {
        return Err(SekhmetSanitizeError::InvalidEmail);
    }
    Ok(trimmed.to_ascii_lowercase())
}

/// Validates OS service binary/working paths against directory traversal and command injection.
pub fn validate_safe_os_path(path: &str) -> Result<String, SekhmetSanitizeError> {
    if path.is_empty() || path.len() > 256 {
        return Err(SekhmetSanitizeError::UnsafePath);
    }
    let lower = path.to_ascii_lowercase();
    if lower.contains("..")
        || lower.contains("%2e")
        || lower.contains("%00")
        || path.bytes().any(|b| {
            b < 0x20
                || b == 0x7F
                || matches!(
                    b,
                    b';' | b'|' | b'&' | b'$' | b'`' | b'"' | b'\'' | b'>' | b'<'
                )
        })
    {
        return Err(SekhmetSanitizeError::UnsafePath);
    }
    Ok(path.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_formula_and_ansi_neutralization() {
        let poisoned = "\x1b[31m=CMD|' /C calc'!A0\x1b[0m";
        let safe = sanitize_boundary_text(poisoned, 128).unwrap();
        assert_eq!(safe, "'=CMD|' /C calc'!A0");
    }

    #[test]
    fn test_unsafe_path_rejected() {
        assert!(validate_safe_os_path("/usr/local/bin/sekhmet").is_ok());
        assert!(validate_safe_os_path("/usr/bin/../etc/passwd").is_err());
        assert!(validate_safe_os_path("/usr/bin/sekhmet; rm -rf /").is_err());
    }
}
