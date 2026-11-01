# Changelog — Sekhmet Sovereign Auth & Identity Engine

All notable changes to the official pre-compiled distribution of `sekhmet` are documented in this file.

## [v0.1.0] — 2026-11-01

### Added
- **Universal Multi-OS Standalone Binaries**: Pre-compiled release executables for Linux (`x86_64`, `aarch64`), Windows (`x86_64`), and macOS (`x86_64`, `aarch64`).
- **Single-Source-of-Truth (SST) Configuration (`sekhmet.yaml`)**: Built-in `sekhmet config init` and `sekhmet config validate` commands covering network bindings, token TTLs, password length policies, admin 2FA enforcement, perimeter rate limits, and tier quotas.
- **RFC-Compliant Identity & Token Custody**:
  - RFC 9106 Argon2id password hashing with constant-time dummy verification against account enumeration.
  - RFC 8032 Ed25519 asymmetric JWT signing (`alg: EdDSA`) and RFC 7517 `/.well-known/jwks.json` discovery.
  - RFC 6238 TOTP two-factor authentication and 6-digit email OTP verification gates.
- **Boundary-Locked API Keys (`skm_live_...`)**: IPv4/IPv6 bitwise CIDR prefix enforcement and wildcard domain origin validation.
- **Multi-OS Native Service Lifecycle**: `sekhmet service preview|install` supporting `systemd`, `openrc`, `freebsd`, `windows`, and `macos`.
- **Tamper-Evident Audit Chain**: Built-in `sekhmet audit` CLI and `/v1/audit/verify` endpoint.
