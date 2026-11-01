# 🦁 SOVEREIGN SEKHMET AUTH & IDENTITY ARCHITECTURE STANDARD

> **Workspace Root:** `/home/emhcet/private/projects/desktop/rust/sekhmet`  
> **Classical Archetype:** **Sekhmet (سخمت)** — *The Powerful One*, Solar Lioness & Guardian of the Pharaoh's Threshold (Nilotic Pantheon)  
> **Global Standards Inherited:** `AGY-RULE-SOVEREIGN-FLAGSHIP-01`, `AGY-RULE-SOVEREIGN-SECURITY-01`, `SOVEREIGN-RFC-BAREMETAL-01`, `SOVEREIGN-FORTHRIGHT-01`, `SOVEREIGN-QUOTA-BROTHERHOOD-01`  
> **Master Release Key:** `4E428019A109578B` (`Rick Walker <rick@rmediatech.com>`)

---

## 🏗️ 1. One-Job-Principle (OJP) Sub-Crate Architecture

| Crate | Sovereign Responsibility |
| :--- | :--- |
| **`sekhmet`** *(Root)* | Thin CLI & Axum HTTP/JSON server (`serve`, `service`, `audit`) |
| **`sekhmet-sanitize`** | Boundary defense: formula neutralization, ANSI CSI/OSC scrubbing, RFC 5322 email & OS service path validation |
| **`sekhmet-crypto`** | Bare-metal RFC crypto: RFC 9106 Argon2id timing equalizer, RFC 8032 Ed25519 + RFC 7519 JWT/JWKS, RFC 6238 TOTP & SHA-256 Merkle chain |
| **`sekhmet-cidr`** | Bitwise IPv4/IPv6 CIDR prefix evaluator & domain origin allowlist guard |
| **`sekhmet-shield`** | Phylax structural honeypots (`<5ns`), sliding token-bucket rate limiter & Slow-Shield cross-IP handle velocity guard |
| **`sekhmet-service`** | Multi-OS bare-metal service manifest generator & installer (`systemd`, `OpenRC`, `FreeBSD rc.d`, `Windows SCM`, `macOS launchd`) |
| **`sekhmet-store`** | Pristine single-schema SQLite WAL persistence (`schema.sql`) with tamper-evident SHA-256 Merkle audit log |
| **`sekhmet-config`** | Single-Source-of-Truth (SST) bare-metal YAML configuration parser, validator & canonical generator (`sekhmet.yaml`) |
