<p align="center">
  <img src="assets/sekhmet_emblem.svg" width="220" height="220" alt="Sekhmet Sovereign Emblem" />
</p>

<h1 align="center">SEKHMET — Universal Sovereign Auth & Identity Engine</h1>

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS%20%7C%20BSD-blue.svg" alt="Platform" />
  <img src="https://img.shields.io/badge/Standards-RFC%207519%20%7C%20RFC%208032%20%7C%20RFC%206238%20%7C%20RFC%209106-brightgreen.svg" alt="RFC Standards" />
  <img src="https://img.shields.io/badge/Provenance-GPG%20Signed%20(SOVEREIGN--SIGN--01)-blueviolet.svg" alt="Signed" />
  <img src="https://img.shields.io/badge/Privacy-100%25%20Zero--Cloud%20Local%20Custody-success.svg" alt="Privacy" />
</p>

> **Distribution Hub:** Official Pre-Compiled Standalone Binaries & Cryptographic Verification  
> **Supported Operating Systems:** Linux (`x86_64`, `aarch64`) • Windows (`x86_64`) • macOS (`x86_64`, Apple Silicon `aarch64`) • FreeBSD  
> **Universal Stack Compatibility:** Drop-in HTTP/JSON & Ed25519 JWKS identity engine for **Node.js, PHP, Python, Go, Rust, C/C++, Desktop, and Mobile (Android/iOS)** applications.

---

## 🏛️ 1. Overview

**Sekhmet** is a self-contained, zero-cloud authentication, session management, and API key custody daemon distributed as a single standalone executable. It replaces third-party cloud identity providers and heavyweight runtime containers with a single local binary that starts in milliseconds, requires zero external database servers, and speaks standard IETF RFC protocols over HTTP/JSON.

### Key Capabilities
* **Universal Language Interoperability**: Any web, desktop, or mobile application integrates via standard HTTP/JSON requests or verifies asymmetric Ed25519 JWTs locally using the `/.well-known/jwks.json` discovery endpoint.
* **Single-Source-of-Truth (SST) Configuration (`sekhmet.yaml`)**: Customize network bindings, token lifetimes, password policies, rate-limit thresholds, and subscription tier quotas in one declarative file.
* **Built-In Multi-OS Service Installer**: Install and run natively as a background system service across Linux (`systemd` and `OpenRC`), Windows (`Service Control Manager`), FreeBSD (`rc.d`), and macOS (`launchd`).
* **Multi-Factor & Email Verification**: Native RFC 6238 TOTP two-factor authentication and 6-digit email OTP verification gates.
* **Boundary-Locked API Keys (`skm_live_...`)**: Mint and verify machine/tenant API keys locked to specific IPv4/IPv6 CIDR blocks and wildcard domain origins.
* **Tamper-Evident Audit Verification**: Built-in cryptographic hash-chain auditing (`sekhmet audit`) to verify historical log integrity at any time.

---

## 📦 2. Pre-Compiled Binary Matrix (`v0.1.0`)

All binaries in [`bin/`](bin/) are self-contained standalone executables signed with the RMediaTech Sovereign Release Key (`4E428019A109578B`):

| Target Operating System | Architecture | Binary Path | Detached GPG Signature |
| :--- | :--- | :--- | :--- |
| **Linux (Static Standalone)** | `x86_64` | [`bin/sekhmet-v0.1.0-linux-x86_64`](bin/sekhmet-v0.1.0-linux-x86_64) | [`.sha256.asc`](bin/sekhmet-v0.1.0-linux-x86_64.sha256.asc) |
| **Linux (ARM64 Static)** | `aarch64` | [`bin/sekhmet-v0.1.0-linux-aarch64`](bin/sekhmet-v0.1.0-linux-aarch64) | [`.sha256.asc`](bin/sekhmet-v0.1.0-linux-aarch64.sha256.asc) |
| **Windows (Standalone PE)** | `x86_64` | [`bin/sekhmet-v0.1.0-windows-x86_64.exe`](bin/sekhmet-v0.1.0-windows-x86_64.exe) | [`.sha256.asc`](bin/sekhmet-v0.1.0-windows-x86_64.exe.sha256.asc) |
| **macOS (Intel)** | `x86_64` | [`bin/sekhmet-v0.1.0-macos-x86_64`](bin/sekhmet-v0.1.0-macos-x86_64) | [`.sha256.asc`](bin/sekhmet-v0.1.0-macos-x86_64.sha256.asc) |
| **macOS (Apple Silicon)** | `aarch64` | [`bin/sekhmet-v0.1.0-macos-aarch64`](bin/sekhmet-v0.1.0-macos-aarch64) | [`.sha256.asc`](bin/sekhmet-v0.1.0-macos-aarch64.sha256.asc) |

### Cryptographic Verification (`SOVEREIGN-SIGN-01`)
```bash
# 1. Import the Sovereign Release Public Key
gpg --import SOVEREIGN_RELEASE_KEY.asc

# 2. Verify the Master Checksum Manifest Signature
gpg --verify SHA256SUMS.asc SHA256SUMS

# 3. Verify Binary Integrity
sha256sum -c SHA256SUMS
```

---

## 🚀 3. Quick Start & Service Installation

### Step 1: Generate & Validate SST Configuration (`sekhmet.yaml`)
```bash
chmod +x ./bin/sekhmet-v0.1.0-linux-x86_64
./bin/sekhmet-v0.1.0-linux-x86_64 config init --out ./sekhmet.yaml
./bin/sekhmet-v0.1.0-linux-x86_64 config validate --config ./sekhmet.yaml
```

### Step 2: Run Interactively or Install as an OS Service
```bash
# Run directly in the foreground
./bin/sekhmet-v0.1.0-linux-x86_64 serve --config ./sekhmet.yaml

# Preview or install native OS service (systemd | openrc | freebsd | windows | macos)
./bin/sekhmet-v0.1.0-linux-x86_64 service preview --config ./sekhmet.yaml --os systemd
sudo ./bin/sekhmet-v0.1.0-linux-x86_64 service install --config ./sekhmet.yaml --os systemd
```

---

## 🔌 4. Language-Agnostic HTTP/JSON API Reference

Once running (default `http://127.0.0.1:4410`), any application stack can call these endpoints directly:

| Endpoint | Method | Purpose |
| :--- | :--- | :--- |
| `/healthz` | `GET` | Liveness and configured issuer status |
| `/.well-known/jwks.json` | `GET` | RFC 7517 Ed25519 public key discovery (`OKP` / `EdDSA`) |
| `/v1/tenants` | `POST` | Register an application tenant (`community`, `starter`, `business`, `profleet`) |
| `/v1/tenants/subscription` | `POST` | Update tenant tier or active/suspended status |
| `/v1/auth/register` | `POST` | Register a user account (with optional RFC 6238 TOTP secret) |
| `/v1/auth/verify-email` | `POST` | Verify 6-digit email OTP code |
| `/v1/auth/login` | `POST` | Authenticate credentials (+ optional TOTP) and issue Ed25519 JWT |
| `/v1/auth/introspect` | `POST` | Verify JWT signature, expiration, tenant binding, and revocation state |
| `/v1/auth/revoke` | `POST` | Immediately revoke an active session `jti` |
| `/v1/keys/mint` | `POST` | Mint a `skm_live_...` API key with optional IPv4/IPv6 CIDR & domain locks |
| `/v1/keys/verify` | `POST` | Verify an API key against caller IP and domain origin |
| `/v1/audit/verify` | `GET` | Cryptographically verify the entire tamper-evident audit chain |

See [`docs/01_EMPIRICAL_VERIFICATION_AND_API_GUIDE.md`](docs/01_EMPIRICAL_VERIFICATION_AND_API_GUIDE.md) for copy-paste integration examples in **Node.js, PHP, Python, Go, and cURL**.

---

## 📄 License

Copyright © 2026 RMediaTech LLC. All rights reserved. Distributed under the RMediaTech Sovereign Binary Distribution License.
