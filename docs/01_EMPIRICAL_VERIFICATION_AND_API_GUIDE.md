# 📘 Sekhmet Public Integration & Empirical Verification Guide

> **Version:** `v0.1.0`  
> **Standard:** `SOVEREIGN-RFC-BAREMETAL-01` & `SOVEREIGN-SIGN-01`

---

## 1. Multi-Language Integration Examples

Because `sekhmet` speaks pure HTTP/JSON and standard RFC 7519 / RFC 8032 Ed25519 tokens, you can integrate it into any application stack in seconds without installing vendor SDKs.

### A. Node.js / TypeScript (`fetch`)
```javascript
const SEKHMET_URL = "http://127.0.0.1:4410";

export async function verifyUserToken(token, expectedTenantId) {
  const res = await fetch(`${SEKHMET_URL}/v1/auth/introspect`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ token, expected_tenant_id: expectedTenantId }),
  });
  return await res.json(); // { active: true, sub: "usr_...", tid: "...", role: "..." }
}
```

### B. PHP (`curl` / Web Backend)
```php
<?php
function sekhmet_verify_api_key(string $apiKey, string $callerIp, string $callerDomain): array {
    $ch = curl_init("http://127.0.0.1:4410/v1/keys/verify");
    $payload = json_encode([
        "api_key" => $apiKey,
        "caller_ip" => $callerIp,
        "caller_domain" => $callerDomain
    ]);
    curl_setopt_array($ch, [
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => $payload,
        CURLOPT_HTTPHEADER => ["Content-Type: application/json"],
        CURLOPT_RETURNTRANSFER => true,
    ]);
    $response = curl_exec($ch);
    curl_close($ch);
    return json_decode($response, true);
}
?>
```

### C. Python (`urllib` / FastAPI / Django)
```python
import urllib.request, json

def sekhmet_login(tenant_id: str, email: str, password: str, totp_code: str = None) -> dict:
    payload = {"tenant_id": tenant_id, "email": email, "password": password}
    if totp_code:
        payload["totp_code"] = totp_code
    req = urllib.request.Request(
        "http://127.0.0.1:4410/v1/auth/login",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode("utf-8"))
```

---

## 2. Empirical Verification Summary

Every release binary of `sekhmet` undergoes 6-dimensional verification prior to publication:

1. **Cooperative RFC Parity ("The Good")**:
   - Verified against official IETF **RFC 6238 Appendix B** TOTP test vectors (`59s` through `20000000000s`) and **RFC 8032 Ed25519 Test Vector 1**.
   - Full lifecycle verification: tenant creation, user registration, email OTP verification, TOTP 2FA login, JWKS discovery, CIDR/domain-locked API key minting, session revocation, and SST YAML round-trip configuration.
2. **Policy & Quota Enforcement ("The Bad")**:
   - Unverified email accounts blocked from minting API keys (`403 EMAIL_VERIFICATION_REQUIRED`).
   - Per-tier key quotas strictly enforced (`403 KEY_QUOTA_EXCEEDED`).
   - Suspended subscriptions immediately halt key verification (`402`/`403`).
3. **Corrupted Boundary & Wire Resilience ("The Ugly")**:
   - Truncated JSON frames, oversized tokens, `alg: none` JWT headers, and bit-flipped signatures rejected with zero runtime panics.
   - Spreadsheet formula injection payloads (`=`, `+`, `-`, `@`, `\t`, `\r`) and ANSI escape sequences neutralized at the ingestion boundary.
4. **Concurrent Multi-Client Stress ("The Unpredictable")**:
   - Verified under parallel multi-client registration and audit log writes with 100% linear hash-chain preservation.
5. **Boundary & Network Edge Cases**:
   - IPv4 (`/32`, `/24`) and IPv6 (`2001:db8::/32`) bitwise CIDR prefix matching and wildcard subdomain origin verification (`*.example.com`).
6. **Tamper Detection & Recovery**:
   - Direct modification of any historical audit record is immediately flagged by `GET /v1/audit/verify` (`409 MERKLE_TAMPER_DETECTED`) and `sekhmet audit`, with full recovery upon restoration and WAL checkpoint vacuuming.
