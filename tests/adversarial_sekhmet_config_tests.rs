use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use sekhmet::{build_sekhmet_router, SekhmetAppState};
use sekhmet_config::{SekhmetConfigError, SekhmetSstConfig};
use serde_json::{json, Value};
use tower::ServiceExt;

#[test]
fn test_1_canonical_sst_yaml_roundtrip_parity() {
    let default_cfg = SekhmetSstConfig::default();
    let yaml = default_cfg.render_canonical_yaml();
    let parsed = SekhmetSstConfig::parse_yaml(&yaml).expect("canonical YAML must parse cleanly");
    assert_eq!(parsed, default_cfg);
}

#[tokio::test]
async fn test_2_enterprise_custom_sst_config_live_enforcement() {
    let custom_yaml = r#"
# Enterprise Custom Sekhmet SST Configuration
server:
  bind_addr: "0.0.0.0:4420"
  trust_forwarded_headers: false

storage:
  db_path: ":memory:"
  signing_key_seed_hex: "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"

tokens:
  issuer: "auth.citadel.sovereign"
  access_token_ttl_secs: 900
  email_otp_ttl_secs: 600

policy:
  min_password_length: 14
  require_totp_for_admins: true

shield:
  honeypot_enabled: true
  ip_burst_capacity: 60.0
  ip_refill_per_sec: 15.0
  max_failed_logins_per_handle_per_min: 5

tiers:
  community_max_keys: 2
  community_max_cidrs: 2
  community_max_domains: 2
"#;

    let cfg = SekhmetSstConfig::parse_yaml(custom_yaml).expect("valid enterprise config");
    assert_eq!(cfg.issuer, "auth.citadel.sovereign");
    assert_eq!(cfg.min_password_length, 14);
    assert!(cfg.require_totp_for_admins);
    assert_eq!(cfg.tiers["community"].max_keys, 2);

    let state = SekhmetAppState::from_config(cfg).unwrap();
    let app = build_sekhmet_router(state);

    // 1. Verify /healthz reports custom SST issuer
    let req = Request::builder()
        .method("GET")
        .uri("/healthz")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let hz: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(hz["issuer"], "auth.citadel.sovereign");

    // 2. Create tenant
    let req = Request::builder()
        .method("POST")
        .uri("/v1/tenants")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_vec(&json!({
                "tenant_id": "ent-01",
                "display_name": "Enterprise One"
            }))
            .unwrap(),
        ))
        .unwrap();
    assert_eq!(
        app.clone().oneshot(req).await.unwrap().status(),
        StatusCode::CREATED
    );

    // 3. Rude Policy Check: Password shorter than 14 chars must be rejected
    let req = Request::builder()
        .method("POST")
        .uri("/v1/auth/register")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_vec(&json!({
                "tenant_id": "ent-01",
                "email": "admin@ent.local",
                "display_name": "Admin User",
                "password": "ShortPass12!",
                "role": "member"
            }))
            .unwrap(),
        ))
        .unwrap();
    assert_eq!(
        app.clone().oneshot(req).await.unwrap().status(),
        StatusCode::BAD_REQUEST
    );

    // 4. Rude Policy Check: Admin without TOTP must be rejected when require_totp_for_admins=true
    let req = Request::builder()
        .method("POST")
        .uri("/v1/auth/register")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_vec(&json!({
                "tenant_id": "ent-01",
                "email": "admin@ent.local",
                "display_name": "Admin User",
                "password": "EnterpriseLongPassword_2026!",
                "role": "admin"
            }))
            .unwrap(),
        ))
        .unwrap();
    assert_eq!(
        app.clone().oneshot(req).await.unwrap().status(),
        StatusCode::BAD_REQUEST
    );
}

#[test]
fn test_3_adversarial_yaml_config_attacks_rejected() {
    // 1. Allocation Bomb (> 64 KB)
    let bomb = "a".repeat(70_000);
    assert_eq!(
        SekhmetSstConfig::parse_yaml(&bomb),
        Err(SekhmetConfigError::PayloadTooLarge)
    );

    // 2. Formula Injection in Issuer
    let formula_yaml = "tokens:\n  issuer: \"=CMD|' /C calc'!A0\"\n";
    assert!(matches!(
        SekhmetSstConfig::parse_yaml(formula_yaml),
        Err(SekhmetConfigError::ValidationError { .. })
    ));

    // 3. Path Traversal & Shell Injection in db_path
    let traversal_yaml = "storage:\n  db_path: \"/var/lib/../../etc/shadow\"\n";
    assert!(matches!(
        SekhmetSstConfig::parse_yaml(traversal_yaml),
        Err(SekhmetConfigError::ValidationError { .. })
    ));

    let shell_yaml = "storage:\n  db_path: \"/var/lib/sekhmet.db; rm -rf /\"\n";
    assert!(matches!(
        SekhmetSstConfig::parse_yaml(shell_yaml),
        Err(SekhmetConfigError::ValidationError { .. })
    ));

    // 4. NaN / Infinite float in rate limiter
    let nan_yaml = "shield:\n  ip_burst_capacity: NaN\n";
    assert!(matches!(
        SekhmetSstConfig::parse_yaml(nan_yaml),
        Err(SekhmetConfigError::ValidationError { .. })
    ));

    // 5. Unknown key injection
    let unknown_yaml = "server:\n  backdoor_port: 9999\n";
    assert!(matches!(
        SekhmetSstConfig::parse_yaml(unknown_yaml),
        Err(SekhmetConfigError::UnknownKey { .. })
    ));
}
