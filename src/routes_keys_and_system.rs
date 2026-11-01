use crate::routes::{check_quarantine_guard, extract_caller_ip, map_store_err};
use crate::SekhmetAppState;
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use sekhmet_store::now_unix;
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Deserialize)]
pub struct IntrospectReq {
    pub token: String,
    pub expected_tenant_id: Option<String>,
}

pub async fn introspect_handler(
    State(state): State<SekhmetAppState>,
    Json(req): Json<IntrospectReq>,
) -> impl IntoResponse {
    let Ok(keyring) = state.keyring() else {
        return (StatusCode::OK, Json(json!({"active": false})));
    };
    let now = now_unix();
    let Ok((claims, replacement_opt)) = keyring.verify_jwt_with_upgrade(&req.token, now) else {
        return (StatusCode::OK, Json(json!({"active": false})));
    };
    if let Some(ref exp_tid) = req.expected_tenant_id {
        if &claims.tid != exp_tid {
            return (
                StatusCode::OK,
                Json(json!({"active": false, "reason": "CROSS_TENANT_MISMATCH"})),
            );
        }
    }
    let active = state.store.is_jti_active(&claims.jti).unwrap_or(false);
    if !active {
        return (StatusCode::OK, Json(json!({"active": false})));
    }
    let mut resp = json!({
        "active": true,
        "iss": claims.iss,
        "sub": claims.sub,
        "tid": claims.tid,
        "role": claims.role,
        "jti": claims.jti,
        "exp": claims.exp,
        "key_rotated": replacement_opt.is_some()
    });
    if let Some(rep_tok) = replacement_opt {
        resp["replacement_token"] = json!(rep_tok);
    }
    (StatusCode::OK, Json(resp))
}

#[derive(Deserialize)]
pub struct RevokeReq {
    pub tenant_id: String,
    pub jti: String,
}

pub async fn revoke_session_handler(
    State(state): State<SekhmetAppState>,
    Json(req): Json<RevokeReq>,
) -> impl IntoResponse {
    match state.store.revoke_jti(&req.tenant_id, &req.jti) {
        Ok(()) => (StatusCode::OK, Json(json!({"status": "ok", "revoked": true}))),
        Err(e) => map_store_err(e),
    }
}

#[derive(Deserialize)]
pub struct MintKeyReq {
    pub access_token: String,
    pub label: String,
    pub allowed_cidrs: Option<String>,
    pub allowed_domains: Option<String>,
}

pub async fn mint_api_key_handler(
    State(state): State<SekhmetAppState>,
    headers: HeaderMap,
    Json(req): Json<MintKeyReq>,
) -> impl IntoResponse {
    let ip = extract_caller_ip(&headers, state.config.trust_forwarded_headers);
    if let Some(q_resp) = check_quarantine_guard(&state, &ip) {
        return q_resp;
    }
    let Ok(keyring) = state.keyring() else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"status": "error", "code": "KEYRING_ERROR"})),
        );
    };
    let now = now_unix();
    let Ok((claims, _)) = keyring.verify_jwt_with_upgrade(&req.access_token, now) else {
        let _ = state.store.learn_threat_signal(&ip, 3, "FORGED_TOKEN_MINT_ATTEMPT");
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"status": "error", "code": "INVALID_TOKEN"})),
        );
    };
    if !state.store.is_jti_active(&claims.jti).unwrap_or(false) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"status": "error", "code": "SESSION_REVOKED"})),
        );
    }
    let cidrs = req.allowed_cidrs.as_deref().unwrap_or("");
    let domains = req.allowed_domains.as_deref().unwrap_or("");
    match state
        .store
        .mint_api_key(&claims.tid, &claims.sub, &req.label, cidrs, domains)
    {
        Ok(minted) => (
            StatusCode::CREATED,
            Json(json!({
                "status": "ok",
                "key_id": minted.key_id,
                "key_prefix": minted.key_prefix,
                "api_key": minted.raw_key,
                "label": minted.label,
                "allowed_cidrs": minted.allowed_cidrs,
                "allowed_domains": minted.allowed_domains
            })),
        ),
        Err(e) => map_store_err(e),
    }
}

#[derive(Deserialize, Serialize)]
pub struct VerifyKeyReq {
    pub api_key: String,
    pub caller_ip: String,
    pub caller_domain: String,
}

pub async fn verify_api_key_handler(
    State(state): State<SekhmetAppState>,
    Json(req): Json<VerifyKeyReq>,
) -> impl IntoResponse {
    if let Some(q_resp) = check_quarantine_guard(&state, &req.caller_ip) {
        return q_resp;
    }
    match state
        .store
        .verify_api_key(&req.api_key, &req.caller_ip, &req.caller_domain)
    {
        Ok(ctx) => (
            StatusCode::OK,
            Json(json!({
                "status": "ok",
                "valid": true,
                "key_id": ctx.key_id,
                "tenant_id": ctx.tenant_id,
                "owner_user_id": ctx.owner_user_id,
                "subscription_tier": ctx.subscription_tier
            })),
        ),
        Err(e) => {
            let _ = state
                .store
                .learn_threat_signal(&req.caller_ip, 3, "API_KEY_BOUNDARY_OR_BRUTEFORCE");
            map_store_err(e)
        }
    }
}

pub async fn verify_audit_handler(State(state): State<SekhmetAppState>) -> impl IntoResponse {
    match state.store.verify_merkle_chain() {
        Ok((entries, head_hash)) => (
            StatusCode::OK,
            Json(json!({
                "status": "ok",
                "merkle_verified": true,
                "total_entries": entries,
                "head_hash": head_hash
            })),
        ),
        Err(e) => map_store_err(e),
    }
}

#[derive(Deserialize)]
pub struct SelfHealReq {
    pub retiring_grace_ttl_secs: Option<i64>,
}

pub async fn self_heal_handler(
    State(state): State<SekhmetAppState>,
    payload: Option<Json<SelfHealReq>>,
) -> impl IntoResponse {
    let grace = payload
        .and_then(|p| p.retiring_grace_ttl_secs)
        .unwrap_or(state.config.access_token_ttl_secs);
    match state.store.self_heal(grace) {
        Ok(report) => (StatusCode::OK, Json(json!(report))),
        Err(e) => map_store_err(e),
    }
}

pub async fn intelligence_handler(State(state): State<SekhmetAppState>) -> impl IntoResponse {
    match state.store.get_intelligence_summary() {
        Ok(summary) => (StatusCode::OK, Json(json!(summary))),
        Err(e) => map_store_err(e),
    }
}
