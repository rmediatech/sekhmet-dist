use crate::SekhmetAppState;
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use sekhmet_crypto::{generate_random_hex, SekhmetClaims};
use sekhmet_shield::SekhmetPerimeterShield;
use sekhmet_store::{now_unix, SekhmetStoreError};
use serde::Deserialize;
use serde_json::json;

pub(crate) fn extract_caller_ip(headers: &HeaderMap, trust_forwarded: bool) -> String {
    if !trust_forwarded {
        return "127.0.0.1".to_string();
    }
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .unwrap_or("127.0.0.1")
        .trim()
        .to_string()
}

pub(crate) fn check_quarantine_guard(
    state: &SekhmetAppState,
    ip: &str,
) -> Option<(StatusCode, Json<serde_json::Value>)> {
    if let Ok(Some(q)) = state.store.check_threat_quarantine(ip) {
        return Some((
            StatusCode::FORBIDDEN,
            Json(json!({
                "status": "error",
                "code": "THREAT_QUARANTINED",
                "quarantined_until": q.quarantined_until,
                "subnet_herd_promoted": q.subnet_herd_promoted,
                "reason": q.last_reason
            })),
        ));
    }
    None
}

pub(crate) fn map_store_err(err: SekhmetStoreError) -> (StatusCode, Json<serde_json::Value>) {
    match err {
        SekhmetStoreError::Validation(_) => (
            StatusCode::BAD_REQUEST,
            Json(json!({"status": "error", "code": "VALIDATION_ERROR", "message": "Input validation constraint violated."})),
        ),
        SekhmetStoreError::InvalidCredentials => (
            StatusCode::UNAUTHORIZED,
            Json(json!({"status": "error", "code": "INVALID_CREDENTIALS", "message": "Authentication failed."})),
        ),
        SekhmetStoreError::TotpRequiredOrInvalid => (
            StatusCode::UNAUTHORIZED,
            Json(json!({"status": "error", "code": "TOTP_REQUIRED", "message": "Valid RFC 6238 TOTP code required."})),
        ),
        SekhmetStoreError::EmailVerificationRequired => (
            StatusCode::FORBIDDEN,
            Json(json!({"status": "error", "code": "EMAIL_VERIFICATION_REQUIRED", "message": "Email OTP verification required before minting keys."})),
        ),
        SekhmetStoreError::SubscriptionInactive => (
            StatusCode::PAYMENT_REQUIRED,
            Json(json!({"status": "error", "code": "SUBSCRIPTION_INACTIVE", "message": "Tenant subscription is not active."})),
        ),
        SekhmetStoreError::KeyQuotaExceeded => (
            StatusCode::FORBIDDEN,
            Json(json!({"status": "error", "code": "KEY_QUOTA_EXCEEDED", "message": "Subscription tier API key quota reached."})),
        ),
        SekhmetStoreError::ApiKeyUnauthorized => (
            StatusCode::FORBIDDEN,
            Json(json!({"status": "error", "code": "API_KEY_UNAUTHORIZED", "message": "API key unauthorized for caller IP, domain, or state."})),
        ),
        SekhmetStoreError::MerkleTamperDetected(seq) => (
            StatusCode::CONFLICT,
            Json(json!({"status": "error", "code": "MERKLE_TAMPER_DETECTED", "seq": seq})),
        ),
        SekhmetStoreError::DatabaseError => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"status": "error", "code": "INTERNAL_ERROR", "message": "Storage operation failed."})),
        ),
    }
}

pub async fn healthz_handler(State(state): State<SekhmetAppState>) -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(json!({
            "status": "ok",
            "engine": "sekhmet",
            "issuer": state.config.issuer,
            "standard": "SOVEREIGN-RFC-BAREMETAL-01"
        })),
    )
}

pub async fn robots_txt_handler() -> impl IntoResponse {
    (StatusCode::OK, "User-agent: *\nDisallow: /\n")
}

pub async fn jwks_handler(State(state): State<SekhmetAppState>) -> impl IntoResponse {
    match state.keyring() {
        Ok(kr) => (StatusCode::OK, Json(kr.jwks_json())),
        Err(e) => map_store_err(e),
    }
}

#[derive(Deserialize)]
pub struct CreateTenantReq {
    pub tenant_id: String,
    pub display_name: String,
    pub tier: Option<String>,
}

pub async fn create_tenant_handler(
    State(state): State<SekhmetAppState>,
    Json(req): Json<CreateTenantReq>,
) -> impl IntoResponse {
    let tier = req.tier.as_deref().unwrap_or("community");
    match state
        .store
        .create_tenant(&req.tenant_id, &req.display_name, tier)
    {
        Ok(clean_name) => (
            StatusCode::CREATED,
            Json(json!({"status": "ok", "tenant_id": req.tenant_id, "display_name": clean_name, "tier": tier})),
        ),
        Err(e) => map_store_err(e),
    }
}

#[derive(Deserialize)]
pub struct UpdateSubReq {
    pub tenant_id: String,
    pub tier: String,
    pub status: String,
}

pub async fn update_subscription_handler(
    State(state): State<SekhmetAppState>,
    Json(req): Json<UpdateSubReq>,
) -> impl IntoResponse {
    match state
        .store
        .update_tenant_subscription(&req.tenant_id, &req.tier, &req.status)
    {
        Ok(()) => (
            StatusCode::OK,
            Json(json!({"status": "ok", "tenant_id": req.tenant_id, "tier": req.tier, "subscription_status": req.status})),
        ),
        Err(e) => map_store_err(e),
    }
}

#[derive(Deserialize)]
pub struct RegisterUserReq {
    pub tenant_id: String,
    pub email: String,
    pub display_name: String,
    pub password: String,
    pub role: Option<String>,
    pub totp_secret_hex: Option<String>,
    pub website_url: Option<String>,
    pub company_fax: Option<String>,
}

pub async fn register_user_handler(
    State(state): State<SekhmetAppState>,
    headers: HeaderMap,
    Json(req): Json<RegisterUserReq>,
) -> impl IntoResponse {
    let ip = extract_caller_ip(&headers, state.config.trust_forwarded_headers);
    if let Some(q_resp) = check_quarantine_guard(&state, &ip) {
        return q_resp;
    }
    if state.config.honeypot_enabled
        && SekhmetPerimeterShield::check_honeypot(
            req.website_url.as_deref(),
            req.company_fax.as_deref(),
        )
        .is_err()
    {
        let _ = state
            .store
            .learn_threat_signal(&ip, 10, "HONEYPOT_TRAP_TRIGGERED");
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"status": "error", "code": "HONEYPOT_TRIGGERED"})),
        );
    }
    if state.shield.check_ip_rate_limit(&ip, 1.0).is_err() {
        let _ = state.store.learn_threat_signal(&ip, 3, "IP_RATE_LIMIT_BURST");
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({"status": "error", "code": "RATE_LIMITED"})),
        );
    }
    if req.password.len() < state.config.min_password_length {
        return map_store_err(SekhmetStoreError::Validation(
            "Password shorter than policy minimum.".to_string(),
        ));
    }
    let role = req.role.as_deref().unwrap_or("member");
    if state.config.require_totp_for_admins
        && matches!(role, "owner" | "admin")
        && req.totp_secret_hex.is_none()
    {
        return map_store_err(SekhmetStoreError::Validation(
            "TOTP secret required for admin/owner roles.".to_string(),
        ));
    }
    match state.store.register_user(
        &req.tenant_id,
        &req.email,
        &req.display_name,
        &req.password,
        role,
        req.totp_secret_hex.as_deref(),
    ) {
        Ok(reg) => (
            StatusCode::CREATED,
            Json(json!({
                "status": "ok",
                "user_id": reg.user_id,
                "tenant_id": reg.tenant_id,
                "email": reg.email,
                "display_name": reg.display_name,
                "verification_otp": reg.otp_code
            })),
        ),
        Err(e) => map_store_err(e),
    }
}

#[derive(Deserialize)]
pub struct VerifyEmailReq {
    pub tenant_id: String,
    pub email: String,
    pub otp_code: String,
}

pub async fn verify_email_handler(
    State(state): State<SekhmetAppState>,
    headers: HeaderMap,
    Json(req): Json<VerifyEmailReq>,
) -> impl IntoResponse {
    let ip = extract_caller_ip(&headers, state.config.trust_forwarded_headers);
    if let Some(q_resp) = check_quarantine_guard(&state, &ip) {
        return q_resp;
    }
    match state
        .store
        .verify_email_otp(&req.tenant_id, &req.email, &req.otp_code)
    {
        Ok(()) => (
            StatusCode::OK,
            Json(json!({"status": "ok", "is_email_verified": true})),
        ),
        Err(e) => {
            let _ = state.store.learn_threat_signal(&ip, 3, "EMAIL_OTP_BRUTEFORCE");
            map_store_err(e)
        }
    }
}

#[derive(Deserialize)]
pub struct PasswordResetRequestReq {
    pub tenant_id: String,
    pub email: String,
}

pub async fn password_reset_request_handler(
    State(state): State<SekhmetAppState>,
    headers: HeaderMap,
    Json(req): Json<PasswordResetRequestReq>,
) -> impl IntoResponse {
    let ip = extract_caller_ip(&headers, state.config.trust_forwarded_headers);
    if let Some(q_resp) = check_quarantine_guard(&state, &ip) {
        return q_resp;
    }
    match state
        .store
        .request_password_reset(&req.tenant_id, &req.email)
    {
        Ok(otp) => (
            StatusCode::OK,
            Json(json!({"status": "ok", "reset_otp": otp})),
        ),
        Err(e) => map_store_err(e),
    }
}

#[derive(Deserialize)]
pub struct PasswordResetConfirmReq {
    pub tenant_id: String,
    pub email: String,
    pub otp_code: String,
    pub new_password: String,
}

pub async fn password_reset_confirm_handler(
    State(state): State<SekhmetAppState>,
    headers: HeaderMap,
    Json(req): Json<PasswordResetConfirmReq>,
) -> impl IntoResponse {
    let ip = extract_caller_ip(&headers, state.config.trust_forwarded_headers);
    if let Some(q_resp) = check_quarantine_guard(&state, &ip) {
        return q_resp;
    }
    match state.store.confirm_password_reset(
        &req.tenant_id,
        &req.email,
        &req.otp_code,
        &req.new_password,
        state.config.min_password_length,
    ) {
        Ok(()) => (
            StatusCode::OK,
            Json(json!({"status": "ok", "password_updated": true, "prior_sessions_revoked": true})),
        ),
        Err(e) => {
            let _ = state
                .store
                .learn_threat_signal(&ip, 3, "PASSWORD_RESET_OTP_BRUTEFORCE");
            map_store_err(e)
        }
    }
}

#[derive(Deserialize)]
pub struct LoginReq {
    pub tenant_id: String,
    pub email: String,
    pub password: String,
    pub totp_code: Option<String>,
    pub website_url: Option<String>,
    pub company_fax: Option<String>,
}

pub async fn login_handler(
    State(state): State<SekhmetAppState>,
    headers: HeaderMap,
    Json(req): Json<LoginReq>,
) -> impl IntoResponse {
    let ip = extract_caller_ip(&headers, state.config.trust_forwarded_headers);
    if let Some(q_resp) = check_quarantine_guard(&state, &ip) {
        return q_resp;
    }
    if state.config.honeypot_enabled
        && SekhmetPerimeterShield::check_honeypot(
            req.website_url.as_deref(),
            req.company_fax.as_deref(),
        )
        .is_err()
    {
        let _ = state
            .store
            .learn_threat_signal(&ip, 10, "HONEYPOT_TRAP_TRIGGERED");
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"status": "error", "code": "HONEYPOT_TRIGGERED"})),
        );
    }
    if state.shield.check_ip_rate_limit(&ip, 2.0).is_err() {
        let _ = state.store.learn_threat_signal(&ip, 3, "IP_RATE_LIMIT_BURST");
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({"status": "error", "code": "RATE_LIMITED"})),
        );
    }
    let handle_key = format!("{}:{}", req.tenant_id, req.email);
    let is_trusted_subnet = state
        .store
        .is_trusted_user_subnet(&req.tenant_id, &req.email, &ip);
    if !is_trusted_subnet && state.shield.check_handle_velocity(&handle_key).is_err() {
        let _ = state
            .store
            .learn_threat_signal(&ip, 4, "ACCOUNT_VELOCITY_BRUTEFORCE");
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({"status": "error", "code": "ACCOUNT_VELOCITY_COOLDOWN"})),
        );
    }

    match state.store.authenticate_user(
        &req.tenant_id,
        &req.email,
        &req.password,
        req.totp_code.as_deref(),
    ) {
        Ok(user) => {
            let Ok(keyring) = state.keyring() else {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"status": "error", "code": "KEYRING_ERROR"})),
                );
            };
            let now = now_unix();
            let ttl = state.config.access_token_ttl_secs;
            let jti = format!("jti_{}", generate_random_hex(12));
            let claims = SekhmetClaims {
                iss: state.config.issuer.clone(),
                sub: user.user_id.clone(),
                tid: user.tenant_id.clone(),
                role: user.role.clone(),
                jti: jti.clone(),
                iat: now,
                exp: now + ttl,
            };
            let Ok(token) = keyring.sign_jwt(&claims) else {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"status": "error", "code": "SIGNING_FAILED"})),
                );
            };
            let _ = state
                .store
                .create_session(&user.tenant_id, &user.user_id, &jti, ttl, &ip);
            let baseline = state
                .store
                .learn_and_evaluate_user_baseline(&user.user_id, &user.tenant_id, &ip)
                .ok();
            (
                StatusCode::OK,
                Json(json!({
                    "status": "ok",
                    "access_token": token,
                    "token_type": "Bearer",
                    "expires_in": ttl,
                    "jti": jti,
                    "user": user,
                    "baseline": baseline
                })),
            )
        }
        Err(e) => {
            state.shield.record_handle_failure(&handle_key);
            let _ = state
                .store
                .learn_threat_signal(&ip, 2, "AUTH_CREDENTIAL_FAILURE");
            map_store_err(e)
        }
    }
}
