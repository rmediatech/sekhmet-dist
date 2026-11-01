pub mod routes;
pub mod routes_keys_and_system;

use axum::{
    routing::{get, post},
    Router,
};
use sekhmet_config::SekhmetSstConfig;
use sekhmet_crypto::SekhmetKeyRing;
use sekhmet_shield::SekhmetPerimeterShield;
use sekhmet_store::{SekhmetStore, SekhmetStoreError, TierLimits};
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Clone)]
pub struct SekhmetAppState {
    pub store: Arc<SekhmetStore>,
    pub shield: Arc<SekhmetPerimeterShield>,
    pub config: Arc<SekhmetSstConfig>,
}

impl SekhmetAppState {
    pub fn new(db_path: &str) -> Result<Self, SekhmetStoreError> {
        let mut cfg = SekhmetSstConfig::default();
        cfg.db_path = db_path.to_string();
        Self::from_config(cfg)
    }

    pub fn from_config(cfg: SekhmetSstConfig) -> Result<Self, SekhmetStoreError> {
        let mut tier_map = HashMap::new();
        for (k, v) in &cfg.tiers {
            tier_map.insert(
                k.clone(),
                TierLimits {
                    max_keys: v.max_keys,
                    max_cidrs: v.max_cidrs,
                    max_domains: v.max_domains,
                },
            );
        }
        let store = SekhmetStore::open_with_tiers(&cfg.db_path, tier_map)?;
        // Initialize or verify root keypair in skm_keystore on boot
        let _ = store.load_or_init_keyring(cfg.signing_key_seed_hex.as_deref())?;
        let shield = SekhmetPerimeterShield::new(
            cfg.ip_burst_capacity,
            cfg.ip_refill_per_sec,
            cfg.max_failed_logins_per_handle_per_min,
        );
        Ok(Self {
            store: Arc::new(store),
            shield: Arc::new(shield),
            config: Arc::new(cfg),
        })
    }

    /// Resolves the active + retiring Key Ring live from SQLite WAL (<20us) for 0-downtime CLI key rotation.
    pub fn keyring(&self) -> Result<SekhmetKeyRing, SekhmetStoreError> {
        self.store
            .load_or_init_keyring(self.config.signing_key_seed_hex.as_deref())
    }

    /// Spawns the autonomous background self-healing & threat-compaction pulse.
    pub fn spawn_autonomous_self_healing_pulse(&self) {
        let store = self.store.clone();
        let grace_ttl = self.config.access_token_ttl_secs;
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
            loop {
                interval.tick().await;
                let _ = store.self_heal(grace_ttl);
            }
        });
    }
}

pub fn build_sekhmet_router(state: SekhmetAppState) -> Router {
    Router::new()
        .route("/healthz", get(routes::healthz_handler))
        .route("/robots.txt", get(routes::robots_txt_handler))
        .route("/.well-known/jwks.json", get(routes::jwks_handler))
        .route("/v1/tenants", post(routes::create_tenant_handler))
        .route(
            "/v1/tenants/subscription",
            post(routes::update_subscription_handler),
        )
        .route("/v1/auth/register", post(routes::register_user_handler))
        .route("/v1/auth/verify-email", post(routes::verify_email_handler))
        .route("/v1/auth/login", post(routes::login_handler))
        .route(
            "/v1/auth/password-reset/request",
            post(routes::password_reset_request_handler),
        )
        .route(
            "/v1/auth/password-reset/confirm",
            post(routes::password_reset_confirm_handler),
        )
        .route(
            "/v1/auth/introspect",
            post(routes_keys_and_system::introspect_handler),
        )
        .route(
            "/v1/auth/revoke",
            post(routes_keys_and_system::revoke_session_handler),
        )
        .route(
            "/v1/keys/mint",
            post(routes_keys_and_system::mint_api_key_handler),
        )
        .route(
            "/v1/keys/verify",
            post(routes_keys_and_system::verify_api_key_handler),
        )
        .route(
            "/v1/audit/verify",
            get(routes_keys_and_system::verify_audit_handler),
        )
        .route(
            "/v1/system/self-heal",
            post(routes_keys_and_system::self_heal_handler),
        )
        .route(
            "/v1/system/intelligence",
            get(routes_keys_and_system::intelligence_handler),
        )
        .with_state(state)
}
