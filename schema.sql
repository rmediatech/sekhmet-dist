-- ============================================================================
-- SEKHMET (سخمت) — PRISTINE SINGLE-SCHEMA TOPOLOGY (SQLite WAL)
-- Standard: AGY-RULE-SOVEREIGN-FLAGSHIP-01 & SOVEREIGN-RFC-BAREMETAL-01
-- Zero incremental migrations. Sub-second deterministic initialization.
-- ============================================================================

PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA foreign_keys = ON;
PRAGMA temp_store = MEMORY;
PRAGMA busy_timeout = 5000;

CREATE TABLE IF NOT EXISTS skm_keystore (
    key_slot            TEXT PRIMARY KEY CHECK (key_slot IN ('root_ed25519', 'retiring_ed25519')),
    seed_hex            TEXT NOT NULL CHECK (length(seed_hex) = 64),
    key_id              TEXT NOT NULL CHECK (length(key_id) BETWEEN 8 AND 64),
    created_at          INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS skm_tenants (
    tenant_id           TEXT PRIMARY KEY CHECK (length(tenant_id) BETWEEN 3 AND 64),
    display_name        TEXT NOT NULL CHECK (length(display_name) BETWEEN 1 AND 128),
    subscription_tier   TEXT NOT NULL DEFAULT 'community' CHECK (subscription_tier IN ('community', 'starter', 'business', 'profleet')),
    subscription_status TEXT NOT NULL DEFAULT 'active' CHECK (subscription_status IN ('active', 'past_due', 'suspended', 'canceled')),
    max_api_keys        INTEGER NOT NULL DEFAULT 1 CHECK (max_api_keys >= 0 AND max_api_keys <= 1000),
    created_at          INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS skm_users (
    user_id             TEXT PRIMARY KEY CHECK (length(user_id) BETWEEN 3 AND 64),
    tenant_id           TEXT NOT NULL REFERENCES skm_tenants(tenant_id) ON DELETE CASCADE,
    email               TEXT NOT NULL CHECK (length(email) BETWEEN 3 AND 254),
    display_name        TEXT NOT NULL CHECK (length(display_name) BETWEEN 1 AND 128),
    password_hash       TEXT NOT NULL CHECK (length(password_hash) BETWEEN 32 AND 512),
    totp_secret_hex     TEXT,
    is_email_verified   INTEGER NOT NULL DEFAULT 0 CHECK (is_email_verified IN (0, 1)),
    email_otp_hash      TEXT,
    email_otp_expires   INTEGER,
    role                TEXT NOT NULL DEFAULT 'member' CHECK (role IN ('owner', 'admin', 'member', 'service')),
    is_locked           INTEGER NOT NULL DEFAULT 0 CHECK (is_locked IN (0, 1)),
    created_at          INTEGER NOT NULL,
    UNIQUE(tenant_id, email)
);

CREATE TABLE IF NOT EXISTS skm_sessions (
    session_id          TEXT PRIMARY KEY CHECK (length(session_id) BETWEEN 16 AND 128),
    tenant_id           TEXT NOT NULL REFERENCES skm_tenants(tenant_id) ON DELETE CASCADE,
    user_id             TEXT NOT NULL REFERENCES skm_users(user_id) ON DELETE CASCADE,
    token_jti           TEXT NOT NULL UNIQUE CHECK (length(token_jti) BETWEEN 16 AND 128),
    issued_at           INTEGER NOT NULL,
    expires_at          INTEGER NOT NULL,
    is_revoked          INTEGER NOT NULL DEFAULT 0 CHECK (is_revoked IN (0, 1)),
    client_ip           TEXT NOT NULL CHECK (length(client_ip) <= 64)
);

CREATE TABLE IF NOT EXISTS skm_api_keys (
    key_id              TEXT PRIMARY KEY CHECK (length(key_id) BETWEEN 8 AND 64),
    tenant_id           TEXT NOT NULL REFERENCES skm_tenants(tenant_id) ON DELETE CASCADE,
    owner_user_id       TEXT NOT NULL REFERENCES skm_users(user_id) ON DELETE CASCADE,
    key_prefix          TEXT NOT NULL CHECK (length(key_prefix) BETWEEN 8 AND 32),
    secret_hash_hex     TEXT NOT NULL UNIQUE CHECK (length(secret_hash_hex) = 64),
    label               TEXT NOT NULL CHECK (length(label) BETWEEN 1 AND 128),
    allowed_cidrs       TEXT NOT NULL DEFAULT '' CHECK (length(allowed_cidrs) <= 2048),
    allowed_domains     TEXT NOT NULL DEFAULT '' CHECK (length(allowed_domains) <= 2048),
    is_revoked          INTEGER NOT NULL DEFAULT 0 CHECK (is_revoked IN (0, 1)),
    created_at          INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS skm_merkle_audit_log (
    seq                 INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp           INTEGER NOT NULL,
    tenant_id           TEXT NOT NULL CHECK (length(tenant_id) <= 64),
    actor_id            TEXT NOT NULL CHECK (length(actor_id) <= 128),
    event_type          TEXT NOT NULL CHECK (length(event_type) <= 64),
    detail_sanitized    TEXT NOT NULL CHECK (length(detail_sanitized) <= 1024),
    prev_hash           TEXT NOT NULL CHECK (length(prev_hash) = 64),
    entry_hash          TEXT NOT NULL UNIQUE CHECK (length(entry_hash) = 64)
);

CREATE TABLE IF NOT EXISTS skm_threat_memory (
    ip_or_cidr          TEXT PRIMARY KEY CHECK (length(ip_or_cidr) BETWEEN 3 AND 64),
    strike_count        INTEGER NOT NULL DEFAULT 1,
    threat_score        INTEGER NOT NULL DEFAULT 1,
    quarantined_until   INTEGER NOT NULL DEFAULT 0,
    last_reason         TEXT NOT NULL CHECK (length(last_reason) <= 128),
    updated_at          INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS skm_user_baselines (
    user_id             TEXT NOT NULL REFERENCES skm_users(user_id) ON DELETE CASCADE,
    subnet_prefix       TEXT NOT NULL CHECK (length(subnet_prefix) BETWEEN 3 AND 64),
    hit_count           INTEGER NOT NULL DEFAULT 1,
    first_seen          INTEGER NOT NULL,
    last_seen           INTEGER NOT NULL,
    PRIMARY KEY (user_id, subnet_prefix)
);

CREATE TABLE IF NOT EXISTS skm_forensic_quarantine (
    quarantine_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    healed_at           INTEGER NOT NULL,
    corrupted_seq       INTEGER NOT NULL,
    corrupted_hash      TEXT NOT NULL CHECK (length(corrupted_hash) <= 128),
    forensic_summary    TEXT NOT NULL CHECK (length(forensic_summary) <= 1024)
);

CREATE INDEX IF NOT EXISTS idx_skm_users_tenant_email ON skm_users(tenant_id, email);
CREATE INDEX IF NOT EXISTS idx_skm_sessions_jti ON skm_sessions(token_jti);
CREATE INDEX IF NOT EXISTS idx_skm_sessions_expires ON skm_sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_skm_api_keys_tenant ON skm_api_keys(tenant_id, is_revoked);
CREATE INDEX IF NOT EXISTS idx_skm_audit_tenant_seq ON skm_merkle_audit_log(tenant_id, seq);
CREATE INDEX IF NOT EXISTS idx_skm_threat_quarantine ON skm_threat_memory(quarantined_until);
