package postgres

// migrationV1SQL establishes the engineering baseline schema (design §11).
const migrationV1SQL = `
-- KVLT Engineering Baseline — PostgreSQL schema (design §11)
-- All timestamps stored as TIMESTAMPTZ (UTC). Byte fields stored as BYTEA.

CREATE TABLE IF NOT EXISTS tenants (
    id            TEXT PRIMARY KEY,
    name          TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'active',
    crk_version_id TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS tenant_envelope_configs (
    tenant_id       TEXT PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    default_format  TEXT NOT NULL,
    allowed_formats TEXT[] NOT NULL,
    profiles        JSONB NOT NULL DEFAULT '[]',
    aad_required    BOOLEAN NOT NULL DEFAULT FALSE,
    version         INTEGER NOT NULL DEFAULT 1,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS keys (
    id              TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    purpose         TEXT NOT NULL,
    policy_id       TEXT NOT NULL,
    suite_id        TEXT NOT NULL,
    current_version INTEGER NOT NULL DEFAULT 1,
    status          TEXT NOT NULL DEFAULT 'ACTIVE',
    tags            JSONB NOT NULL DEFAULT '{}',
    expires_at      TIMESTAMPTZ,
    archived_at     TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_keys_tenant ON keys(tenant_id);
CREATE INDEX IF NOT EXISTS idx_keys_tenant_archived ON keys(tenant_id, archived_at);

CREATE TABLE IF NOT EXISTS key_versions (
    id            TEXT PRIMARY KEY,
    key_id        TEXT NOT NULL REFERENCES keys(id) ON DELETE CASCADE,
    version_no    INTEGER NOT NULL,
    suite_id      TEXT NOT NULL,
    wrapped_dek   BYTEA NOT NULL,
    wrap_metadata BYTEA NOT NULL,
    status        TEXT NOT NULL DEFAULT 'ACTIVE',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(key_id, version_no)
);
CREATE INDEX IF NOT EXISTS idx_key_versions_key ON key_versions(key_id);

CREATE TABLE IF NOT EXISTS crk_versions (
    id         TEXT PRIMARY KEY,
    version    INTEGER NOT NULL UNIQUE,
    epoch      BIGINT NOT NULL DEFAULT 0,
    status     TEXT NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS crk_node_envelopes (
    id             TEXT PRIMARY KEY,
    crk_version_id TEXT NOT NULL REFERENCES crk_versions(id) ON DELETE CASCADE,
    node_id        TEXT NOT NULL,
    envelope       BYTEA NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(crk_version_id, node_id)
);

-- Cluster epoch is a single-row table.
CREATE TABLE IF NOT EXISTS cluster_state (
    id            INTEGER PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    cluster_epoch BIGINT NOT NULL DEFAULT 0,
    attestation_epoch BIGINT NOT NULL DEFAULT 0
);
INSERT INTO cluster_state (id) VALUES (1) ON CONFLICT DO NOTHING;

CREATE TABLE IF NOT EXISTS nodes (
    node_id            TEXT PRIMARY KEY,
    role               TEXT NOT NULL,
    status             TEXT NOT NULL DEFAULT 'registered',
    ready_reason       TEXT NOT NULL DEFAULT '',
    cluster_epoch      BIGINT NOT NULL DEFAULT 0,
    attestation_epoch  BIGINT NOT NULL DEFAULT 0,
    baseline           JSONB NOT NULL DEFAULT '{}',
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS dek_leases (
    lease_id       TEXT PRIMARY KEY,
    key_version_id TEXT NOT NULL,
    node_id        TEXT NOT NULL,
    tenant_id      TEXT NOT NULL,
    purpose        TEXT NOT NULL DEFAULT '',
    suite_id       TEXT NOT NULL DEFAULT '',
    expires_at     TIMESTAMPTZ NOT NULL,
    revoked        BOOLEAN NOT NULL DEFAULT FALSE,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_dek_leases_node ON dek_leases(node_id);

CREATE TABLE IF NOT EXISTS nonce_leases (
    lease_id       TEXT PRIMARY KEY,
    key_version_id TEXT NOT NULL,
    node_id        TEXT NOT NULL,
    domain         BIGINT NOT NULL,
    start_counter  BIGINT NOT NULL,
    end_counter    BIGINT NOT NULL,
    used_counter   BIGINT NOT NULL,
    expires_at     TIMESTAMPTZ NOT NULL,
    status         TEXT NOT NULL DEFAULT 'ACTIVE',
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_nonce_leases_node ON nonce_leases(node_id);
CREATE INDEX IF NOT EXISTS idx_nonce_leases_kv_domain ON nonce_leases(key_version_id, domain);

-- Monotonic nonce counter per (key_version_id, domain).
-- domain is BIGINT because it's a SHA-256 truncated uint32 (0..4294967295),
-- which exceeds INTEGER (int4) max of 2147483647.
CREATE TABLE IF NOT EXISTS nonce_counters (
    key_version_id TEXT NOT NULL,
    domain         BIGINT NOT NULL,
    next_start     BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (key_version_id, domain)
);

CREATE TABLE IF NOT EXISTS idempotency_keys (
    key             TEXT PRIMARY KEY,
    principal_id    TEXT NOT NULL DEFAULT '',
    tenant_id       TEXT NOT NULL DEFAULT '',
    method          TEXT NOT NULL DEFAULT '',
    path            TEXT NOT NULL DEFAULT '',
    request_hash    TEXT NOT NULL DEFAULT '',
    response_status INTEGER NOT NULL DEFAULT 0,
    response_hash   TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Lifecycle jobs
CREATE TABLE IF NOT EXISTS lifecycle_jobs (
    id              TEXT PRIMARY KEY,
    type            TEXT NOT NULL,
    tenant_id       TEXT NOT NULL DEFAULT '',
    key_id          TEXT NOT NULL DEFAULT '',
    key_version_id  TEXT NOT NULL DEFAULT '',
    payload         BYTEA,
    status          TEXT NOT NULL DEFAULT 'PENDING',
    attempt         INTEGER NOT NULL DEFAULT 0,
    next_run_at     TIMESTAMPTZ,
    lease_owner     TEXT NOT NULL DEFAULT '',
    lease_until     TIMESTAMPTZ,
    idempotency_key TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_lifecycle_jobs_status ON lifecycle_jobs(status);

-- Outbox events
CREATE TABLE IF NOT EXISTS outbox_events (
    id           TEXT PRIMARY KEY,
    event_type   TEXT NOT NULL,
    aggregate_id TEXT NOT NULL DEFAULT '',
    payload      BYTEA,
    status       TEXT NOT NULL DEFAULT 'PENDING',
    attempts     INTEGER NOT NULL DEFAULT 0,
    next_run_at  TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_outbox_events_status ON outbox_events(status);

-- Audit chain (append-only)
CREATE TABLE IF NOT EXISTS audit_events (
    event_id       TEXT PRIMARY KEY,
    request_id     TEXT NOT NULL DEFAULT '',
    tenant_hash    TEXT NOT NULL DEFAULT '',
    actor_type     TEXT NOT NULL DEFAULT '',
    actor_hash     TEXT NOT NULL DEFAULT '',
    action         TEXT NOT NULL DEFAULT '',
    target_type    TEXT NOT NULL DEFAULT '',
    target_id_hash TEXT NOT NULL DEFAULT '',
    result         TEXT NOT NULL DEFAULT '',
    error_code     TEXT NOT NULL DEFAULT '',
    timestamp      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    metadata       JSONB NOT NULL DEFAULT '{}',
    chain_name     TEXT NOT NULL DEFAULT 'system',
    sequence       BIGINT NOT NULL,
    prev_hash      TEXT NOT NULL DEFAULT '',
    current_hash   TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_audit_events_chain ON audit_events(chain_name, sequence);

CREATE TABLE IF NOT EXISTS audit_chain_heads (
    chain_name TEXT PRIMARY KEY,
    sequence   BIGINT NOT NULL DEFAULT 0,
    head_hash  TEXT NOT NULL DEFAULT '',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Attestation
CREATE TABLE IF NOT EXISTS attestation_challenges (
    challenge_id TEXT PRIMARY KEY,
    node_id      TEXT NOT NULL,
    nonce        TEXT NOT NULL,
    expires_at   TIMESTAMPTZ NOT NULL,
    used         BOOLEAN NOT NULL DEFAULT FALSE,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS attestation_reports (
    id               TEXT PRIMARY KEY,
    node_id          TEXT NOT NULL,
    baseline_version TEXT NOT NULL DEFAULT '',
    pcr_digest       TEXT NOT NULL DEFAULT '',
    event_log_digest TEXT NOT NULL DEFAULT '',
    quote_valid      BOOLEAN NOT NULL DEFAULT FALSE,
    nonce            TEXT NOT NULL DEFAULT '',
    status           TEXT NOT NULL DEFAULT 'PASS',
    expires_at       TIMESTAMPTZ,
    audit_event_id   TEXT NOT NULL DEFAULT '',
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_attestation_reports_node ON attestation_reports(node_id, created_at DESC);

CREATE TABLE IF NOT EXISTS attestation_baselines (
    version       TEXT PRIMARY KEY,
    pcr_profile   JSONB NOT NULL DEFAULT '{}',
    firmware_hash TEXT NOT NULL DEFAULT '',
    os_image_hash TEXT NOT NULL DEFAULT '',
    status        TEXT NOT NULL DEFAULT 'active',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Schema migrations for existing tables (idempotent).
-- domain was INTEGER (int4) which overflows for uint32 values > 2147483647.
ALTER TABLE nonce_leases ALTER COLUMN domain TYPE BIGINT;
ALTER TABLE nonce_counters ALTER COLUMN domain TYPE BIGINT;
ALTER TABLE keys ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;
ALTER TABLE keys ADD COLUMN IF NOT EXISTS archived_at TIMESTAMPTZ;
ALTER TABLE tenant_envelope_configs ADD COLUMN IF NOT EXISTS profiles JSONB NOT NULL DEFAULT '[]';
ALTER TABLE tenant_envelope_configs ADD COLUMN IF NOT EXISTS aad_required BOOLEAN NOT NULL DEFAULT FALSE;
`

// migrationV2PurposeSQL normalizes a historical metadata-only purpose value
// before enforcing the only purpose supported by this symmetric AEAD baseline.
const migrationV2PurposeSQL = `
UPDATE keys SET purpose = 'encrypt_decrypt' WHERE purpose <> 'encrypt_decrypt';
ALTER TABLE keys DROP CONSTRAINT IF EXISTS keys_purpose_check;
ALTER TABLE keys ADD CONSTRAINT keys_purpose_check CHECK (purpose = 'encrypt_decrypt');
`

const migrationV3ArchiveDestroyedKeysSQL = `
ALTER TABLE keys ADD COLUMN IF NOT EXISTS archived_at TIMESTAMPTZ;
CREATE INDEX IF NOT EXISTS idx_keys_tenant_archived ON keys(tenant_id, archived_at);
`

const migrationV4KeyUploadDownloadSQL = `
ALTER TABLE keys DROP CONSTRAINT IF EXISTS keys_purpose_check;
ALTER TABLE keys ADD CONSTRAINT keys_purpose_check CHECK (purpose IN ('encrypt_decrypt', 'key_wrap'));

CREATE TABLE IF NOT EXISTS key_uploads (
    id               TEXT PRIMARY KEY,
    tenant_id        TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    target_id        TEXT NOT NULL,
    sequence         BIGINT NOT NULL CHECK (sequence > 0),
    kek_id           TEXT NOT NULL REFERENCES keys(id),
    kek_version      INTEGER NOT NULL,
    data_key_id      TEXT NOT NULL REFERENCES keys(id),
    data_key_version INTEGER NOT NULL,
    wrap_suite_id    TEXT NOT NULL,
    nonce            BYTEA NOT NULL,
    wrapped_key      BYTEA NOT NULL,
    tag              BYTEA NOT NULL,
    aad              BYTEA NOT NULL,
    status           TEXT NOT NULL DEFAULT 'UPLOAD_PENDING'
        CHECK (status IN ('UPLOAD_PENDING', 'CONFIRMED')),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    confirmed_at     TIMESTAMPTZ,
    confirmed_by     TEXT NOT NULL DEFAULT '',
    UNIQUE (tenant_id, target_id, sequence)
);
CREATE INDEX IF NOT EXISTS idx_key_upload_tenant ON key_uploads(tenant_id, created_at DESC);

CREATE TABLE IF NOT EXISTS key_downloads (
    id               TEXT PRIMARY KEY,
    tenant_id        TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    target_id        TEXT NOT NULL,
    sequence         BIGINT NOT NULL CHECK (sequence > 0),
    kek_id           TEXT NOT NULL REFERENCES keys(id),
    kek_version      INTEGER NOT NULL,
    data_key_id      TEXT NOT NULL,
    data_key_version INTEGER NOT NULL,
    data_suite_id    TEXT NOT NULL,
    request_digest   TEXT NOT NULL,
    operation        TEXT NOT NULL CHECK (operation IN ('CREATE_KEY', 'CREATE_VERSION')),
    status           TEXT NOT NULL DEFAULT 'RECEIVED'
        CHECK (status IN ('RECEIVED', 'IMPORTED')),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    imported_at      TIMESTAMPTZ,
    imported_by      TEXT NOT NULL DEFAULT '',
    UNIQUE (tenant_id, target_id, sequence)
);
CREATE INDEX IF NOT EXISTS idx_key_download_tenant ON key_downloads(tenant_id, created_at DESC);
`
