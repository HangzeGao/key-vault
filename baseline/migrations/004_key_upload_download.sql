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
