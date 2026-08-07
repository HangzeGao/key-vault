CREATE TABLE IF NOT EXISTS ccsds_security_associations (
    id                     TEXT PRIMARY KEY,
    tenant_id              TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    spi                    INTEGER NOT NULL CHECK (spi BETWEEN 0 AND 65535),
    direction              TEXT NOT NULL CHECK (direction IN ('TC_TX', 'TC_RECOVERY_TX', 'AOS_RX')),
    key_id                 TEXT NOT NULL REFERENCES keys(id),
    key_version            INTEGER NOT NULL CHECK (key_version > 0),
    policy_version         INTEGER NOT NULL CHECK (policy_version > 0),
    suite_id               TEXT NOT NULL,
    state                  TEXT NOT NULL CHECK (state IN ('PREINSTALLED', 'ACTIVE', 'GRACE', 'DISABLED')),
    sequence_number_length INTEGER NOT NULL CHECK (sequence_number_length BETWEEN 0 AND 8),
    transmitted_iv_length  INTEGER NOT NULL CHECK (transmitted_iv_length BETWEEN 0 AND 16),
    tag_length             INTEGER NOT NULL CHECK (tag_length BETWEEN 0 AND 32),
    replay_window          INTEGER NOT NULL CHECK (replay_window BETWEEN 0 AND 64),
    nonce_prefix           BYTEA NOT NULL,
    CHECK (
        (direction = 'TC_TX' AND suite_id IN ('AES_256_CTR', 'SM4_CTR')
         AND sequence_number_length = 0 AND transmitted_iv_length = 4
         AND tag_length = 0 AND replay_window = 0 AND octet_length(nonce_prefix) = 6)
        OR
        (direction = 'TC_RECOVERY_TX' AND suite_id IN ('AES_256_GCM', 'SM4_GCM')
         AND sequence_number_length = 0 AND transmitted_iv_length = 4
         AND tag_length = 16 AND replay_window = 0 AND octet_length(nonce_prefix) = 6)
        OR
        (direction = 'AOS_RX' AND octet_length(nonce_prefix) = 0)
    ),
    UNIQUE (tenant_id, direction, spi),
    UNIQUE (key_id, key_version),
    FOREIGN KEY (key_id, key_version) REFERENCES key_versions(key_id, version_no)
);

CREATE TABLE IF NOT EXISTS ccsds_tx_states (
    association_id TEXT PRIMARY KEY REFERENCES ccsds_security_associations(id) ON DELETE CASCADE,
    next_iv_counter BIGINT NOT NULL DEFAULT 0 CHECK (next_iv_counter BETWEEN 0 AND 4294967296),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS ccsds_rx_replay_states (
    association_id   TEXT PRIMARY KEY REFERENCES ccsds_security_associations(id) ON DELETE CASCADE,
    highest_sequence NUMERIC(20, 0) NOT NULL DEFAULT 0 CHECK (highest_sequence >= 0),
    bitmap           BYTEA NOT NULL DEFAULT decode('0000000000000000', 'hex'),
    seen             BOOLEAN NOT NULL DEFAULT FALSE,
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (octet_length(bitmap) = 8)
);
