// Package securitystate owns the durable ground-side security state required
// by the CCSDS TC/AOS profile. It deliberately does not expose generic key
// vault, cluster, lease, upload/download, or outbox persistence.
package securitystate

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/kvlt/key-vault/internal/repository/models"
	_ "modernc.org/sqlite"
)

const schemaVersion = 1

var (
	ErrNotFound = errors.New("securitystate: not found")
	ErrConflict = errors.New("securitystate: conflict")
)

// Store is the single-node SQLite adapter. Transactions begin with an
// immediate write lock so state transitions remain serializable even if two
// local processes accidentally open the same file.
type Store struct {
	db   *sql.DB
	path string
}

// Diagnostics is a redacted operational snapshot. It never contains SQL,
// record values, identifiers, key material, or the full database path.
type Diagnostics struct {
	ObservedAt   time.Time
	Schema       int
	DatabaseSize int64
	WALSize      int64
	Associations int64
	AuditEvents  int64
	IntegrityOK  bool
}

// Open creates or opens the only supported durable store.
func Open(ctx context.Context, path string) (*Store, error) {
	if path == "" {
		return nil, errors.New("securitystate: database path is required")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("securitystate: resolve database path: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(abs), 0o700); err != nil {
		return nil, fmt.Errorf("securitystate: create database directory: %w", err)
	}

	query := url.Values{}
	query.Set("_busy_timeout", "5000")
	query.Set("_foreign_keys", "on")
	query.Set("_journal_mode", "wal")
	query.Set("_synchronous", "full")
	query.Set("_txlock", "immediate")
	dsn := "file:" + filepath.ToSlash(abs) + "?" + query.Encode()
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("securitystate: open sqlite: %w", err)
	}
	// A single connection is sufficient for the command rate and makes write
	// ordering explicit. SQLite WAL still permits external read-only tooling.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	store := &Store{db: db, path: abs}
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("securitystate: ping sqlite: %w", err)
	}
	if err := store.migrate(ctx); err != nil {
		db.Close()
		return nil, err
	}
	if err := os.Chmod(abs, 0o600); err != nil {
		db.Close()
		return nil, fmt.Errorf("securitystate: restrict database permissions: %w", err)
	}
	return store, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }

func (s *Store) migrate(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("securitystate: begin schema transaction: %w", err)
	}
	defer tx.Rollback()
	for _, statement := range schemaStatements {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("securitystate: apply schema: %w", err)
		}
	}
	var version int
	if err := tx.QueryRowContext(ctx, `SELECT version FROM schema_meta WHERE singleton=1`).Scan(&version); err != nil {
		return fmt.Errorf("securitystate: read schema version: %w", err)
	}
	if version != schemaVersion {
		return fmt.Errorf("securitystate: schema version %d is unsupported; expected %d", version, schemaVersion)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("securitystate: commit schema: %w", err)
	}
	return nil
}

var schemaStatements = []string{
	`CREATE TABLE IF NOT EXISTS schema_meta (
		singleton INTEGER PRIMARY KEY CHECK (singleton=1),
		version INTEGER NOT NULL CHECK (version=1)
	) STRICT`,
	`INSERT INTO schema_meta(singleton, version) VALUES(1, 1) ON CONFLICT(singleton) DO NOTHING`,
	`CREATE TABLE IF NOT EXISTS tenants (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		status TEXT NOT NULL CHECK (status='active'),
		created_at TEXT NOT NULL,
		updated_at TEXT NOT NULL
	) STRICT`,
	`CREATE TABLE IF NOT EXISTS protocol_keys (
		id TEXT PRIMARY KEY,
		tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
		name TEXT NOT NULL,
		purpose TEXT NOT NULL CHECK (purpose IN ('encrypt_decrypt','authenticate_verify')),
		usage_scope TEXT NOT NULL CHECK (usage_scope='PROTOCOL'),
		policy_id TEXT NOT NULL,
		suite_id TEXT NOT NULL,
		current_version INTEGER NOT NULL CHECK (current_version>0),
		status TEXT NOT NULL CHECK (status IN ('ACTIVE','DISABLED','DESTROYED')),
		tags_json TEXT NOT NULL,
		created_at TEXT NOT NULL,
		updated_at TEXT NOT NULL
	) STRICT`,
	`CREATE TABLE IF NOT EXISTS protocol_key_versions (
		id TEXT PRIMARY KEY,
		key_id TEXT NOT NULL REFERENCES protocol_keys(id) ON DELETE CASCADE,
		version_no INTEGER NOT NULL CHECK (version_no>0),
		suite_id TEXT NOT NULL,
		wrapped_key BLOB NOT NULL CHECK (length(wrapped_key)>0),
		wrap_metadata BLOB NOT NULL CHECK (length(wrap_metadata)>0),
		status TEXT NOT NULL CHECK (status IN ('ACTIVE','PRE_ACTIVE','DECRYPT_ONLY','DESTROYED')),
		created_at TEXT NOT NULL,
		UNIQUE(key_id, version_no)
	) STRICT`,
	`CREATE TABLE IF NOT EXISTS crk_versions (
		id TEXT PRIMARY KEY,
		version INTEGER NOT NULL UNIQUE CHECK (version>0),
		status TEXT NOT NULL CHECK (status='active'),
		created_at TEXT NOT NULL
	) STRICT`,
	`CREATE TABLE IF NOT EXISTS crk_envelopes (
		id TEXT PRIMARY KEY,
		crk_version_id TEXT NOT NULL REFERENCES crk_versions(id) ON DELETE CASCADE,
		node_id TEXT NOT NULL,
		envelope BLOB NOT NULL CHECK (length(envelope)>0),
		created_at TEXT NOT NULL,
		UNIQUE(crk_version_id, node_id)
	) STRICT`,
	`CREATE TABLE IF NOT EXISTS security_associations (
		id TEXT PRIMARY KEY,
		tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
		spi INTEGER NOT NULL CHECK (spi BETWEEN 0 AND 65535),
		direction TEXT NOT NULL CHECK (direction IN ('TC_TX','TC_RECOVERY_TX','AOS_RX')),
		key_id TEXT NOT NULL REFERENCES protocol_keys(id),
		key_version INTEGER NOT NULL CHECK (key_version>0),
		security_epoch INTEGER NOT NULL CHECK (security_epoch>=0),
		policy_version INTEGER NOT NULL CHECK (policy_version>0),
		suite_id TEXT NOT NULL,
		state TEXT NOT NULL CHECK (state IN ('CURRENT','NEXT','ACTIVE','DISABLED')),
		sequence_number_length INTEGER NOT NULL CHECK (sequence_number_length BETWEEN 0 AND 8),
		transmitted_iv_length INTEGER NOT NULL CHECK (transmitted_iv_length BETWEEN 0 AND 16),
		tag_length INTEGER NOT NULL CHECK (tag_length BETWEEN 0 AND 32),
		replay_window INTEGER NOT NULL CHECK (replay_window BETWEEN 0 AND 64),
		nonce_prefix BLOB NOT NULL,
		UNIQUE(tenant_id, direction, spi),
		FOREIGN KEY(key_id, key_version) REFERENCES protocol_key_versions(key_id, version_no)
	) STRICT`,
	`CREATE UNIQUE INDEX IF NOT EXISTS one_current_tc ON security_associations(tenant_id)
		WHERE direction='TC_TX' AND state='CURRENT'`,
	`CREATE UNIQUE INDEX IF NOT EXISTS one_next_tc ON security_associations(tenant_id)
		WHERE direction='TC_TX' AND state='NEXT'`,
	`CREATE UNIQUE INDEX IF NOT EXISTS one_recovery_tc ON security_associations(tenant_id)
		WHERE direction='TC_RECOVERY_TX' AND state='ACTIVE'`,
	`CREATE TABLE IF NOT EXISTS tx_states (
		association_id TEXT PRIMARY KEY REFERENCES security_associations(id) ON DELETE CASCADE,
		next_iv INTEGER NOT NULL DEFAULT 0 CHECK (next_iv BETWEEN 0 AND 4294967296),
		updated_at TEXT NOT NULL
	) STRICT`,
	`CREATE TABLE IF NOT EXISTS rx_states (
		association_id TEXT PRIMARY KEY REFERENCES security_associations(id) ON DELETE CASCADE,
		highest_sequence TEXT NOT NULL DEFAULT '0',
		bitmap BLOB NOT NULL DEFAULT X'0000000000000000' CHECK (length(bitmap)=8),
		seen INTEGER NOT NULL DEFAULT 0 CHECK (seen IN (0,1)),
		updated_at TEXT NOT NULL
	) STRICT`,
	`CREATE TABLE IF NOT EXISTS audit_chain_heads (
		chain_name TEXT PRIMARY KEY,
		sequence INTEGER NOT NULL CHECK (sequence>=0),
		head_hash TEXT NOT NULL,
		updated_at TEXT NOT NULL
	) STRICT`,
	`CREATE TABLE IF NOT EXISTS audit_events (
		event_id TEXT PRIMARY KEY,
		request_id TEXT NOT NULL,
		tenant_hash TEXT NOT NULL,
		actor_type TEXT NOT NULL,
		actor_hash TEXT NOT NULL,
		action TEXT NOT NULL,
		target_type TEXT NOT NULL,
		target_id_hash TEXT NOT NULL,
		result TEXT NOT NULL,
		error_code TEXT NOT NULL,
		timestamp TEXT NOT NULL,
		metadata_json TEXT NOT NULL,
		chain_name TEXT NOT NULL REFERENCES audit_chain_heads(chain_name) ON DELETE RESTRICT,
		sequence INTEGER NOT NULL CHECK (sequence>0),
		prev_hash TEXT NOT NULL,
		current_hash TEXT NOT NULL,
		UNIQUE(chain_name, sequence)
	) STRICT`,
}

func (s *Store) EnsureTenant(ctx context.Context, id, name string) error {
	if id == "" || name == "" {
		return errors.New("securitystate: tenant id and name are required")
	}
	now := formatTime(time.Now())
	_, err := s.db.ExecContext(ctx, `INSERT INTO tenants(id,name,status,created_at,updated_at)
		VALUES(?,?,'active',?,?)
		ON CONFLICT(id) DO UPDATE SET name=excluded.name, updated_at=excluded.updated_at`, id, name, now, now)
	return wrap("ensure tenant", err)
}

func (s *Store) CreateProtocolKey(ctx context.Context, key *models.Key, version *models.KeyVersion) error {
	if key == nil || version == nil || key.ID == "" || key.TenantID == "" || version.ID == "" ||
		version.KeyID != key.ID || version.VersionNo != key.CurrentVersion || key.UsageScope != models.KeyUsageProtocol {
		return errors.New("securitystate: invalid protocol key")
	}
	tags, err := json.Marshal(key.Tags)
	if err != nil {
		return fmt.Errorf("securitystate: encode key tags: %w", err)
	}
	now := time.Now().UTC()
	if key.CreatedAt.IsZero() {
		key.CreatedAt = now
	}
	key.UpdatedAt = now
	if version.CreatedAt.IsZero() {
		version.CreatedAt = now
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return wrap("begin protocol key", err)
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `INSERT INTO protocol_keys
		(id,tenant_id,name,purpose,usage_scope,policy_id,suite_id,current_version,status,tags_json,created_at,updated_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`, key.ID, key.TenantID, key.Name, key.Purpose, string(key.UsageScope),
		key.PolicyID, key.SuiteID, key.CurrentVersion, key.Status, string(tags), formatTime(key.CreatedAt), formatTime(key.UpdatedAt))
	if err != nil {
		return conflict("create protocol key", err)
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO protocol_key_versions
		(id,key_id,version_no,suite_id,wrapped_key,wrap_metadata,status,created_at)
		VALUES(?,?,?,?,?,?,?,?)`, version.ID, version.KeyID, version.VersionNo, version.SuiteID,
		version.WrappedDEK, version.WrapMetadata, version.Status, formatTime(version.CreatedAt))
	if err != nil {
		return conflict("create protocol key version", err)
	}
	return wrap("commit protocol key", tx.Commit())
}

func (s *Store) GetKey(ctx context.Context, tenantID, keyID string) (*models.Key, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id,tenant_id,name,purpose,usage_scope,policy_id,suite_id,
		current_version,status,tags_json,created_at,updated_at FROM protocol_keys WHERE id=? AND tenant_id=?`, keyID, tenantID)
	var key models.Key
	var scope, tags, created, updated string
	if err := row.Scan(&key.ID, &key.TenantID, &key.Name, &key.Purpose, &scope, &key.PolicyID, &key.SuiteID,
		&key.CurrentVersion, &key.Status, &tags, &created, &updated); err != nil {
		return nil, notFound("get protocol key", err)
	}
	key.UsageScope = models.KeyUsageScope(scope)
	if key.UsageScope != models.KeyUsageProtocol {
		return nil, fmt.Errorf("securitystate: invalid persisted key scope %q", scope)
	}
	if err := json.Unmarshal([]byte(tags), &key.Tags); err != nil {
		return nil, fmt.Errorf("securitystate: decode key tags: %w", err)
	}
	var err error
	if key.CreatedAt, err = parseTime(created); err != nil {
		return nil, err
	}
	if key.UpdatedAt, err = parseTime(updated); err != nil {
		return nil, err
	}
	return &key, nil
}

func (s *Store) GetKeyVersion(ctx context.Context, versionID string) (*models.KeyVersion, error) {
	return scanKeyVersion(s.db.QueryRowContext(ctx, `SELECT id,key_id,version_no,suite_id,wrapped_key,
		wrap_metadata,status,created_at FROM protocol_key_versions WHERE id=?`, versionID))
}

func (s *Store) GetKeyVersionByNo(ctx context.Context, keyID string, version uint32) (*models.KeyVersion, error) {
	return scanKeyVersion(s.db.QueryRowContext(ctx, `SELECT id,key_id,version_no,suite_id,wrapped_key,
		wrap_metadata,status,created_at FROM protocol_key_versions WHERE key_id=? AND version_no=?`, keyID, version))
}

type rowScanner interface{ Scan(...any) error }

func scanKeyVersion(row rowScanner) (*models.KeyVersion, error) {
	var version models.KeyVersion
	var created string
	if err := row.Scan(&version.ID, &version.KeyID, &version.VersionNo, &version.SuiteID, &version.WrappedDEK,
		&version.WrapMetadata, &version.Status, &created); err != nil {
		return nil, notFound("get protocol key version", err)
	}
	var err error
	version.CreatedAt, err = parseTime(created)
	if err != nil {
		return nil, err
	}
	return &version, nil
}

func (s *Store) LoadLatestCRK(ctx context.Context, nodeID string) (*models.CRKVersion, *models.CRKNodeEnvelope, error) {
	row := s.db.QueryRowContext(ctx, `SELECT v.id,v.version,v.status,v.created_at,e.id,e.node_id,e.envelope,e.created_at
		FROM crk_versions v JOIN crk_envelopes e ON e.crk_version_id=v.id
		WHERE e.node_id=? ORDER BY v.version DESC LIMIT 1`, nodeID)
	var version models.CRKVersion
	var envelope models.CRKNodeEnvelope
	var versionCreated, envelopeCreated string
	if err := row.Scan(&version.ID, &version.Version, &version.Status, &versionCreated,
		&envelope.ID, &envelope.NodeID, &envelope.Envelope, &envelopeCreated); err != nil {
		return nil, nil, notFound("load CRK", err)
	}
	envelope.CRKVersionID = version.ID
	var err error
	version.CreatedAt, err = parseTime(versionCreated)
	if err != nil {
		return nil, nil, err
	}
	envelope.CreatedAt, err = parseTime(envelopeCreated)
	if err != nil {
		return nil, nil, err
	}
	return &version, &envelope, nil
}

func (s *Store) SaveCRK(ctx context.Context, version *models.CRKVersion, envelope *models.CRKNodeEnvelope) error {
	if version == nil || envelope == nil || version.ID == "" || envelope.CRKVersionID != version.ID || envelope.NodeID == "" {
		return errors.New("securitystate: invalid CRK state")
	}
	now := time.Now().UTC()
	if version.CreatedAt.IsZero() {
		version.CreatedAt = now
	}
	if envelope.CreatedAt.IsZero() {
		envelope.CreatedAt = now
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return wrap("begin CRK save", err)
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `INSERT INTO crk_versions(id,version,status,created_at) VALUES(?,?,?,?)`,
		version.ID, version.Version, version.Status, formatTime(version.CreatedAt)); err != nil {
		return conflict("save CRK version", err)
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO crk_envelopes(id,crk_version_id,node_id,envelope,created_at)
		VALUES(?,?,?,?,?)`, envelope.ID, envelope.CRKVersionID, envelope.NodeID, envelope.Envelope,
		formatTime(envelope.CreatedAt)); err != nil {
		return conflict("save CRK envelope", err)
	}
	return wrap("commit CRK", tx.Commit())
}

func (s *Store) Diagnostics(ctx context.Context) (*Diagnostics, error) {
	if err := s.db.PingContext(ctx); err != nil {
		return nil, err
	}
	var associations, auditEvents int64
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM security_associations`).Scan(&associations); err != nil {
		return nil, err
	}
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM audit_events`).Scan(&auditEvents); err != nil {
		return nil, err
	}
	var integrity string
	if err := s.db.QueryRowContext(ctx, `PRAGMA quick_check`).Scan(&integrity); err != nil {
		return nil, err
	}
	var size, walSize int64
	if info, err := os.Stat(s.path); err == nil {
		size = info.Size()
	}
	if info, err := os.Stat(s.path + "-wal"); err == nil {
		walSize = info.Size()
	}
	return &Diagnostics{ObservedAt: time.Now().UTC(), Schema: schemaVersion, DatabaseSize: size,
		WALSize: walSize, Associations: associations, AuditEvents: auditEvents, IntegrityOK: integrity == "ok"}, nil
}

func formatTime(value time.Time) string {
	return value.UTC().Truncate(time.Microsecond).Format(time.RFC3339Nano)
}

func parseTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("securitystate: decode timestamp: %w", err)
	}
	return parsed.UTC(), nil
}

func wrap(operation string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("securitystate: %s: %w", operation, err)
}

func notFound(operation string, err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("%w: %s", ErrNotFound, operation)
	}
	return wrap(operation, err)
}

func conflict(operation string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%w: %s: %v", ErrConflict, operation, err)
}
