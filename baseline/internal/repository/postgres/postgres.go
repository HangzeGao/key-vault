// Package postgres implements the repository interface backed by PostgreSQL.
// Used when cfg.Database.Driver == "postgres". Provides durable storage so
// keys, audit chains, and lifecycle state survive restarts (design §11).
package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/kvlt/key-vault/internal/repository"
	"github.com/kvlt/key-vault/internal/repository/models"
)

// Errors are aliases for the common repository errors so upper layers can
// handle memory and postgres backends uniformly via errors.Is.
var (
	ErrNotFound = repository.ErrNotFound
	ErrConflict = repository.ErrConflict
)

// Store is the PostgreSQL-backed repository.
type Store struct {
	pool *pgxpool.Pool
}

// New creates a new PostgreSQL store. dsn is the connection string.
// The caller should run Migrate() before serving requests.
func New(ctx context.Context, dsn string) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("postgres: parse dsn: %w", err)
	}
	cfg.MaxConns = 20
	cfg.MinConns = 2
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("postgres: connect: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("postgres: ping: %w", err)
	}
	return &Store{pool: pool}, nil
}

// Close releases the connection pool.
func (s *Store) Close() error {
	s.pool.Close()
	return nil
}

// Ping checks the database connection is alive.
func (s *Store) Ping(ctx context.Context) error {
	return s.pool.Ping(ctx)
}

type migration struct {
	version int
	name    string
	sql     string
}

var schemaMigrations = []migration{
	{version: 1, name: "engineering_baseline_schema", sql: migrationV1SQL},
	{version: 2, name: "enforce_encrypt_decrypt_purpose", sql: migrationV2PurposeSQL},
	{version: 3, name: "archive_destroyed_keys", sql: migrationV3ArchiveDestroyedKeysSQL},
	{version: 4, name: "key_upload_download", sql: migrationV4KeyUploadDownloadSQL},
}

// Migrate applies each embedded schema migration exactly once. A transaction-
// scoped advisory lock prevents concurrent instances from racing at startup.
func (s *Store) Migrate(ctx context.Context) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin migration transaction: %w", err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version INTEGER PRIMARY KEY,
		name TEXT NOT NULL,
		applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	)`); err != nil {
		return fmt.Errorf("create migration ledger: %w", err)
	}
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", int64(20260712)); err != nil {
		return fmt.Errorf("acquire migration lock: %w", err)
	}
	for _, migration := range schemaMigrations {
		var applied bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = $1)`, migration.version).Scan(&applied); err != nil {
			return fmt.Errorf("check migration %d: %w", migration.version, err)
		}
		if applied {
			continue
		}
		if _, err := tx.Exec(ctx, migration.sql); err != nil {
			return fmt.Errorf("apply migration %d (%s): %w", migration.version, migration.name, err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations (version, name) VALUES ($1, $2)`, migration.version, migration.name); err != nil {
			return fmt.Errorf("record migration %d: %w", migration.version, err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit migrations: %w", err)
	}
	return nil
}

// isUniqueViolation returns true if err is a PG unique constraint violation.
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == "23505"
	}
	return false
}

// isNoRows returns true if err is pgx.ErrNoRows.
func isNoRows(err error) bool { return errors.Is(err, pgx.ErrNoRows) }

// newID generates a prefixed UUID-based ID.
func newID(prefix string) string {
	return fmt.Sprintf("%s_%s", prefix, uuid.NewString()[:12])
}

// --- Tenant ---

func (s *Store) UpsertTenant(ctx context.Context, t *models.Tenant) error {
	now := time.Now().UTC()
	if t.CreatedAt.IsZero() {
		t.CreatedAt = now
	}
	t.UpdatedAt = now
	_, err := s.pool.Exec(ctx,
		`INSERT INTO tenants (id, name, status, crk_version_id, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6)
		 ON CONFLICT (id) DO UPDATE SET name=$2, status=$3, crk_version_id=$4, updated_at=$6`,
		t.ID, t.Name, t.Status, t.CRKVersionID, t.CreatedAt, t.UpdatedAt)
	return err
}

func (s *Store) GetTenant(ctx context.Context, id string) (*models.Tenant, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT id, name, status, crk_version_id, created_at, updated_at FROM tenants WHERE id=$1`, id)
	var t models.Tenant
	if err := row.Scan(&t.ID, &t.Name, &t.Status, &t.CRKVersionID, &t.CreatedAt, &t.UpdatedAt); err != nil {
		if isNoRows(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &t, nil
}

// --- Tenant Envelope Config ---

func (s *Store) GetTenantEnvelopeConfig(ctx context.Context, tenantID string) (*models.TenantEnvelopeConfig, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT tenant_id, default_format, allowed_formats, profiles, aad_required, version, created_at, updated_at, updated_by
		 FROM tenant_envelope_configs WHERE tenant_id=$1`, tenantID)
	var c models.TenantEnvelopeConfig
	var profilesJSON []byte
	if err := row.Scan(&c.TenantID, &c.DefaultFormat, &c.AllowedFormats, &profilesJSON, &c.AADRequired, &c.Version, &c.CreatedAt, &c.UpdatedAt, &c.UpdatedBy); err != nil {
		if isNoRows(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if len(profilesJSON) > 0 {
		_ = json.Unmarshal(profilesJSON, &c.Profiles)
	}
	return &c, nil
}

func (s *Store) UpsertTenantEnvelopeConfig(ctx context.Context, cfg *models.TenantEnvelopeConfig) error {
	now := time.Now().UTC()
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	// Row lock makes the version check and update one atomic boundary.
	var existingVer int
	err = tx.QueryRow(ctx,
		`SELECT version FROM tenant_envelope_configs WHERE tenant_id=$1 FOR UPDATE`, cfg.TenantID).Scan(&existingVer)
	if err == nil {
		if cfg.Version > 0 && cfg.Version != existingVer {
			return fmt.Errorf("%w: envelope config version mismatch (expected %d, got %d)", ErrConflict, existingVer, cfg.Version)
		}
		cfg.Version = existingVer + 1
		profilesJSON, _ := json.Marshal(cfg.Profiles)
		_, err = tx.Exec(ctx,
			`UPDATE tenant_envelope_configs SET default_format=$2, allowed_formats=$3, profiles=$4, aad_required=$5, version=$6, updated_at=$7, updated_by=$8
			 WHERE tenant_id=$1`,
			cfg.TenantID, cfg.DefaultFormat, cfg.AllowedFormats, profilesJSON, cfg.AADRequired, cfg.Version, now, cfg.UpdatedBy)
		if err != nil {
			return err
		}
		cfg.UpdatedAt = now
		return tx.Commit(ctx)
	}
	if !isNoRows(err) {
		return err
	}
	// Insert new.
	if cfg.Version > 0 {
		return fmt.Errorf("%w: envelope config does not exist but version > 0", ErrConflict)
	}
	cfg.Version = 1
	cfg.CreatedAt = now
	cfg.UpdatedAt = now
	profilesJSON, _ := json.Marshal(cfg.Profiles)
	_, err = tx.Exec(ctx,
		`INSERT INTO tenant_envelope_configs (tenant_id, default_format, allowed_formats, profiles, aad_required, version, created_at, updated_at, updated_by)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		cfg.TenantID, cfg.DefaultFormat, cfg.AllowedFormats, profilesJSON, cfg.AADRequired, cfg.Version, cfg.CreatedAt, cfg.UpdatedAt, cfg.UpdatedBy)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// --- Keys ---

func (s *Store) CreateKey(ctx context.Context, k *models.Key, kv *models.KeyVersion) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	now := time.Now().UTC()
	if k.CreatedAt.IsZero() {
		k.CreatedAt = now
	}
	k.UpdatedAt = now
	if kv.CreatedAt.IsZero() {
		kv.CreatedAt = now
	}
	tagsJSON, _ := json.Marshal(k.Tags)
	var expiresAt any
	if !k.ExpiresAt.IsZero() {
		expiresAt = k.ExpiresAt
	}
	_, err = tx.Exec(ctx,
		`INSERT INTO keys (id, tenant_id, name, purpose, policy_id, suite_id, current_version, status, tags, expires_at, archived_at, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NULL, $11, $12)`,
		k.ID, k.TenantID, k.Name, k.Purpose, k.PolicyID, k.SuiteID, k.CurrentVersion, k.Status, tagsJSON, expiresAt, k.CreatedAt, k.UpdatedAt)
	if err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("%w: key %s exists", ErrConflict, k.ID)
		}
		return err
	}
	_, err = tx.Exec(ctx,
		`INSERT INTO key_versions (id, key_id, version_no, suite_id, wrapped_dek, wrap_metadata, status, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		kv.ID, kv.KeyID, kv.VersionNo, kv.SuiteID, kv.WrappedDEK, kv.WrapMetadata, kv.Status, kv.CreatedAt)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) GetKey(ctx context.Context, tenantID, keyID string) (*models.Key, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT id, tenant_id, name, purpose, policy_id, suite_id, current_version, status, tags, expires_at, archived_at, created_at, updated_at
		 FROM keys WHERE id=$1 AND tenant_id=$2`, keyID, tenantID)
	k, err := scanKey(row)
	if err != nil {
		if isNoRows(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return k, nil
}

func (s *Store) ListKeys(ctx context.Context, tenantID string) ([]*models.Key, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, tenant_id, name, purpose, policy_id, suite_id, current_version, status, tags, expires_at, archived_at, created_at, updated_at
		 FROM keys WHERE tenant_id=$1 AND archived_at IS NULL ORDER BY created_at DESC`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*models.Key
	for rows.Next() {
		k, err := scanKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

func (s *Store) ListKeysIncludingArchived(ctx context.Context, tenantID string) ([]*models.Key, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, tenant_id, name, purpose, policy_id, suite_id, current_version, status, tags, expires_at, archived_at, created_at, updated_at
		 FROM keys WHERE tenant_id=$1 ORDER BY created_at DESC`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*models.Key
	for rows.Next() {
		k, err := scanKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

func (s *Store) ListAllKeys(ctx context.Context) ([]*models.Key, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, tenant_id, name, purpose, policy_id, suite_id, current_version, status, tags, expires_at, archived_at, created_at, updated_at
		 FROM keys ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*models.Key
	for rows.Next() {
		k, err := scanKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

func (s *Store) UpdateKeyMetadata(ctx context.Context, tenantID, keyID, name string, tags map[string]string, expiresAt time.Time) (*models.Key, error) {
	tagsJSON, _ := json.Marshal(tags)
	var expiresAtValue any
	if !expiresAt.IsZero() {
		expiresAtValue = expiresAt
	}
	ct, err := s.pool.Exec(ctx,
		`UPDATE keys SET name=$3, tags=$4, expires_at=$5, updated_at=NOW() WHERE id=$1 AND tenant_id=$2`,
		keyID, tenantID, name, tagsJSON, expiresAtValue)
	if err != nil {
		return nil, err
	}
	if ct.RowsAffected() == 0 {
		return nil, ErrNotFound
	}
	return s.GetKey(ctx, tenantID, keyID)
}

func (s *Store) UpdateKeyStatus(ctx context.Context, keyID, expectedCurrent, newStatus string) error {
	ct, err := s.pool.Exec(ctx,
		`UPDATE keys SET status=$3, updated_at=NOW() WHERE id=$1 AND status=$2`,
		keyID, expectedCurrent, newStatus)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		// Either not found or status mismatch.
		var actual string
		e2 := s.pool.QueryRow(ctx, `SELECT status FROM keys WHERE id=$1`, keyID).Scan(&actual)
		if isNoRows(e2) {
			return ErrNotFound
		}
		return fmt.Errorf("%w: expected %s, got %s", ErrConflict, expectedCurrent, actual)
	}
	return nil
}

func (s *Store) ArchiveDestroyedKey(ctx context.Context, tenantID, keyID string) (*models.Key, error) {
	ct, err := s.pool.Exec(ctx,
		`UPDATE keys SET archived_at=COALESCE(archived_at, NOW()), updated_at=NOW() WHERE id=$1 AND tenant_id=$2 AND status='DESTROYED'`,
		keyID, tenantID)
	if err != nil {
		return nil, err
	}
	if ct.RowsAffected() == 0 {
		var actual string
		e2 := s.pool.QueryRow(ctx, `SELECT status FROM keys WHERE id=$1 AND tenant_id=$2`, keyID, tenantID).Scan(&actual)
		if isNoRows(e2) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("%w: expected DESTROYED, got %s", ErrConflict, actual)
	}
	return s.GetKey(ctx, tenantID, keyID)
}

func (s *Store) DestroyKeyMaterial(ctx context.Context, keyID string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	ct, err := tx.Exec(ctx,
		`UPDATE keys SET status='DESTROYED', updated_at=NOW() WHERE id=$1 AND status='DESTROY_PENDING'`,
		keyID)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		var actual string
		e2 := tx.QueryRow(ctx, `SELECT status FROM keys WHERE id=$1`, keyID).Scan(&actual)
		if isNoRows(e2) {
			return ErrNotFound
		}
		return fmt.Errorf("%w: expected DESTROY_PENDING, got %s", ErrConflict, actual)
	}
	_, err = tx.Exec(ctx,
		`UPDATE key_versions SET wrapped_dek='\x'::bytea, wrap_metadata='\x'::bytea, status='DESTROYED' WHERE key_id=$1`,
		keyID)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) CreatePendingKeyVersion(ctx context.Context, keyID string, v *models.KeyVersion) error {
	ct, err := s.pool.Exec(ctx, `INSERT INTO key_versions (id,key_id,version_no,suite_id,wrapped_dek,wrap_metadata,status,created_at)
		SELECT $1,$2,$3,$4,$5,$6,'PRE_ACTIVE',$7 FROM keys WHERE id=$2 AND current_version+1=$3`,
		v.ID, keyID, v.VersionNo, v.SuiteID, v.WrappedDEK, v.WrapMetadata, v.CreatedAt)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrConflict
	}
	return nil
}

func (s *Store) ActivateKeyVersion(ctx context.Context, keyID string, versionNo uint32) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	ct, err := tx.Exec(ctx, `UPDATE key_versions SET status='ACTIVE' WHERE key_id=$1 AND version_no=$2 AND status='PRE_ACTIVE'`, keyID, versionNo)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrConflict
	}
	_, err = tx.Exec(ctx, `UPDATE key_versions SET status='DECRYPT_ONLY' WHERE key_id=$1 AND version_no=(SELECT current_version FROM keys WHERE id=$1)`, keyID)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE keys SET current_version=$2,updated_at=NOW() WHERE id=$1`, keyID, versionNo)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) GetKeyVersion(ctx context.Context, versionID string) (*models.KeyVersion, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT id, key_id, version_no, suite_id, wrapped_dek, wrap_metadata, status, created_at
		 FROM key_versions WHERE id=$1`, versionID)
	return scanKeyVersion(row)
}

func (s *Store) GetKeyVersionByNo(ctx context.Context, keyID string, versionNo uint32) (*models.KeyVersion, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT id, key_id, version_no, suite_id, wrapped_dek, wrap_metadata, status, created_at
		 FROM key_versions WHERE key_id=$1 AND version_no=$2`, keyID, versionNo)
	kv, err := scanKeyVersion(row)
	if err != nil {
		if isNoRows(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return kv, nil
}

func (s *Store) GetCurrentKeyVersion(ctx context.Context, keyID string) (*models.KeyVersion, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT kv.id, kv.key_id, kv.version_no, kv.suite_id, kv.wrapped_dek, kv.wrap_metadata, kv.status, kv.created_at
		 FROM key_versions kv
		 JOIN keys k ON k.id = kv.key_id
		 WHERE kv.key_id=$1 AND kv.version_no = k.current_version`, keyID)
	kv, err := scanKeyVersion(row)
	if err != nil {
		if isNoRows(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return kv, nil
}

func (s *Store) CreateKeyUpload(ctx context.Context, p *models.KeyUpload) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO key_uploads
		(id,tenant_id,target_id,sequence,kek_id,kek_version,data_key_id,data_key_version,wrap_suite_id,nonce,wrapped_key,tag,aad,status,created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,
		p.ID, p.TenantID, p.TargetID, p.Sequence, p.KEKID, p.KEKVersion,
		p.DataKeyID, p.DataKeyVersion, p.WrapSuiteID, p.Nonce, p.WrappedKey,
		p.Tag, p.AAD, p.Status, p.CreatedAt)
	if isUniqueViolation(err) {
		return ErrConflict
	}
	return err
}

func (s *Store) GetKeyUpload(ctx context.Context, tenantID, uploadID string) (*models.KeyUpload, error) {
	var p models.KeyUpload
	var confirmedAt *time.Time
	err := s.pool.QueryRow(ctx, `SELECT id,tenant_id,target_id,sequence,kek_id,kek_version,
		data_key_id,data_key_version,wrap_suite_id,nonce,wrapped_key,tag,aad,status,created_at,confirmed_at,confirmed_by
		FROM key_uploads WHERE id=$1 AND tenant_id=$2`, uploadID, tenantID).
		Scan(&p.ID, &p.TenantID, &p.TargetID, &p.Sequence, &p.KEKID, &p.KEKVersion,
			&p.DataKeyID, &p.DataKeyVersion, &p.WrapSuiteID, &p.Nonce, &p.WrappedKey,
			&p.Tag, &p.AAD, &p.Status, &p.CreatedAt, &confirmedAt, &p.ConfirmedBy)
	if isNoRows(err) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if confirmedAt != nil {
		p.ConfirmedAt = *confirmedAt
	}
	return &p, nil
}

func (s *Store) ConfirmKeyUpload(ctx context.Context, tenantID, uploadID, principalID string, confirmedAt time.Time) error {
	ct, err := s.pool.Exec(ctx, `UPDATE key_uploads
		SET status='CONFIRMED', confirmed_at=$4, confirmed_by=$3
		WHERE id=$1 AND tenant_id=$2 AND status='UPLOAD_PENDING'`,
		uploadID, tenantID, principalID, confirmedAt)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		var status string
		err := s.pool.QueryRow(ctx, `SELECT status FROM key_uploads WHERE id=$1 AND tenant_id=$2`, uploadID, tenantID).Scan(&status)
		if isNoRows(err) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if status == "CONFIRMED" {
			return nil
		}
		return ErrConflict
	}
	return nil
}

func (s *Store) CreateKeyDownload(ctx context.Context, d *models.KeyDownload) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO key_downloads
		(id,tenant_id,target_id,sequence,kek_id,kek_version,data_key_id,data_key_version,
		 data_suite_id,request_digest,operation,status,created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
		d.ID, d.TenantID, d.TargetID, d.Sequence, d.KEKID, d.KEKVersion,
		d.DataKeyID, d.DataKeyVersion, d.DataSuiteID, d.RequestDigest,
		d.Operation, d.Status, d.CreatedAt)
	if isUniqueViolation(err) {
		return ErrConflict
	}
	return err
}

func (s *Store) GetKeyDownload(ctx context.Context, tenantID, downloadID string) (*models.KeyDownload, error) {
	var d models.KeyDownload
	var importedAt *time.Time
	err := s.pool.QueryRow(ctx, `SELECT id,tenant_id,target_id,sequence,kek_id,kek_version,
		data_key_id,data_key_version,data_suite_id,request_digest,operation,status,
		created_at,imported_at,imported_by
		FROM key_downloads WHERE id=$1 AND tenant_id=$2`, downloadID, tenantID).
		Scan(&d.ID, &d.TenantID, &d.TargetID, &d.Sequence, &d.KEKID, &d.KEKVersion,
			&d.DataKeyID, &d.DataKeyVersion, &d.DataSuiteID, &d.RequestDigest,
			&d.Operation, &d.Status, &d.CreatedAt, &importedAt, &d.ImportedBy)
	if isNoRows(err) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if importedAt != nil {
		d.ImportedAt = *importedAt
	}
	return &d, nil
}

func (s *Store) CompleteKeyDownload(ctx context.Context, tenantID, downloadID, principalID string, importedAt time.Time) error {
	ct, err := s.pool.Exec(ctx, `UPDATE key_downloads
		SET status='IMPORTED', imported_at=$4, imported_by=$3
		WHERE id=$1 AND tenant_id=$2 AND status='RECEIVED'`,
		downloadID, tenantID, principalID, importedAt)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		var status string
		err := s.pool.QueryRow(ctx, `SELECT status FROM key_downloads WHERE id=$1 AND tenant_id=$2`, downloadID, tenantID).Scan(&status)
		if isNoRows(err) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if status == "IMPORTED" {
			return nil
		}
		return ErrConflict
	}
	return nil
}

// scanner is the common interface for pgx.Row and pgx.Rows.
type scanner interface {
	Scan(dest ...any) error
}

func scanKey(row scanner) (*models.Key, error) {
	var k models.Key
	var tagsJSON []byte
	var expiresAt *time.Time
	var archivedAt *time.Time
	err := row.Scan(&k.ID, &k.TenantID, &k.Name, &k.Purpose, &k.PolicyID, &k.SuiteID, &k.CurrentVersion, &k.Status, &tagsJSON, &expiresAt, &archivedAt, &k.CreatedAt, &k.UpdatedAt)
	if err != nil {
		return nil, err
	}
	if expiresAt != nil {
		k.ExpiresAt = *expiresAt
	}
	if archivedAt != nil {
		k.ArchivedAt = *archivedAt
	}
	if tagsJSON != nil {
		_ = json.Unmarshal(tagsJSON, &k.Tags)
	}
	return &k, nil
}

func scanKeyVersion(row scanner) (*models.KeyVersion, error) {
	var kv models.KeyVersion
	err := row.Scan(&kv.ID, &kv.KeyID, &kv.VersionNo, &kv.SuiteID, &kv.WrappedDEK, &kv.WrapMetadata, &kv.Status, &kv.CreatedAt)
	if err != nil {
		if isNoRows(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &kv, nil
}
