package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/kvlt/key-vault/internal/repository/models"
)

// --- CRK ---

func (s *Store) CreateCRKVersion(ctx context.Context, v *models.CRKVersion) error {
	v.CreatedAt = time.Now().UTC()
	_, err := s.pool.Exec(ctx,
		`INSERT INTO crk_versions (id, version, epoch, status, created_at) VALUES ($1, $2, $3, $4, $5)`,
		v.ID, v.Version, v.Epoch, v.Status, v.CreatedAt)
	if err != nil && isUniqueViolation(err) {
		return fmt.Errorf("%w: crk version %s exists", ErrConflict, v.ID)
	}
	// Bump cluster epoch.
	if err == nil {
		_, _ = s.pool.Exec(ctx, `UPDATE cluster_state SET cluster_epoch = cluster_epoch + 1 WHERE id=1`)
	}
	return err
}

func (s *Store) GetCRKVersion(ctx context.Context, id string) (*models.CRKVersion, error) {
	row := s.pool.QueryRow(ctx, `SELECT id, version, epoch, status, created_at FROM crk_versions WHERE id=$1`, id)
	var v models.CRKVersion
	if err := row.Scan(&v.ID, &v.Version, &v.Epoch, &v.Status, &v.CreatedAt); err != nil {
		if isNoRows(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &v, nil
}

func (s *Store) GetLatestCRKVersion(ctx context.Context) (*models.CRKVersion, error) {
	row := s.pool.QueryRow(ctx, `SELECT id, version, epoch, status, created_at FROM crk_versions ORDER BY version DESC LIMIT 1`)
	var v models.CRKVersion
	if err := row.Scan(&v.ID, &v.Version, &v.Epoch, &v.Status, &v.CreatedAt); err != nil {
		if isNoRows(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &v, nil
}

func (s *Store) CreateCRKNodeEnvelope(ctx context.Context, e *models.CRKNodeEnvelope) error {
	e.CreatedAt = time.Now().UTC()
	_, err := s.pool.Exec(ctx,
		`INSERT INTO crk_node_envelopes (id, crk_version_id, node_id, envelope, created_at) VALUES ($1, $2, $3, $4, $5)`,
		e.ID, e.CRKVersionID, e.NodeID, e.Envelope, e.CreatedAt)
	if err != nil && isUniqueViolation(err) {
		return fmt.Errorf("%w: crk envelope %s exists", ErrConflict, e.ID)
	}
	return err
}

func (s *Store) GetCRKNodeEnvelope(ctx context.Context, crkVersionID, nodeID string) (*models.CRKNodeEnvelope, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT id, crk_version_id, node_id, envelope, created_at FROM crk_node_envelopes WHERE crk_version_id=$1 AND node_id=$2`,
		crkVersionID, nodeID)
	var e models.CRKNodeEnvelope
	if err := row.Scan(&e.ID, &e.CRKVersionID, &e.NodeID, &e.Envelope, &e.CreatedAt); err != nil {
		if isNoRows(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &e, nil
}

func (s *Store) UpdateCRKNodeEnvelope(ctx context.Context, e *models.CRKNodeEnvelope) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE crk_node_envelopes SET envelope=$1 WHERE id=$2`,
		e.Envelope, e.ID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) ClusterEpoch(ctx context.Context) (uint64, error) {
	var epoch uint64
	err := s.pool.QueryRow(ctx, `SELECT cluster_epoch FROM cluster_state WHERE id=1`).Scan(&epoch)
	return epoch, err
}

// --- Nodes ---

func (s *Store) UpsertNode(ctx context.Context, n *models.Node) error {
	now := time.Now().UTC()
	if _, err := s.GetNode(ctx, n.NodeID); err != nil {
		// Insert new.
		n.CreatedAt = now
	}
	n.UpdatedAt = now
	baselineJSON, _ := json.Marshal(n.Baseline)
	_, err := s.pool.Exec(ctx,
		`INSERT INTO nodes (node_id, role, status, ready_reason, cluster_epoch, attestation_epoch, baseline, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		 ON CONFLICT (node_id) DO UPDATE SET role=$2, status=$3, ready_reason=$4, cluster_epoch=$5, attestation_epoch=$6, baseline=$7, updated_at=$9`,
		n.NodeID, n.Role, n.Status, n.ReadyReason, n.ClusterEpoch, n.AttestationEpoch, baselineJSON, n.CreatedAt, n.UpdatedAt)
	return err
}

func (s *Store) GetNode(ctx context.Context, nodeID string) (*models.Node, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT node_id, role, status, ready_reason, cluster_epoch, attestation_epoch, baseline, created_at, updated_at FROM nodes WHERE node_id=$1`, nodeID)
	var n models.Node
	var baselineJSON []byte
	if err := row.Scan(&n.NodeID, &n.Role, &n.Status, &n.ReadyReason, &n.ClusterEpoch, &n.AttestationEpoch, &baselineJSON, &n.CreatedAt, &n.UpdatedAt); err != nil {
		if isNoRows(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if baselineJSON != nil {
		_ = json.Unmarshal(baselineJSON, &n.Baseline)
	}
	return &n, nil
}

func (s *Store) ListAllNodes(ctx context.Context) ([]*models.Node, error) {
	rows, err := s.pool.Query(ctx, `SELECT node_id, role, status, ready_reason, cluster_epoch, attestation_epoch, baseline, created_at, updated_at FROM nodes ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*models.Node
	for rows.Next() {
		var n models.Node
		var baselineJSON []byte
		if err := rows.Scan(&n.NodeID, &n.Role, &n.Status, &n.ReadyReason, &n.ClusterEpoch, &n.AttestationEpoch, &baselineJSON, &n.CreatedAt, &n.UpdatedAt); err != nil {
			return nil, err
		}
		if baselineJSON != nil {
			_ = json.Unmarshal(baselineJSON, &n.Baseline)
		}
		out = append(out, &n)
	}
	return out, rows.Err()
}

// --- DEK Leases ---

func (s *Store) CreateDEKLease(ctx context.Context, l *models.DEKLease) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO dek_leases (lease_id, key_version_id, node_id, tenant_id, purpose, suite_id, expires_at, revoked, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())`,
		l.LeaseID, l.KeyVersionID, l.NodeID, l.TenantID, l.Purpose, l.SuiteID, l.ExpiresAt, l.Revoked)
	if err != nil && isUniqueViolation(err) {
		return fmt.Errorf("%w: dek lease %s exists", ErrConflict, l.LeaseID)
	}
	return err
}

func (s *Store) RevokeDEKLease(ctx context.Context, leaseID string) error {
	ct, err := s.pool.Exec(ctx, `UPDATE dek_leases SET revoked=TRUE WHERE lease_id=$1`, leaseID)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) ListDEKLeasesByNode(ctx context.Context, nodeID string) ([]*models.DEKLease, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT lease_id, key_version_id, node_id, tenant_id, purpose, suite_id, expires_at, revoked FROM dek_leases WHERE node_id=$1`, nodeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*models.DEKLease
	for rows.Next() {
		var l models.DEKLease
		if err := rows.Scan(&l.LeaseID, &l.KeyVersionID, &l.NodeID, &l.TenantID, &l.Purpose, &l.SuiteID, &l.ExpiresAt, &l.Revoked); err != nil {
			return nil, err
		}
		out = append(out, &l)
	}
	return out, rows.Err()
}

func (s *Store) RevokeDEKLeasesByNode(ctx context.Context, nodeID string) (int, error) {
	ct, err := s.pool.Exec(ctx, `UPDATE dek_leases SET revoked=TRUE WHERE node_id=$1 AND revoked=FALSE`, nodeID)
	if err != nil {
		return 0, err
	}
	return int(ct.RowsAffected()), nil
}

// --- Nonce Leases ---

func (s *Store) AllocateNonceRange(ctx context.Context, keyVersionID, nodeID string, domain uint32, size uint64, ttl time.Duration) (*models.NonceLease, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	// Atomic counter increment.
	var start uint64
	err = tx.QueryRow(ctx,
		`INSERT INTO nonce_counters (key_version_id, domain, next_start) VALUES ($1, $2, $3)
		 ON CONFLICT (key_version_id, domain) DO UPDATE SET next_start = nonce_counters.next_start + $3
		 RETURNING next_start - $3`,
		keyVersionID, domain, size).Scan(&start)
	if err != nil {
		return nil, err
	}
	end := start + size
	leaseID := newID("nls")
	_, err = tx.Exec(ctx,
		`INSERT INTO nonce_leases (lease_id, key_version_id, node_id, domain, start_counter, end_counter, used_counter, expires_at, status, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'ACTIVE', NOW())`,
		leaseID, keyVersionID, nodeID, domain, start, end, start, time.Now().UTC().Add(ttl))
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &models.NonceLease{
		LeaseID:      leaseID,
		KeyVersionID: keyVersionID,
		NodeID:       nodeID,
		Domain:       domain,
		StartCounter: start,
		EndCounter:   end,
		UsedCounter:  start,
		ExpiresAt:    time.Now().UTC().Add(ttl),
		Status:       "ACTIVE",
	}, nil
}

func (s *Store) UpdateNonceUsed(ctx context.Context, leaseID string, used uint64) error {
	ct, err := s.pool.Exec(ctx, `UPDATE nonce_leases SET used_counter=$2 WHERE lease_id=$1`, leaseID, used)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) GetNonceLease(ctx context.Context, leaseID string) (*models.NonceLease, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT lease_id, key_version_id, node_id, domain, start_counter, end_counter, used_counter, expires_at, status FROM nonce_leases WHERE lease_id=$1`, leaseID)
	var l models.NonceLease
	if err := row.Scan(&l.LeaseID, &l.KeyVersionID, &l.NodeID, &l.Domain, &l.StartCounter, &l.EndCounter, &l.UsedCounter, &l.ExpiresAt, &l.Status); err != nil {
		if isNoRows(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &l, nil
}

func (s *Store) FreezeNonceLeasesByNode(ctx context.Context, nodeID string) (int, error) {
	ct, err := s.pool.Exec(ctx, `UPDATE nonce_leases SET status='FROZEN' WHERE node_id=$1 AND status='ACTIVE'`, nodeID)
	if err != nil {
		return 0, err
	}
	return int(ct.RowsAffected()), nil
}

// --- Idempotency ---

func (s *Store) RecordIdempotency(ctx context.Context, ik *models.IdempotencyKey) error {
	ik.CreatedAt = time.Now().UTC()
	_, err := s.pool.Exec(ctx,
		`INSERT INTO idempotency_keys (key, principal_id, tenant_id, method, path, request_hash, response_status, response_hash, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		 ON CONFLICT (key) DO NOTHING`,
		ik.Key, ik.PrincipalID, ik.TenantID, ik.Method, ik.Path, ik.RequestHash, ik.ResponseStatus, ik.ResponseHash, ik.CreatedAt)
	return err
}

func (s *Store) GetIdempotency(ctx context.Context, key string) (*models.IdempotencyKey, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT key, principal_id, tenant_id, method, path, request_hash, response_status, response_hash, created_at FROM idempotency_keys WHERE key=$1`, key)
	var ik models.IdempotencyKey
	if err := row.Scan(&ik.Key, &ik.PrincipalID, &ik.TenantID, &ik.Method, &ik.Path, &ik.RequestHash, &ik.ResponseStatus, &ik.ResponseHash, &ik.CreatedAt); err != nil {
		if isNoRows(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &ik, nil
}

// --- Lifecycle / Outbox ---

func (s *Store) CreateLifecycleJob(ctx context.Context, j *models.LifecycleJob) error {
	now := time.Now().UTC()
	if j.CreatedAt.IsZero() {
		j.CreatedAt = now
	}
	j.UpdatedAt = now
	_, err := s.pool.Exec(ctx,
		`INSERT INTO lifecycle_jobs (id, type, tenant_id, key_id, key_version_id, payload, status, attempt, next_run_at, lease_owner, lease_until, idempotency_key, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
		j.ID, j.Type, j.TenantID, j.KeyID, j.KeyVersionID, j.Payload, j.Status, j.Attempt, j.NextRunAt, j.LeaseOwner, j.LeaseUntil, j.IdempotencyKey, j.CreatedAt, j.UpdatedAt)
	if err != nil && isUniqueViolation(err) {
		return fmt.Errorf("%w: job %s exists", ErrConflict, j.ID)
	}
	return err
}

func (s *Store) ClaimLifecycleJob(ctx context.Context, owner string, leaseTTL time.Duration) (*models.LifecycleJob, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	now := time.Now().UTC()
	// SELECT ... FOR UPDATE SKIP LOCKED to pick the next eligible job.
	row := tx.QueryRow(ctx,
		`SELECT id, type, tenant_id, key_id, key_version_id, payload, status, attempt, next_run_at, lease_owner, lease_until, idempotency_key, created_at, updated_at
		 FROM lifecycle_jobs
		 WHERE (status='PENDING' OR (status='RUNNING' AND lease_until < $1))
		   AND (next_run_at IS NULL OR next_run_at <= $1)
		 ORDER BY created_at ASC
		 FOR UPDATE SKIP LOCKED
		 LIMIT 1`, now)
	var j models.LifecycleJob
	if err := row.Scan(&j.ID, &j.Type, &j.TenantID, &j.KeyID, &j.KeyVersionID, &j.Payload, &j.Status, &j.Attempt, &j.NextRunAt, &j.LeaseOwner, &j.LeaseUntil, &j.IdempotencyKey, &j.CreatedAt, &j.UpdatedAt); err != nil {
		if isNoRows(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	_, err = tx.Exec(ctx,
		`UPDATE lifecycle_jobs SET status='RUNNING', attempt=attempt+1, lease_owner=$2, lease_until=$3, updated_at=$4 WHERE id=$1`,
		j.ID, owner, now.Add(leaseTTL), now)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	j.Status = "RUNNING"
	j.Attempt++
	j.LeaseOwner = owner
	leaseUntil := now.Add(leaseTTL)
	j.LeaseUntil = &leaseUntil
	return &j, nil
}

func (s *Store) CompleteLifecycleJob(ctx context.Context, jobID string) error {
	ct, err := s.pool.Exec(ctx, `UPDATE lifecycle_jobs SET status='DONE', lease_owner='', lease_until=NULL, updated_at=NOW() WHERE id=$1`, jobID)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) FailLifecycleJob(ctx context.Context, jobID string, backoff time.Duration) error {
	ct, err := s.pool.Exec(ctx,
		`UPDATE lifecycle_jobs SET status='PENDING', lease_owner='', lease_until=NULL, next_run_at=NOW() + $2, updated_at=NOW() WHERE id=$1`,
		jobID, backoff)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) GetLifecycleJob(ctx context.Context, id string) (*models.LifecycleJob, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT id, type, tenant_id, key_id, key_version_id, payload, status, attempt, next_run_at, lease_owner, lease_until, idempotency_key, created_at, updated_at FROM lifecycle_jobs WHERE id=$1`, id)
	var j models.LifecycleJob
	if err := row.Scan(&j.ID, &j.Type, &j.TenantID, &j.KeyID, &j.KeyVersionID, &j.Payload, &j.Status, &j.Attempt, &j.NextRunAt, &j.LeaseOwner, &j.LeaseUntil, &j.IdempotencyKey, &j.CreatedAt, &j.UpdatedAt); err != nil {
		if isNoRows(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &j, nil
}

func (s *Store) ListLifecycleJobs(ctx context.Context, status string, limit int) ([]*models.LifecycleJob, error) {
	if limit <= 0 {
		limit = 100
	}
	var rows pgx.Rows
	var err error
	if status != "" {
		rows, err = s.pool.Query(ctx, `SELECT id, type, tenant_id, key_id, key_version_id, payload, status, attempt, next_run_at, lease_owner, lease_until, idempotency_key, created_at, updated_at FROM lifecycle_jobs WHERE status=$1 ORDER BY created_at DESC LIMIT $2`, status, limit)
	} else {
		rows, err = s.pool.Query(ctx, `SELECT id, type, tenant_id, key_id, key_version_id, payload, status, attempt, next_run_at, lease_owner, lease_until, idempotency_key, created_at, updated_at FROM lifecycle_jobs ORDER BY created_at DESC LIMIT $1`, limit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*models.LifecycleJob
	for rows.Next() {
		var j models.LifecycleJob
		if err := rows.Scan(&j.ID, &j.Type, &j.TenantID, &j.KeyID, &j.KeyVersionID, &j.Payload, &j.Status, &j.Attempt, &j.NextRunAt, &j.LeaseOwner, &j.LeaseUntil, &j.IdempotencyKey, &j.CreatedAt, &j.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, &j)
	}
	return out, rows.Err()
}

func (s *Store) CreateOutboxEvent(ctx context.Context, e *models.OutboxEvent) error {
	e.CreatedAt = time.Now().UTC()
	_, err := s.pool.Exec(ctx,
		`INSERT INTO outbox_events (id, event_type, aggregate_id, payload, status, attempts, next_run_at, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		e.ID, e.EventType, e.AggregateID, e.Payload, e.Status, e.Attempts, e.NextRunAt, e.CreatedAt)
	if err != nil && isUniqueViolation(err) {
		return fmt.Errorf("%w: outbox event %s exists", ErrConflict, e.ID)
	}
	return err
}

func (s *Store) ClaimOutboxEvent(ctx context.Context) (*models.OutboxEvent, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	now := time.Now().UTC()
	row := tx.QueryRow(ctx,
		`SELECT id, event_type, aggregate_id, payload, status, attempts, next_run_at, created_at FROM outbox_events
		 WHERE status='PENDING' AND (next_run_at IS NULL OR next_run_at <= $1)
		 ORDER BY created_at ASC FOR UPDATE SKIP LOCKED LIMIT 1`, now)
	var e models.OutboxEvent
	if err := row.Scan(&e.ID, &e.EventType, &e.AggregateID, &e.Payload, &e.Status, &e.Attempts, &e.NextRunAt, &e.CreatedAt); err != nil {
		if isNoRows(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	_, err = tx.Exec(ctx, `UPDATE outbox_events SET attempts=attempts+1 WHERE id=$1`, e.ID)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	e.Attempts++
	return &e, nil
}

func (s *Store) CompleteOutboxEvent(ctx context.Context, id string) error {
	ct, err := s.pool.Exec(ctx, `UPDATE outbox_events SET status='SENT' WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) ListOutboxEvents(ctx context.Context, status string, limit int) ([]*models.OutboxEvent, error) {
	if limit <= 0 {
		limit = 100
	}
	var rows pgx.Rows
	var err error
	if status != "" {
		rows, err = s.pool.Query(ctx, `SELECT id, event_type, aggregate_id, payload, status, attempts, next_run_at, created_at FROM outbox_events WHERE status=$1 ORDER BY created_at DESC LIMIT $2`, status, limit)
	} else {
		rows, err = s.pool.Query(ctx, `SELECT id, event_type, aggregate_id, payload, status, attempts, next_run_at, created_at FROM outbox_events ORDER BY created_at DESC LIMIT $1`, limit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*models.OutboxEvent
	for rows.Next() {
		var e models.OutboxEvent
		if err := rows.Scan(&e.ID, &e.EventType, &e.AggregateID, &e.Payload, &e.Status, &e.Attempts, &e.NextRunAt, &e.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, &e)
	}
	return out, rows.Err()
}

// RetryLifecycleJob resets a FAILED job to PENDING and clears backoff.
// The WHERE status='FAILED' clause enforces state validation in the database.
func (s *Store) RetryLifecycleJob(ctx context.Context, jobID string) error {
	ct, err := s.pool.Exec(ctx,
		`UPDATE lifecycle_jobs SET status='PENDING', lease_owner='', lease_until=NULL, next_run_at=NULL, updated_at=NOW() WHERE id=$1 AND status='FAILED'`,
		jobID)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		// Distinguish not-found from wrong-state.
		var exists int
		err := s.pool.QueryRow(ctx, `SELECT 1 FROM lifecycle_jobs WHERE id=$1`, jobID).Scan(&exists)
		if err != nil {
			return ErrNotFound
		}
		return ErrConflict
	}
	return nil
}

// ReplayOutboxEvent resets a SENT/stuck event to PENDING for reprocessing.
// Returns ErrConflict if already PENDING.
func (s *Store) ReplayOutboxEvent(ctx context.Context, eventID string) error {
	ct, err := s.pool.Exec(ctx,
		`UPDATE outbox_events SET status='PENDING', next_run_at=NULL WHERE id=$1 AND status<>'PENDING'`,
		eventID)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		var exists int
		err := s.pool.QueryRow(ctx, `SELECT 1 FROM outbox_events WHERE id=$1`, eventID).Scan(&exists)
		if err != nil {
			return ErrNotFound
		}
		return ErrConflict
	}
	return nil
}

// TableSizes returns approximate row counts via pg_class.reltuples to avoid
// full-table scans on large tables (stats may lag behind actual counts).
func (s *Store) TableSizes(ctx context.Context) (map[string]int64, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT relname::text AS table_name, GREATEST(COALESCE(reltuples, 0), 0)::bigint AS approx_rows
		 FROM pg_class
		 WHERE relkind='r' AND relname IN (
		   'tenants','keys','key_versions','crk_versions','crk_node_envelopes','nodes',
		   'dek_leases','nonce_leases','lifecycle_jobs','outbox_events','audit_events',
		   'tenant_envelope_configs','cluster_state','nonce_counters','idempotency_keys',
		   'audit_chain_heads','attestation_challenges','attestation_reports','attestation_baselines'
		 )`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]int64)
	for rows.Next() {
		var name string
		var count int64
		if err := rows.Scan(&name, &count); err != nil {
			return nil, err
		}
		out[name] = count
	}
	return out, rows.Err()
}

// --- Audit chain ---

func (s *Store) AppendAuditEvent(ctx context.Context, e *models.AuditEvent) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if e.ChainName == "" {
		e.ChainName = "system"
	}
	// Get or create chain head with row lock.
	var seq uint64
	var prevHash string
	err = tx.QueryRow(ctx,
		`INSERT INTO audit_chain_heads (chain_name, sequence, head_hash, updated_at) VALUES ($1, 0, '', NOW())
		 ON CONFLICT (chain_name) DO UPDATE SET updated_at=NOW()
		 RETURNING sequence, head_hash`, e.ChainName).Scan(&seq, &prevHash)
	if err != nil {
		return err
	}
	seq++
	e.Sequence = seq
	e.PrevHash = prevHash
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now().UTC()
	}
	// Truncate timestamp to microsecond BEFORE computing hash and storing.
	// PG TIMESTAMPTZ may round (not truncate) to microsecond, causing a 1us
	// shift between the value used for hashing and the value read back. By
	// truncating here, the stored value exactly matches the hashed value.
	e.Timestamp = e.Timestamp.UTC().Truncate(time.Microsecond)
	// Compute hash.
	canon := canonicalAuditEvent(e, seq, prevHash)
	h := sha256.New()
	h.Write([]byte(prevHash))
	h.Write(canon)
	e.CurrentHash = hex.EncodeToString(h.Sum(nil))
	metaJSON, _ := json.Marshal(e.Metadata)
	_, err = tx.Exec(ctx,
		`INSERT INTO audit_events (event_id, request_id, tenant_hash, actor_type, actor_hash, action, target_type, target_id_hash, result, error_code, timestamp, metadata, chain_name, sequence, prev_hash, current_hash)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`,
		e.EventID, e.RequestID, e.TenantHash, e.ActorType, e.ActorHash, e.Action, e.TargetType, e.TargetIDHash, e.Result, e.ErrorCode, e.Timestamp, metaJSON, e.ChainName, e.Sequence, e.PrevHash, e.CurrentHash)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE audit_chain_heads SET sequence=$2, head_hash=$3, updated_at=NOW() WHERE chain_name=$1`, e.ChainName, seq, e.CurrentHash)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) ListAuditEvents(ctx context.Context, chainName string, limit int) ([]*models.AuditEvent, error) {
	if limit <= 0 {
		limit = 100
	}
	var rows pgx.Rows
	var err error
	if chainName != "" {
		rows, err = s.pool.Query(ctx, `SELECT event_id, request_id, tenant_hash, actor_type, actor_hash, action, target_type, target_id_hash, result, error_code, timestamp, metadata, chain_name, sequence, prev_hash, current_hash FROM audit_events WHERE chain_name=$1 ORDER BY sequence DESC LIMIT $2`, chainName, limit)
	} else {
		rows, err = s.pool.Query(ctx, `SELECT event_id, request_id, tenant_hash, actor_type, actor_hash, action, target_type, target_id_hash, result, error_code, timestamp, metadata, chain_name, sequence, prev_hash, current_hash FROM audit_events ORDER BY sequence DESC LIMIT $1`, limit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*models.AuditEvent
	for rows.Next() {
		var e models.AuditEvent
		var metaJSON []byte
		if err := rows.Scan(&e.EventID, &e.RequestID, &e.TenantHash, &e.ActorType, &e.ActorHash, &e.Action, &e.TargetType, &e.TargetIDHash, &e.Result, &e.ErrorCode, &e.Timestamp, &metaJSON, &e.ChainName, &e.Sequence, &e.PrevHash, &e.CurrentHash); err != nil {
			return nil, err
		}
		if metaJSON != nil {
			_ = json.Unmarshal(metaJSON, &e.Metadata)
		}
		out = append(out, &e)
	}
	return out, rows.Err()
}

func (s *Store) DeleteAuditEvents(ctx context.Context, chainName string) (int, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)

	var ct pgconn.CommandTag
	if chainName == "" {
		ct, err = tx.Exec(ctx, `DELETE FROM audit_events`)
		if err != nil {
			return 0, err
		}
		if _, err = tx.Exec(ctx, `DELETE FROM audit_chain_heads`); err != nil {
			return 0, err
		}
	} else {
		ct, err = tx.Exec(ctx, `DELETE FROM audit_events WHERE chain_name=$1`, chainName)
		if err != nil {
			return 0, err
		}
		if _, err = tx.Exec(ctx, `DELETE FROM audit_chain_heads WHERE chain_name=$1`, chainName); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return int(ct.RowsAffected()), nil
}

func (s *Store) GetAuditChainHead(ctx context.Context, chainName string) (*models.AuditChainHead, error) {
	row := s.pool.QueryRow(ctx, `SELECT chain_name, sequence, head_hash, updated_at FROM audit_chain_heads WHERE chain_name=$1`, chainName)
	var h models.AuditChainHead
	if err := row.Scan(&h.ChainName, &h.Sequence, &h.HeadHash, &h.UpdatedAt); err != nil {
		if isNoRows(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &h, nil
}

func (s *Store) ListAuditChainHeads(ctx context.Context) ([]*models.AuditChainHead, error) {
	rows, err := s.pool.Query(ctx, `SELECT chain_name, sequence, head_hash, updated_at FROM audit_chain_heads`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*models.AuditChainHead
	for rows.Next() {
		var h models.AuditChainHead
		if err := rows.Scan(&h.ChainName, &h.Sequence, &h.HeadHash, &h.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, &h)
	}
	return out, rows.Err()
}

func (s *Store) VerifyAuditChain(ctx context.Context, chainName string) (uint64, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT event_id, request_id, tenant_hash, actor_type, actor_hash, action, target_type, target_id_hash, result, error_code, timestamp, metadata, sequence, prev_hash, current_hash
		 FROM audit_events WHERE chain_name=$1 ORDER BY sequence ASC`, chainName)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	var prevHash string
	var expectedSeq uint64 = 1
	for rows.Next() {
		var e models.AuditEvent
		var metaJSON []byte
		if err := rows.Scan(&e.EventID, &e.RequestID, &e.TenantHash, &e.ActorType, &e.ActorHash, &e.Action, &e.TargetType, &e.TargetIDHash, &e.Result, &e.ErrorCode, &e.Timestamp, &metaJSON, &e.Sequence, &e.PrevHash, &e.CurrentHash); err != nil {
			return 0, err
		}
		if metaJSON != nil {
			_ = json.Unmarshal(metaJSON, &e.Metadata)
		}
		if e.Sequence != expectedSeq {
			return e.Sequence, fmt.Errorf("sequence gap: expected %d got %d", expectedSeq, e.Sequence)
		}
		if e.PrevHash != prevHash {
			return e.Sequence, fmt.Errorf("prev_hash mismatch at seq %d", e.Sequence)
		}
		canon := canonicalAuditEvent(&e, e.Sequence, prevHash)
		h := sha256.New()
		h.Write([]byte(prevHash))
		h.Write(canon)
		recomputed := hex.EncodeToString(h.Sum(nil))
		if recomputed != e.CurrentHash {
			slog.Error("audit hash mismatch diagnostic",
				"seq", e.Sequence,
				"stored_hash", e.CurrentHash,
				"recomputed_hash", recomputed,
				"event_id", e.EventID,
				"timestamp_raw", e.Timestamp.String(),
				"timestamp_utc_micro", e.Timestamp.UTC().Truncate(time.Microsecond).String(),
				"timestamp_formatted", e.Timestamp.UTC().Truncate(time.Microsecond).Format(time.RFC3339Nano),
				"action", e.Action,
				"actor_hash", e.ActorHash,
				"result", e.Result,
				"prev_hash", prevHash,
				"stored_prev_hash", e.PrevHash,
				"metadata", fmt.Sprintf("%v", e.Metadata),
				"canon_len", len(canon),
			)
			return e.Sequence, fmt.Errorf("hash mismatch at seq %d", e.Sequence)
		}
		prevHash = e.CurrentHash
		expectedSeq++
	}
	return 0, rows.Err()
}

// canonicalAuditEvent mirrors memory.canonicalAuditEvent for hash-chain consistency.
// Timestamp is truncated to microsecond precision to match PostgreSQL TIMESTAMPTZ
// storage precision (Go time has nanosecond precision, PG stores microseconds).
func canonicalAuditEvent(e *models.AuditEvent, seq uint64, prevHash string) []byte {
	var b []byte
	b = append(b, []byte(e.EventID)...)
	b = append(b, '|')
	b = append(b, []byte(e.RequestID)...)
	b = append(b, '|')
	b = append(b, []byte(e.TenantHash)...)
	b = append(b, '|')
	b = append(b, []byte(e.ActorType)...)
	b = append(b, '|')
	b = append(b, []byte(e.ActorHash)...)
	b = append(b, '|')
	b = append(b, []byte(e.Action)...)
	b = append(b, '|')
	b = append(b, []byte(e.TargetType)...)
	b = append(b, '|')
	b = append(b, []byte(e.TargetIDHash)...)
	b = append(b, '|')
	b = append(b, []byte(e.Result)...)
	b = append(b, '|')
	b = append(b, []byte(e.ErrorCode)...)
	b = append(b, '|')
	// Truncate to microsecond: PG TIMESTAMPTZ only stores 6 digits, Go has 9.
	ts := e.Timestamp.UTC().Truncate(time.Microsecond)
	b = append(b, []byte(ts.Format(time.RFC3339Nano))...)
	b = append(b, '|')
	b = append(b, []byte(fmt.Sprintf("%d", seq))...)
	b = append(b, '|')
	b = append(b, []byte(prevHash)...)
	keys := make([]string, 0, len(e.Metadata))
	for k := range e.Metadata {
		keys = append(keys, k)
	}
	for i := 0; i < len(keys); i++ {
		for j := i + 1; j < len(keys); j++ {
			if keys[i] > keys[j] {
				keys[i], keys[j] = keys[j], keys[i]
			}
		}
	}
	for _, k := range keys {
		b = append(b, '|')
		b = append(b, []byte(k)...)
		b = append(b, '=')
		b = append(b, []byte(e.Metadata[k])...)
	}
	return b
}

// --- Attestation ---

func (s *Store) CreateAttestationChallenge(ctx context.Context, c *models.AttestationChallenge) error {
	c.CreatedAt = time.Now().UTC()
	_, err := s.pool.Exec(ctx,
		`INSERT INTO attestation_challenges (challenge_id, node_id, nonce, expires_at, used, created_at) VALUES ($1, $2, $3, $4, FALSE, $5)`,
		c.ChallengeID, c.NodeID, c.Nonce, c.ExpiresAt, c.CreatedAt)
	if err != nil && isUniqueViolation(err) {
		return fmt.Errorf("%w: challenge %s exists", ErrConflict, c.ChallengeID)
	}
	return err
}

func (s *Store) GetAttestationChallenge(ctx context.Context, id string) (*models.AttestationChallenge, error) {
	row := s.pool.QueryRow(ctx, `SELECT challenge_id, node_id, nonce, expires_at, used, created_at FROM attestation_challenges WHERE challenge_id=$1`, id)
	var c models.AttestationChallenge
	if err := row.Scan(&c.ChallengeID, &c.NodeID, &c.Nonce, &c.ExpiresAt, &c.Used, &c.CreatedAt); err != nil {
		if isNoRows(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &c, nil
}

func (s *Store) MarkChallengeUsed(ctx context.Context, id string) error {
	ct, err := s.pool.Exec(ctx, `UPDATE attestation_challenges SET used=TRUE WHERE challenge_id=$1`, id)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) CreateAttestationReport(ctx context.Context, r *models.AttestationReport) error {
	r.CreatedAt = time.Now().UTC()
	_, err := s.pool.Exec(ctx,
		`INSERT INTO attestation_reports (id, node_id, baseline_version, pcr_digest, event_log_digest, quote_valid, nonce, status, expires_at, audit_event_id, created_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		r.ID, r.NodeID, r.BaselineVersion, r.PCRDigest, r.EventLogDigest, r.QuoteValid, r.Nonce, r.Status, r.ExpiresAt, r.AuditEventID, r.CreatedAt)
	if err != nil && isUniqueViolation(err) {
		return fmt.Errorf("%w: report %s exists", ErrConflict, r.ID)
	}
	return err
}

func (s *Store) GetLatestAttestationReport(ctx context.Context, nodeID string) (*models.AttestationReport, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT id, node_id, baseline_version, pcr_digest, event_log_digest, quote_valid, nonce, status, expires_at, audit_event_id, created_at
		 FROM attestation_reports WHERE node_id=$1 ORDER BY created_at DESC LIMIT 1`, nodeID)
	var r models.AttestationReport
	if err := row.Scan(&r.ID, &r.NodeID, &r.BaselineVersion, &r.PCRDigest, &r.EventLogDigest, &r.QuoteValid, &r.Nonce, &r.Status, &r.ExpiresAt, &r.AuditEventID, &r.CreatedAt); err != nil {
		if isNoRows(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &r, nil
}

func (s *Store) ListAttestationReports(ctx context.Context, nodeID string, limit int) ([]*models.AttestationReport, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.pool.Query(ctx,
		`SELECT id, node_id, baseline_version, pcr_digest, event_log_digest, quote_valid, nonce, status, expires_at, audit_event_id, created_at
		 FROM attestation_reports WHERE node_id=$1 ORDER BY created_at DESC LIMIT $2`, nodeID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*models.AttestationReport
	for rows.Next() {
		var r models.AttestationReport
		if err := rows.Scan(&r.ID, &r.NodeID, &r.BaselineVersion, &r.PCRDigest, &r.EventLogDigest, &r.QuoteValid, &r.Nonce, &r.Status, &r.ExpiresAt, &r.AuditEventID, &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, &r)
	}
	return out, rows.Err()
}

func (s *Store) UpsertAttestationBaseline(ctx context.Context, b *models.AttestationBaseline) error {
	if b.CreatedAt.IsZero() {
		b.CreatedAt = time.Now().UTC()
	}
	pcrJSON, _ := json.Marshal(b.PCRProfile)
	_, err := s.pool.Exec(ctx,
		`INSERT INTO attestation_baselines (version, pcr_profile, firmware_hash, os_image_hash, status, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6)
		 ON CONFLICT (version) DO UPDATE SET pcr_profile=$2, firmware_hash=$3, os_image_hash=$4, status=$5`,
		b.Version, pcrJSON, b.FirmwareHash, b.OSImageHash, b.Status, b.CreatedAt)
	return err
}

func (s *Store) GetActiveAttestationBaseline(ctx context.Context) (*models.AttestationBaseline, error) {
	row := s.pool.QueryRow(ctx, `SELECT version, pcr_profile, firmware_hash, os_image_hash, status, created_at FROM attestation_baselines WHERE status='active' LIMIT 1`)
	var b models.AttestationBaseline
	var pcrJSON []byte
	if err := row.Scan(&b.Version, &pcrJSON, &b.FirmwareHash, &b.OSImageHash, &b.Status, &b.CreatedAt); err != nil {
		if isNoRows(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if pcrJSON != nil {
		_ = json.Unmarshal(pcrJSON, &b.PCRProfile)
	}
	return &b, nil
}

func (s *Store) ListAttestationBaselines(ctx context.Context) ([]*models.AttestationBaseline, error) {
	rows, err := s.pool.Query(ctx, `SELECT version, pcr_profile, firmware_hash, os_image_hash, status, created_at FROM attestation_baselines ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*models.AttestationBaseline
	for rows.Next() {
		var b models.AttestationBaseline
		var pcrJSON []byte
		if err := rows.Scan(&b.Version, &pcrJSON, &b.FirmwareHash, &b.OSImageHash, &b.Status, &b.CreatedAt); err != nil {
			return nil, err
		}
		if pcrJSON != nil {
			_ = json.Unmarshal(pcrJSON, &b.PCRProfile)
		}
		out = append(out, &b)
	}
	return out, rows.Err()
}

func (s *Store) BumpAttestationEpoch(ctx context.Context) (uint64, error) {
	var epoch uint64
	err := s.pool.QueryRow(ctx, `UPDATE cluster_state SET attestation_epoch = attestation_epoch + 1 WHERE id=1 RETURNING attestation_epoch`).Scan(&epoch)
	return epoch, err
}

func (s *Store) GetAttestationEpoch(ctx context.Context) (uint64, error) {
	var epoch uint64
	err := s.pool.QueryRow(ctx, `SELECT attestation_epoch FROM cluster_state WHERE id=1`).Scan(&epoch)
	return epoch, err
}
