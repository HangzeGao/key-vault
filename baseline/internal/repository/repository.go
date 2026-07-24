// Package repository defines the storage interface implemented by memory and
// postgres backends. The engineering baseline ships with an in-memory store;
// production deployments use the PostgreSQL backend for durability.
package repository

import (
	"context"
	"errors"
	"time"

	"github.com/kvlt/key-vault/internal/repository/models"
)

// Common errors returned by all Repository implementations. Both memory and
// postgres backends alias these so callers can use errors.Is uniformly.
var (
	ErrNotFound = errors.New("repository: not found")
	ErrConflict = errors.New("repository: conflict")
)

// DatabaseDiagnostics is a redacted, backend-neutral operational snapshot.
// It intentionally contains no connection strings, SQL text, record values,
// identifiers, or cryptographic material.
type DatabaseDiagnostics struct {
	ObservedAt time.Time
	Role       string
	Latency    time.Duration
	Pool       DatabasePoolStats
	Schema     DatabaseSchemaStats
	Storage    DatabaseStorageStats
	Workload   DatabaseWorkloadStats
	Protection DatabaseProtectionStats
	Integrity  DatabaseIntegrityStats
	Tables     []DatabaseTableStats
	Unavailable []string
}

type DatabasePoolStats struct {
	Max               int32
	Total             int32
	Acquired          int32
	Idle              int32
	AcquireWaitEvents int64
}

type DatabaseSchemaStats struct {
	Current  int
	Expected int
}

type DatabaseStorageStats struct {
	DatabaseBytes int64
}

type DatabaseWorkloadStats struct {
	ActiveConnections int64
	LockWaiters       int64
	LongTransactions  int64
	OldestTransaction time.Duration
}

type DatabaseProtectionStats struct {
	ReplicaCount       int64
	ReplicationLag     time.Duration
	BackupStatus       string
}

type DatabaseIntegrityStats struct {
	OrphanKeyVersions       int64
	DestroyedMaterialRows   int64
	ExpiredActiveDEKLeases  int64
	ExpiredActiveNonceLeases int64
}

type DatabaseTableStats struct {
	Name          string
	EstimatedRows int64
	TableBytes    int64
	IndexBytes    int64
	StatsUpdatedAt time.Time
}

// Repository is the storage interface. Each method mirrors a method on
// memory.Store. Backends MUST enforce the same concurrency and consistency
// rules: row-lock style serialization, monotonic counters, append-only audit.
type Repository interface {
	// Tenant
	UpsertTenant(ctx context.Context, t *models.Tenant) error
	GetTenant(ctx context.Context, id string) (*models.Tenant, error)

	// Tenant Envelope Config
	GetTenantEnvelopeConfig(ctx context.Context, tenantID string) (*models.TenantEnvelopeConfig, error)
	UpsertTenantEnvelopeConfig(ctx context.Context, cfg *models.TenantEnvelopeConfig) error

	// Keys
	CreateKey(ctx context.Context, k *models.Key, kv *models.KeyVersion) error
	GetKey(ctx context.Context, tenantID, keyID string) (*models.Key, error)
	ListKeys(ctx context.Context, tenantID string) ([]*models.Key, error)
	ListKeysIncludingArchived(ctx context.Context, tenantID string) ([]*models.Key, error)
	ListAllKeys(ctx context.Context) ([]*models.Key, error)
	UpdateKeyMetadata(ctx context.Context, tenantID, keyID, name string, tags map[string]string, expiresAt time.Time) (*models.Key, error)
	UpdateKeyStatus(ctx context.Context, keyID, expectedCurrent, newStatus string) error
	ArchiveDestroyedKey(ctx context.Context, tenantID, keyID string) (*models.Key, error)
	DestroyKeyMaterial(ctx context.Context, keyID string) error
	RotateKey(ctx context.Context, keyID string, newVersion *models.KeyVersion) error
	GetKeyVersion(ctx context.Context, versionID string) (*models.KeyVersion, error)
	GetKeyVersionByNo(ctx context.Context, keyID string, versionNo uint32) (*models.KeyVersion, error)
	GetCurrentKeyVersion(ctx context.Context, keyID string) (*models.KeyVersion, error)

	// CRK
	CreateCRKVersion(ctx context.Context, v *models.CRKVersion) error
	GetCRKVersion(ctx context.Context, id string) (*models.CRKVersion, error)
	GetLatestCRKVersion(ctx context.Context) (*models.CRKVersion, error)
	CreateCRKNodeEnvelope(ctx context.Context, e *models.CRKNodeEnvelope) error
	GetCRKNodeEnvelope(ctx context.Context, crkVersionID, nodeID string) (*models.CRKNodeEnvelope, error)
	UpdateCRKNodeEnvelope(ctx context.Context, e *models.CRKNodeEnvelope) error
	ClusterEpoch(ctx context.Context) (uint64, error)

	// Nodes
	UpsertNode(ctx context.Context, n *models.Node) error
	GetNode(ctx context.Context, nodeID string) (*models.Node, error)
	ListAllNodes(ctx context.Context) ([]*models.Node, error)

	// DEK Leases
	CreateDEKLease(ctx context.Context, l *models.DEKLease) error
	RevokeDEKLease(ctx context.Context, leaseID string) error
	ListDEKLeasesByNode(ctx context.Context, nodeID string) ([]*models.DEKLease, error)
	RevokeDEKLeasesByNode(ctx context.Context, nodeID string) (int, error)

	// Nonce Leases
	AllocateNonceRange(ctx context.Context, keyVersionID, nodeID string, domain uint32, size uint64, ttl time.Duration) (*models.NonceLease, error)
	UpdateNonceUsed(ctx context.Context, leaseID string, used uint64) error
	GetNonceLease(ctx context.Context, leaseID string) (*models.NonceLease, error)
	FreezeNonceLeasesByNode(ctx context.Context, nodeID string) (int, error)

	// Idempotency
	RecordIdempotency(ctx context.Context, ik *models.IdempotencyKey) error
	GetIdempotency(ctx context.Context, key string) (*models.IdempotencyKey, error)

	// Lifecycle / Outbox
	CreateLifecycleJob(ctx context.Context, j *models.LifecycleJob) error
	ClaimLifecycleJob(ctx context.Context, owner string, leaseTTL time.Duration) (*models.LifecycleJob, error)
	CompleteLifecycleJob(ctx context.Context, jobID string) error
	FailLifecycleJob(ctx context.Context, jobID string, backoff time.Duration) error
	GetLifecycleJob(ctx context.Context, id string) (*models.LifecycleJob, error)
	ListLifecycleJobs(ctx context.Context, status string, limit int) ([]*models.LifecycleJob, error)
	CreateOutboxEvent(ctx context.Context, e *models.OutboxEvent) error
	ClaimOutboxEvent(ctx context.Context) (*models.OutboxEvent, error)
	CompleteOutboxEvent(ctx context.Context, id string) error
	ListOutboxEvents(ctx context.Context, status string, limit int) ([]*models.OutboxEvent, error)

	// Ops plane: lifecycle retry, outbox replay, and redacted diagnostics.
	RetryLifecycleJob(ctx context.Context, jobID string) error
	ReplayOutboxEvent(ctx context.Context, eventID string) error
	DatabaseDiagnostics(ctx context.Context) (*DatabaseDiagnostics, error)

	// Audit chain
	AppendAuditEvent(ctx context.Context, e *models.AuditEvent) error
	ListAuditEvents(ctx context.Context, chainName string, limit int) ([]*models.AuditEvent, error)
	DeleteAuditEvents(ctx context.Context, chainName string) (int, error)
	GetAuditChainHead(ctx context.Context, chainName string) (*models.AuditChainHead, error)
	ListAuditChainHeads(ctx context.Context) ([]*models.AuditChainHead, error)
	VerifyAuditChain(ctx context.Context, chainName string) (brokenSeq uint64, err error)

	// Attestation
	CreateAttestationChallenge(ctx context.Context, c *models.AttestationChallenge) error
	GetAttestationChallenge(ctx context.Context, id string) (*models.AttestationChallenge, error)
	MarkChallengeUsed(ctx context.Context, id string) error
	CreateAttestationReport(ctx context.Context, r *models.AttestationReport) error
	GetLatestAttestationReport(ctx context.Context, nodeID string) (*models.AttestationReport, error)
	ListAttestationReports(ctx context.Context, nodeID string, limit int) ([]*models.AttestationReport, error)
	UpsertAttestationBaseline(ctx context.Context, b *models.AttestationBaseline) error
	GetActiveAttestationBaseline(ctx context.Context) (*models.AttestationBaseline, error)
	ListAttestationBaselines(ctx context.Context) ([]*models.AttestationBaseline, error)
	BumpAttestationEpoch(ctx context.Context) (uint64, error)
	GetAttestationEpoch(ctx context.Context) (uint64, error)

	// Close releases resources (connection pool, etc.).
	Close() error

	// Ping verifies the backend is reachable. For memory it always returns nil;
	// for postgres it checks the connection pool.
	Ping(ctx context.Context) error
}
