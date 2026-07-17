// Package models defines the persistent data model types per design §11.
// These are shared across repository implementations.
package models

import (
	"time"
)

// Tenant is a tenant record.
type Tenant struct {
	ID           string
	Name         string
	Status       string
	CRKVersionID string // reserved; may be empty
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// Key is a logical key.
type Key struct {
	ID             string
	TenantID       string
	Name           string
	Purpose        string // encrypt_decrypt | datakey
	PolicyID       string
	SuiteID        string
	CurrentVersion uint32
	Status         string
	Tags           map[string]string
	ExpiresAt      time.Time
	ArchivedAt     time.Time
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// KeyVersion is a version of a key with a wrapped DEK.
type KeyVersion struct {
	ID           string
	KeyID        string
	VersionNo    uint32
	SuiteID      string
	WrappedDEK   []byte // CRK-sealed; never plaintext
	WrapMetadata []byte // JSON: crk_version, aad_digest, wrap_alg
	Status       string
	CreatedAt    time.Time
}

// CRKVersion is a CRK version metadata record.
type CRKVersion struct {
	ID        string
	Version   uint32
	Epoch     uint64 // cluster_epoch; repository-maintained
	Status    string
	CreatedAt time.Time
}

// CRKNodeEnvelope is a CRK envelope sealed for a specific node.
type CRKNodeEnvelope struct {
	ID           string
	CRKVersionID string
	NodeID       string
	Envelope     []byte // JSON-encoded provider.CRKEnvelope
	CreatedAt    time.Time
}

// Node is a registered service node.
type Node struct {
	NodeID           string
	Role             string // management | key | data
	Status           string
	ReadyReason      string // static_registration | attestation
	ClusterEpoch     uint64
	AttestationEpoch uint64
	Baseline         NodeBaseline
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// NodeBaseline is the host security baseline per design §6.6.
type NodeBaseline struct {
	SELinuxStatus  string
	KernelVersion  string
	VirtPlatform   string
	TPM2TSSVersion string
	SwtpmIsolated  bool
}

// DEKLease is a DEK lease record (design §11.1).
type DEKLease struct {
	LeaseID      string
	KeyVersionID string
	NodeID       string
	TenantID     string
	Purpose      string
	SuiteID      string
	ExpiresAt    time.Time
	Revoked      bool
}

// NonceLease is a nonce counter-range lease (design §11.2).
type NonceLease struct {
	LeaseID      string
	KeyVersionID string
	NodeID       string
	Domain       uint32
	StartCounter uint64
	EndCounter   uint64
	UsedCounter  uint64
	ExpiresAt    time.Time
	Status       string // ACTIVE | RELEASED | EXPIRED | FROZEN
}

// IdempotencyKey records a processed idempotent request.
type IdempotencyKey struct {
	Key            string
	PrincipalID    string
	TenantID       string
	Method         string
	Path           string
	RequestHash    string
	ResponseStatus int
	ResponseHash   string
	CreatedAt      time.Time
}

// --- Baseline: Attestation ---

// AttestationReport records a node attestation result.
type AttestationReport struct {
	ID              string // report ID
	NodeID          string
	BaselineVersion string    // baseline version used for verification
	PCRDigest       string    // hex SHA-256 of PCR profile
	EventLogDigest  string    // hex SHA-256 of event log
	QuoteValid      bool      // TPM Quote signature verification result
	Nonce           string    // challenge nonce used
	Status          string    // PASS | FAIL
	ExpiresAt       time.Time // attestation validity window
	AuditEventID    string    // linked audit event
	CreatedAt       time.Time
}

// AttestationChallenge is a one-time challenge issued to a node.
type AttestationChallenge struct {
	ChallengeID string
	NodeID      string
	Nonce       string
	ExpiresAt   time.Time
	Used        bool
	CreatedAt   time.Time
}

// AttestationBaseline is a trusted baseline version.
type AttestationBaseline struct {
	Version      string
	PCRProfile   map[uint32]string // register -> expected hex digest
	FirmwareHash string
	OSImageHash  string
	Status       string // active | deprecated
	CreatedAt    time.Time
}

// --- Baseline: Lifecycle / Outbox ---

// LifecycleJob is an async lifecycle task.
type LifecycleJob struct {
	ID             string
	Type           string // key_expiry_check | cache_invalidate | destroy_due | audit_forward
	TenantID       string
	KeyID          string
	KeyVersionID   string
	Payload        []byte // JSON job-specific payload
	Status         string // PENDING | RUNNING | DONE | FAILED
	Attempt        int
	NextRunAt      *time.Time
	LeaseOwner     string
	LeaseUntil     *time.Time
	IdempotencyKey string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// OutboxEvent is a transactional outbox event.
type OutboxEvent struct {
	ID          string
	EventType   string // e.g. key.rotated, node.revoked, policy.reloaded
	AggregateID string
	Payload     []byte // JSON
	Status      string // PENDING | SENT
	Attempts    int
	NextRunAt   *time.Time
	CreatedAt   time.Time
}

// --- Baseline: Audit chain ---

// AuditEvent is a persisted audit event with hash-chain fields.
type AuditEvent struct {
	EventID      string
	RequestID    string
	TenantHash   string
	ActorType    string
	ActorHash    string
	Action       string
	TargetType   string
	TargetIDHash string
	Result       string
	ErrorCode    string
	Timestamp    time.Time
	Metadata     map[string]string
	ChainName    string // e.g. "tenant:t-default" or "system"
	Sequence     uint64 // monotonic per chain
	PrevHash     string
	CurrentHash  string
}

// AuditChainHead tracks the latest hash and sequence for a chain.
type AuditChainHead struct {
	ChainName string
	Sequence  uint64
	HeadHash  string
	UpdatedAt time.Time
}

// TenantEnvelopeConfig is the per-tenant envelope format configuration (design §8.6).
type TenantEnvelopeConfig struct {
	TenantID       string
	DefaultFormat  string
	AllowedFormats []string
	Profiles       []EnvelopeFormatProfile
	AADRequired    bool
	Version        int
	CreatedAt      time.Time
	UpdatedAt      time.Time
	UpdatedBy      string
}

// EnvelopeFormatProfile describes a tenant-owned external envelope format.
// It maps external fields to the immutable CoreEnvelope model. The Adapter
// chooses the parser/renderer implementation, while FormatID is the business
// format name clients request, such as "partner-json-v1".
type EnvelopeFormatProfile struct {
	FormatID      string                 `json:"format_id"`
	Adapter       string                 `json:"adapter"`
	FieldMappings []EnvelopeFieldMapping `json:"field_mappings,omitempty"`
	Extensions    []EnvelopeExtension    `json:"extensions,omitempty"`
	Description   string                 `json:"description,omitempty"`
}

type EnvelopeFieldMapping struct {
	Path         string `json:"path"`
	Source       string `json:"source"`
	Required     bool   `json:"required"`
	Encoding     string `json:"encoding,omitempty"`
	DefaultValue string `json:"default_value,omitempty"`
}

type EnvelopeExtension struct {
	Name         string `json:"name"`
	Type         string `json:"type"`
	Required     bool   `json:"required"`
	DefaultValue string `json:"default_value,omitempty"`
	Description  string `json:"description,omitempty"`
}
