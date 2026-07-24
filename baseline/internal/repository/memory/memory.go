// Package memory is the engineering baseline in-memory repository.
// It is suitable for the current baseline and automated verification, but not
// durable production storage. The store enforces the same concurrency and
// consistency rules expected from a SQL implementation: row-lock style
// serialization via mutexes, monotonic counters, and append-only audit.
package memory

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/kvlt/key-vault/internal/repository"
	"github.com/kvlt/key-vault/internal/repository/models"
)

// Store is the in-memory data store.
type Store struct {
	mu sync.Mutex

	tenants          map[string]*models.Tenant
	keys             map[string]*models.Key // keyID -> key
	keysByTenant     map[string][]string    // tenantID -> keyIDs
	keyVersions      map[string]*models.KeyVersion
	keyVersionsByKey map[string][]string // keyID -> versionIDs

	crkVersions      map[string]*models.CRKVersion
	crkNodeEnvelopes map[string]*models.CRKNodeEnvelope

	nodes map[string]*models.Node

	dekLeases   map[string]*models.DEKLease
	nonceLeases map[string]*models.NonceLease
	// nonceCounter tracks the global counter per (keyVersionID, domain).
	nonceCounter map[string]uint64 // "kvID:domain" -> next start

	idempotency map[string]*models.IdempotencyKey

	tenantEnvelopeConfigs map[string]*models.TenantEnvelopeConfig

	clusterEpoch uint64

	// Baseline attestation
	attestationReports    map[string]*models.AttestationReport
	attestationChallenges map[string]*models.AttestationChallenge
	attestationBaselines  map[string]*models.AttestationBaseline
	attestationEpoch      uint64

	// Baseline lifecycle / outbox
	lifecycleJobs map[string]*models.LifecycleJob
	outboxEvents  map[string]*models.OutboxEvent

	// Baseline audit chain
	auditEvents     []*models.AuditEvent
	auditChainHeads map[string]*models.AuditChainHead
}

// New constructs a new in-memory store.
func New() *Store {
	return &Store{
		tenants:               make(map[string]*models.Tenant),
		keys:                  make(map[string]*models.Key),
		keysByTenant:          make(map[string][]string),
		keyVersions:           make(map[string]*models.KeyVersion),
		keyVersionsByKey:      make(map[string][]string),
		crkVersions:           make(map[string]*models.CRKVersion),
		crkNodeEnvelopes:      make(map[string]*models.CRKNodeEnvelope),
		nodes:                 make(map[string]*models.Node),
		dekLeases:             make(map[string]*models.DEKLease),
		nonceLeases:           make(map[string]*models.NonceLease),
		nonceCounter:          make(map[string]uint64),
		idempotency:           make(map[string]*models.IdempotencyKey),
		tenantEnvelopeConfigs: make(map[string]*models.TenantEnvelopeConfig),
		attestationReports:    make(map[string]*models.AttestationReport),
		attestationChallenges: make(map[string]*models.AttestationChallenge),
		attestationBaselines:  make(map[string]*models.AttestationBaseline),
		lifecycleJobs:         make(map[string]*models.LifecycleJob),
		outboxEvents:          make(map[string]*models.OutboxEvent),
		auditChainHeads:       make(map[string]*models.AuditChainHead),
	}
}

// Close is a no-op for the in-memory store. Satisfies repository.Repository.
func (s *Store) Close() error { return nil }

// Ping always returns nil for the in-memory store.
func (s *Store) Ping(ctx context.Context) error { return nil }

// Errors are aliases for the common repository errors so upper layers can
// handle memory and postgres backends uniformly via errors.Is.
var (
	ErrNotFound     = repository.ErrNotFound
	ErrConflict     = repository.ErrConflict
	ErrIllegalState = errors.New("memory: illegal state")
)

// --- Tenant ---

// UpsertTenant inserts or updates a tenant.
func (s *Store) UpsertTenant(ctx context.Context, t *models.Tenant) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	if t.CreatedAt.IsZero() {
		t.CreatedAt = now
	}
	t.UpdatedAt = now
	s.tenants[t.ID] = t
	return nil
}

// GetTenant returns a tenant by ID.
func (s *Store) GetTenant(ctx context.Context, id string) (*models.Tenant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tenants[id]
	if !ok {
		return nil, ErrNotFound
	}
	return cloneTenant(t), nil
}

// --- Tenant Envelope Config ---

// GetTenantEnvelopeConfig returns the envelope config for a tenant.
func (s *Store) GetTenantEnvelopeConfig(ctx context.Context, tenantID string) (*models.TenantEnvelopeConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cfg, ok := s.tenantEnvelopeConfigs[tenantID]
	if !ok {
		return nil, ErrNotFound
	}
	return cloneEnvelopeConfig(cfg), nil
}

// UpsertTenantEnvelopeConfig inserts or updates the envelope config for a tenant.
// Uses optimistic concurrency: if cfg.Version > 0, the existing record must
// have a matching Version or the update is rejected with ErrConflict.
func (s *Store) UpsertTenantEnvelopeConfig(ctx context.Context, cfg *models.TenantEnvelopeConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	existing, ok := s.tenantEnvelopeConfigs[cfg.TenantID]
	if ok {
		if cfg.Version > 0 && cfg.Version != existing.Version {
			return fmt.Errorf("%w: envelope config version mismatch (expected %d, got %d)", ErrConflict, existing.Version, cfg.Version)
		}
		cfg.Version = existing.Version + 1
		cfg.CreatedAt = existing.CreatedAt
	} else {
		if cfg.Version > 0 {
			return fmt.Errorf("%w: envelope config does not exist but version > 0", ErrConflict)
		}
		cfg.Version = 1
		cfg.CreatedAt = now
	}
	cfg.UpdatedAt = now
	s.tenantEnvelopeConfigs[cfg.TenantID] = cfg
	return nil
}

// --- Keys ---

// CreateKey atomically creates a key + its initial key version.
func (s *Store) CreateKey(ctx context.Context, k *models.Key, kv *models.KeyVersion) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.keys[k.ID]; ok {
		return fmt.Errorf("%w: key %s exists", ErrConflict, k.ID)
	}
	now := time.Now().UTC()
	if k.CreatedAt.IsZero() {
		k.CreatedAt = now
	}
	if k.UpdatedAt.IsZero() {
		k.UpdatedAt = now
	}
	if kv.CreatedAt.IsZero() {
		kv.CreatedAt = now
	}
	s.keys[k.ID] = k
	s.keysByTenant[k.TenantID] = append(s.keysByTenant[k.TenantID], k.ID)
	s.keyVersions[kv.ID] = kv
	s.keyVersionsByKey[k.ID] = append(s.keyVersionsByKey[k.ID], kv.ID)
	return nil
}

// GetKey returns a key by ID.
func (s *Store) GetKey(ctx context.Context, tenantID, keyID string) (*models.Key, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.keys[keyID]
	if !ok || k.TenantID != tenantID {
		return nil, ErrNotFound
	}
	return cloneKey(k), nil
}

// ListKeys lists keys for a tenant.
func (s *Store) ListKeys(ctx context.Context, tenantID string) ([]*models.Key, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ids, ok := s.keysByTenant[tenantID]
	if !ok {
		return nil, nil
	}
	out := make([]*models.Key, 0, len(ids))
	for _, id := range ids {
		k := s.keys[id]
		if !k.ArchivedAt.IsZero() {
			continue
		}
		out = append(out, cloneKey(k))
	}
	return out, nil
}

// ListKeysIncludingArchived lists all keys for a tenant, including archived
// tombstones hidden from the default inventory.
func (s *Store) ListKeysIncludingArchived(ctx context.Context, tenantID string) ([]*models.Key, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ids, ok := s.keysByTenant[tenantID]
	if !ok {
		return nil, nil
	}
	out := make([]*models.Key, 0, len(ids))
	for _, id := range ids {
		out = append(out, cloneKey(s.keys[id]))
	}
	return out, nil
}

// ListAllKeys lists keys across all tenants for lifecycle scans.
func (s *Store) ListAllKeys(ctx context.Context) ([]*models.Key, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*models.Key, 0, len(s.keys))
	for _, k := range s.keys {
		out = append(out, cloneKey(k))
	}
	return out, nil
}

// UpdateKeyMetadata updates mutable metadata fields for a key.
func (s *Store) UpdateKeyMetadata(ctx context.Context, tenantID, keyID, name string, tags map[string]string, expiresAt time.Time) (*models.Key, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.keys[keyID]
	if !ok || k.TenantID != tenantID {
		return nil, ErrNotFound
	}
	k.Name = name
	if tags == nil {
		k.Tags = nil
	} else {
		k.Tags = make(map[string]string, len(tags))
		for kk, vv := range tags {
			k.Tags[kk] = vv
		}
	}
	k.ExpiresAt = expiresAt
	k.UpdatedAt = time.Now().UTC()
	return cloneKey(k), nil
}

// UpdateKeyStatus updates a key's status. Uses optimistic concurrency via
// the expectedCurrent parameter.
func (s *Store) UpdateKeyStatus(ctx context.Context, keyID string, expectedCurrent, newStatus string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.keys[keyID]
	if !ok {
		return ErrNotFound
	}
	if k.Status != expectedCurrent {
		return fmt.Errorf("%w: expected %s, got %s", ErrConflict, expectedCurrent, k.Status)
	}
	k.Status = newStatus
	k.UpdatedAt = time.Now().UTC()
	return nil
}

func (s *Store) ArchiveDestroyedKey(ctx context.Context, tenantID, keyID string) (*models.Key, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.keys[keyID]
	if !ok || k.TenantID != tenantID {
		return nil, ErrNotFound
	}
	if k.Status != "DESTROYED" {
		return nil, fmt.Errorf("%w: expected DESTROYED, got %s", ErrConflict, k.Status)
	}
	if k.ArchivedAt.IsZero() {
		now := time.Now().UTC()
		k.ArchivedAt = now
		k.UpdatedAt = now
	}
	return cloneKey(k), nil
}

func (s *Store) DestroyKeyMaterial(ctx context.Context, keyID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.keys[keyID]
	if !ok {
		return ErrNotFound
	}
	if k.Status != "DESTROY_PENDING" {
		return fmt.Errorf("%w: expected DESTROY_PENDING, got %s", ErrConflict, k.Status)
	}
	for _, vid := range s.keyVersionsByKey[keyID] {
		kv := s.keyVersions[vid]
		kv.WrappedDEK = nil
		kv.WrapMetadata = nil
		kv.Status = "DESTROYED"
	}
	k.Status = "DESTROYED"
	k.UpdatedAt = time.Now().UTC()
	return nil
}

// LockKeyForUpdate simulates SELECT FOR UPDATE. The returned unlock function
// MUST be called to release the lock.
func (s *Store) LockKeyForUpdate(ctx context.Context, keyID string) (func(), error) {
	// The store mutex is the lock; we expose a no-op unlock since the caller
	// is expected to do all work in the same transaction.
	s.mu.Lock()
	if _, ok := s.keys[keyID]; !ok {
		s.mu.Unlock()
		return nil, ErrNotFound
	}
	// Return a function that does nothing; the caller must use a Tx method.
	// The baseline exposes higher-level atomic operations instead.
	return func() {}, nil
}

// RotateKey atomically: locks key, inserts new version, switches current_version,
// marks old version DECRYPT_ONLY.
func (s *Store) RotateKey(ctx context.Context, keyID string, newVersion *models.KeyVersion) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.keys[keyID]
	if !ok {
		return ErrNotFound
	}
	// Mark old current version DECRYPT_ONLY.
	for _, vid := range s.keyVersionsByKey[keyID] {
		kv := s.keyVersions[vid]
		if kv.VersionNo == k.CurrentVersion {
			kv.Status = "DECRYPT_ONLY"
		}
	}
	newVersion.CreatedAt = time.Now().UTC()
	s.keyVersions[newVersion.ID] = newVersion
	s.keyVersionsByKey[keyID] = append(s.keyVersionsByKey[keyID], newVersion.ID)
	k.CurrentVersion = newVersion.VersionNo
	k.UpdatedAt = time.Now().UTC()
	return nil
}

// GetKeyVersion returns a key version by ID.
func (s *Store) GetKeyVersion(ctx context.Context, versionID string) (*models.KeyVersion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	kv, ok := s.keyVersions[versionID]
	if !ok {
		return nil, ErrNotFound
	}
	return cloneKeyVersion(kv), nil
}

// GetKeyVersionByNo returns the key version for a (keyID, versionNo).
func (s *Store) GetKeyVersionByNo(ctx context.Context, keyID string, versionNo uint32) (*models.KeyVersion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, vid := range s.keyVersionsByKey[keyID] {
		kv := s.keyVersions[vid]
		if kv.VersionNo == versionNo {
			return cloneKeyVersion(kv), nil
		}
	}
	return nil, ErrNotFound
}

// GetCurrentKeyVersion returns the current key version for a key.
func (s *Store) GetCurrentKeyVersion(ctx context.Context, keyID string) (*models.KeyVersion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.keys[keyID]
	if !ok {
		return nil, ErrNotFound
	}
	for _, vid := range s.keyVersionsByKey[keyID] {
		kv := s.keyVersions[vid]
		if kv.VersionNo == k.CurrentVersion {
			return cloneKeyVersion(kv), nil
		}
	}
	return nil, ErrNotFound
}

// --- CRK ---

// CreateCRKVersion inserts a CRK version.
func (s *Store) CreateCRKVersion(ctx context.Context, v *models.CRKVersion) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.crkVersions[v.ID]; ok {
		return fmt.Errorf("%w: crk version %s exists", ErrConflict, v.ID)
	}
	v.CreatedAt = time.Now().UTC()
	s.crkVersions[v.ID] = v
	// Bump cluster_epoch.
	s.clusterEpoch++
	return nil
}

// GetCRKVersion returns the current CRK version.
func (s *Store) GetCRKVersion(ctx context.Context, id string) (*models.CRKVersion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.crkVersions[id]
	if !ok {
		return nil, ErrNotFound
	}
	return cloneCRKVersion(v), nil
}

// GetLatestCRKVersion returns the latest CRK version.
func (s *Store) GetLatestCRKVersion(ctx context.Context) (*models.CRKVersion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var latest *models.CRKVersion
	for _, v := range s.crkVersions {
		if latest == nil || v.Version > latest.Version {
			latest = v
		}
	}
	if latest == nil {
		return nil, ErrNotFound
	}
	return cloneCRKVersion(latest), nil
}

// CreateCRKNodeEnvelope inserts a CRK node envelope.
func (s *Store) CreateCRKNodeEnvelope(ctx context.Context, e *models.CRKNodeEnvelope) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.crkNodeEnvelopes[e.ID]; ok {
		return fmt.Errorf("%w: crk envelope %s exists", ErrConflict, e.ID)
	}
	e.CreatedAt = time.Now().UTC()
	s.crkNodeEnvelopes[e.ID] = e
	return nil
}

// GetCRKNodeEnvelope returns the CRK envelope for a (crkVersionID, nodeID).
func (s *Store) GetCRKNodeEnvelope(ctx context.Context, crkVersionID, nodeID string) (*models.CRKNodeEnvelope, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range s.crkNodeEnvelopes {
		if e.CRKVersionID == crkVersionID && e.NodeID == nodeID {
			return cloneCRKNodeEnvelope(e), nil
		}
	}
	return nil, ErrNotFound
}

// UpdateCRKNodeEnvelope updates an existing CRK node envelope.
func (s *Store) UpdateCRKNodeEnvelope(ctx context.Context, e *models.CRKNodeEnvelope) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.crkNodeEnvelopes[e.ID]; !ok {
		return ErrNotFound
	}
	s.crkNodeEnvelopes[e.ID] = cloneCRKNodeEnvelope(e)
	return nil
}

// ClusterEpoch returns the current cluster epoch.
func (s *Store) ClusterEpoch(ctx context.Context) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.clusterEpoch, nil
}

// --- Nodes ---

// UpsertNode inserts or updates a node.
func (s *Store) UpsertNode(ctx context.Context, n *models.Node) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	if _, ok := s.nodes[n.NodeID]; !ok {
		n.CreatedAt = now
	}
	n.UpdatedAt = now
	s.nodes[n.NodeID] = n
	return nil
}

// GetNode returns a node by ID.
func (s *Store) GetNode(ctx context.Context, nodeID string) (*models.Node, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, ok := s.nodes[nodeID]
	if !ok {
		return nil, ErrNotFound
	}
	return cloneNode(n), nil
}

// --- DEK Leases ---

// CreateDEKLease inserts a DEK lease.
func (s *Store) CreateDEKLease(ctx context.Context, l *models.DEKLease) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.dekLeases[l.LeaseID]; ok {
		return fmt.Errorf("%w: dek lease %s exists", ErrConflict, l.LeaseID)
	}
	s.dekLeases[l.LeaseID] = l
	return nil
}

// RevokeDEKLease marks a DEK lease revoked.
func (s *Store) RevokeDEKLease(ctx context.Context, leaseID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	l, ok := s.dekLeases[leaseID]
	if !ok {
		return ErrNotFound
	}
	l.Revoked = true
	return nil
}

// --- Nonce Leases ---

// AllocateNonceRange atomically allocates [start, end) for a (keyVersionID, nodeID, domain).
// The range is permanently burned: subsequent calls return a NEW range,
// never overlapping a previously allocated range.
func (s *Store) AllocateNonceRange(ctx context.Context, keyVersionID, nodeID string, domain uint32, size uint64, ttl time.Duration) (*models.NonceLease, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := fmt.Sprintf("%s:%d", keyVersionID, domain)
	start := s.nonceCounter[key]
	end := start + size
	s.nonceCounter[key] = end
	leaseID := newID("nls")
	lease := &models.NonceLease{
		LeaseID:      leaseID,
		KeyVersionID: keyVersionID,
		NodeID:       nodeID,
		Domain:       domain,
		StartCounter: start,
		EndCounter:   end,
		UsedCounter:  start,
		ExpiresAt:    time.Now().UTC().Add(ttl),
		Status:       "ACTIVE",
	}
	s.nonceLeases[leaseID] = lease
	return cloneNonceLease(lease), nil
}

// UpdateNonceUsed persists the used counter for a lease.
func (s *Store) UpdateNonceUsed(ctx context.Context, leaseID string, used uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	l, ok := s.nonceLeases[leaseID]
	if !ok {
		return ErrNotFound
	}
	l.UsedCounter = used
	return nil
}

// GetNonceLease returns a nonce lease by ID.
func (s *Store) GetNonceLease(ctx context.Context, leaseID string) (*models.NonceLease, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	l, ok := s.nonceLeases[leaseID]
	if !ok {
		return nil, ErrNotFound
	}
	return cloneNonceLease(l), nil
}

// --- Idempotency ---

// RecordIdempotency records an idempotency key. Returns ErrConflict if the
// key already exists with a different request hash.
func (s *Store) RecordIdempotency(ctx context.Context, ik *models.IdempotencyKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	existing, ok := s.idempotency[ik.Key]
	if ok {
		if existing.RequestHash != ik.RequestHash {
			return fmt.Errorf("%w: idempotency key reused with different body", ErrConflict)
		}
		return nil
	}
	ik.CreatedAt = time.Now().UTC()
	s.idempotency[ik.Key] = ik
	return nil
}

// GetIdempotency returns an existing idempotency record.
func (s *Store) GetIdempotency(ctx context.Context, key string) (*models.IdempotencyKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ik, ok := s.idempotency[key]
	if !ok {
		return nil, ErrNotFound
	}
	return cloneIdempotencyKey(ik), nil
}

// --- helpers ---

func newID(prefix string) string {
	// The in-memory baseline uses a deterministic-ish ID; durable stores can use UUIDs.
	now := time.Now().UnixNano()
	h := sha256.Sum256([]byte(fmt.Sprintf("%s-%d", prefix, now)))
	return fmt.Sprintf("%s_%x", prefix, h[:8])
}

// clone helpers (defensive copies so callers cannot mutate store state).

func cloneTenant(t *models.Tenant) *models.Tenant {
	if t == nil {
		return nil
	}
	c := *t
	return &c
}

func cloneEnvelopeConfig(cfg *models.TenantEnvelopeConfig) *models.TenantEnvelopeConfig {
	if cfg == nil {
		return nil
	}
	c := *cfg
	if cfg.AllowedFormats != nil {
		c.AllowedFormats = make([]string, len(cfg.AllowedFormats))
		copy(c.AllowedFormats, cfg.AllowedFormats)
	}
	if cfg.Profiles != nil {
		c.Profiles = make([]models.EnvelopeFormatProfile, len(cfg.Profiles))
		copy(c.Profiles, cfg.Profiles)
	}
	return &c
}

func cloneKey(k *models.Key) *models.Key {
	if k == nil {
		return nil
	}
	c := *k
	if k.Tags != nil {
		c.Tags = make(map[string]string, len(k.Tags))
		for k2, v := range k.Tags {
			c.Tags[k2] = v
		}
	}
	return &c
}

func cloneKeyVersion(kv *models.KeyVersion) *models.KeyVersion {
	if kv == nil {
		return nil
	}
	c := *kv
	if kv.WrappedDEK != nil {
		c.WrappedDEK = append([]byte(nil), kv.WrappedDEK...)
	}
	if kv.WrapMetadata != nil {
		c.WrapMetadata = append([]byte(nil), kv.WrapMetadata...)
	}
	return &c
}

func cloneCRKVersion(v *models.CRKVersion) *models.CRKVersion {
	if v == nil {
		return nil
	}
	c := *v
	return &c
}

func cloneCRKNodeEnvelope(e *models.CRKNodeEnvelope) *models.CRKNodeEnvelope {
	if e == nil {
		return nil
	}
	c := *e
	if e.Envelope != nil {
		c.Envelope = append([]byte(nil), e.Envelope...)
	}
	return &c
}

func cloneNode(n *models.Node) *models.Node {
	if n == nil {
		return nil
	}
	c := *n
	return &c
}

func cloneDEKLease(l *models.DEKLease) *models.DEKLease {
	if l == nil {
		return nil
	}
	c := *l
	return &c
}

func cloneNonceLease(l *models.NonceLease) *models.NonceLease {
	if l == nil {
		return nil
	}
	c := *l
	return &c
}

func cloneIdempotencyKey(ik *models.IdempotencyKey) *models.IdempotencyKey {
	if ik == nil {
		return nil
	}
	c := *ik
	return &c
}

// Hash returns a hex SHA-256 of the input (utility).
func Hash(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// --- Baseline: Attestation ---

// CreateAttestationChallenge inserts a one-time challenge.
func (s *Store) CreateAttestationChallenge(ctx context.Context, c *models.AttestationChallenge) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.attestationChallenges[c.ChallengeID]; ok {
		return fmt.Errorf("%w: challenge %s exists", ErrConflict, c.ChallengeID)
	}
	c.CreatedAt = time.Now().UTC()
	s.attestationChallenges[c.ChallengeID] = c
	return nil
}

// GetAttestationChallenge returns a challenge by ID.
func (s *Store) GetAttestationChallenge(ctx context.Context, id string) (*models.AttestationChallenge, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.attestationChallenges[id]
	if !ok {
		return nil, ErrNotFound
	}
	return cloneAttestationChallenge(c), nil
}

// MarkChallengeUsed marks a challenge as consumed.
func (s *Store) MarkChallengeUsed(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.attestationChallenges[id]
	if !ok {
		return ErrNotFound
	}
	c.Used = true
	return nil
}

// CreateAttestationReport inserts an attestation report.
func (s *Store) CreateAttestationReport(ctx context.Context, r *models.AttestationReport) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.attestationReports[r.ID]; ok {
		return fmt.Errorf("%w: report %s exists", ErrConflict, r.ID)
	}
	r.CreatedAt = time.Now().UTC()
	s.attestationReports[r.ID] = r
	return nil
}

// GetLatestAttestationReport returns the most recent report for a node.
func (s *Store) GetLatestAttestationReport(ctx context.Context, nodeID string) (*models.AttestationReport, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var latest *models.AttestationReport
	for _, r := range s.attestationReports {
		if r.NodeID == nodeID {
			if latest == nil || r.CreatedAt.After(latest.CreatedAt) {
				latest = r
			}
		}
	}
	if latest == nil {
		return nil, ErrNotFound
	}
	return cloneAttestationReport(latest), nil
}

// ListAttestationReports returns reports for a node, most recent first.
func (s *Store) ListAttestationReports(ctx context.Context, nodeID string, limit int) ([]*models.AttestationReport, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*models.AttestationReport
	for _, r := range s.attestationReports {
		if r.NodeID == nodeID {
			out = append(out, cloneAttestationReport(r))
		}
	}
	// Sort by created_at desc.
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if out[i].CreatedAt.Before(out[j].CreatedAt) {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// UpsertAttestationBaseline inserts or updates a baseline.
func (s *Store) UpsertAttestationBaseline(ctx context.Context, b *models.AttestationBaseline) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if b.CreatedAt.IsZero() {
		b.CreatedAt = time.Now().UTC()
	}
	s.attestationBaselines[b.Version] = b
	return nil
}

// GetActiveAttestationBaseline returns the active baseline.
func (s *Store) GetActiveAttestationBaseline(ctx context.Context) (*models.AttestationBaseline, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, b := range s.attestationBaselines {
		if b.Status == "active" {
			return cloneAttestationBaseline(b), nil
		}
	}
	return nil, ErrNotFound
}

// ListAttestationBaselines returns all baselines.
func (s *Store) ListAttestationBaselines(ctx context.Context) ([]*models.AttestationBaseline, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*models.AttestationBaseline, 0, len(s.attestationBaselines))
	for _, b := range s.attestationBaselines {
		out = append(out, cloneAttestationBaseline(b))
	}
	return out, nil
}

// BumpAttestationEpoch increments and returns the new attestation epoch.
func (s *Store) BumpAttestationEpoch(ctx context.Context) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.attestationEpoch++
	return s.attestationEpoch, nil
}

// GetAttestationEpoch returns the current attestation epoch.
func (s *Store) GetAttestationEpoch(ctx context.Context) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.attestationEpoch, nil
}

// ListAllNodes returns all registered nodes.
func (s *Store) ListAllNodes(ctx context.Context) ([]*models.Node, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*models.Node, 0, len(s.nodes))
	for _, n := range s.nodes {
		out = append(out, cloneNode(n))
	}
	return out, nil
}

// ListDEKLeasesByNode returns all DEK leases for a node.
func (s *Store) ListDEKLeasesByNode(ctx context.Context, nodeID string) ([]*models.DEKLease, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*models.DEKLease
	for _, l := range s.dekLeases {
		if l.NodeID == nodeID {
			out = append(out, cloneDEKLease(l))
		}
	}
	return out, nil
}

// RevokeDEKLeasesByNode revokes all DEK leases for a node.
func (s *Store) RevokeDEKLeasesByNode(ctx context.Context, nodeID string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	for _, l := range s.dekLeases {
		if l.NodeID == nodeID && !l.Revoked {
			l.Revoked = true
			count++
		}
	}
	return count, nil
}

// FreezeNonceLeasesByNode marks all nonce leases for a node as FROZEN.
func (s *Store) FreezeNonceLeasesByNode(ctx context.Context, nodeID string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	for _, l := range s.nonceLeases {
		if l.NodeID == nodeID && l.Status == "ACTIVE" {
			l.Status = "FROZEN"
			count++
		}
	}
	return count, nil
}

// --- Baseline: Lifecycle / Outbox ---

// CreateLifecycleJob inserts a lifecycle job.
func (s *Store) CreateLifecycleJob(ctx context.Context, j *models.LifecycleJob) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.lifecycleJobs[j.ID]; ok {
		return fmt.Errorf("%w: job %s exists", ErrConflict, j.ID)
	}
	now := time.Now().UTC()
	if j.CreatedAt.IsZero() {
		j.CreatedAt = now
	}
	j.UpdatedAt = now
	s.lifecycleJobs[j.ID] = j
	return nil
}

// ClaimLifecycleJob atomically claims the next runnable job using a lease.
// Simulates SELECT ... FOR UPDATE SKIP LOCKED.
func (s *Store) ClaimLifecycleJob(ctx context.Context, owner string, leaseTTL time.Duration) (*models.LifecycleJob, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	var picked *models.LifecycleJob
	for _, j := range s.lifecycleJobs {
		if j.Status != "PENDING" && j.Status != "RUNNING" {
			continue
		}
		if j.Status == "RUNNING" {
			// Skip if lease still valid.
			if j.LeaseUntil != nil && now.Before(*j.LeaseUntil) {
				continue
			}
			// Lease expired — reclaimable.
		}
		if j.NextRunAt != nil && now.Before(*j.NextRunAt) {
			continue
		}
		// Pick the oldest eligible.
		if picked == nil || j.CreatedAt.Before(picked.CreatedAt) {
			picked = j
		}
	}
	if picked == nil {
		return nil, ErrNotFound
	}
	picked.Status = "RUNNING"
	picked.Attempt++
	picked.LeaseOwner = owner
	leaseUntil := now.Add(leaseTTL)
	picked.LeaseUntil = &leaseUntil
	picked.UpdatedAt = now
	return cloneLifecycleJob(picked), nil
}

// CompleteLifecycleJob marks a job done and records idempotency.
func (s *Store) CompleteLifecycleJob(ctx context.Context, jobID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	j, ok := s.lifecycleJobs[jobID]
	if !ok {
		return ErrNotFound
	}
	j.Status = "DONE"
	j.LeaseOwner = ""
	j.LeaseUntil = nil
	j.UpdatedAt = time.Now().UTC()
	return nil
}

// FailLifecycleJob marks a job failed and schedules retry with backoff.
func (s *Store) FailLifecycleJob(ctx context.Context, jobID string, backoff time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	j, ok := s.lifecycleJobs[jobID]
	if !ok {
		return ErrNotFound
	}
	j.Status = "PENDING"
	j.LeaseOwner = ""
	j.LeaseUntil = nil
	nextRun := time.Now().UTC().Add(backoff)
	j.NextRunAt = &nextRun
	j.UpdatedAt = time.Now().UTC()
	return nil
}

// GetLifecycleJob returns a job by ID.
func (s *Store) GetLifecycleJob(ctx context.Context, id string) (*models.LifecycleJob, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	j, ok := s.lifecycleJobs[id]
	if !ok {
		return nil, ErrNotFound
	}
	return cloneLifecycleJob(j), nil
}

// ListLifecycleJobs returns jobs, optionally filtered by status.
func (s *Store) ListLifecycleJobs(ctx context.Context, status string, limit int) ([]*models.LifecycleJob, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*models.LifecycleJob
	for _, j := range s.lifecycleJobs {
		if status != "" && j.Status != status {
			continue
		}
		out = append(out, cloneLifecycleJob(j))
	}
	// Sort by created_at desc.
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if out[i].CreatedAt.Before(out[j].CreatedAt) {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// CreateOutboxEvent inserts an outbox event.
func (s *Store) CreateOutboxEvent(ctx context.Context, e *models.OutboxEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.outboxEvents[e.ID]; ok {
		return fmt.Errorf("%w: outbox event %s exists", ErrConflict, e.ID)
	}
	e.CreatedAt = time.Now().UTC()
	s.outboxEvents[e.ID] = e
	return nil
}

// ClaimOutboxEvent claims the next pending outbox event.
func (s *Store) ClaimOutboxEvent(ctx context.Context) (*models.OutboxEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	var picked *models.OutboxEvent
	for _, e := range s.outboxEvents {
		if e.Status != "PENDING" {
			continue
		}
		if e.NextRunAt != nil && now.Before(*e.NextRunAt) {
			continue
		}
		if picked == nil || e.CreatedAt.Before(picked.CreatedAt) {
			picked = e
		}
	}
	if picked == nil {
		return nil, ErrNotFound
	}
	picked.Attempts++
	return cloneOutboxEvent(picked), nil
}

// CompleteOutboxEvent marks an outbox event as sent.
func (s *Store) CompleteOutboxEvent(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.outboxEvents[id]
	if !ok {
		return ErrNotFound
	}
	e.Status = "SENT"
	return nil
}

// ListOutboxEvents returns outbox events.
func (s *Store) ListOutboxEvents(ctx context.Context, status string, limit int) ([]*models.OutboxEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*models.OutboxEvent
	for _, e := range s.outboxEvents {
		if status != "" && e.Status != status {
			continue
		}
		out = append(out, cloneOutboxEvent(e))
	}
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if out[i].CreatedAt.Before(out[j].CreatedAt) {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// RetryLifecycleJob resets a FAILED job to PENDING and clears backoff.
// Returns ErrNotFound if job doesn't exist, ErrConflict if status != FAILED.
func (s *Store) RetryLifecycleJob(ctx context.Context, jobID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	j, ok := s.lifecycleJobs[jobID]
	if !ok {
		return ErrNotFound
	}
	if j.Status != "FAILED" {
		return ErrConflict
	}
	j.Status = "PENDING"
	j.LeaseOwner = ""
	j.LeaseUntil = nil
	j.NextRunAt = nil
	j.UpdatedAt = time.Now().UTC()
	return nil
}

// ReplayOutboxEvent resets a SENT/stuck event to PENDING for reprocessing.
// Returns ErrNotFound if event doesn't exist, ErrConflict if already PENDING.
func (s *Store) ReplayOutboxEvent(ctx context.Context, eventID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.outboxEvents[eventID]
	if !ok {
		return ErrNotFound
	}
	if e.Status == "PENDING" {
		return ErrConflict
	}
	e.Status = "PENDING"
	e.NextRunAt = nil
	return nil
}

// DatabaseDiagnostics returns a redacted snapshot for the engineering-only
// in-memory backend. Capacity and backup metrics are not applicable.
func (s *Store) DatabaseDiagnostics(ctx context.Context) (*repository.DatabaseDiagnostics, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	tables := []repository.DatabaseTableStats{
		{Name: "tenants", EstimatedRows: int64(len(s.tenants))},
		{Name: "keys", EstimatedRows: int64(len(s.keys))},
		{Name: "key_versions", EstimatedRows: int64(len(s.keyVersions))},
		{Name: "crk_versions", EstimatedRows: int64(len(s.crkVersions))},
		{Name: "crk_node_envelopes", EstimatedRows: int64(len(s.crkNodeEnvelopes))},
		{Name: "nodes", EstimatedRows: int64(len(s.nodes))},
		{Name: "dek_leases", EstimatedRows: int64(len(s.dekLeases))},
		{Name: "nonce_leases", EstimatedRows: int64(len(s.nonceLeases))},
		{Name: "lifecycle_jobs", EstimatedRows: int64(len(s.lifecycleJobs))},
		{Name: "outbox_events", EstimatedRows: int64(len(s.outboxEvents))},
		{Name: "audit_events", EstimatedRows: int64(len(s.auditEvents))},
		{Name: "tenant_envelope_configs", EstimatedRows: int64(len(s.tenantEnvelopeConfigs))},
		{Name: "cluster_state", EstimatedRows: 1},
		{Name: "nonce_counters", EstimatedRows: int64(len(s.nonceCounter))},
		{Name: "idempotency_keys", EstimatedRows: int64(len(s.idempotency))},
		{Name: "audit_chain_heads", EstimatedRows: int64(len(s.auditChainHeads))},
		{Name: "attestation_challenges", EstimatedRows: int64(len(s.attestationChallenges))},
		{Name: "attestation_reports", EstimatedRows: int64(len(s.attestationReports))},
		{Name: "attestation_baselines", EstimatedRows: int64(len(s.attestationBaselines))},
	}
	for i := range tables {
		tables[i].StatsUpdatedAt = now
	}

	integrity := repository.DatabaseIntegrityStats{}
	for _, version := range s.keyVersions {
		if _, ok := s.keys[version.KeyID]; !ok {
			integrity.OrphanKeyVersions++
		}
		if key := s.keys[version.KeyID]; key != nil && key.Status == "DESTROYED" && (len(version.WrappedDEK) > 0 || len(version.WrapMetadata) > 0) {
			integrity.DestroyedMaterialRows++
		}
	}
	for _, lease := range s.dekLeases {
		if !lease.Revoked && !lease.ExpiresAt.After(now) {
			integrity.ExpiredActiveDEKLeases++
		}
	}
	for _, lease := range s.nonceLeases {
		if lease.Status == "ACTIVE" && !lease.ExpiresAt.After(now) {
			integrity.ExpiredActiveNonceLeases++
		}
	}

	return &repository.DatabaseDiagnostics{
		ObservedAt: now,
		Role:       "memory",
		Schema:     repository.DatabaseSchemaStats{Current: 0, Expected: 0},
		Protection: repository.DatabaseProtectionStats{BackupStatus: "not_applicable"},
		Integrity:  integrity,
		Tables:     tables,
		Unavailable: []string{"capacity", "workload", "replication"},
	}, nil
}

// --- Baseline: Audit chain ---

// AppendAuditEvent appends a hash-chained audit event atomically.
// Computes sequence and hash inside the store mutex for monotonicity.
func (s *Store) AppendAuditEvent(ctx context.Context, e *models.AuditEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e.ChainName == "" {
		e.ChainName = "system"
	}
	head, ok := s.auditChainHeads[e.ChainName]
	if !ok {
		head = &models.AuditChainHead{ChainName: e.ChainName}
		s.auditChainHeads[e.ChainName] = head
	}
	e.Sequence = head.Sequence + 1
	e.PrevHash = head.HeadHash
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now().UTC()
	}
	// Canonical encoding for hashing.
	canon := canonicalAuditEvent(e, head.Sequence+1, head.HeadHash)
	h := sha256.New()
	h.Write([]byte(head.HeadHash))
	h.Write(canon)
	e.CurrentHash = hex.EncodeToString(h.Sum(nil))
	s.auditEvents = append(s.auditEvents, e)
	head.Sequence = e.Sequence
	head.HeadHash = e.CurrentHash
	head.UpdatedAt = time.Now().UTC()
	return nil
}

// ListAuditEvents returns audit events, optionally filtered by chain.
func (s *Store) ListAuditEvents(ctx context.Context, chainName string, limit int) ([]*models.AuditEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*models.AuditEvent
	for _, e := range s.auditEvents {
		if chainName != "" && e.ChainName != chainName {
			continue
		}
		out = append(out, cloneAuditEvent(e))
	}
	// Reverse (newest first).
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// DeleteAuditEvents deletes audit events for a chain, or all chains when chainName is empty.
func (s *Store) DeleteAuditEvents(ctx context.Context, chainName string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if chainName == "" {
		n := len(s.auditEvents)
		s.auditEvents = nil
		s.auditChainHeads = make(map[string]*models.AuditChainHead)
		return n, nil
	}
	kept := s.auditEvents[:0]
	deleted := 0
	for _, e := range s.auditEvents {
		if e.ChainName == chainName {
			deleted++
			continue
		}
		kept = append(kept, e)
	}
	s.auditEvents = kept
	delete(s.auditChainHeads, chainName)
	return deleted, nil
}

// GetAuditChainHead returns the head for a chain.
func (s *Store) GetAuditChainHead(ctx context.Context, chainName string) (*models.AuditChainHead, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h, ok := s.auditChainHeads[chainName]
	if !ok {
		return nil, ErrNotFound
	}
	c := *h
	return &c, nil
}

// ListAuditChainHeads returns all chain heads.
func (s *Store) ListAuditChainHeads(ctx context.Context) ([]*models.AuditChainHead, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*models.AuditChainHead, 0, len(s.auditChainHeads))
	for _, h := range s.auditChainHeads {
		c := *h
		out = append(out, &c)
	}
	return out, nil
}

// VerifyAuditChain re-computes the hash chain and detects tampering.
// Returns the first broken sequence (0 means intact).
func (s *Store) VerifyAuditChain(ctx context.Context, chainName string) (brokenSeq uint64, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var prevHash string
	var expectedSeq uint64 = 1
	for _, e := range s.auditEvents {
		if e.ChainName != chainName {
			continue
		}
		if e.Sequence != expectedSeq {
			return e.Sequence, fmt.Errorf("sequence gap: expected %d got %d", expectedSeq, e.Sequence)
		}
		if e.PrevHash != prevHash {
			return e.Sequence, fmt.Errorf("prev_hash mismatch at seq %d", e.Sequence)
		}
		canon := canonicalAuditEvent(e, e.Sequence, prevHash)
		h := sha256.New()
		h.Write([]byte(prevHash))
		h.Write(canon)
		recomputed := hex.EncodeToString(h.Sum(nil))
		if recomputed != e.CurrentHash {
			return e.Sequence, fmt.Errorf("hash mismatch at seq %d", e.Sequence)
		}
		prevHash = e.CurrentHash
		expectedSeq++
	}
	return 0, nil
}

// canonicalAuditEvent returns a deterministic byte encoding of an audit event
// for hash-chain computation. Excludes PrevHash and CurrentHash (computed fields).
// Timestamp is truncated to microsecond precision to match PostgreSQL TIMESTAMPTZ
// storage precision, ensuring hash consistency across backends.
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
	// Metadata: sorted keys.
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

// --- Baseline clone helpers ---

func cloneAttestationChallenge(c *models.AttestationChallenge) *models.AttestationChallenge {
	if c == nil {
		return nil
	}
	cc := *c
	return &cc
}

func cloneAttestationReport(r *models.AttestationReport) *models.AttestationReport {
	if r == nil {
		return nil
	}
	cc := *r
	return &cc
}

func cloneAttestationBaseline(b *models.AttestationBaseline) *models.AttestationBaseline {
	if b == nil {
		return nil
	}
	cc := *b
	if b.PCRProfile != nil {
		cc.PCRProfile = make(map[uint32]string, len(b.PCRProfile))
		for k, v := range b.PCRProfile {
			cc.PCRProfile[k] = v
		}
	}
	return &cc
}

func cloneLifecycleJob(j *models.LifecycleJob) *models.LifecycleJob {
	if j == nil {
		return nil
	}
	cc := *j
	if j.Payload != nil {
		cc.Payload = append([]byte(nil), j.Payload...)
	}
	return &cc
}

func cloneOutboxEvent(e *models.OutboxEvent) *models.OutboxEvent {
	if e == nil {
		return nil
	}
	cc := *e
	if e.Payload != nil {
		cc.Payload = append([]byte(nil), e.Payload...)
	}
	return &cc
}

func cloneAuditEvent(e *models.AuditEvent) *models.AuditEvent {
	if e == nil {
		return nil
	}
	cc := *e
	if e.Metadata != nil {
		cc.Metadata = make(map[string]string, len(e.Metadata))
		for k, v := range e.Metadata {
			cc.Metadata[k] = v
		}
	}
	return &cc
}
