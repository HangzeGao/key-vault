package memory

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/kvlt/key-vault/internal/repository"
	"github.com/kvlt/key-vault/internal/repository/models"
)

func newTestStore() *Store {
	return New()
}

// --- Tenant ---

func TestTenantCRUD(t *testing.T) {
	ctx := context.Background()
	s := newTestStore()

	tenant := &models.Tenant{
		ID:     "t-test",
		Name:   "test-tenant",
		Status: "active",
	}
	if err := s.UpsertTenant(ctx, tenant); err != nil {
		t.Fatalf("UpsertTenant: %v", err)
	}

	got, err := s.GetTenant(ctx, "t-test")
	if err != nil {
		t.Fatalf("GetTenant: %v", err)
	}
	if got.Name != "test-tenant" {
		t.Errorf("Name = %s, want test-tenant", got.Name)
	}

	// Update.
	tenant.Name = "updated-tenant"
	if err := s.UpsertTenant(ctx, tenant); err != nil {
		t.Fatalf("UpsertTenant(update): %v", err)
	}
	got, _ = s.GetTenant(ctx, "t-test")
	if got.Name != "updated-tenant" {
		t.Errorf("Name after update = %s, want updated-tenant", got.Name)
	}

	// Not found.
	_, err = s.GetTenant(ctx, "nonexistent")
	if !errors.Is(err, repository.ErrNotFound) {
		t.Errorf("GetTenant(nonexistent) error = %v, want ErrNotFound", err)
	}
}

// --- Envelope Config ---

func TestEnvelopeConfigOptimisticConcurrency(t *testing.T) {
	ctx := context.Background()
	s := newTestStore()

	// Create.
	cfg := &models.TenantEnvelopeConfig{
		TenantID:       "t-env",
		DefaultFormat:  "json-v1",
		AllowedFormats: []string{"json-v1", "configurable-json-v1"},
	}
	if err := s.UpsertTenantEnvelopeConfig(ctx, cfg); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if cfg.Version != 1 {
		t.Errorf("Version after create = %d, want 1", cfg.Version)
	}

	// Read back.
	got, err := s.GetTenantEnvelopeConfig(ctx, "t-env")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Version != 1 {
		t.Errorf("Version = %d, want 1", got.Version)
	}

	// Update with correct version.
	got.DefaultFormat = "json-v1"
	if err := s.UpsertTenantEnvelopeConfig(ctx, got); err != nil {
		t.Fatalf("Upsert(update): %v", err)
	}
	if got.Version != 2 {
		t.Errorf("Version after update = %d, want 2", got.Version)
	}

	// Update with stale version should fail.
	stale := &models.TenantEnvelopeConfig{
		TenantID:      "t-env",
		DefaultFormat: "json-v1",
		Version:       1, // stale
	}
	err = s.UpsertTenantEnvelopeConfig(ctx, stale)
	if !errors.Is(err, repository.ErrConflict) {
		t.Errorf("Upsert(stale) error = %v, want ErrConflict", err)
	}

	// Not found.
	_, err = s.GetTenantEnvelopeConfig(ctx, "nonexistent")
	if !errors.Is(err, repository.ErrNotFound) {
		t.Errorf("Get(nonexistent) error = %v, want ErrNotFound", err)
	}
}

// --- Keys ---

func TestCreateKeyAndVersion(t *testing.T) {
	ctx := context.Background()
	s := newTestStore()

	// Create tenant first (FK constraint in postgres, but memory is lenient).
	_ = s.UpsertTenant(ctx, &models.Tenant{ID: "t-1", Name: "t1", Status: "active"})

	k := &models.Key{
		ID:             "k-1",
		TenantID:       "t-1",
		Name:           "test-key",
		Purpose:        "encrypt_decrypt",
		PolicyID:       "pol-1",
		SuiteID:        "AES-256-GCM",
		CurrentVersion: 1,
		Status:         "ACTIVE",
		Tags:           map[string]string{"env": "test"},
	}
	kv := &models.KeyVersion{
		ID:           "kv-1",
		KeyID:        "k-1",
		VersionNo:    1,
		SuiteID:      "AES-256-GCM",
		WrappedDEK:   []byte("wrapped"),
		WrapMetadata: []byte(`{"alg":"crk"}`),
		Status:       "ACTIVE",
	}
	if err := s.CreateKey(ctx, k, kv); err != nil {
		t.Fatalf("CreateKey: %v", err)
	}

	// Duplicate should conflict.
	err := s.CreateKey(ctx, k, kv)
	if !errors.Is(err, repository.ErrConflict) {
		t.Errorf("CreateKey(duplicate) error = %v, want ErrConflict", err)
	}

	// Get.
	got, err := s.GetKey(ctx, "t-1", "k-1")
	if err != nil {
		t.Fatalf("GetKey: %v", err)
	}
	if got.Name != "test-key" {
		t.Errorf("Name = %s", got.Name)
	}
	if got.Tags["env"] != "test" {
		t.Errorf("Tags[env] = %s", got.Tags["env"])
	}

	// Wrong tenant.
	_, err = s.GetKey(ctx, "t-other", "k-1")
	if !errors.Is(err, repository.ErrNotFound) {
		t.Errorf("GetKey(wrong tenant) error = %v, want ErrNotFound", err)
	}

	// List.
	keys, err := s.ListKeys(ctx, "t-1")
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	if len(keys) != 1 {
		t.Errorf("ListKeys count = %d, want 1", len(keys))
	}
}

func TestUpdateKeyStatusOptimistic(t *testing.T) {
	ctx := context.Background()
	s := newTestStore()
	_ = s.UpsertTenant(ctx, &models.Tenant{ID: "t-1", Name: "t1", Status: "active"})

	k := &models.Key{ID: "k-1", TenantID: "t-1", Name: "k", Purpose: "encrypt_decrypt", PolicyID: "p", SuiteID: "s", CurrentVersion: 1, Status: "ACTIVE"}
	kv := &models.KeyVersion{ID: "kv-1", KeyID: "k-1", VersionNo: 1, SuiteID: "s", WrappedDEK: []byte("w"), Status: "ACTIVE"}
	_ = s.CreateKey(ctx, k, kv)

	// Correct expected current.
	if err := s.UpdateKeyStatus(ctx, "k-1", "ACTIVE", "DISABLED"); err != nil {
		t.Fatalf("UpdateKeyStatus: %v", err)
	}
	got, _ := s.GetKey(ctx, "t-1", "k-1")
	if got.Status != "DISABLED" {
		t.Errorf("Status = %s, want DISABLED", got.Status)
	}

	// Stale expected current should conflict.
	err := s.UpdateKeyStatus(ctx, "k-1", "ACTIVE", "DESTROY_PENDING")
	if !errors.Is(err, repository.ErrConflict) {
		t.Errorf("UpdateKeyStatus(stale) error = %v, want ErrConflict", err)
	}

	// Nonexistent key.
	err = s.UpdateKeyStatus(ctx, "nonexistent", "ACTIVE", "DISABLED")
	if !errors.Is(err, repository.ErrNotFound) {
		t.Errorf("UpdateKeyStatus(nonexistent) error = %v, want ErrNotFound", err)
	}
}

func TestArchiveDestroyedKeyHidesFromDefaultList(t *testing.T) {
	ctx := context.Background()
	s := New()
	k := &models.Key{ID: "k-archive", TenantID: "t-1", Name: "k", Purpose: "encrypt_decrypt", PolicyID: "p", SuiteID: "s", CurrentVersion: 1, Status: "DESTROYED"}
	k.Status = "DESTROYED"
	kv := &models.KeyVersion{ID: "kv-archive", KeyID: "k-archive", VersionNo: 1, SuiteID: "s", WrappedDEK: []byte("w"), Status: "DESTROYED"}
	if err := s.CreateKey(ctx, k, kv); err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	if _, err := s.ArchiveDestroyedKey(ctx, "t-1", "k-archive"); err != nil {
		t.Fatalf("ArchiveDestroyedKey: %v", err)
	}
	keys, err := s.ListKeys(ctx, "t-1")
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	if len(keys) != 0 {
		t.Fatalf("default ListKeys returned archived keys: %d", len(keys))
	}
	all, err := s.ListKeysIncludingArchived(ctx, "t-1")
	if err != nil {
		t.Fatalf("ListKeysIncludingArchived: %v", err)
	}
	if len(all) != 1 || all[0].ArchivedAt.IsZero() {
		t.Fatalf("including archived = %+v, want archived tombstone", all)
	}
}

func TestArchiveDestroyedKeyRejectsActiveKey(t *testing.T) {
	ctx := context.Background()
	s := New()
	k := &models.Key{ID: "k-active-archive", TenantID: "t-1", Name: "k", Purpose: "encrypt_decrypt", PolicyID: "p", SuiteID: "s", CurrentVersion: 1, Status: "ACTIVE"}
	kv := &models.KeyVersion{ID: "kv-active-archive", KeyID: "k-active-archive", VersionNo: 1, SuiteID: "s", WrappedDEK: []byte("w"), Status: "ACTIVE"}
	if err := s.CreateKey(ctx, k, kv); err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	if _, err := s.ArchiveDestroyedKey(ctx, "t-1", "k-active-archive"); !errors.Is(err, ErrConflict) {
		t.Fatalf("ArchiveDestroyedKey error = %v, want ErrConflict", err)
	}
}

func TestPrepareAndActivateImportedKeyVersion(t *testing.T) {
	ctx := context.Background()
	s := New()
	now := time.Now().UTC()
	k := &models.Key{ID: "k-static", TenantID: "t-1", CurrentVersion: 1, Status: "ACTIVE", CreatedAt: now, UpdatedAt: now}
	v1 := &models.KeyVersion{ID: "kv-static-1", KeyID: k.ID, VersionNo: 1, SuiteID: "SM4_GCM", Status: "ACTIVE", CreatedAt: now}
	if err := s.CreateKey(ctx, k, v1); err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	v2 := &models.KeyVersion{ID: "kv-static-2", KeyID: k.ID, VersionNo: 2, SuiteID: "SM4_GCM", Status: "PRE_ACTIVE", WrappedDEK: []byte("wrapped"), CreatedAt: now}
	if err := s.CreatePendingKeyVersion(ctx, k.ID, v2); err != nil {
		t.Fatalf("CreatePendingKeyVersion: %v", err)
	}
	current, err := s.GetCurrentKeyVersion(ctx, k.ID)
	if err != nil || current.VersionNo != 1 {
		t.Fatalf("current before activation = %#v, %v", current, err)
	}
	if err := s.ActivateKeyVersion(ctx, k.ID, 2); err != nil {
		t.Fatalf("ActivateKeyVersion: %v", err)
	}
	current, err = s.GetCurrentKeyVersion(ctx, k.ID)
	if err != nil || current.VersionNo != 2 || current.Status != "ACTIVE" {
		t.Fatalf("current after activation = %#v, %v", current, err)
	}
	old, err := s.GetKeyVersionByNo(ctx, k.ID, 1)
	if err != nil || old.Status != "DECRYPT_ONLY" {
		t.Fatalf("old version = %#v, %v", old, err)
	}
}

func TestUpdateKeyMetadata(t *testing.T) {
	ctx := context.Background()
	s := newTestStore()
	_ = s.UpsertTenant(ctx, &models.Tenant{ID: "t-1", Name: "t1", Status: "active"})
	k := &models.Key{ID: "k-1", TenantID: "t-1", Name: "old", Purpose: "encrypt_decrypt", PolicyID: "p", SuiteID: "s", CurrentVersion: 1, Status: "ACTIVE"}
	kv := &models.KeyVersion{ID: "kv-1", KeyID: "k-1", VersionNo: 1, SuiteID: "s", WrappedDEK: []byte("w"), Status: "ACTIVE"}
	_ = s.CreateKey(ctx, k, kv)

	updated, err := s.UpdateKeyMetadata(ctx, "t-1", "k-1", "new-name", map[string]string{"a": "b"}, time.Time{})
	if err != nil {
		t.Fatalf("UpdateKeyMetadata: %v", err)
	}
	if updated.Name != "new-name" {
		t.Errorf("Name = %s, want new-name", updated.Name)
	}
	if updated.Tags["a"] != "b" {
		t.Errorf("Tags[a] = %s, want b", updated.Tags["a"])
	}
}

// --- CRK ---

func TestCRKVersion(t *testing.T) {
	ctx := context.Background()
	s := newTestStore()

	v1 := &models.CRKVersion{ID: "crk-v1", Version: 1, Epoch: 1, Status: "active"}
	if err := s.CreateCRKVersion(ctx, v1); err != nil {
		t.Fatalf("CreateCRKVersion: %v", err)
	}

	// Duplicate.
	err := s.CreateCRKVersion(ctx, v1)
	if !errors.Is(err, repository.ErrConflict) {
		t.Errorf("CreateCRKVersion(duplicate) error = %v, want ErrConflict", err)
	}

	// Get.
	got, err := s.GetCRKVersion(ctx, "crk-v1")
	if err != nil {
		t.Fatalf("GetCRKVersion: %v", err)
	}
	if got.Version != 1 {
		t.Errorf("Version = %d", got.Version)
	}

	// Latest.
	v2 := &models.CRKVersion{ID: "crk-v2", Version: 2, Epoch: 2, Status: "active"}
	_ = s.CreateCRKVersion(ctx, v2)
	latest, _ := s.GetLatestCRKVersion(ctx)
	if latest.Version != 2 {
		t.Errorf("Latest Version = %d, want 2", latest.Version)
	}

	// No CRK versions.
	s2 := newTestStore()
	_, err = s2.GetLatestCRKVersion(ctx)
	if !errors.Is(err, repository.ErrNotFound) {
		t.Errorf("GetLatestCRKVersion(empty) error = %v, want ErrNotFound", err)
	}
}

// --- Idempotency ---

func TestIdempotencyRecordAndGet(t *testing.T) {
	ctx := context.Background()
	s := newTestStore()

	ik := &models.IdempotencyKey{
		Key:            "idem-001",
		PrincipalID:    "p-1",
		Method:         "POST",
		Path:           "/keys",
		RequestHash:    "abc123",
		ResponseStatus: 201,
		ResponseHash:   "def456",
	}
	if err := s.RecordIdempotency(ctx, ik); err != nil {
		t.Fatalf("RecordIdempotency: %v", err)
	}

	// Get.
	got, err := s.GetIdempotency(ctx, "idem-001")
	if err != nil {
		t.Fatalf("GetIdempotency: %v", err)
	}
	if got.RequestHash != "abc123" {
		t.Errorf("RequestHash = %s", got.RequestHash)
	}

	// Re-record with same hash (idempotent replay).
	err = s.RecordIdempotency(ctx, ik)
	if err != nil {
		t.Errorf("RecordIdempotency(replay) error = %v, want nil", err)
	}

	// Re-record with different hash (conflict).
	ik2 := &models.IdempotencyKey{
		Key:         "idem-001",
		RequestHash: "different",
	}
	err = s.RecordIdempotency(ctx, ik2)
	if !errors.Is(err, repository.ErrConflict) {
		t.Errorf("RecordIdempotency(different hash) error = %v, want ErrConflict", err)
	}

	// Not found.
	_, err = s.GetIdempotency(ctx, "nonexistent")
	if !errors.Is(err, repository.ErrNotFound) {
		t.Errorf("GetIdempotency(nonexistent) error = %v, want ErrNotFound", err)
	}
}

// --- Audit Chain ---

func TestAuditChainAppendAndVerify(t *testing.T) {
	ctx := context.Background()
	s := newTestStore()

	// Append 3 events to the same chain.
	for i := 0; i < 3; i++ {
		e := &models.AuditEvent{
			EventID:   "evt-" + string(rune('A'+i)),
			Action:    "key.create",
			ActorType: "principal",
			ActorHash: "hash-1",
			Result:    "success",
			ChainName: "tenant:t-1",
		}
		if err := s.AppendAuditEvent(ctx, e); err != nil {
			t.Fatalf("AppendAuditEvent[%d]: %v", i, err)
		}
		if e.Sequence != uint64(i+1) {
			t.Errorf("Event %d Sequence = %d, want %d", i, e.Sequence, i+1)
		}
		if e.PrevHash == "" && i > 0 {
			t.Errorf("Event %d PrevHash empty but should be set", i)
		}
		if e.CurrentHash == "" {
			t.Errorf("Event %d CurrentHash empty", i)
		}
	}

	// Verify chain integrity.
	broken, err := s.VerifyAuditChain(ctx, "tenant:t-1")
	if err != nil {
		t.Fatalf("VerifyAuditChain: broken at seq %d: %v", broken, err)
	}
	if broken != 0 {
		t.Errorf("VerifyAuditChain broken = %d, want 0", broken)
	}

	// Chain head.
	head, _ := s.GetAuditChainHead(ctx, "tenant:t-1")
	if head.Sequence != 3 {
		t.Errorf("Head Sequence = %d, want 3", head.Sequence)
	}

	// List events.
	events, _ := s.ListAuditEvents(ctx, "tenant:t-1", 10)
	if len(events) != 3 {
		t.Errorf("ListAuditEvents count = %d, want 3", len(events))
	}
	// Should be newest first.
	if events[0].Sequence != 3 {
		t.Errorf("First event Sequence = %d, want 3 (newest first)", events[0].Sequence)
	}
}

func TestAuditChainMultipleChains(t *testing.T) {
	ctx := context.Background()
	s := newTestStore()

	_ = s.AppendAuditEvent(ctx, &models.AuditEvent{EventID: "e1", Action: "a", ChainName: "chain-A"})
	_ = s.AppendAuditEvent(ctx, &models.AuditEvent{EventID: "e2", Action: "a", ChainName: "chain-B"})
	_ = s.AppendAuditEvent(ctx, &models.AuditEvent{EventID: "e3", Action: "a", ChainName: "chain-A"})

	// Each chain should have its own sequence.
	hA, _ := s.GetAuditChainHead(ctx, "chain-A")
	hB, _ := s.GetAuditChainHead(ctx, "chain-B")
	if hA.Sequence != 2 {
		t.Errorf("Chain-A Sequence = %d, want 2", hA.Sequence)
	}
	if hB.Sequence != 1 {
		t.Errorf("Chain-B Sequence = %d, want 1", hB.Sequence)
	}

	// Verify both chains.
	if broken, err := s.VerifyAuditChain(ctx, "chain-A"); err != nil || broken != 0 {
		t.Errorf("Verify(chain-A): broken=%d err=%v", broken, err)
	}
	if broken, err := s.VerifyAuditChain(ctx, "chain-B"); err != nil || broken != 0 {
		t.Errorf("Verify(chain-B): broken=%d err=%v", broken, err)
	}
}

func TestAuditChainDefaultChainName(t *testing.T) {
	ctx := context.Background()
	s := newTestStore()

	e := &models.AuditEvent{EventID: "e1", Action: "a"} // no ChainName
	_ = s.AppendAuditEvent(ctx, e)
	if e.ChainName != "system" {
		t.Errorf("ChainName = %s, want 'system' (default)", e.ChainName)
	}
}

// --- Nonce Leases ---

func TestAllocateNonceRange(t *testing.T) {
	ctx := context.Background()
	s := newTestStore()

	// First allocation.
	lease1, err := s.AllocateNonceRange(ctx, "kv-1", "node-1", 0, 100, 10*time.Minute)
	if err != nil {
		t.Fatalf("AllocateNonceRange[1]: %v", err)
	}
	if lease1.StartCounter != 0 {
		t.Errorf("StartCounter = %d, want 0", lease1.StartCounter)
	}
	if lease1.EndCounter != 100 {
		t.Errorf("EndCounter = %d, want 100", lease1.EndCounter)
	}
	if lease1.Status != "ACTIVE" {
		t.Errorf("Status = %s, want ACTIVE", lease1.Status)
	}

	// Second allocation should continue from where first left off.
	lease2, _ := s.AllocateNonceRange(ctx, "kv-1", "node-1", 0, 50, 10*time.Minute)
	if lease2.StartCounter != 100 {
		t.Errorf("StartCounter[2] = %d, want 100", lease2.StartCounter)
	}
	if lease2.EndCounter != 150 {
		t.Errorf("EndCounter[2] = %d, want 150", lease2.EndCounter)
	}

	// Different domain has its own counter.
	lease3, _ := s.AllocateNonceRange(ctx, "kv-1", "node-1", 1, 10, 10*time.Minute)
	if lease3.StartCounter != 0 {
		t.Errorf("StartCounter[domain=1] = %d, want 0", lease3.StartCounter)
	}
}

func TestFreezeNonceLeasesByNode(t *testing.T) {
	ctx := context.Background()
	s := newTestStore()

	_, _ = s.AllocateNonceRange(ctx, "kv-1", "node-1", 0, 100, 10*time.Minute)
	time.Sleep(1 * time.Millisecond) // ensure unique lease IDs
	_, _ = s.AllocateNonceRange(ctx, "kv-2", "node-1", 0, 100, 10*time.Minute)
	time.Sleep(1 * time.Millisecond)
	_, _ = s.AllocateNonceRange(ctx, "kv-3", "node-2", 0, 100, 10*time.Minute)

	n, err := s.FreezeNonceLeasesByNode(ctx, "node-1")
	if err != nil {
		t.Fatalf("FreezeNonceLeasesByNode: %v", err)
	}
	if n != 2 {
		t.Errorf("Frozen count = %d, want 2", n)
	}

	// node-2 should not be affected.
	n2, _ := s.FreezeNonceLeasesByNode(ctx, "node-2")
	if n2 != 1 {
		t.Errorf("node-2 frozen count = %d, want 1", n2)
	}
}

// --- Lifecycle / Outbox ---

func TestLifecycleJobClaimAndComplete(t *testing.T) {
	ctx := context.Background()
	s := newTestStore()

	j := &models.LifecycleJob{
		ID:        "job-1",
		Type:      "key_expiry_check",
		Status:    "PENDING",
		NextRunAt: func() *time.Time { t := time.Now().Add(-1 * time.Minute); return &t }(), // eligible
	}
	if err := s.CreateLifecycleJob(ctx, j); err != nil {
		t.Fatalf("CreateLifecycleJob: %v", err)
	}

	// Duplicate.
	err := s.CreateLifecycleJob(ctx, j)
	if !errors.Is(err, repository.ErrConflict) {
		t.Errorf("CreateLifecycleJob(duplicate) error = %v, want ErrConflict", err)
	}

	// Claim.
	claimed, err := s.ClaimLifecycleJob(ctx, "worker-1", 30*time.Second)
	if err != nil {
		t.Fatalf("ClaimLifecycleJob: %v", err)
	}
	if claimed.ID != "job-1" {
		t.Errorf("Claimed ID = %s, want job-1", claimed.ID)
	}
	if claimed.Status != "RUNNING" {
		t.Errorf("Status = %s, want RUNNING", claimed.Status)
	}
	if claimed.LeaseOwner != "worker-1" {
		t.Errorf("LeaseOwner = %s, want worker-1", claimed.LeaseOwner)
	}
	if claimed.Attempt != 1 {
		t.Errorf("Attempt = %d, want 1", claimed.Attempt)
	}

	// No more jobs to claim.
	_, err = s.ClaimLifecycleJob(ctx, "worker-2", 30*time.Second)
	if !errors.Is(err, repository.ErrNotFound) {
		t.Errorf("ClaimLifecycleJob(empty) error = %v, want ErrNotFound", err)
	}

	// Complete.
	if err := s.CompleteLifecycleJob(ctx, "job-1"); err != nil {
		t.Fatalf("CompleteLifecycleJob: %v", err)
	}
	got, _ := s.GetLifecycleJob(ctx, "job-1")
	if got.Status != "DONE" {
		t.Errorf("Status after complete = %s, want DONE", got.Status)
	}

	// Complete nonexistent.
	err = s.CompleteLifecycleJob(ctx, "nonexistent")
	if !errors.Is(err, repository.ErrNotFound) {
		t.Errorf("CompleteLifecycleJob(nonexistent) error = %v, want ErrNotFound", err)
	}
}

func TestLifecycleJobFailAndRetry(t *testing.T) {
	ctx := context.Background()
	s := newTestStore()

	j := &models.LifecycleJob{
		ID:        "job-2",
		Type:      "cache_invalidate",
		Status:    "PENDING",
		NextRunAt: func() *time.Time { t := time.Now().Add(-1 * time.Minute); return &t }(),
	}
	_ = s.CreateLifecycleJob(ctx, j)
	_, _ = s.ClaimLifecycleJob(ctx, "worker-1", 30*time.Second)

	// Fail with backoff.
	if err := s.FailLifecycleJob(ctx, "job-2", 5*time.Minute); err != nil {
		t.Fatalf("FailLifecycleJob: %v", err)
	}
	got, _ := s.GetLifecycleJob(ctx, "job-2")
	if got.Status != "PENDING" {
		t.Errorf("Status after fail = %s, want PENDING", got.Status)
	}
	if got.LeaseOwner != "" {
		t.Errorf("LeaseOwner after fail = %s, want empty", got.LeaseOwner)
	}
}

func TestOutboxEventClaimAndComplete(t *testing.T) {
	ctx := context.Background()
	s := newTestStore()

	e := &models.OutboxEvent{
		ID:        "evt-1",
		EventType: "key.rotated",
		Status:    "PENDING",
	}
	if err := s.CreateOutboxEvent(ctx, e); err != nil {
		t.Fatalf("CreateOutboxEvent: %v", err)
	}

	// Claim.
	claimed, err := s.ClaimOutboxEvent(ctx)
	if err != nil {
		t.Fatalf("ClaimOutboxEvent: %v", err)
	}
	if claimed.ID != "evt-1" {
		t.Errorf("Claimed ID = %s, want evt-1", claimed.ID)
	}
	if claimed.Attempts != 1 {
		t.Errorf("Attempts = %d, want 1", claimed.Attempts)
	}

	// Complete the event.
	if err := s.CompleteOutboxEvent(ctx, "evt-1"); err != nil {
		t.Fatalf("CompleteOutboxEvent: %v", err)
	}
	events, _ := s.ListOutboxEvents(ctx, "", 10)
	if events[0].Status != "SENT" {
		t.Errorf("Status after complete = %s, want SENT", events[0].Status)
	}

	// No more PENDING events.
	_, err = s.ClaimOutboxEvent(ctx)
	if !errors.Is(err, repository.ErrNotFound) {
		t.Errorf("ClaimOutboxEvent(empty) error = %v, want ErrNotFound", err)
	}

	// Complete nonexistent.
	err = s.CompleteOutboxEvent(ctx, "nonexistent")
	if !errors.Is(err, repository.ErrNotFound) {
		t.Errorf("CompleteOutboxEvent(nonexistent) error = %v, want ErrNotFound", err)
	}
}

// --- DEK Leases ---

func TestDEKLeaseRevoke(t *testing.T) {
	ctx := context.Background()
	s := newTestStore()

	l := &models.DEKLease{
		LeaseID:      "lease-1",
		KeyVersionID: "kv-1",
		NodeID:       "node-1",
		TenantID:     "t-1",
		ExpiresAt:    time.Now().Add(1 * time.Hour),
	}
	if err := s.CreateDEKLease(ctx, l); err != nil {
		t.Fatalf("CreateDEKLease: %v", err)
	}

	// Revoke by node.
	n, err := s.RevokeDEKLeasesByNode(ctx, "node-1")
	if err != nil {
		t.Fatalf("RevokeDEKLeasesByNode: %v", err)
	}
	if n != 1 {
		t.Errorf("Revoked = %d, want 1", n)
	}

	// Revoke individual (already revoked, should still return not found for nonexistent).
	err = s.RevokeDEKLease(ctx, "nonexistent")
	if !errors.Is(err, repository.ErrNotFound) {
		t.Errorf("RevokeDEKLease(nonexistent) error = %v, want ErrNotFound", err)
	}
}

// --- Close ---

func TestCloseIsNoOp(t *testing.T) {
	s := newTestStore()
	if err := s.Close(); err != nil {
		t.Errorf("Close() error = %v", err)
	}
}

// --- Interface compliance ---

func TestStoreImplementsRepository(t *testing.T) {
	var _ repository.Repository = (*Store)(nil)
}
