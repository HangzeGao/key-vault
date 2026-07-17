package keys

import (
	"context"
	"sort"
	"testing"
	"time"

	"github.com/kvlt/key-vault/internal/repository/memory"
	"github.com/kvlt/key-vault/internal/repository/models"
)

func TestSupportedPurpose(t *testing.T) {
	if !isSupportedPurpose(PurposeEncryptDecrypt) {
		t.Fatal("encrypt_decrypt must be supported")
	}
	for _, purpose := range []string{"signing", "datakey", ""} {
		if isSupportedPurpose(purpose) {
			t.Fatalf("purpose %q must be rejected", purpose)
		}
	}
}

func TestArchiveDestroyedKey(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	svc := New(store, nil, nil)
	createKeyForExpiryTest(t, store, &models.Key{
		ID:             "destroyed",
		TenantID:       "t-default",
		Name:           "destroyed",
		Purpose:        "encrypt_decrypt",
		PolicyID:       "policy-default",
		SuiteID:        "AES_256_GCM",
		CurrentVersion: 1,
		Status:         "DESTROYED",
	})

	dto, err := svc.ArchiveDestroyedKey(ctx, "t-default", "destroyed", "admin")
	if err != nil {
		t.Fatalf("ArchiveDestroyedKey: %v", err)
	}
	if dto.ArchivedAt == nil {
		t.Fatal("ArchivedAt is nil")
	}
	keys, err := svc.ListKeys(ctx, "t-default", false)
	if err != nil {
		t.Fatalf("ListKeys(default): %v", err)
	}
	if len(keys) != 0 {
		t.Fatalf("default ListKeys returned archived key: %d", len(keys))
	}
	keys, err = svc.ListKeys(ctx, "t-default", true)
	if err != nil {
		t.Fatalf("ListKeys(include archived): %v", err)
	}
	if len(keys) != 1 || keys[0].ArchivedAt == nil {
		t.Fatalf("include archived = %+v, want archived key", keys)
	}
}

func TestArchiveDestroyedKeyRejectsNonDestroyed(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	svc := New(store, nil, nil)
	createKeyForExpiryTest(t, store, &models.Key{
		ID:             "active",
		TenantID:       "t-default",
		Name:           "active",
		Purpose:        "encrypt_decrypt",
		PolicyID:       "policy-default",
		SuiteID:        "AES_256_GCM",
		CurrentVersion: 1,
		Status:         "ACTIVE",
	})
	if _, err := svc.ArchiveDestroyedKey(ctx, "t-default", "active", "admin"); err == nil {
		t.Fatal("ArchiveDestroyedKey accepted ACTIVE key")
	}
}

func TestReconcileDestroyDueJobsRepairsHistoricalPendingKey(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	svc := New(store, nil, nil)
	updatedAt := time.Now().UTC().Add(-25 * time.Hour)
	createKeyForExpiryTest(t, store, &models.Key{
		ID:             "pending-without-job",
		TenantID:       "t-default",
		Name:           "pending",
		Purpose:        "encrypt_decrypt",
		PolicyID:       "policy-default",
		SuiteID:        "AES_256_GCM",
		CurrentVersion: 1,
		Status:         "DESTROY_PENDING",
		UpdatedAt:      updatedAt,
	})

	if err := svc.ReconcileDestroyDueJobs(ctx); err != nil {
		t.Fatalf("ReconcileDestroyDueJobs: %v", err)
	}
	jobs, err := store.ListLifecycleJobs(ctx, "", 10)
	if err != nil {
		t.Fatalf("ListLifecycleJobs: %v", err)
	}
	if len(jobs) != 1 {
		t.Fatalf("jobs = %d, want 1", len(jobs))
	}
	if jobs[0].Type != "destroy_due" || jobs[0].KeyID != "pending-without-job" {
		t.Fatalf("job = %+v, want destroy_due for key", jobs[0])
	}
	if jobs[0].NextRunAt == nil || jobs[0].NextRunAt.After(time.Now().UTC()) {
		t.Fatalf("next_run_at = %v, want due job", jobs[0].NextRunAt)
	}
}

func TestReconcileDestroyDueJobsDoesNotBypassFailedJob(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	svc := New(store, nil, nil)
	createKeyForExpiryTest(t, store, &models.Key{
		ID:             "pending-with-failed-job",
		TenantID:       "t-default",
		Name:           "pending",
		Purpose:        "encrypt_decrypt",
		PolicyID:       "policy-default",
		SuiteID:        "AES_256_GCM",
		CurrentVersion: 1,
		Status:         "DESTROY_PENDING",
		UpdatedAt:      time.Now().UTC().Add(-25 * time.Hour),
	})
	if err := store.CreateLifecycleJob(ctx, &models.LifecycleJob{
		ID:     "failed-destroy",
		Type:   "destroy_due",
		KeyID:  "pending-with-failed-job",
		Status: "FAILED",
	}); err != nil {
		t.Fatalf("CreateLifecycleJob: %v", err)
	}

	if err := svc.ReconcileDestroyDueJobs(ctx); err != nil {
		t.Fatalf("ReconcileDestroyDueJobs: %v", err)
	}
	jobs, err := store.ListLifecycleJobs(ctx, "", 10)
	if err != nil {
		t.Fatalf("ListLifecycleJobs: %v", err)
	}
	if len(jobs) != 1 {
		t.Fatalf("jobs = %d, want only the failed job", len(jobs))
	}
}

func TestCheckExpiryReturnsExpiredAndApproachingKeys(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	svc := New(store, nil, nil)
	now := time.Now().UTC()

	createKeyForExpiryTest(t, store, &models.Key{
		ID:             "expired",
		TenantID:       "t-default",
		Name:           "expired",
		Purpose:        "encrypt_decrypt",
		PolicyID:       "policy-default",
		SuiteID:        "AES_256_GCM",
		CurrentVersion: 1,
		Status:         "ACTIVE",
		ExpiresAt:      now.Add(-time.Hour),
	})
	createKeyForExpiryTest(t, store, &models.Key{
		ID:             "approaching",
		TenantID:       "t-default",
		Name:           "approaching",
		Purpose:        "encrypt_decrypt",
		PolicyID:       "policy-default",
		SuiteID:        "AES_256_GCM",
		CurrentVersion: 1,
		Status:         "ACTIVE",
		ExpiresAt:      now.Add(2 * time.Hour),
	})
	createKeyForExpiryTest(t, store, &models.Key{
		ID:             "outside-window",
		TenantID:       "t-default",
		Name:           "outside-window",
		Purpose:        "encrypt_decrypt",
		PolicyID:       "policy-default",
		SuiteID:        "AES_256_GCM",
		CurrentVersion: 1,
		Status:         "ACTIVE",
		ExpiresAt:      now.Add(48 * time.Hour),
	})
	createKeyForExpiryTest(t, store, &models.Key{
		ID:             "disabled-expired",
		TenantID:       "t-default",
		Name:           "disabled-expired",
		Purpose:        "encrypt_decrypt",
		PolicyID:       "policy-default",
		SuiteID:        "AES_256_GCM",
		CurrentVersion: 1,
		Status:         "DISABLED",
		ExpiresAt:      now.Add(-time.Hour),
	})
	createKeyForExpiryTest(t, store, &models.Key{
		ID:             "never-expires",
		TenantID:       "t-default",
		Name:           "never-expires",
		Purpose:        "encrypt_decrypt",
		PolicyID:       "policy-default",
		SuiteID:        "AES_256_GCM",
		CurrentVersion: 1,
		Status:         "ACTIVE",
	})

	candidates, err := svc.CheckExpiry(ctx, 24*time.Hour)
	if err != nil {
		t.Fatalf("CheckExpiry: %v", err)
	}
	got := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		got = append(got, candidate.KeyID)
	}
	sort.Strings(got)
	want := []string{"approaching", "expired"}
	if len(got) != len(want) {
		t.Fatalf("candidate ids = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("candidate ids = %v, want %v", got, want)
		}
	}
}

func createKeyForExpiryTest(t *testing.T, store *memory.Store, key *models.Key) {
	t.Helper()
	err := store.CreateKey(context.Background(), key, &models.KeyVersion{
		ID:           key.ID + "-v1",
		KeyID:        key.ID,
		VersionNo:    key.CurrentVersion,
		SuiteID:      key.SuiteID,
		WrappedDEK:   []byte("wrapped"),
		WrapMetadata: []byte(`{"alg":"test"}`),
		Status:       "ACTIVE",
	})
	if err != nil {
		t.Fatalf("CreateKey(%s): %v", key.ID, err)
	}
}
