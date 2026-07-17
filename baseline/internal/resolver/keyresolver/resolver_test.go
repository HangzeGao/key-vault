package keyresolver

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/kvlt/key-vault/internal/crypto/aad"
	"github.com/kvlt/key-vault/internal/crypto/aead"
	"github.com/kvlt/key-vault/internal/tpm/provider"
)

func TestIssueDEKLeaseCacheDoesNotShareReturnedDEK(t *testing.T) {
	ctx := context.Background()
	r := newTestResolver(t, ctx)

	material, err := r.GenerateAndWrapDEK(ctx, aead.SuiteAES256GCM, "kv-1")
	if err != nil {
		t.Fatalf("GenerateAndWrapDEK: %v", err)
	}
	r.SetFetchDEKHook(func(context.Context, string) ([]byte, []byte, error) {
		return material.WrappedDEK, material.WrapMetadata, nil
	})

	first, err := r.IssueDEKLease(ctx, "kv-1", "key-1", 1, aead.SuiteAES256GCM, "tenant-1", "batch-encrypt", "node-1")
	if err != nil {
		t.Fatalf("IssueDEKLease first: %v", err)
	}
	originalDEK := append([]byte(nil), first.DEK...)

	zeroize(first.DEK)

	second, err := r.IssueDEKLease(ctx, "kv-1", "key-1", 1, aead.SuiteAES256GCM, "tenant-1", "batch-encrypt", "node-1")
	if err != nil {
		t.Fatalf("IssueDEKLease second: %v", err)
	}
	if allZero(second.DEK) {
		t.Fatal("cached lease returned a zeroized DEK")
	}
	if !bytes.Equal(second.DEK, originalDEK) {
		t.Fatal("cached lease returned different DEK material")
	}
	if first.LeaseID == second.LeaseID {
		t.Fatal("cached lease reuse should return a fresh lease id")
	}

	second.DEK[0] ^= 0xff
	third, err := r.IssueDEKLease(ctx, "kv-1", "key-1", 1, aead.SuiteAES256GCM, "tenant-1", "batch-encrypt", "node-1")
	if err != nil {
		t.Fatalf("IssueDEKLease third: %v", err)
	}
	if !bytes.Equal(third.DEK, originalDEK) {
		t.Fatal("mutating a returned cached lease changed the cache")
	}
}

func TestFetchDEKHookIsResolverScoped(t *testing.T) {
	ctx := context.Background()
	r1 := New(nil, "", time.Minute)
	r2 := New(nil, "", time.Minute)
	r1.SetFetchDEKHook(func(context.Context, string) ([]byte, []byte, error) {
		return []byte("wrapped"), []byte("meta"), nil
	})

	wrapped, meta, err := r1.fetchWrappedDEK(ctx, "kv-1")
	if err != nil {
		t.Fatalf("r1 fetchWrappedDEK: %v", err)
	}
	if string(wrapped) != "wrapped" || string(meta) != "meta" {
		t.Fatal("r1 fetchWrappedDEK returned unexpected material")
	}
	if _, _, err := r2.fetchWrappedDEK(ctx, "kv-1"); err == nil {
		t.Fatal("r2 fetchWrappedDEK succeeded without a hook")
	}
}

func newTestResolver(t *testing.T, ctx context.Context) *Resolver {
	t.Helper()

	p, err := provider.NewSoftwareProvider(t.TempDir())
	if err != nil {
		t.Fatalf("NewSoftwareProvider: %v", err)
	}
	r := New(p, "test-nrwk", time.Minute)
	baselineDigest := []byte("baseline")
	policyDigest := []byte("policy")
	if err := r.Init(ctx, "cluster-1", "node-1", "data", baselineDigest, policyDigest); err != nil {
		t.Fatalf("Init: %v", err)
	}
	nrwk, err := p.EnsureNRWK(ctx, "test-nrwk")
	if err != nil {
		t.Fatalf("EnsureNRWK: %v", err)
	}
	crk := bytes.Repeat([]byte{0x42}, 32)
	env, err := p.SealCRK(ctx, nrwk, crk, aad.CRKAAD{
		ClusterID:      "cluster-1",
		NodeID:         "node-1",
		PlaneRole:      "data",
		CRKVersion:     1,
		NRWKName:       "test-nrwk",
		BaselineDigest: baselineDigest,
		PolicyDigest:   policyDigest,
	})
	if err != nil {
		t.Fatalf("SealCRK: %v", err)
	}
	r.SetCRKEnvelope(env)
	return r
}

func allZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}
