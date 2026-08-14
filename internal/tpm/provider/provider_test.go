package provider

import (
	"context"
	"testing"

	"github.com/kvlt/key-vault/internal/crypto/aad"
)

func TestSoftwareProviderSealedObjectContext(t *testing.T) {
	ctx := context.Background()
	p, err := NewSoftwareProvider(t.TempDir())
	if err != nil {
		t.Fatalf("NewSoftwareProvider: %v", err)
	}
	storage, err := p.EnsureStorage(ctx, "seal-test")
	if err != nil {
		t.Fatalf("EnsureStorage: %v", err)
	}
	a := aad.SealContext{
		Purpose:        "test",
		ObjectID:       "object-a",
		NodeID:         "node-a",
		StorageName:    "seal-test",
		BaselineDigest: []byte{0x01},
		PolicyDigest:   []byte{0x02},
	}
	env, err := p.Seal(ctx, storage, []byte("01234567890123456789012345678901"), a)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if env.ContextDigest == "" {
		t.Fatal("ContextDigest is empty")
	}
	if _, err := p.Unseal(ctx, storage, env, a); err != nil {
		t.Fatalf("Unseal: %v", err)
	}
	wrong := a
	wrong.NodeID = "node-b"
	if _, err := p.Unseal(ctx, storage, env, wrong); err == nil {
		t.Fatal("expected AAD mismatch")
	}
}
