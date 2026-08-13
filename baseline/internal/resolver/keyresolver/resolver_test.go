package keyresolver

import (
	"bytes"
	"context"
	"testing"

	"github.com/kvlt/key-vault/internal/crypto/suite"
	"github.com/kvlt/key-vault/internal/tpm/provider"
)

func TestDirectSealAndIssueKey(t *testing.T) {
	ctx := context.Background()
	tpm, err := provider.NewSoftwareProvider(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	resolver := New(tpm)
	if err := resolver.Init(ctx, "test-storage", "node-1", []byte("baseline"), []byte("policy")); err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{0x42}, suite.SM4GCM.KeyBytes())
	material, err := resolver.SealExternalKey(ctx, suite.SM4GCM, "kv-1", key)
	if err != nil {
		t.Fatal(err)
	}
	resolver.SetFetchHook(func(context.Context, string) ([]byte, error) {
		return material.SealedMaterial, nil
	})
	lease, err := resolver.IssueKey(ctx, "kv-1", "key-1", 1, suite.SM4GCM,
		"tenant-1", "encrypt_decrypt", "node-1")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(lease.Key, key) {
		t.Fatal("unsealed key mismatch")
	}
	lease.Key[0] ^= 0xff
	second, err := resolver.IssueKey(ctx, "kv-1", "key-1", 1, suite.SM4GCM,
		"tenant-1", "encrypt_decrypt", "node-1")
	if err != nil || !bytes.Equal(second.Key, key) {
		t.Fatalf("fresh unseal was affected by caller mutation: %v", err)
	}
}

func TestDirectSealRejectsIdentitySubstitution(t *testing.T) {
	ctx := context.Background()
	tpm, _ := provider.NewSoftwareProvider(t.TempDir())
	resolver := New(tpm)
	if err := resolver.Init(ctx, "test-storage", "node-1", []byte("baseline"), []byte("policy")); err != nil {
		t.Fatal(err)
	}
	material, err := resolver.SealExternalKey(ctx, suite.SM4GCM, "kv-1", make([]byte, 16))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.UnsealKey(ctx, material.SealedMaterial, "kv-2"); err == nil {
		t.Fatal("sealed root accepted under another key identity")
	}
}
