package provider

import (
	"bytes"
	"context"
	"testing"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/kvlt/key-vault/internal/crypto/aad"
)

func testPolicyContext() aad.SealContext {
	return aad.SealContext{Purpose: "test", ObjectID: "object-a", NodeID: "node-a",
		StorageName: "seal-a", BaselineDigest: bytes.Repeat([]byte{1}, 32), PolicyDigest: bytes.Repeat([]byte{2}, 32)}
}

func TestNativeProviderSealUnsealAndRestart(t *testing.T) {
	sim, err := simulator.GetWithFixedSeedInsecure(42)
	if err != nil {
		t.Skipf("TPM simulator unavailable in this build: %v", err)
	}
	p, err := newNativeProviderWithTransport(sim, []int{7})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	ctx := context.Background()
	a := testPolicyContext()
	storage, err := p.EnsureStorage(ctx, a.StorageName)
	if err != nil {
		t.Fatal(err)
	}
	secret := bytes.Repeat([]byte{0x5a}, 32)
	env, err := p.Seal(ctx, storage, secret, a)
	if err != nil {
		t.Fatal(err)
	}
	got, err := p.Unseal(ctx, storage, env, a)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatal("unsealed secret mismatch")
	}
	if err := sim.Reset(); err != nil {
		t.Fatal(err)
	}
	got, err = p.Unseal(ctx, storage, env, a)
	if err != nil {
		t.Fatalf("unseal after restart: %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatal("restart secret mismatch")
	}
}

func TestNativeProviderRejectsWrongContextAndCorruption(t *testing.T) {
	sim, err := simulator.GetWithFixedSeedInsecure(43)
	if err != nil {
		t.Skipf("TPM simulator unavailable in this build: %v", err)
	}
	p, err := newNativeProviderWithTransport(sim, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	a := testPolicyContext()
	storage, _ := p.EnsureStorage(context.Background(), a.StorageName)
	env, err := p.Seal(context.Background(), storage, []byte("secret"), a)
	if err != nil {
		t.Fatal(err)
	}
	wrong := a
	wrong.PolicyDigest = bytes.Repeat([]byte{9}, 32)
	if _, err := p.Unseal(context.Background(), storage, env, wrong); err == nil {
		t.Fatal("wrong policy context accepted")
	}
	env.Blob[0] ^= 0xff
	if _, err := p.Unseal(context.Background(), storage, env, a); err == nil {
		t.Fatal("corrupt envelope accepted")
	}
}

func TestNativeProviderRejectsIncompletePolicyContext(t *testing.T) {
	p := &NativeProvider{}
	if err := validateNativeInputs(context.Background(), &TPMObjectRef{Name: "n"}, aad.SealContext{}); err == nil {
		t.Fatal("incomplete context accepted")
	}
	_ = p
}

func TestNativeContextPasswordFitsSHA256AuthValue(t *testing.T) {
	password, err := nativeContextPassword(testPolicyContext())
	if err != nil {
		t.Fatal(err)
	}
	if len(password) != 32 {
		t.Fatalf("native TPM auth length = %d, want 32", len(password))
	}
}
