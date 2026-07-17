package provider

import (
	"bytes"
	"context"
	"testing"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/kvlt/key-vault/internal/crypto/aad"
)

func testPolicyContext() aad.CRKAAD {
	return aad.CRKAAD{ClusterID: "cluster-a", NodeID: "node-a", PlaneRole: "management", CRKVersion: 1,
		NRWKName: "nrwk-a", BaselineDigest: bytes.Repeat([]byte{1}, 32), PolicyDigest: bytes.Repeat([]byte{2}, 32)}
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
	nrwk, err := p.EnsureNRWK(ctx, a.NRWKName)
	if err != nil {
		t.Fatal(err)
	}
	secret := bytes.Repeat([]byte{0x5a}, 32)
	env, err := p.SealCRK(ctx, nrwk, secret, a)
	if err != nil {
		t.Fatal(err)
	}
	got, err := p.UnsealCRK(ctx, nrwk, env, a)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatal("unsealed CRK mismatch")
	}
	if err := sim.Reset(); err != nil {
		t.Fatal(err)
	}
	got, err = p.UnsealCRK(ctx, nrwk, env, a)
	if err != nil {
		t.Fatalf("unseal after restart: %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatal("restart CRK mismatch")
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
	nrwk, _ := p.EnsureNRWK(context.Background(), a.NRWKName)
	env, err := p.SealCRK(context.Background(), nrwk, []byte("secret"), a)
	if err != nil {
		t.Fatal(err)
	}
	wrong := a
	wrong.PolicyDigest = bytes.Repeat([]byte{9}, 32)
	if _, err := p.UnsealCRK(context.Background(), nrwk, env, wrong); err == nil {
		t.Fatal("wrong policy context accepted")
	}
	env.WrappedCRK[0] ^= 0xff
	if _, err := p.UnsealCRK(context.Background(), nrwk, env, a); err == nil {
		t.Fatal("corrupt envelope accepted")
	}
}

func TestNativeProviderRejectsIncompletePolicyContext(t *testing.T) {
	p := &NativeProvider{}
	if err := validateNativeInputs(context.Background(), &TPMObjectRef{Name: "n"}, aad.CRKAAD{}); err == nil {
		t.Fatal("incomplete context accepted")
	}
	_ = p
}
