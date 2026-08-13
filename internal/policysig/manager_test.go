package policysig

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"testing"
	"time"

	"github.com/kvlt/key-vault/internal/domain/policy"
)

func TestLoadSignedUpdatesSharedVersionedEngine(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	engine := policy.NewEngine()
	manager := New(engine, nil)
	manager.AddSigningKey("test-key", pub)

	v1, err := GenerateDefaultSignedPolicy(priv, "test-key")
	if err != nil {
		t.Fatalf("GenerateDefaultSignedPolicy: %v", err)
	}
	if err := manager.LoadSigned(context.Background(), v1); err != nil {
		t.Fatalf("LoadSigned(v1): %v", err)
	}

	stableEngine := manager.Engine()
	v2 := cloneSignedPolicy(v1)
	v2.Version = 2
	v2.EffectiveAt = time.Now().UTC().Add(-time.Second)
	for i := range v2.Suites {
		if v2.Suites[i].SuiteID == "SM4_GCM" {
			v2.Suites[i].Status = policy.SuiteStatusDisabled
		}
	}
	signPolicyForTest(t, v2, priv, "test-key")
	if err := manager.LoadSigned(context.Background(), v2); err != nil {
		t.Fatalf("LoadSigned(v2): %v", err)
	}

	if manager.Engine() != stableEngine || stableEngine != engine {
		t.Fatal("policy reload replaced the Engine pointer")
	}
	current, err := engine.Get(v2.PolicyID)
	if err != nil {
		t.Fatalf("Get current: %v", err)
	}
	if current.Version != 2 {
		t.Fatalf("current version = %d, want 2", current.Version)
	}
	if _, err := engine.GetVersion(v1.PolicyID, 1); err != nil {
		t.Fatalf("historical version missing after reload: %v", err)
	}

	// Manager owns the accepted package rather than exposing caller-owned data.
	v2.Version = 99
	if got := manager.Current().Version; got != 2 {
		t.Fatalf("manager current version mutated through caller input: %d", got)
	}
}

func TestLoadSignedSemanticFailureKeepsLastValidVersion(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	engine := policy.NewEngine()
	manager := New(engine, nil)
	manager.AddSigningKey("test-key", pub)

	v1, err := GenerateDefaultSignedPolicy(priv, "test-key")
	if err != nil {
		t.Fatalf("GenerateDefaultSignedPolicy: %v", err)
	}
	if err := manager.LoadSigned(context.Background(), v1); err != nil {
		t.Fatalf("LoadSigned(v1): %v", err)
	}

	invalid := cloneSignedPolicy(v1)
	invalid.Version = 2
	invalid.EffectiveAt = time.Now().UTC().Add(-time.Second)
	for i := range invalid.Suites {
		if invalid.Suites[i].SuiteID == invalid.DefaultSuite {
			invalid.Suites[i].Status = policy.SuiteStatusBlocked
		}
	}
	signPolicyForTest(t, invalid, priv, "test-key")
	if err := manager.LoadSigned(context.Background(), invalid); err == nil {
		t.Fatal("LoadSigned accepted a blocked default suite")
	}

	current, err := engine.Get(v1.PolicyID)
	if err != nil {
		t.Fatalf("Get current: %v", err)
	}
	if current.Version != 1 || manager.Current().Version != 1 {
		t.Fatalf("failed load changed current version: engine=%d manager=%d", current.Version, manager.Current().Version)
	}
	if _, err := engine.GetVersion(v1.PolicyID, 2); err == nil {
		t.Fatal("failed signed policy remained in the catalog")
	}
}

func TestLoadSignedRejectsRollbackAndSameVersionMutation(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	manager := New(policy.NewEngine(), nil)
	manager.AddSigningKey("test-key", pub)
	v1, err := GenerateDefaultSignedPolicy(priv, "test-key")
	if err != nil {
		t.Fatal(err)
	}
	v2 := cloneSignedPolicy(v1)
	v2.Version = 2
	v2.EffectiveAt = time.Now().UTC().Add(-time.Second)
	signPolicyForTest(t, v2, priv, "test-key")
	if err := manager.LoadSigned(context.Background(), v2); err != nil {
		t.Fatalf("LoadSigned(v2): %v", err)
	}
	if err := manager.LoadSigned(context.Background(), v1); err == nil {
		t.Fatal("signed policy rollback was accepted")
	}
	mutated := cloneSignedPolicy(v2)
	mutated.Suites[1].Status = policy.SuiteStatusDisabled
	signPolicyForTest(t, mutated, priv, "test-key")
	if err := manager.LoadSigned(context.Background(), mutated); err == nil {
		t.Fatal("same policy version with different content was accepted")
	}
}

func signPolicyForTest(t *testing.T, sp *SignedPolicy, priv ed25519.PrivateKey, keyID string) {
	t.Helper()
	payloadHash, canonical, err := canonicalPolicyPayload(sp)
	if err != nil {
		t.Fatalf("canonicalPolicyPayload: %v", err)
	}
	sp.Signature = PolicySignature{
		Alg:         "Ed25519",
		KeyID:       keyID,
		Sig:         hex.EncodeToString(ed25519.Sign(priv, canonical)),
		PayloadHash: payloadHash,
	}
}
