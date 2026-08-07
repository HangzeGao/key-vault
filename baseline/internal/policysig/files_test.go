package policysig

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/kvlt/key-vault/internal/domain/policy"
)

func TestPersistentTrustBundleVerifiesSignedPolicy(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := GenerateDefaultSignedPolicy(privateKey, "root-2026")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	trustPath := filepath.Join(dir, "trust.json")
	policyPath := filepath.Join(dir, "policy.json")
	writeJSONFile(t, trustPath, TrustBundle{Keys: []TrustBundleKey{{
		KeyID: "root-2026", Alg: "Ed25519",
		PublicKeyB64: base64.StdEncoding.EncodeToString(publicKey), Status: "active",
	}}})
	writeJSONFile(t, policyPath, signed)

	bundle, err := LoadTrustBundle(trustPath)
	if err != nil {
		t.Fatalf("LoadTrustBundle: %v", err)
	}
	loaded, err := LoadSignedPolicy(policyPath)
	if err != nil {
		t.Fatalf("LoadSignedPolicy: %v", err)
	}
	engine := policy.NewEngine()
	manager := New(engine, nil)
	if err := InstallTrustBundle(manager, bundle); err != nil {
		t.Fatalf("InstallTrustBundle: %v", err)
	}
	if err := manager.LoadSigned(context.Background(), loaded); err != nil {
		t.Fatalf("LoadSigned: %v", err)
	}
	if current, err := engine.Get(loaded.PolicyID); err != nil || current.Version != loaded.Version {
		t.Fatalf("persistent policy was not activated: policy=%v err=%v", current, err)
	}
}

func TestTrustBundleRejectsUnknownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trust.json")
	if err := os.WriteFile(path, []byte(`{"keys":[],"private_key":"forbidden"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadTrustBundle(path); err == nil {
		t.Fatal("trust bundle accepted an unknown private-key field")
	}
}

func writeJSONFile(t *testing.T, path string, value any) {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
}
