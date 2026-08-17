package bootstrap

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/kvlt/key-vault/internal/config"
)

func TestLoadAccessVerifierReadsOnlyControlledFile(t *testing.T) {
	data := sha256.Sum256([]byte("data"))
	ops := sha256.Sum256([]byte("ops"))
	path := filepath.Join(t.TempDir(), "verifiers.json")
	raw := `{"tenant_id":"t-mission","data_token_sha256":"` + hex.EncodeToString(data[:]) + `","ops_token_sha256":"` + hex.EncodeToString(ops[:]) + `"}`
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Auth.TokenVerifiersFile = path
	verifier, err := loadAccessVerifier(cfg)
	if err != nil || verifier.TenantID() != "t-mission" {
		t.Fatalf("verifier=%v err=%v", verifier, err)
	}
}

func TestLoadAccessVerifierFailsClosedInProduction(t *testing.T) {
	cfg := config.Default()
	cfg.Environment = "production"
	if _, err := loadAccessVerifier(cfg); err == nil {
		t.Fatal("missing production verifier accepted")
	}
	cfg.Environment = "development"
	if verifier, err := loadAccessVerifier(cfg); err != nil || verifier != nil {
		t.Fatalf("development empty verifier=%v err=%v", verifier, err)
	}
}
