//go:build !windows

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProductionRejectsPermissiveSecretFile(t *testing.T) {
	cfg := productionConfig(t)
	if err := os.Chmod(cfg.Auth.TokenVerifiersFile, 0o640); err != nil {
		t.Fatal(err)
	}
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "owner-only") {
		t.Fatalf("permissive secret file accepted: %v", err)
	}
}

func TestProductionRejectsSymlinkedSecretFile(t *testing.T) {
	cfg := productionConfig(t)
	link := filepath.Join(t.TempDir(), "tls-key-link")
	if err := os.Symlink(cfg.Server.TLSKeyFile, link); err != nil {
		t.Fatal(err)
	}
	cfg.Server.TLSKeyFile = link
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "non-symlink") {
		t.Fatalf("symlinked secret file accepted: %v", err)
	}
}
