package bootstrap

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/kvlt/key-vault/internal/auth/principal"
	"github.com/kvlt/key-vault/internal/config"
)

func TestLoadAccessTokensUsesOneStrictPlanePerToken(t *testing.T) {
	t.Setenv("KVLT_ACCESS_TOKENS", `[
		{"token":"data-token-012345678901234567890123456789","tenant_id":"t-default","scopes":["ccsds:tc:protect","ccsds:aos:unprotect"],"plane":"data"},
		{"token":"ops-token-0123456789012345678901234567890","tenant_id":"t-default","scopes":["audit:read","ops:read"],"plane":"ops"}
	]`)
	tokens, err := loadAccessTokens(config.Default())
	if err != nil {
		t.Fatal(err)
	}
	if len(tokens) != 2 {
		t.Fatalf("token count = %d", len(tokens))
	}
	for token, identity := range tokens {
		if token[:4] == "data" && !identity.CanAccessPlane(principal.PlaneData) {
			t.Fatal("data token lost data plane")
		}
		if token[:3] == "ops" && !identity.CanAccessPlane(principal.PlaneOps) {
			t.Fatal("ops token lost ops plane")
		}
		if identity.AuthMethod != "access_token" {
			t.Fatalf("unexpected auth method %q", identity.AuthMethod)
		}
	}
}

func TestLoadAccessTokensRejectsLegacyOrWeakContracts(t *testing.T) {
	for _, raw := range []string{
		`[{"token":"short","tenant_id":"t-default","scopes":["ops:read"],"plane":"ops"}]`,
		`[{"token":"token-01234567890123456789012345678901","tenant_id":"t-default","scopes":["ops:read"],"plane":"management"}]`,
		`[{"token":"token-01234567890123456789012345678901","tenant_id":"t-default","scopes":["ops:read"],"planes":["data","ops"]}]`,
		`[{"token":"token-01234567890123456789012345678901","tenant_id":"t-default","scopes":["ops:read"],"plane":"ops"}] trailing`,
		`[{"token":"data-token-012345678901234567890123456789","tenant_id":"t-default","scopes":["ccsds:tc:protect","ccsds:aos:unprotect"],"plane":"data"},{"token":"data-token-112345678901234567890123456789","tenant_id":"t-default","scopes":["ccsds:tc:protect","ccsds:aos:unprotect"],"plane":"data"}]`,
		`[{"token":"data-token-012345678901234567890123456789","tenant_id":"t-default","scopes":["ops:read"],"plane":"data"},{"token":"ops-token-0123456789012345678901234567890","tenant_id":"t-default","scopes":["audit:read","ops:read"],"plane":"ops"}]`,
	} {
		t.Setenv("KVLT_ACCESS_TOKENS", raw)
		if _, err := loadAccessTokens(config.Default()); err == nil {
			t.Fatalf("obsolete access contract accepted: %s", raw)
		}
	}
}

func TestLoadAccessTokensReadsControlledFile(t *testing.T) {
	t.Setenv("KVLT_ACCESS_TOKENS", "")
	path := filepath.Join(t.TempDir(), "tokens.json")
	if err := os.WriteFile(path, []byte(`[
		{"token":"data-token-012345678901234567890123456789","tenant_id":"t-default","scopes":["ccsds:tc:protect","ccsds:aos:unprotect"],"plane":"data"},
		{"token":"ops-token-0123456789012345678901234567890","tenant_id":"t-default","scopes":["audit:read","ops:read"],"plane":"ops"}
	]`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Auth.AccessTokensFile = path
	tokens, err := loadAccessTokens(cfg)
	if err != nil || len(tokens) != 2 {
		t.Fatalf("tokens=%v err=%v", tokens, err)
	}
}

func TestLoadAccessTokensRequiresLongProductionSecrets(t *testing.T) {
	t.Setenv("KVLT_ACCESS_TOKENS", `[
		{"token":"data-token-012345678901234567890123456789","tenant_id":"t-default","scopes":["ccsds:tc:protect","ccsds:aos:unprotect"],"plane":"data"},
		{"token":"ops-token-0123456789012345678901234567890","tenant_id":"t-default","scopes":["audit:read","ops:read"],"plane":"ops"}
	]`)
	cfg := config.Default()
	cfg.Environment = "production"
	if _, err := loadAccessTokens(cfg); err == nil {
		t.Fatal("short example production tokens were accepted")
	}
}
