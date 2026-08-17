package access

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func fixedToken(value byte) string {
	return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{value}, TokenBytes))
}

func TestVerifierAuthenticatesOnlyFixedPlaneTokens(t *testing.T) {
	dataToken, opsToken := fixedToken(1), fixedToken(2)
	verifier, err := NewVerifier("t-default", dataToken, opsToken)
	if err != nil {
		t.Fatal(err)
	}
	data := verifier.Authenticate(dataToken)
	ops := verifier.Authenticate(opsToken)
	if data == nil || data.Plane != "data" || !data.HasScope("ccsds:tc:protect") || data.HasScope("ops:read") {
		t.Fatalf("data principal=%+v", data)
	}
	if ops == nil || ops.Plane != "ops" || !ops.HasScope("ops:read") || ops.HasScope("ccsds:tc:protect") {
		t.Fatalf("ops principal=%+v", ops)
	}
	data.Scopes[0] = "mutated"
	if again := verifier.Authenticate(dataToken); again == nil || !again.HasScope("ccsds:tc:protect") {
		t.Fatal("caller mutated verifier principal template")
	}
	for _, invalid := range []string{"", "short", strings.Repeat("A", 44), fixedToken(3)} {
		if verifier.Authenticate(invalid) != nil {
			t.Fatalf("invalid token authenticated: length=%d", len(invalid))
		}
	}
}

func TestVerifierConstructorsRejectInvalidInputs(t *testing.T) {
	valid := fixedToken(1)
	for _, test := range []struct {
		tenant, data, ops string
	}{
		{"", valid, fixedToken(2)},
		{"t-default", "short", fixedToken(2)},
		{"t-default", valid, "short"},
		{"t-default", valid, valid},
	} {
		if _, err := NewVerifier(test.tenant, test.data, test.ops); err == nil {
			t.Fatalf("invalid verifier input accepted: %+v", test)
		}
	}
	var nilVerifier *Verifier
	if nilVerifier.TenantID() != "" || nilVerifier.Authenticate(valid) != nil {
		t.Fatal("nil verifier did not fail closed")
	}
}

func TestParseVerifierRejectsNonCanonicalOrLegacyDocuments(t *testing.T) {
	dataHash := sha256.Sum256([]byte(fixedToken(1)))
	opsHash := sha256.Sum256([]byte(fixedToken(2)))
	valid := `{"tenant_id":"t-default","data_token_sha256":"` + hex.EncodeToString(dataHash[:]) + `","ops_token_sha256":"` + hex.EncodeToString(opsHash[:]) + `"}`
	if verifier, err := ParseVerifier([]byte(valid)); err != nil || verifier.TenantID() != "t-default" {
		t.Fatalf("valid verifier rejected: %v", err)
	}
	invalid := []string{
		`not-json`,
		`{"tenant_id":"t-default","data_token_sha256":"` + strings.ToUpper(hex.EncodeToString(dataHash[:])) + `","ops_token_sha256":"` + hex.EncodeToString(opsHash[:]) + `"}`,
		`{"tenant_id":"bad tenant","data_token_sha256":"` + hex.EncodeToString(dataHash[:]) + `","ops_token_sha256":"` + hex.EncodeToString(opsHash[:]) + `"}`,
		`{"tenant_id":"t-default","data_token_sha256":"` + hex.EncodeToString(dataHash[:]) + `","ops_token_sha256":"` + hex.EncodeToString(dataHash[:]) + `"}`,
		`{"tenant_id":"t-default","data_token_sha256":"` + hex.EncodeToString(dataHash[:]) + `","ops_token_sha256":"` + hex.EncodeToString(opsHash[:]) + `","token":"legacy"}`,
		valid + `{}`,
		`{"tenant_id":"t-default","data_token_sha256":"` + strings.Repeat("0", 64) + `","ops_token_sha256":"` + hex.EncodeToString(opsHash[:]) + `"}`,
	}
	for _, raw := range invalid {
		if _, err := ParseVerifier([]byte(raw)); err == nil {
			t.Fatalf("invalid verifier accepted: %s", raw)
		}
	}
}

func TestLoadVerifierAndTokenValidationFailures(t *testing.T) {
	if _, err := LoadVerifier(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing verifier file accepted")
	}
	if ValidateToken(fixedToken(1)) != nil {
		t.Fatal("valid token rejected")
	}
	for _, token := range []string{"", strings.Repeat("A", 42), strings.Repeat("!", 43), strings.Repeat("A", 44)} {
		if ValidateToken(token) == nil {
			t.Fatalf("invalid token accepted: length=%d", len(token))
		}
	}
}

func TestGeneratedBundleWritesControlledFilesAndRefusesOverwrite(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "credentials")
	bundle, err := GenerateBundle("t-default")
	if err != nil {
		t.Fatal(err)
	}
	if err := bundle.Write(directory); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{DataTokenFile, OpsTokenFile, VerifierFile} {
		info, err := os.Stat(filepath.Join(directory, name))
		if err != nil || !info.Mode().IsRegular() {
			t.Fatalf("%s: %v", name, err)
		}
		if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
			t.Fatalf("%s permissions=%o", name, info.Mode().Perm())
		}
	}
	dataRaw, _ := os.ReadFile(filepath.Join(directory, DataTokenFile))
	opsRaw, _ := os.ReadFile(filepath.Join(directory, OpsTokenFile))
	verifierRaw, _ := os.ReadFile(filepath.Join(directory, VerifierFile))
	if bytes.Contains(verifierRaw, bytes.TrimSpace(dataRaw)) || bytes.Contains(verifierRaw, bytes.TrimSpace(opsRaw)) {
		t.Fatal("server verifier document disclosed a bearer token")
	}
	verifier, err := LoadVerifier(filepath.Join(directory, VerifierFile))
	if err != nil || verifier.Authenticate(strings.TrimSpace(string(dataRaw))) == nil || verifier.Authenticate(strings.TrimSpace(string(opsRaw))) == nil {
		t.Fatalf("generated bundle unusable: %v", err)
	}
	if err := bundle.Write(directory); err == nil {
		t.Fatal("existing credential files were overwritten")
	}
}

func TestVerifierRotationHasNoGraceWindow(t *testing.T) {
	oldVerifier, err := NewVerifier("t-default", fixedToken(1), fixedToken(2))
	if err != nil {
		t.Fatal(err)
	}
	newVerifier, err := NewVerifier("t-default", fixedToken(3), fixedToken(4))
	if err != nil {
		t.Fatal(err)
	}
	if oldVerifier.Authenticate(fixedToken(3)) != nil || newVerifier.Authenticate(fixedToken(1)) != nil {
		t.Fatal("rotation unexpectedly accepted a previous or future token")
	}
}

func TestBundleRejectsInvalidInputsAndSymlinkDirectory(t *testing.T) {
	if _, err := GenerateBundle("bad tenant"); err == nil {
		t.Fatal("invalid tenant accepted")
	}
	if err := (*Bundle)(nil).Write(t.TempDir()); err == nil {
		t.Fatal("nil bundle accepted")
	}
	if err := (&Bundle{}).Write(""); err == nil {
		t.Fatal("invalid bundle accepted")
	}
	filePath := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(filePath, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	bundle, _ := GenerateBundle("t-default")
	if err := bundle.Write(filePath); err == nil {
		t.Fatal("regular output file accepted as a directory")
	}
	partial := t.TempDir()
	if err := os.WriteFile(filepath.Join(partial, OpsTokenFile), []byte("reserved"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := bundle.Write(partial); err == nil {
		t.Fatal("partial bundle conflict accepted")
	}
	if _, err := os.Stat(filepath.Join(partial, DataTokenFile)); !os.IsNotExist(err) {
		t.Fatal("failed bundle write did not remove its partial Data token")
	}
	if runtime.GOOS == "windows" {
		return
	}
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := bundle.Write(link); err == nil {
		t.Fatal("symlink output directory accepted")
	}
}

func TestRandomTokenUsesProvidedEntropySource(t *testing.T) {
	token, err := randomToken(bytes.NewReader(bytes.Repeat([]byte{7}, TokenBytes)))
	if err != nil || token != fixedToken(7) {
		t.Fatalf("token=%q err=%v", token, err)
	}
	if _, err := randomToken(strings.NewReader("short")); err == nil {
		t.Fatal("short entropy source accepted")
	}
}

func TestBundleGenerationFailsClosedOnEntropyErrorsAndDuplicates(t *testing.T) {
	if _, err := generateBundle("bad tenant", bytes.NewReader(nil)); err == nil {
		t.Fatal("invalid tenant accepted")
	}
	if _, err := generateBundle("t-default", strings.NewReader("short")); err == nil {
		t.Fatal("first token entropy failure accepted")
	}
	if _, err := generateBundle("t-default", bytes.NewReader(bytes.Repeat([]byte{1}, TokenBytes))); err == nil {
		t.Fatal("second token entropy failure accepted")
	}
	if _, err := generateBundle("t-default", bytes.NewReader(bytes.Repeat([]byte{1}, 2*TokenBytes))); err == nil {
		t.Fatal("duplicate generated tokens accepted")
	}
}

func TestTenantIDBoundaries(t *testing.T) {
	for _, valid := range []string{"a", "Tenant_01.example", strings.Repeat("a", 64)} {
		if !validTenantID(valid) {
			t.Fatalf("valid tenant rejected: %q", valid)
		}
	}
	for _, invalid := range []string{"", "bad tenant", "租户", strings.Repeat("a", 65)} {
		if validTenantID(invalid) {
			t.Fatalf("invalid tenant accepted: %q", invalid)
		}
	}
}

func TestCountersSnapshot(t *testing.T) {
	var counters Counters
	counters.RejectSourceIP()
	counters.RejectToken()
	counters.RejectPlane()
	counters.RejectRate()
	if got := counters.Snapshot(); got != (CounterSnapshot{1, 1, 1, 1}) {
		t.Fatalf("snapshot=%+v", got)
	}
	var nilCounters *Counters
	nilCounters.RejectToken()
	if nilCounters.Snapshot() != (CounterSnapshot{}) {
		t.Fatal("nil counters not zero")
	}
}
