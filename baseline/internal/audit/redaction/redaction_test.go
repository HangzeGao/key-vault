package redaction

import (
	"strings"
	"testing"
)

func TestMaybeRedactJSONRecurses(t *testing.T) {
	out, err := MaybeRedactJSON(map[string]any{"safe": "ok", "nested": []any{map[string]any{"token": "bearer-secret", "wrapped_crk": "blob", "plaintext": "hello"}}})
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	for _, secret := range []string{"bearer-secret", "blob", "hello"} {
		if strings.Contains(s, secret) {
			t.Fatalf("secret %q leaked in %s", secret, s)
		}
	}
	if !strings.Contains(s, `"safe":"ok"`) {
		t.Fatalf("safe field removed: %s", s)
	}
}

func TestSensitiveKeyExactMatches(t *testing.T) {
	sensitive := []string{
		"token", "password", "secret", "plaintext", "dek", "crk",
		"ciphertext", "envelope", "private_key", "key_bytes",
		"access_token", "refresh_token", "auth_token", "csrf_token",
		"api_key", "wrapped_envelope",
	}
	for _, key := range sensitive {
		if !sensitiveKey(key) {
			t.Errorf("expected %q to be sensitive", key)
		}
	}
}

func TestSensitiveKeySuffixMatches(t *testing.T) {
	sensitive := []string{
		"user_password", "api_secret", "data_plaintext",
		"tenant_dek", "root_crk", "auth_token",
	}
	for _, key := range sensitive {
		if !sensitiveKey(key) {
			t.Errorf("expected %q to be sensitive via suffix match", key)
		}
	}
}

func TestSensitiveKeyNonSensitive(t *testing.T) {
	// These field names use sensitive-sounding words as prefixes or in
	// non-secret contexts; they must NOT be redacted.
	safe := []string{
		"token_type", "token_id", "token_expiry",
		"envelope_format", "envelope_version", "envelope_adapter",
		"ciphertext_suite", "ciphertext_algorithm",
		"key_id", "key_version", "key_state",
		"secret_name", // wait — "secret_name" ends with "_name", not "_secret"
		"password_hash", // ends with "_hash"
	}
	for _, key := range safe {
		if sensitiveKey(key) {
			t.Errorf("expected %q to be safe but was marked sensitive", key)
		}
	}
}

func TestSensitiveKeyNormalization(t *testing.T) {
	// Hyphens and spaces should be normalized to underscores.
	cases := map[string]bool{
		"access-token":     true,
		"Access Token":     true,
		"private-key":      true,
		"Private Key":      true,
		"envelope-format":  false, // prefix use, not sensitive
	}
	for key, want := range cases {
		if got := sensitiveKey(key); got != want {
			t.Errorf("sensitiveKey(%q) = %v, want %v", key, got, want)
		}
	}
}
