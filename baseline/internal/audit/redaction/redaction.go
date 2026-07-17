// Package redaction provides hashing helpers for sensitive identifiers
// in audit events and logs, per design §15.1 and §18.2.
package redaction

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
)

// pepper is a process-wide HMAC key used to prevent trivial rainbow-table
// attacks on hashed identifiers. In production it should be loaded from
// a secret; the baseline derives it from a fixed root + cluster_id for determinism
// within a deployment.
var pepper = []byte("kvlt-redaction-pepper-v1")

// SetPepper overrides the default pepper. Must be called once at startup.
func SetPepper(p []byte) {
	if len(p) > 0 {
		pepper = p
	}
}

// Hash returns a hex-encoded HMAC-SHA256 of the input under the pepper.
// The same input always yields the same hash within a process; different
// deployments with different peppers yield different hashes.
func Hash(s string) string {
	mac := hmac.New(sha256.New, pepper)
	mac.Write([]byte(s))
	return hex.EncodeToString(mac.Sum(nil))
}

// HashBytes is like Hash but for byte slices.
func HashBytes(b []byte) string {
	mac := hmac.New(sha256.New, pepper)
	mac.Write(b)
	return hex.EncodeToString(mac.Sum(nil))
}

// ShortHash returns the first 16 hex chars of Hash(s).
func ShortHash(s string) string {
	return Hash(s)[:16]
}

// MaybeRedactJSON recursively replaces values whose field names denote secret
// material. It handles nested objects and arrays as a defense-in-depth boundary.
func MaybeRedactJSON(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var value any
	if err := json.Unmarshal(b, &value); err != nil {
		return nil, err
	}
	return json.Marshal(redactValue(value))
}

func redactValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(typed))
		for key, item := range typed {
			if sensitiveKey(key) {
				out[key] = "<redacted>"
			} else {
				out[key] = redactValue(item)
			}
		}
		return out
	case []any:
		out := make([]any, len(typed))
		for i, item := range typed {
			out[i] = redactValue(item)
		}
		return out
	default:
		return value
	}
}

// exactMarkers are field names that are always sensitive when matched exactly.
var exactMarkers = []string{
	"token", "authorization", "password", "secret", "plaintext",
	"dek", "crk", "wrapped_material", "wrapped_crk", "key_bytes", "private_key",
	"ciphertext", "envelope",
	// common compound sensitive field names
	"access_token", "refresh_token", "id_token", "auth_token", "csrf_token",
	"bearer_token", "session_token", "api_key", "signing_key", "private_key",
	"wrapped_dek", "wrapped_envelope", "core_envelope",
}

// suffixMarkers are markers where any field ending in "_<marker>" is sensitive.
// Only include markers with low false-positive risk (e.g. "_password" is always
// sensitive; "_envelope" is not because envelope_format is not secret material).
var suffixMarkers = []string{
	"password", "secret", "plaintext", "dek", "crk",
	"key_bytes", "private_key", "wrapped_material", "wrapped_crk",
	"authorization", "token",
}

func sensitiveKey(key string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(key, "-", "_"), " ", "_"))
	for _, m := range exactMarkers {
		if normalized == m {
			return true
		}
	}
	for _, m := range suffixMarkers {
		if strings.HasSuffix(normalized, "_"+m) {
			return true
		}
	}
	return false
}
