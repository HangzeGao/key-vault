package envelope

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"

	"github.com/kvlt/key-vault/internal/crypto/aead"
)

// TestDefaultRegistryFormats verifies that only binary and JSON formats are
// registered. PEM and Base64 were removed per design 搂8.
func TestDefaultRegistryFormats(t *testing.T) {
	r := DefaultRegistry()
	formats := r.ListFormats()
	if len(formats) != 3 {
		t.Fatalf("expected 3 formats, got %d: %+v", len(formats), formats)
	}
	ids := make(map[FormatID]bool)
	for _, f := range formats {
		ids[f.ID] = true
	}
	if !ids[FormatKVLTBinaryV1] {
		t.Error("kvlt-binary-v1 format not registered")
	}
	if !ids[FormatJSONV1] {
		t.Error("json-v1 format not registered")
	}
	if !ids[FormatConfigurableJSONV1] {
		t.Error("configurable-json-v1 format not registered")
	}
}

func TestJSONCodecOmitsAADHashForECB(t *testing.T) {
	key := bytes.Repeat([]byte{0x66}, 32)
	sealed, err := Seal(aead.SuiteAES256ECB, key, "key-ecb-json", 1, 1, nil, []byte("payload"), []byte("ignored"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	env, err := Parse(sealed)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	encoded, err := DefaultRegistry().Encode(FormatJSONV1, env)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	var obj map[string]any
	if err := json.Unmarshal(encoded, &obj); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if _, ok := obj["aad_hash"]; ok {
		t.Fatalf("ECB JSON unexpectedly carried aad_hash: %s", encoded)
	}
	parsed, err := DefaultRegistry().Parse(FormatJSONV1, encoded)
	if err != nil {
		t.Fatalf("Parse JSON: %v", err)
	}
	if parsed.SuiteID != aead.SuiteAES256ECB {
		t.Fatalf("suite = %s, want AES_256_ECB", parsed.SuiteID)
	}
}

// TestRegistryCodec verifies Codec lookup for registered and unregistered formats.
func TestRegistryCodec(t *testing.T) {
	r := DefaultRegistry()
	if _, err := r.Codec(FormatKVLTBinaryV1); err != nil {
		t.Errorf("Codec(kvlt-binary-v1) error: %v", err)
	}
	if _, err := r.Codec(FormatJSONV1); err != nil {
		t.Errorf("Codec(json-v1) error: %v", err)
	}
	if _, err := r.Codec(FormatConfigurableJSONV1); err != nil {
		t.Errorf("Codec(configurable-json-v1) error: %v", err)
	}
	if _, err := r.Codec("pem-v1"); err == nil {
		t.Error("Codec(pem-v1) should fail 鈥?PEM format was removed")
	}
	if _, err := r.Codec("base64-v1"); err == nil {
		t.Error("Codec(base64-v1) should fail 鈥?Base64 format was removed")
	}
}

// TestRegistryDetect verifies auto-detection of binary vs JSON envelopes.
func TestRegistryDetect(t *testing.T) {
	r := DefaultRegistry()

	key := bytes.Repeat([]byte{0x42}, 32)
	nonce := bytes.Repeat([]byte{0x11}, 12)
	plaintext := []byte("detect-test")
	keyID := "key-detect-001"

	callerAAD := testCallerAAD{
		TenantID:   "t-detect",
		KeyID:      keyID,
		KeyVersion: 1,
		Purpose:    "detect",
		SuiteID:    uint16(aead.SuiteAES256GCM),
	}
	aadBytes, _ := callerAAD.Canonical()

	sealed, err := Seal(aead.SuiteAES256GCM, key, keyID, 1, 1, nonce, plaintext, aadBytes)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	// Binary detection.
	binCodec, err := r.Detect(sealed)
	if err != nil {
		t.Fatalf("Detect(binary) error: %v", err)
	}
	if binCodec.ID() != FormatKVLTBinaryV1 {
		t.Errorf("Detect(binary) = %s, want kvlt-binary-v1", binCodec.ID())
	}

	// JSON detection: encode to JSON then detect.
	jsonBytes, err := r.Encode(FormatJSONV1, mustParseEnvelope(t, sealed))
	if err != nil {
		t.Fatalf("Encode(json): %v", err)
	}
	jsonCodec, err := r.Detect(jsonBytes)
	if err != nil {
		t.Fatalf("Detect(json) error: %v", err)
	}
	if jsonCodec.ID() != FormatJSONV1 {
		t.Errorf("Detect(json) = %s, want json-v1", jsonCodec.ID())
	}

	// Unknown format.
	_, err = r.Detect([]byte{0xFF, 0xFF, 0xFF, 0xFF})
	if !errors.Is(err, ErrInvalid) {
		t.Errorf("Detect(unknown) error = %v, want ErrInvalid", err)
	}
}

// TestRegistryJSONRoundTrip verifies Seal -> JSON encode -> JSON decode -> Open.
func TestRegistryJSONRoundTrip(t *testing.T) {
	r := DefaultRegistry()

	key := bytes.Repeat([]byte{0x55}, 32)
	nonce := bytes.Repeat([]byte{0x22}, 12)
	plaintext := []byte("json-roundtrip-test")
	keyID := "key-json-rt-001"

	callerAAD := testCallerAAD{
		TenantID:   "t-json",
		KeyID:      keyID,
		KeyVersion: 1,
		Purpose:    "json-rt",
		SuiteID:    uint16(aead.SuiteAES256GCM),
	}
	aadBytes, _ := callerAAD.Canonical()

	sealed, err := Seal(aead.SuiteAES256GCM, key, keyID, 1, 1, nonce, plaintext, aadBytes)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	// Parse binary, encode to JSON, parse JSON, verify fields match.
	envBin, err := r.Parse(FormatKVLTBinaryV1, sealed)
	if err != nil {
		t.Fatalf("Parse(binary): %v", err)
	}
	jsonBytes, err := r.Encode(FormatJSONV1, envBin)
	if err != nil {
		t.Fatalf("Encode(json): %v", err)
	}
	envJSON, err := r.Parse(FormatJSONV1, jsonBytes)
	if err != nil {
		t.Fatalf("Parse(json): %v", err)
	}
	if envJSON.KeyVersion != envBin.KeyVersion {
		t.Errorf("KeyVersion mismatch: %d vs %d", envJSON.KeyVersion, envBin.KeyVersion)
	}
	if !bytes.Equal(envJSON.Ciphertext, envBin.Ciphertext) {
		t.Error("Ciphertext mismatch after JSON round-trip")
	}
	if !bytes.Equal(envJSON.Nonce, envBin.Nonce) {
		t.Error("Nonce mismatch after JSON round-trip")
	}
	if !bytes.Equal(envJSON.Tag, envBin.Tag) {
		t.Error("Tag mismatch after JSON round-trip")
	}
}

// TestJSONCodecAllowsUnknownFields verifies JSON decoding tolerates configured extension fields.
func TestJSONCodecAllowsUnknownFields(t *testing.T) {
	r := DefaultRegistry()
	// Construct a valid JSON envelope then add an unknown field.
	key := bytes.Repeat([]byte{0x42}, 32)
	nonce := bytes.Repeat([]byte{0x11}, 12)
	plaintext := []byte("strict-json")
	keyID := "key-strict-001"
	callerAAD := testCallerAAD{
		TenantID: "t-strict", KeyID: keyID, KeyVersion: 1,
		Purpose: "strict", SuiteID: uint16(aead.SuiteAES256GCM),
	}
	aadBytes, _ := callerAAD.Canonical()
	sealed, err := Seal(aead.SuiteAES256GCM, key, keyID, 1, 1, nonce, plaintext, aadBytes)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	env, err := r.Parse(FormatKVLTBinaryV1, sealed)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	jsonBytes, err := r.Encode(FormatJSONV1, env)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	// Add an unknown field via map manipulation.
	var raw map[string]any
	if err := json.Unmarshal(jsonBytes, &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	raw["unknown_field"] = "malicious"
	tampered, _ := json.Marshal(raw)

	_, err = r.Parse(FormatJSONV1, tampered)
	if err != nil {
		t.Errorf("Parse(json with unknown fields) error = %v, want nil", err)
	}
}

// TestJSONCodecRejectsWrongVersion verifies version check in JSON decode.
func TestJSONCodecRejectsWrongVersion(t *testing.T) {
	je := jsonEnvelope{
		Version:    99, // wrong version
		Nonce:      base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{0x11}, 12)),
		Ciphertext: base64.RawStdEncoding.EncodeToString([]byte("ct")),
		Tag:        base64.RawStdEncoding.EncodeToString([]byte("tag1234567890123456")),
		AADHash:    base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{0x00}, 32)),
	}
	b, _ := json.Marshal(je)
	r := DefaultRegistry()
	_, err := r.Parse(FormatJSONV1, b)
	if err == nil {
		t.Error("Parse(json with wrong version) should fail")
	}
}

func TestConfigurableJSONProfileRoundTrip(t *testing.T) {
	r := DefaultRegistry()
	key := bytes.Repeat([]byte{0x77}, 32)
	nonce := bytes.Repeat([]byte{0x33}, 12)
	plaintext := []byte("configurable-json-roundtrip")
	keyID := "key-config-json-001"
	callerAAD := testCallerAAD{
		TenantID:   "t-config",
		KeyID:      keyID,
		KeyVersion: 1,
		Purpose:    "config",
		SuiteID:    uint16(aead.SuiteAES256GCM),
	}
	aadBytes, _ := callerAAD.Canonical()
	sealed, err := Seal(aead.SuiteAES256GCM, key, keyID, 1, 1, nonce, plaintext, aadBytes)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	profile := &FormatProfile{
		FormatID: "partner-json-v1",
		Adapter:  FormatConfigurableJSONV1,
		FieldMappings: []FieldMapping{
			{Path: "$.kid", Source: "core.key_id", Required: true},
			{Path: "$.ver", Source: "core.key_version", Required: true},
			{Path: "$.alg", Source: "derived.algorithm_name", Required: true},
			{Path: "$.meta.suite", Source: "core.suite_id", Required: true},
			{Path: "$.meta.version", Source: "core.version", Required: true},
			{Path: "$.meta.flags", Source: "core.flags", Required: true},
			{Path: "$.meta.policy", Source: "core.policy_version", Required: true},
			{Path: "$.iv", Source: "core.nonce", Required: true, Encoding: "base64url"},
			{Path: "$.data", Source: "core.ciphertext", Required: true, Encoding: "base64url"},
			{Path: "$.tag", Source: "core.tag", Required: true, Encoding: "base64url"},
			{Path: "$.aad", Source: "core.aad_hash", Required: true, Encoding: "base64url"},
			{Path: "$.traceId", Source: "extension.trace_id"},
		},
	}
	rendered, err := r.EncodeWithProfile(profile, mustParseEnvelope(t, sealed), RenderContext{Extensions: map[string]any{"trace_id": "trace-1"}})
	if err != nil {
		t.Fatalf("EncodeWithProfile: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(rendered, &raw); err != nil {
		t.Fatalf("unmarshal rendered: %v", err)
	}
	if raw["kid"] != keyID || raw["traceId"] != "trace-1" {
		t.Fatalf("rendered fields mismatch: %+v", raw)
	}
	parsed, exts, err := r.ParseWithProfile(profile, rendered)
	if err != nil {
		t.Fatalf("ParseWithProfile: %v", err)
	}
	if string(parsed.KeyID) != keyID || parsed.KeyVersion != 1 {
		t.Fatalf("parsed core mismatch: %+v", parsed)
	}
	if exts["trace_id"] != "trace-1" {
		t.Fatalf("extension mismatch: %+v", exts)
	}
	_, pt, err := r.OpenWithProfile(profile, rendered, key, aadBytes)
	if err != nil {
		t.Fatalf("OpenWithProfile: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Fatalf("plaintext = %q, want %q", pt, plaintext)
	}

	raw["meta"].(map[string]any)["suite"] = 1.5
	tampered, err := json.Marshal(raw)
	if err != nil {
		t.Fatalf("marshal tampered: %v", err)
	}
	if _, _, err := r.ParseWithProfile(profile, tampered); err == nil {
		t.Fatal("ParseWithProfile accepted fractional suite_id")
	}
}

// mustParseEnvelope is a test helper that parses a binary envelope or fails.
func mustParseEnvelope(t *testing.T, b []byte) *Envelope {
	t.Helper()
	env, err := Parse(b)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return env
}
