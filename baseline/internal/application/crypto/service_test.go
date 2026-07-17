package crypto

import (
	"bytes"
	"github.com/kvlt/key-vault/internal/errorsx"
	"testing"

	"github.com/kvlt/key-vault/internal/crypto/aead"
	"github.com/kvlt/key-vault/internal/crypto/envelope"
	"github.com/kvlt/key-vault/internal/repository/models"
)

func TestEnvelopeProfileUsesTenantProfile(t *testing.T) {
	cfg := &models.TenantEnvelopeConfig{AllowedFormats: []string{"partner-json-v1"}, Profiles: []models.EnvelopeFormatProfile{
		{
			FormatID: "partner-json-v1",
			Adapter:  string(envelope.FormatConfigurableJSONV1),
			FieldMappings: []models.EnvelopeFieldMapping{
				{Path: "$.kid", Source: "core.key_id", Required: true},
				{Path: "$.traceId", Source: "extension.trace_id"},
			},
			Extensions: []models.EnvelopeExtension{
				{Name: "trace_id", Type: "string"},
			},
		},
	}}

	profile := envelopeProfile(cfg, "partner-json-v1")
	if profile.FormatID != "partner-json-v1" {
		t.Fatalf("FormatID = %s", profile.FormatID)
	}
	if profile.Adapter != envelope.FormatConfigurableJSONV1 {
		t.Fatalf("Adapter = %s", profile.Adapter)
	}
	if len(profile.FieldMappings) != 2 {
		t.Fatalf("FieldMappings = %d", len(profile.FieldMappings))
	}
	if profile.FieldMappings[0].Source != "core.key_id" || profile.FieldMappings[1].Source != "extension.trace_id" {
		t.Fatalf("unexpected mappings: %+v", profile.FieldMappings)
	}
}

func TestTenantAADPolicy(t *testing.T) {
	optional := &models.TenantEnvelopeConfig{}
	required := &models.TenantEnvelopeConfig{AADRequired: true}
	if err := validateTenantAADPolicy(optional, nil); err != nil {
		t.Fatalf("optional AAD rejected: %v", err)
	}
	if err := validateTenantAADPolicy(required, []byte("aad")); err != nil {
		t.Fatalf("non-empty AAD rejected: %v", err)
	}
	if err := validateTenantAADPolicy(required, nil); errorsx.AsCode(err) != errorsx.CodeBadRequest {
		t.Fatalf("required empty AAD code = %s", errorsx.AsCode(err))
	}
}

func TestEnvelopeProfileFallsBackToBuiltin(t *testing.T) {
	profile := envelopeProfile(nil, envelope.FormatJSONV1)
	if profile == nil || profile.Adapter != envelope.FormatJSONV1 {
		t.Fatalf("profile = %+v", profile)
	}
}

func TestDetectEnvelopeProfileTriesConfigurableJSONProfiles(t *testing.T) {
	registry := envelope.DefaultRegistry()
	keyID := "key-auto-profile"
	key := bytes.Repeat([]byte{0x42}, 32)
	nonce := bytes.Repeat([]byte{0x11}, 12)
	aadBytes := []byte("opaque-aad")
	sealed, err := envelope.Seal(aead.SuiteAES256GCM, key, keyID, 1, 1, nonce, []byte("hello"), aadBytes)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	core, err := envelope.Parse(sealed)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	cfg := &models.TenantEnvelopeConfig{Profiles: []models.EnvelopeFormatProfile{
		{
			FormatID: "partner-json-v1",
			Adapter:  string(envelope.FormatConfigurableJSONV1),
			FieldMappings: []models.EnvelopeFieldMapping{
				{Path: "$.kid", Source: "core.key_id", Required: true},
				{Path: "$.ver", Source: "core.key_version", Required: true},
				{Path: "$.suite", Source: "core.suite_id", Required: true},
				{Path: "$.v", Source: "core.version", Required: true},
				{Path: "$.flags", Source: "core.flags", Required: true},
				{Path: "$.policy", Source: "core.policy_version", Required: true},
				{Path: "$.iv", Source: "core.nonce", Required: true, Encoding: "base64url"},
				{Path: "$.data", Source: "core.ciphertext", Required: true, Encoding: "base64url"},
				{Path: "$.tag", Source: "core.tag", Required: true, Encoding: "base64url"},
				{Path: "$.aad", Source: "core.aad_hash", Required: true, Encoding: "base64url"},
				{Path: "$.traceId", Source: "extension.trace_id", Required: true},
			},
		},
	}}
	rendered, err := registry.EncodeWithProfile(modelProfileToEnvelope(cfg.Profiles[0]), core, envelope.RenderContext{Extensions: map[string]any{"trace_id": "trace-1"}})
	if err != nil {
		t.Fatalf("EncodeWithProfile: %v", err)
	}
	profile, parsed, err := detectEnvelopeProfile(registry, cfg, "", rendered)
	if err != nil {
		t.Fatalf("detectEnvelopeProfile: %v", err)
	}
	if profile.FormatID != "partner-json-v1" {
		t.Fatalf("FormatID = %s", profile.FormatID)
	}
	if string(parsed.KeyID) != keyID {
		t.Fatalf("KeyID = %s", parsed.KeyID)
	}
}

func TestDetectEnvelopeProfileRejectsDisallowedBuiltinFormat(t *testing.T) {
	registry := envelope.DefaultRegistry()
	keyID := "key-disallowed-json"
	key := bytes.Repeat([]byte{0x43}, 32)
	nonce := bytes.Repeat([]byte{0x12}, 12)
	sealed, err := envelope.Seal(aead.SuiteAES256GCM, key, keyID, 1, 1, nonce, []byte("hello"), nil)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	jsonBytes, err := registry.Encode(envelope.FormatJSONV1, mustParseEnvelope(t, sealed))
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	cfg := &models.TenantEnvelopeConfig{AllowedFormats: []string{string(envelope.FormatKVLTBinaryV1)}}
	_, _, err = detectEnvelopeProfile(registry, cfg, "", jsonBytes)
	if errorsx.AsCode(err) != errorsx.CodePolicyDenied {
		t.Fatalf("detect error code = %s, want %s", errorsx.AsCode(err), errorsx.CodePolicyDenied)
	}
}

func mustParseEnvelope(t *testing.T, b []byte) *envelope.Envelope {
	t.Helper()
	env, err := envelope.Parse(b)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return env
}
