package crypto

import (
	"bytes"
	"context"
	"time"

	"github.com/kvlt/key-vault/internal/errorsx"
	"testing"

	"github.com/kvlt/key-vault/internal/crypto/aad"
	"github.com/kvlt/key-vault/internal/crypto/aead"
	"github.com/kvlt/key-vault/internal/crypto/envelope"
	"github.com/kvlt/key-vault/internal/domain/policy"
	"github.com/kvlt/key-vault/internal/repository/memory"
	"github.com/kvlt/key-vault/internal/repository/models"
	"github.com/kvlt/key-vault/internal/resolver/keyresolver"
	"github.com/kvlt/key-vault/internal/tpm/provider"
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
	cfg := &models.TenantEnvelopeConfig{AllowedFormats: []string{string(envelope.FormatConfigurableJSONV1)}}
	_, _, err = detectEnvelopeProfile(registry, cfg, "", jsonBytes)
	if errorsx.AsCode(err) != errorsx.CodePolicyDenied {
		t.Fatalf("detect error code = %s, want %s", errorsx.AsCode(err), errorsx.CodePolicyDenied)
	}
}

func TestEncryptWithoutKeyUsesDefaultECBKey(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	if err := store.UpsertTenant(ctx, &models.Tenant{ID: "t-default", Name: "Default", Status: "active"}); err != nil {
		t.Fatalf("UpsertTenant: %v", err)
	}
	resolver := newTestResolver(t, ctx, store)
	policies := policy.NewEngine()
	if err := policies.Load(policy.DefaultPolicy()); err != nil {
		t.Fatalf("Load policy: %v", err)
	}
	svc := New(store, resolver, policies, nil, 64*1024)

	encrypted, err := svc.Encrypt(ctx, EncryptCommand{Plaintext: []byte("minimal payload"), PrincipalID: "tester"})
	if err != nil {
		t.Fatalf("Encrypt minimal: %v", err)
	}
	if encrypted.KeyID != defaultEncryptKeyID {
		t.Fatalf("KeyID = %s, want %s", encrypted.KeyID, defaultEncryptKeyID)
	}
	if encrypted.SuiteID != defaultEncryptKeySuite {
		t.Fatalf("SuiteID = %s, want %s", encrypted.SuiteID, defaultEncryptKeySuite)
	}
	env, err := envelope.DefaultRegistry().Parse(envelope.FormatJSONV1, encrypted.Ciphertext)
	if err != nil {
		t.Fatalf("Parse envelope: %v", err)
	}
	if env.SuiteID != aead.SuiteAES256ECB || len(env.Nonce) != 0 || len(env.Tag) != 0 {
		t.Fatalf("unexpected default envelope suite/nonce/tag: %s %d %d", env.SuiteID, len(env.Nonce), len(env.Tag))
	}

	decrypted, err := svc.Decrypt(ctx, DecryptCommand{Ciphertext: encrypted.Ciphertext})
	if err != nil {
		t.Fatalf("Decrypt minimal: %v", err)
	}
	if string(decrypted.Plaintext) != "minimal payload" {
		t.Fatalf("Plaintext = %q", decrypted.Plaintext)
	}

}

func newTestResolver(t *testing.T, ctx context.Context, store *memory.Store) *keyresolver.Resolver {
	t.Helper()
	p, err := provider.NewSoftwareProvider(t.TempDir())
	if err != nil {
		t.Fatalf("NewSoftwareProvider: %v", err)
	}
	r := keyresolver.New(p, "test-nrwk", time.Minute)
	baselineDigest := []byte("baseline")
	policyDigest := []byte("policy")
	if err := r.Init(ctx, "cluster-1", "node-1", "data", baselineDigest, policyDigest); err != nil {
		t.Fatalf("Init: %v", err)
	}
	nrwk, err := p.EnsureNRWK(ctx, "test-nrwk")
	if err != nil {
		t.Fatalf("EnsureNRWK: %v", err)
	}
	crk := bytes.Repeat([]byte{0x42}, 32)
	env, err := p.SealCRK(ctx, nrwk, crk, aad.CRKAAD{
		ClusterID:      "cluster-1",
		NodeID:         "node-1",
		PlaneRole:      "data",
		CRKVersion:     1,
		NRWKName:       "test-nrwk",
		BaselineDigest: baselineDigest,
		PolicyDigest:   policyDigest,
	})
	if err != nil {
		t.Fatalf("SealCRK: %v", err)
	}
	r.SetCRKEnvelope(env)
	r.SetFetchDEKHook(func(ctx context.Context, keyVersionID string) ([]byte, []byte, error) {
		kv, err := store.GetKeyVersion(ctx, keyVersionID)
		if err != nil {
			return nil, nil, err
		}
		return kv.WrappedDEK, kv.WrapMetadata, nil
	})
	return r
}

func mustParseEnvelope(t *testing.T, b []byte) *envelope.Envelope {
	t.Helper()
	env, err := envelope.Parse(b)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return env
}
