package bootstrap

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/kvlt/key-vault/internal/application/protection"
	"github.com/kvlt/key-vault/internal/audit/redaction"
	"github.com/kvlt/key-vault/internal/auditchain"
	"github.com/kvlt/key-vault/internal/auth/hmacsign"
	"github.com/kvlt/key-vault/internal/auth/jwt"
	"github.com/kvlt/key-vault/internal/auth/principal"
	"github.com/kvlt/key-vault/internal/config"
	"github.com/kvlt/key-vault/internal/crypto/aad"
	"github.com/kvlt/key-vault/internal/domain/policy"
	"github.com/kvlt/key-vault/internal/policysig"
	"github.com/kvlt/key-vault/internal/protocol/ccsds"
	"github.com/kvlt/key-vault/internal/repository/models"
	"github.com/kvlt/key-vault/internal/resolver/keyresolver"
	"github.com/kvlt/key-vault/internal/securitystate"
	"github.com/kvlt/key-vault/internal/tpm/provider"
)

const (
	clusterID = "ccsds-ground-v1"
	nrwkName  = "ccsds-root-wrap-v1"
	planeRole = "ground"
)

// App contains only the modules used by the CCSDS ground system.
type App struct {
	Cfg                *config.Config
	Store              *securitystate.Store
	TPM                provider.Provider
	Resolver           *keyresolver.Resolver
	Policies           *policy.Engine
	PolicyMgr          *policysig.Manager
	CCSDSFrameSecurity *ccsds.FrameSecurity
	CCSDSStore         ccsds.Store
	JWTVerifier        *jwt.Verifier
	HMACVerifier       *hmacsign.Verifier
	StaticTokens       map[string]*principal.Principal
	AuditChain         *auditchain.Service
}

func Build(ctx context.Context, cfg *config.Config) (_ *App, err error) {
	if cfg == nil {
		return nil, errors.New("bootstrap: nil config")
	}
	if err := configureRedactionPepper(cfg); err != nil {
		return nil, err
	}
	for _, finding := range cfg.Diagnostics() {
		if finding.Level == "warn" {
			slog.Warn("configuration posture", "code", finding.Code, "message", finding.Message)
		} else {
			slog.Info("configuration posture", "code", finding.Code, "message", finding.Message)
		}
	}

	store, err := securitystate.Open(ctx, cfg.Database.Path)
	if err != nil {
		return nil, fmt.Errorf("bootstrap: security state: %w", err)
	}
	defer func() {
		if err != nil {
			_ = store.Close()
		}
	}()

	tpm, err := buildTPM(cfg)
	if err != nil {
		return nil, err
	}
	policies := policy.NewEngine()
	resolver := keyresolver.New(tpm, nrwkName, 5*time.Minute)
	if err := bootstrapRoot(ctx, cfg, store, tpm, resolver); err != nil {
		return nil, fmt.Errorf("bootstrap: root: %w", err)
	}
	resolver.SetFetchDEKHook(func(ctx context.Context, keyVersionID string) ([]byte, []byte, error) {
		version, err := store.GetKeyVersion(ctx, keyVersionID)
		if err != nil {
			return nil, nil, err
		}
		return version.WrappedDEK, version.WrapMetadata, nil
	})

	auditChain := auditchain.New(store)
	policyMgr := policysig.New(policies, &policyAuditAdapter{audit: auditChain})
	if err := configureSignedPolicy(ctx, cfg, policyMgr); err != nil {
		return nil, err
	}

	protectionCore := protection.New(store, resolver, policies, cfg.CCSDS.MaxFrameLength)
	frameSecurity, err := ccsds.New(protectionCore, store, ccsds.Options{
		AOSPrimaryHeaderLength: cfg.CCSDS.AOSPrimaryHeaderLength,
		MaxFrameLength:         cfg.CCSDS.MaxFrameLength,
		NodeID:                 cfg.Server.NodeID,
		TCSpacecraftID:         cfg.CCSDS.TCSpacecraftID,
	})
	if err != nil {
		return nil, fmt.Errorf("bootstrap: CCSDS frame security: %w", err)
	}

	jwtVerifier := jwt.NewVerifier(cfg.Auth.JWTIssuer, cfg.Auth.JWTAudience, cfg.Auth.JWTAlgWhite)
	jwtVerifier.SetMaxTokenTTL(cfg.Auth.DefaultTokenTTL)
	if cfg.Auth.JWKSetURL != "" {
		keySet, err := jwt.NewRemoteKeySet(cfg.Auth.JWKSetURL, cfg.Auth.JWKCacheTTL, nil)
		if err != nil {
			return nil, fmt.Errorf("bootstrap: remote JWKS: %w", err)
		}
		jwtVerifier.SetPublicKeySet(keySet)
	}

	return &App{
		Cfg: cfg, Store: store, TPM: tpm, Resolver: resolver, Policies: policies, PolicyMgr: policyMgr,
		CCSDSFrameSecurity: frameSecurity, CCSDSStore: store,
		JWTVerifier: jwtVerifier, HMACVerifier: hmacsign.NewVerifier(cfg.Auth.HMACMaxSkew),
		StaticTokens: loadStaticTokens(), AuditChain: auditChain,
	}, nil
}

func buildTPM(cfg *config.Config) (provider.Provider, error) {
	switch cfg.TPM.Provider {
	case "swtpm", "software":
		value, err := provider.NewSoftwareProvider(cfg.TPM.StateDir)
		if err != nil {
			return nil, fmt.Errorf("bootstrap: TPM: %w", err)
		}
		return value, nil
	case "tpm2", "hardware", "tpm2-tools":
		value, err := provider.NewHardwareProviderWithOptions(provider.HardwareOptions{
			StateDir: cfg.TPM.StateDir, ToolDir: cfg.TPM.ToolDir, TCTI: cfg.TPM.TCTI,
		})
		if err != nil {
			return nil, fmt.Errorf("bootstrap: TPM: %w", err)
		}
		return value, nil
	case "tss", "esapi", "native":
		value, err := provider.NewNativeProvider(provider.NativeOptions{TCTI: cfg.TPM.TCTI, PCRs: cfg.TPM.PolicyPCRs})
		if err != nil {
			return nil, fmt.Errorf("bootstrap: TPM: %w", err)
		}
		return value, nil
	default:
		return nil, fmt.Errorf("bootstrap: unknown TPM provider %q", cfg.TPM.Provider)
	}
}

func bootstrapRoot(ctx context.Context, cfg *config.Config, store *securitystate.Store,
	tpm provider.Provider, resolver *keyresolver.Resolver) error {
	if err := store.EnsureTenant(ctx, "t-default", "default"); err != nil {
		return err
	}
	for _, tenantID := range collectStaticTokenTenantIDs() {
		if tenantID == "" || tenantID == "t-default" {
			continue
		}
		if err := store.EnsureTenant(ctx, tenantID, strings.TrimPrefix(tenantID, "t-")); err != nil {
			return err
		}
	}
	baseline := hashBaseline(cfg.Baseline)
	policyDigest := sha256.Sum256([]byte("ccsds-default-policy-v1"))
	if err := resolver.Init(ctx, clusterID, cfg.Server.NodeID, planeRole, baseline, policyDigest[:]); err != nil {
		return err
	}

	_, record, err := store.LoadLatestCRK(ctx, cfg.Server.NodeID)
	if err == nil {
		var envelope provider.CRKEnvelope
		if err := json.Unmarshal(record.Envelope, &envelope); err != nil {
			return fmt.Errorf("decode CRK envelope: %w", err)
		}
		resolver.SetCRKEnvelope(&envelope)
		return nil
	}
	if !errors.Is(err, securitystate.ErrNotFound) {
		return err
	}

	root := make([]byte, 32)
	if _, err := rand.Read(root); err != nil {
		return fmt.Errorf("generate CRK: %w", err)
	}
	defer zeroize(root)
	nrwk, err := tpm.EnsureNRWK(ctx, nrwkName)
	if err != nil {
		return err
	}
	envelope, err := tpm.SealCRK(ctx, nrwk, root, aad.CRKAAD{
		ClusterID: clusterID, NodeID: cfg.Server.NodeID, PlaneRole: planeRole, CRKVersion: 1,
		NRWKName: nrwkName, BaselineDigest: baseline, PolicyDigest: policyDigest[:],
	})
	if err != nil {
		return fmt.Errorf("seal CRK: %w", err)
	}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return fmt.Errorf("encode CRK envelope: %w", err)
	}
	version := &models.CRKVersion{ID: "crk-v1", Version: 1, Status: "active", CreatedAt: time.Now().UTC()}
	record = &models.CRKNodeEnvelope{ID: "crkenv-" + cfg.Server.NodeID, CRKVersionID: version.ID,
		NodeID: cfg.Server.NodeID, Envelope: encoded, CreatedAt: time.Now().UTC()}
	if err := store.SaveCRK(ctx, version, record); err != nil {
		return err
	}
	resolver.SetCRKEnvelope(envelope)
	return nil
}

func configureRedactionPepper(cfg *config.Config) error {
	if cfg.Audit.RedactionPepperFile == "" {
		if cfg.Environment == "production" {
			return errors.New("bootstrap: production redaction pepper is not configured")
		}
		return nil
	}
	raw, err := os.ReadFile(cfg.Audit.RedactionPepperFile)
	if err != nil {
		return fmt.Errorf("bootstrap: read redaction pepper: %w", err)
	}
	raw = bytes.TrimSpace(raw)
	if len(raw) < 32 || len(raw) > 4096 {
		return errors.New("bootstrap: redaction pepper must contain 32 to 4096 bytes")
	}
	redaction.SetPepper(raw)
	return nil
}

func configureSignedPolicy(ctx context.Context, cfg *config.Config, manager *policysig.Manager) error {
	if cfg.Policy.TrustedKeysPath != "" || cfg.Policy.SignedPolicyPath != "" {
		if cfg.Policy.TrustedKeysPath == "" || cfg.Policy.SignedPolicyPath == "" {
			return errors.New("bootstrap: policy trust bundle and signed policy must be configured together")
		}
		bundle, err := policysig.LoadTrustBundle(cfg.Policy.TrustedKeysPath)
		if err != nil {
			return fmt.Errorf("bootstrap: load trust bundle: %w", err)
		}
		if err := policysig.InstallTrustBundle(manager, bundle); err != nil {
			return err
		}
		signed, err := policysig.LoadSignedPolicy(cfg.Policy.SignedPolicyPath)
		if err != nil {
			return fmt.Errorf("bootstrap: load signed policy: %w", err)
		}
		return manager.LoadSigned(ctx, signed)
	}
	if cfg.Environment == "production" {
		return errors.New("bootstrap: production policy trust is not configured")
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	if err := manager.AddTrustedSigningKey("development-policy-key", publicKey, "active"); err != nil {
		return err
	}
	signed, err := policysig.GenerateDefaultSignedPolicy(privateKey, "development-policy-key")
	if err != nil {
		return err
	}
	return manager.LoadSigned(ctx, signed)
}

type policyAuditAdapter struct{ audit *auditchain.Service }

func (adapter *policyAuditAdapter) RecordPolicyReload(ctx context.Context, policyID string, version uint32, result, reason string) {
	_ = adapter.audit.Record(ctx, auditchain.RecordRequest{ActorType: "system", ActorHash: "system",
		Action: "policy.reload", TargetType: "policy", TargetIDHash: redaction.ShortHash(policyID), Result: result,
		Metadata: map[string]string{"version": fmt.Sprintf("%d", version), "reason": reason}})
}

func loadStaticTokens() map[string]*principal.Principal {
	tokens := make(map[string]*principal.Principal)
	raw := os.Getenv("KVLT_STATIC_TOKENS")
	if raw == "" {
		return tokens
	}
	var entries []struct {
		Token    string   `json:"token"`
		TenantID string   `json:"tenant_id"`
		Scopes   []string `json:"scopes"`
		Roles    []string `json:"roles"`
		Plane    string   `json:"plane"`
		Planes   []string `json:"planes"`
		NodeID   string   `json:"node_id"`
	}
	if err := json.Unmarshal([]byte(raw), &entries); err != nil {
		slog.Error("KVLT_STATIC_TOKENS parse failed; static authentication disabled", "error", err)
		return tokens
	}
	for _, entry := range entries {
		if len(entry.Token) < 8 || entry.TenantID == "" {
			continue
		}
		plane, planes := staticTokenPlanes(entry.Plane, entry.Planes)
		tokens[entry.Token] = &principal.Principal{ID: "static:" + entry.Token[:8], TenantID: entry.TenantID,
			Scopes: entry.Scopes, Roles: entry.Roles, Plane: plane, Planes: planes, NodeID: entry.NodeID,
			AuthMethod: "static_token"}
	}
	return tokens
}

func collectStaticTokenTenantIDs() []string {
	raw := os.Getenv("KVLT_STATIC_TOKENS")
	if raw == "" {
		return nil
	}
	var entries []struct {
		TenantID string `json:"tenant_id"`
	}
	if json.Unmarshal([]byte(raw), &entries) != nil {
		return nil
	}
	seen := make(map[string]bool)
	var tenants []string
	for _, entry := range entries {
		if entry.TenantID != "" && !seen[entry.TenantID] {
			seen[entry.TenantID] = true
			tenants = append(tenants, entry.TenantID)
		}
	}
	return tenants
}

func staticTokenPlanes(rawPlane string, rawPlanes []string) (principal.Plane, []principal.Plane) {
	var planes []principal.Plane
	add := func(value string) {
		switch value {
		case "data":
			planes = append(planes, principal.PlaneData)
		case "ops":
			planes = append(planes, principal.PlaneOps)
		case "management", "":
			planes = append(planes, principal.PlaneManagement)
		}
	}
	if len(rawPlanes) == 0 {
		add(rawPlane)
	} else {
		for _, value := range rawPlanes {
			add(value)
		}
	}
	if len(planes) == 0 {
		planes = []principal.Plane{principal.PlaneManagement}
	}
	return planes[0], planes
}

func hashBaseline(value config.BaselineConfig) []byte {
	digest := sha256.Sum256([]byte(fmt.Sprintf("%v", value)))
	return digest[:]
}

func zeroize(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
