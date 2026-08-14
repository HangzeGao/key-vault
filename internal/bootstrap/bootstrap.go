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
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/kvlt/key-vault/internal/application/protection"
	"github.com/kvlt/key-vault/internal/audit/redaction"
	"github.com/kvlt/key-vault/internal/auditchain"
	"github.com/kvlt/key-vault/internal/auth/principal"
	"github.com/kvlt/key-vault/internal/config"
	"github.com/kvlt/key-vault/internal/domain/policy"
	"github.com/kvlt/key-vault/internal/downlink"
	"github.com/kvlt/key-vault/internal/policysig"
	"github.com/kvlt/key-vault/internal/protocol/ccsds"
	"github.com/kvlt/key-vault/internal/resolver/keyresolver"
	"github.com/kvlt/key-vault/internal/securitystate"
	"github.com/kvlt/key-vault/internal/tpm/provider"
)

const (
	storageName = "ccsds-ground-seal-v1"
)

// App contains only the modules used by the CCSDS ground system.
type App struct {
	Cfg                *config.Config
	Store              *securitystate.Store
	TPM                provider.Provider
	Resolver           *keyresolver.Resolver
	Downlink           *downlink.Service
	DownlinkSealer     *downlink.TPMSealer
	Policies           *policy.Engine
	PolicyMgr          *policysig.Manager
	CCSDSFrameSecurity *ccsds.FrameSecurity
	CCSDSStore         ccsds.Store
	AccessTokens       map[string]*principal.Principal
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
	accessTokens, err := loadAccessTokens(cfg)
	if err != nil {
		return nil, err
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
	if err := ensureTenants(ctx, store, accessTokens); err != nil {
		return nil, fmt.Errorf("bootstrap: tenants: %w", err)
	}

	tpm, err := buildTPM(cfg)
	if err != nil {
		return nil, err
	}
	policies := policy.NewEngine()
	baseline := hashBaseline(cfg.Baseline)
	policyDigest := sha256.Sum256([]byte("ccsds-default-policy-v1"))
	resolver := keyresolver.New(tpm)
	if err := resolver.Init(ctx, storageName, cfg.Server.NodeID, baseline, policyDigest[:]); err != nil {
		return nil, fmt.Errorf("bootstrap: protocol key resolver: %w", err)
	}
	resolver.SetFetchHook(func(ctx context.Context, keyVersionID string) ([]byte, error) {
		version, err := store.GetKeyVersion(ctx, keyVersionID)
		if err != nil {
			return nil, err
		}
		return version.SealedMaterial, nil
	})
	downlinkSealer, err := downlink.NewTPMSealer(ctx, tpm, storageName, cfg.Server.NodeID, baseline, policyDigest[:])
	if err != nil {
		return nil, fmt.Errorf("bootstrap: downlink TPM sealer: %w", err)
	}
	downlinkService := downlink.NewService(store, downlinkSealer)
	if err := downlinkService.Load(ctx); err != nil {
		return nil, fmt.Errorf("bootstrap: load downlink keys: %w", err)
	}

	auditChain := auditchain.New(store)
	policyMgr := policysig.New(policies, &policyAuditAdapter{audit: auditChain})
	if err := configureSignedPolicy(ctx, cfg, policyMgr); err != nil {
		return nil, err
	}

	protectionCore := protection.New(store, resolver, policies, cfg.CCSDS.MaxFrameLength)
	frameSecurity, err := ccsds.New(protectionCore, store, ccsds.Options{
		MaxFrameLength: cfg.CCSDS.MaxFrameLength,
		NodeID:         cfg.Server.NodeID,
		TCSpacecraftID: cfg.CCSDS.TCSpacecraftID,
	})
	if err != nil {
		return nil, fmt.Errorf("bootstrap: CCSDS frame security: %w", err)
	}

	return &App{
		Cfg: cfg, Store: store, TPM: tpm, Resolver: resolver, Downlink: downlinkService, DownlinkSealer: downlinkSealer,
		Policies: policies, PolicyMgr: policyMgr,
		CCSDSFrameSecurity: frameSecurity, CCSDSStore: store,
		AccessTokens: accessTokens, AuditChain: auditChain,
	}, nil
}

func buildTPM(cfg *config.Config) (provider.Provider, error) {
	switch cfg.TPM.Provider {
	case "swtpm":
		value, err := provider.NewSoftwareProvider(cfg.TPM.StateDir)
		if err != nil {
			return nil, fmt.Errorf("bootstrap: TPM: %w", err)
		}
		return value, nil
	case "native":
		value, err := provider.NewNativeProvider(provider.NativeOptions{TCTI: cfg.TPM.TCTI, PCRs: cfg.TPM.PolicyPCRs})
		if err != nil {
			return nil, fmt.Errorf("bootstrap: TPM: %w", err)
		}
		return value, nil
	default:
		return nil, fmt.Errorf("bootstrap: unknown TPM provider %q", cfg.TPM.Provider)
	}
}

func ensureTenants(ctx context.Context, store *securitystate.Store, accessTokens map[string]*principal.Principal) error {
	if err := store.EnsureTenant(ctx, "t-default", "default"); err != nil {
		return err
	}
	seenTenants := make(map[string]bool)
	for _, identity := range accessTokens {
		tenantID := identity.TenantID
		if tenantID == "" || tenantID == "t-default" {
			continue
		}
		if seenTenants[tenantID] {
			continue
		}
		seenTenants[tenantID] = true
		if err := store.EnsureTenant(ctx, tenantID, strings.TrimPrefix(tenantID, "t-")); err != nil {
			return err
		}
	}
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

func loadAccessTokens(cfg *config.Config) (map[string]*principal.Principal, error) {
	tokens := make(map[string]*principal.Principal)
	raw := []byte(os.Getenv("KVLT_ACCESS_TOKENS"))
	if cfg.Auth.AccessTokensFile != "" {
		var err error
		raw, err = os.ReadFile(cfg.Auth.AccessTokensFile)
		if err != nil {
			return nil, fmt.Errorf("bootstrap: read access token file: %w", err)
		}
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		if cfg.Environment == "production" {
			return nil, errors.New("bootstrap: production access tokens are not configured")
		}
		return tokens, nil
	}
	var entries []struct {
		Token    string   `json:"token"`
		TenantID string   `json:"tenant_id"`
		Scopes   []string `json:"scopes"`
		Plane    string   `json:"plane"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&entries); err != nil {
		return nil, fmt.Errorf("bootstrap: parse access tokens: %w", err)
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return nil, errors.New("bootstrap: trailing or invalid access token data")
	}
	if len(entries) != 2 {
		return nil, errors.New("bootstrap: exactly one Data token and one Ops token are required")
	}
	seenPlanes := make(map[principal.Plane]bool, 2)
	for _, entry := range entries {
		if len(entry.Token) < 32 || entry.TenantID == "" {
			return nil, errors.New("bootstrap: every access token must contain at least 32 characters and a tenant_id")
		}
		if cfg.Environment == "production" && len(entry.Token) < 43 {
			return nil, errors.New("bootstrap: production access tokens must contain at least 43 characters")
		}
		var plane principal.Plane
		switch entry.Plane {
		case "data":
			plane = principal.PlaneData
		case "ops":
			plane = principal.PlaneOps
		default:
			return nil, fmt.Errorf("bootstrap: access token plane %q must be data or ops", entry.Plane)
		}
		if seenPlanes[plane] {
			return nil, fmt.Errorf("bootstrap: duplicate %s plane access token", entry.Plane)
		}
		seenPlanes[plane] = true
		if !exactScopes(entry.Scopes, requiredScopes(plane)) {
			return nil, fmt.Errorf("bootstrap: %s token scopes do not match the fixed plane contract", entry.Plane)
		}
		if _, duplicate := tokens[entry.Token]; duplicate {
			return nil, errors.New("bootstrap: duplicate access token")
		}
		tokens[entry.Token] = &principal.Principal{ID: "static:" + entry.Token[:8], TenantID: entry.TenantID,
			Scopes: entry.Scopes, Plane: plane, AuthMethod: "access_token"}
	}
	return tokens, nil
}

func requiredScopes(plane principal.Plane) []string {
	if plane == principal.PlaneData {
		return []string{"ccsds:tc:protect", "ccsds:downlink:unprotect"}
	}
	return []string{"audit:read", "ops:read"}
}

func exactScopes(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	seen := make(map[string]bool, len(got))
	for _, scope := range got {
		if seen[scope] {
			return false
		}
		seen[scope] = true
	}
	for _, scope := range want {
		if !seen[scope] {
			return false
		}
	}
	return true
}

func hashBaseline(value config.BaselineConfig) []byte {
	digest := sha256.Sum256([]byte(fmt.Sprintf("%v", value)))
	return digest[:]
}
