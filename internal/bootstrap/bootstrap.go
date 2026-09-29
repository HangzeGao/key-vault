package bootstrap

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/kvlt/key-vault/internal/application/protection"
	"github.com/kvlt/key-vault/internal/audit/redaction"
	"github.com/kvlt/key-vault/internal/auditchain"
	"github.com/kvlt/key-vault/internal/auth/access"
	"github.com/kvlt/key-vault/internal/config"
	"github.com/kvlt/key-vault/internal/domain/policy"
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
	Cfg      *config.Config
	Store    *securitystate.Store
	TPM      provider.Provider
	Resolver *keyresolver.Resolver
	downlinkState
	Policies           *policy.Engine
	PolicyMgr          *policysig.Manager
	CCSDSFrameSecurity *ccsds.FrameSecurity
	CCSDSStore         ccsds.Store
	AccessVerifier     *access.Verifier
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
	accessVerifier, err := loadAccessVerifier(cfg)
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
	if err := ensureTenants(ctx, store, accessVerifier); err != nil {
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
	downlinkState, err := initDownlink(ctx, tpm, store, cfg, baseline, policyDigest[:])
	if err != nil {
		return nil, err
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
		Cfg: cfg, Store: store, TPM: tpm, Resolver: resolver, downlinkState: downlinkState,
		Policies: policies, PolicyMgr: policyMgr,
		CCSDSFrameSecurity: frameSecurity, CCSDSStore: store,
		AccessVerifier: accessVerifier, AuditChain: auditChain,
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

func ensureTenants(ctx context.Context, store *securitystate.Store, verifier *access.Verifier) error {
	if err := store.EnsureTenant(ctx, "t-default", "default"); err != nil {
		return err
	}
	if tenantID := verifier.TenantID(); tenantID != "" && tenantID != "t-default" {
		return store.EnsureTenant(ctx, tenantID, strings.TrimPrefix(tenantID, "t-"))
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

func loadAccessVerifier(cfg *config.Config) (*access.Verifier, error) {
	if cfg.Auth.TokenVerifiersFile == "" {
		if cfg.Environment == "production" {
			return nil, errors.New("bootstrap: production token verifiers are not configured")
		}
		return nil, nil
	}
	verifier, err := access.LoadVerifier(cfg.Auth.TokenVerifiersFile)
	if err != nil {
		return nil, fmt.Errorf("bootstrap: access verifier: %w", err)
	}
	return verifier, nil
}

func hashBaseline(value config.BaselineConfig) []byte {
	digest := sha256.Sum256([]byte(fmt.Sprintf("%v", value)))
	return digest[:]
}
