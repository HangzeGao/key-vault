// Package bootstrap wires all components together for the engineering baseline service.
package bootstrap

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/kvlt/key-vault/internal/api/admin"
	cryptoapi "github.com/kvlt/key-vault/internal/api/crypto"
	tenantapi "github.com/kvlt/key-vault/internal/api/tenant"
	"github.com/kvlt/key-vault/internal/application/crypto"
	"github.com/kvlt/key-vault/internal/application/keys"
	"github.com/kvlt/key-vault/internal/application/keytransfer"
	"github.com/kvlt/key-vault/internal/auditchain"
	"github.com/kvlt/key-vault/internal/auth/hmacsign"
	"github.com/kvlt/key-vault/internal/auth/jwt"
	"github.com/kvlt/key-vault/internal/auth/principal"
	"github.com/kvlt/key-vault/internal/config"
	"github.com/kvlt/key-vault/internal/crypto/aad"
	"github.com/kvlt/key-vault/internal/crypto/envelope"
	"github.com/kvlt/key-vault/internal/crypto/nonce"
	"github.com/kvlt/key-vault/internal/domain/policy"
	"github.com/kvlt/key-vault/internal/lifecycle"
	"github.com/kvlt/key-vault/internal/outbox"
	"github.com/kvlt/key-vault/internal/policysig"
	"github.com/kvlt/key-vault/internal/repository"
	"github.com/kvlt/key-vault/internal/repository/memory"
	"github.com/kvlt/key-vault/internal/repository/models"
	"github.com/kvlt/key-vault/internal/repository/postgres"
	"github.com/kvlt/key-vault/internal/resolver/keyresolver"
	"github.com/kvlt/key-vault/internal/tpm/provider"
)

// App is the assembled application.
type App struct {
	Cfg                *config.Config
	Store              repository.Repository
	TPM                provider.Provider
	Resolver           *keyresolver.Resolver
	Policies           *policy.Engine
	PolicyMgr          *policysig.Manager
	KeyService         *keys.Service
	CryptoService      *crypto.Service
	KeyTransferService *keytransfer.Service
	NonceManager       *nonce.Manager
	JWTVerifier        *jwt.Verifier
	HMACVerifier       *hmacsign.Verifier
	StaticTokens       map[string]*principal.Principal
	EnvelopeRegistry   *envelope.Registry
	TenantHandler      *tenantapi.Handler
	AuditChain         *auditchain.Service
	OutboxSvc          *outbox.Service
	Worker             *lifecycle.Worker
}

// Build assembles the application from config.
func Build(ctx context.Context, cfg *config.Config) (*App, error) {
	for _, finding := range cfg.Diagnostics() {
		if finding.Level == "warn" {
			slog.Warn("configuration posture", "code", finding.Code, "message", finding.Message)
			continue
		}
		slog.Info("configuration posture", "code", finding.Code, "message", finding.Message)
	}
	// 1. Repository — memory for baseline, postgres for durable production storage.
	var store repository.Repository
	switch cfg.Database.Driver {
	case "memory", "":
		store = memory.New()
	case "postgres":
		pgStore, err := postgres.New(ctx, cfg.Database.DSN)
		if err != nil {
			return nil, fmt.Errorf("bootstrap: postgres: %w", err)
		}
		if err := pgStore.Migrate(ctx); err != nil {
			pgStore.Close()
			return nil, fmt.Errorf("bootstrap: postgres migrate: %w", err)
		}
		store = pgStore
		slog.Info("postgres storage initialized", "dsn_preview", safePreview(cfg.Database.DSN, 40))
	default:
		return nil, fmt.Errorf("bootstrap: unknown database driver %q (use 'memory' or 'postgres')", cfg.Database.Driver)
	}

	// 2. TPM provider.
	var tpm provider.Provider
	var err error
	switch cfg.TPM.Provider {
	case "swtpm", "software":
		tpm, err = provider.NewSoftwareProvider(cfg.TPM.StateDir)
		if err != nil {
			return nil, fmt.Errorf("bootstrap: tpm: %w", err)
		}
	case "tpm2", "hardware", "tpm2-tools":
		tpm, err = provider.NewHardwareProviderWithOptions(provider.HardwareOptions{
			StateDir: cfg.TPM.StateDir,
			ToolDir:  cfg.TPM.ToolDir,
			TCTI:     cfg.TPM.TCTI,
		})
		if err != nil {
			return nil, fmt.Errorf("bootstrap: tpm: %w", err)
		}
	case "tss", "esapi", "native":
		tpm, err = provider.NewNativeProvider(provider.NativeOptions{TCTI: cfg.TPM.TCTI, PCRs: cfg.TPM.PolicyPCRs})
		if err != nil {
			return nil, fmt.Errorf("bootstrap: native tpm: %w", err)
		}
	default:
		return nil, fmt.Errorf("bootstrap: unknown tpm provider %s", cfg.TPM.Provider)
	}

	// 3. Policy engine.
	polEng := policy.NewEngine()
	defPol := policy.DefaultPolicy()
	if err := polEng.Load(defPol); err != nil {
		return nil, fmt.Errorf("bootstrap: policy: %w", err)
	}

	// 4. Resolver.
	resolver := keyresolver.New(tpm, "kvlt-nrwk-v1", 5*time.Minute)

	// 5. Nonce manager. The allocator delegates to the store.
	alloc := &storeNonceAllocator{store: store}
	nonceMgr := nonce.NewManager(alloc, cfg.Nonce.LeaseSize,
		cfg.Nonce.PrefetchWatermark, cfg.Nonce.ThrottleWatermark, cfg.Nonce.LeaseTTL)

	// 6. Application services.
	keySvc := keys.New(store, resolver, polEng)
	cryptoSvc := crypto.New(store, resolver, polEng, nonceMgr, cfg.Server.MaxRequestBody)
	keyTransferSvc := keytransfer.New(store, resolver, keySvc)
	// 7. Auth verifiers.
	jwtVerifier := jwt.NewVerifier(cfg.Auth.JWTIssuer, cfg.Auth.JWTAudience, cfg.Auth.JWTAlgWhite)
	hmacVerifier := hmacsign.NewVerifier(cfg.Auth.HMACMaxSkew)

	// 8. Bootstrap: create default tenant, NRWK, CRK, CRK envelope.
	if err := bootstrapCluster(ctx, cfg, store, tpm, resolver); err != nil {
		return nil, fmt.Errorf("bootstrap: cluster: %w", err)
	}

	// 8b. Bootstrap: create default tenant envelope config.
	envelopeRegistry := envelope.DefaultRegistry()
	if err := bootstrapEnvelopeConfig(ctx, store); err != nil {
		return nil, fmt.Errorf("bootstrap: envelope config: %w", err)
	}
	tenantHandler := tenantapi.New(store, envelopeRegistry)

	// Wire resolver's fetch hook to the store.
	resolver.SetFetchDEKHook(func(ctx context.Context, keyVersionID string) ([]byte, []byte, error) {
		kv, err := store.GetKeyVersion(ctx, keyVersionID)
		if err != nil {
			return nil, nil, err
		}
		return kv.WrappedDEK, kv.WrapMetadata, nil
	})

	// Audit chain service.
	auditChain := auditchain.New(store)

	// Wire audit into key and crypto services (EB-FR-09).
	auditAdapter := &auditAdapter{ac: auditChain}
	keySvc.SetAuditor(auditAdapter)
	cryptoSvc.SetAuditor(&cryptoAuditAdapter{ac: auditChain})
	keyTransferSvc.SetAuditor(auditAdapter)

	// Outbox service.
	outboxSvc := outbox.New(store)

	// Policy signature manager.
	policyMgr := policysig.New(polEng, &policyAuditAdapter{ac: auditChain})
	// Generate an Ed25519 key pair for baseline policy signing.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("bootstrap: policy key: %w", err)
	}
	policyMgr.AddSigningKey("policy-key-v1", pub)
	signedPol, err := policysig.GenerateDefaultSignedPolicy(priv, "policy-key-v1")
	if err != nil {
		return nil, fmt.Errorf("bootstrap: signed policy: %w", err)
	}
	if err := policyMgr.LoadSigned(ctx, signedPol); err != nil {
		return nil, fmt.Errorf("bootstrap: load signed policy: %w", err)
	}

	// Lifecycle worker.
	worker := lifecycle.New(store, lifecycle.Config{
		OwnerID:             cfg.Lifecycle.OwnerID,
		LeaseTTL:            cfg.Lifecycle.LeaseTTL,
		MaxAttempts:         cfg.Lifecycle.MaxAttempts,
		PollInterval:        cfg.Lifecycle.PollInterval,
		ExpiryScanInterval:  cfg.Lifecycle.ExpiryScanInterval,
		ExpiryWarningWindow: cfg.Lifecycle.ExpiryWarningWindow,
	})
	worker.SetExpiryChecker(keySvc)
	worker.SetDestroyExecutor(keySvc)
	if err := keySvc.ReconcileDestroyDueJobs(ctx); err != nil {
		return nil, fmt.Errorf("bootstrap: reconcile destroy jobs: %w", err)
	}

	return &App{
		Cfg:                cfg,
		Store:              store,
		TPM:                tpm,
		Resolver:           resolver,
		Policies:           polEng,
		PolicyMgr:          policyMgr,
		KeyService:         keySvc,
		CryptoService:      cryptoSvc,
		KeyTransferService: keyTransferSvc,
		NonceManager:       nonceMgr,
		JWTVerifier:        jwtVerifier,
		HMACVerifier:       hmacVerifier,
		StaticTokens:       loadStaticTokens(),
		EnvelopeRegistry:   envelopeRegistry,
		TenantHandler:      tenantHandler,
		AuditChain:         auditChain,
		OutboxSvc:          outboxSvc,
		Worker:             worker,
	}, nil
}

// policyAuditAdapter connects the audit chain service to the policy manager Auditor interface.
type policyAuditAdapter struct {
	ac *auditchain.Service
}

func (a *policyAuditAdapter) RecordPolicyReload(ctx context.Context, policyID string, version uint32, result string, reason string) {
	_ = a.ac.Record(ctx, auditchain.RecordRequest{
		ActorType:    "system",
		ActorHash:    "system",
		Action:       "policy.reload",
		TargetType:   "policy",
		TargetIDHash: hashTruncate(policyID),
		Result:       result,
		Metadata:     map[string]string{"version": fmt.Sprintf("%d", version), "reason": reason},
	})
}

// auditAdapter adapts the auditchain.Service to the keys.Auditor interface.
// It hashes the principal ID and target ID for privacy per design §15.1 and INV-09.
type auditAdapter struct {
	ac *auditchain.Service
}

// Record implements keys.Auditor.
func (a *auditAdapter) Record(ctx context.Context, req keys.AuditRequest) error {
	return a.ac.Record(ctx, auditchain.RecordRequest{
		ActorType:    "principal",
		ActorHash:    hashTruncate(req.PrincipalID),
		TenantID:     req.TenantID,
		Action:       req.Action,
		TargetType:   req.TargetType,
		TargetIDHash: hashTruncate(req.TargetID),
		Result:       req.Result,
		ErrorCode:    req.ErrorCode,
		Metadata:     req.Metadata,
	})
}

// cryptoAuditAdapter adapts the auditchain.Service to the crypto.Auditor interface.
type cryptoAuditAdapter struct {
	ac *auditchain.Service
}

// Record implements crypto.Auditor.
func (a *cryptoAuditAdapter) Record(ctx context.Context, req crypto.AuditRequest) error {
	return a.ac.Record(ctx, auditchain.RecordRequest{
		ActorType:    "principal",
		ActorHash:    hashTruncate(req.PrincipalID),
		TenantID:     req.TenantID,
		Action:       req.Action,
		TargetType:   req.TargetType,
		TargetIDHash: hashTruncate(req.TargetID),
		Result:       req.Result,
		ErrorCode:    req.ErrorCode,
		Metadata:     req.Metadata,
	})
}

func hashTruncate(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:8])
}

// loadStaticTokens reads static token → principal mappings from the
// KVLT_STATIC_TOKENS env var (JSON array of {token, principal} objects).
// This is a development convenience. In production, use JWT/HMAC.
func loadStaticTokens() map[string]*principal.Principal {
	tokens := make(map[string]*principal.Principal)
	raw := os.Getenv("KVLT_STATIC_TOKENS")
	if raw == "" {
		slog.Warn("KVLT_STATIC_TOKENS env var is empty; static token auth disabled")
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
		slog.Error("KVLT_STATIC_TOKENS JSON parse failed; static token auth disabled",
			"error", err, "raw_len", len(raw), "raw_first_40", safePreview(raw, 40))
		return tokens
	}
	for _, e := range entries {
		if len(e.Token) < 8 {
			slog.Warn("static token too short, skipping", "token_len", len(e.Token))
			continue
		}
		plane, planes := staticTokenPlanes(e.Plane, e.Planes)
		tokens[e.Token] = &principal.Principal{
			ID:         "static:" + e.Token[:8],
			TenantID:   e.TenantID,
			Scopes:     e.Scopes,
			Roles:      e.Roles,
			Plane:      plane,
			Planes:     planes,
			NodeID:     e.NodeID,
			AuthMethod: "static_token",
		}
	}
	slog.Info("static tokens loaded", "count", len(tokens))
	return tokens
}

// collectStaticTokenTenantIDs parses KVLT_STATIC_TOKENS and returns the unique
// set of tenant_id values declared across all entries. Used during bootstrap
// to auto-create tenants referenced by static tokens.
func collectStaticTokenTenantIDs() []string {
	raw := os.Getenv("KVLT_STATIC_TOKENS")
	if raw == "" {
		return nil
	}
	var entries []struct {
		TenantID string `json:"tenant_id"`
	}
	if err := json.Unmarshal([]byte(raw), &entries); err != nil {
		return nil
	}
	seen := make(map[string]struct{})
	var ids []string
	for _, e := range entries {
		if e.TenantID == "" {
			continue
		}
		if _, ok := seen[e.TenantID]; ok {
			continue
		}
		seen[e.TenantID] = struct{}{}
		ids = append(ids, e.TenantID)
	}
	return ids
}

func staticTokenPlanes(plane string, rawPlanes []string) (principal.Plane, []principal.Plane) {
	planes := make([]principal.Plane, 0, len(rawPlanes)+1)
	add := func(raw string) {
		switch raw {
		case "data":
			planes = append(planes, principal.PlaneData)
		case "ops":
			planes = append(planes, principal.PlaneOps)
		case "management", "":
			planes = append(planes, principal.PlaneManagement)
		}
	}
	if len(rawPlanes) == 0 {
		add(plane)
	} else {
		for _, raw := range rawPlanes {
			add(raw)
		}
	}
	if len(planes) == 0 {
		planes = append(planes, principal.PlaneManagement)
	}
	return planes[0], planes
}

// safePreview returns the first n bytes of s for diagnostic logging.
// It does not leak full token values.
func safePreview(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// bootstrapCluster creates the default tenant, NRWK, CRK, and CRK envelope.
func bootstrapCluster(ctx context.Context, cfg *config.Config, store repository.Repository,
	tpm provider.Provider, resolver *keyresolver.Resolver) error {
	// Default tenant.
	tenant := &models.Tenant{
		ID:     "t-default",
		Name:   "default",
		Status: "active",
	}
	if err := store.UpsertTenant(ctx, tenant); err != nil {
		return err
	}

	// Auto-create tenants referenced by static tokens (e.g. t-admin, t-data,
	// t-ops). Static token config may declare tenant_id values that don't
	// exist in the store yet; without this, API calls that validate tenant
	// existence (CreateKey, ImportKey) return "tenant not found".
	for _, tid := range collectStaticTokenTenantIDs() {
		if tid == "" || tid == "t-default" {
			continue
		}
		t := &models.Tenant{
			ID:     tid,
			Name:   strings.TrimPrefix(tid, "t-"),
			Status: "active",
		}
		if err := store.UpsertTenant(ctx, t); err != nil {
			return fmt.Errorf("bootstrap: upsert static token tenant %q: %w", tid, err)
		}
		slog.Info("auto-created tenant from static token config", "tenant_id", tid)
	}

	// Initialize resolver (loads/creates NRWK).
	baseline := hashBaseline(cfg.Baseline)
	policyDigest := sha256.Sum256([]byte("kvlt-default-policy-v1"))
	if err := resolver.Init(ctx, "kvlt-cluster-v1", "node-bootstrap", "management", baseline, policyDigest[:]); err != nil {
		return err
	}

	// Create CRK version if none exists.
	latestCRK, err := store.GetLatestCRKVersion(ctx)
	if err == nil {
		// Already bootstrapped — load the persisted CRK envelope into the resolver.
		// Without this, the resolver has no CRK envelope and DEK lease/unwrap fails
		// with "no CRK envelope" after a restart with durable storage.
		crkEnv, gerr := store.GetCRKNodeEnvelope(ctx, latestCRK.ID, "node-bootstrap")
		if gerr != nil {
			return fmt.Errorf("bootstrap: load crk envelope: %w", gerr)
		}
		var env provider.CRKEnvelope
		if err := json.Unmarshal(crkEnv.Envelope, &env); err != nil {
			return fmt.Errorf("bootstrap: decode crk envelope: %w", err)
		}
		resolver.SetCRKEnvelope(&env)
		slog.Info("crk envelope loaded from store", "crk_version", latestCRK.Version)
		return nil
	} else if !errors.Is(err, repository.ErrNotFound) {
		return err
	}

	// Generate CRK plaintext (32 bytes).
	crk := make([]byte, 32)
	if _, err := rand.Read(crk); err != nil {
		return fmt.Errorf("bootstrap: rand crk: %w", err)
	}

	// Create CRK version record.
	crkVer := &models.CRKVersion{
		ID:        "crk-v1",
		Version:   1,
		Epoch:     1,
		Status:    "active",
		CreatedAt: time.Now().UTC(),
	}
	if err := store.CreateCRKVersion(ctx, crkVer); err != nil {
		return err
	}

	// Seal CRK under NRWK.
	nrwk, err := tpm.EnsureNRWK(ctx, "kvlt-nrwk-v1")
	if err != nil {
		return err
	}
	a := aad.CRKAAD{
		ClusterID:      "kvlt-cluster-v1",
		NodeID:         "node-bootstrap",
		PlaneRole:      "management",
		CRKVersion:     1,
		NRWKName:       "kvlt-nrwk-v1",
		BaselineDigest: baseline,
		PolicyDigest:   policyDigest[:],
	}
	env, err := tpm.SealCRK(ctx, nrwk, crk, a)
	if err != nil {
		return fmt.Errorf("bootstrap: seal crk: %w", err)
	}

	// Persist CRK envelope (JSON-encoded).
	envBytes, err := json.Marshal(env)
	if err != nil {
		return err
	}
	crkNodeEnv := &models.CRKNodeEnvelope{
		ID:           "crkenv-bootstrap",
		CRKVersionID: crkVer.ID,
		NodeID:       "node-bootstrap",
		Envelope:     envBytes,
	}
	if err := store.CreateCRKNodeEnvelope(ctx, crkNodeEnv); err != nil {
		return err
	}

	// Cache envelope in resolver.
	resolver.SetCRKEnvelope(env)
	return nil
}

// bootstrapEnvelopeConfig creates the default tenant envelope config for t-default.
func bootstrapEnvelopeConfig(ctx context.Context, store repository.Repository) error {
	_, err := store.GetTenantEnvelopeConfig(ctx, "t-default")
	if err == nil {
		// Already configured.
		return nil
	}
	cfg := &models.TenantEnvelopeConfig{
		TenantID:      "t-default",
		DefaultFormat: string(envelope.FormatJSONV1),
		AllowedFormats: []string{
			string(envelope.FormatJSONV1),
			string(envelope.FormatConfigurableJSONV1),
		},
		Profiles: []models.EnvelopeFormatProfile{
			{
				FormatID: string(envelope.FormatConfigurableJSONV1),
				Adapter:  string(envelope.FormatConfigurableJSONV1),
			},
		},
		UpdatedBy: "bootstrap",
	}
	return store.UpsertTenantEnvelopeConfig(ctx, cfg)
}

// storeNonceAllocator adapts the repository to the nonce.Allocator interface.
type storeNonceAllocator struct {
	store repository.Repository
}

func (a *storeNonceAllocator) AllocateRange(keyVersionID, nodeID string, domain uint32, size uint64, ttl time.Duration) (*nonce.Lease, error) {
	ctx := context.Background()
	nl, err := a.store.AllocateNonceRange(ctx, keyVersionID, nodeID, domain, size, ttl)
	if err != nil {
		return nil, err
	}
	return &nonce.Lease{
		LeaseID:      nl.LeaseID,
		KeyVersionID: nl.KeyVersionID,
		NodeID:       nl.NodeID,
		Domain:       nl.Domain,
		StartCounter: nl.StartCounter,
		EndCounter:   nl.EndCounter,
		UsedCounter:  nl.UsedCounter,
		ExpiresAt:    nl.ExpiresAt,
		Status:       nonce.LeaseStatus(nl.Status),
	}, nil
}

func (a *storeNonceAllocator) UpdateUsed(leaseID string, used uint64) error {
	return a.store.UpdateNonceUsed(context.Background(), leaseID, used)
}

func (a *storeNonceAllocator) GetLease(leaseID string) (*nonce.Lease, error) {
	nl, err := a.store.GetNonceLease(context.Background(), leaseID)
	if err != nil {
		return nil, err
	}
	return &nonce.Lease{
		LeaseID:      nl.LeaseID,
		KeyVersionID: nl.KeyVersionID,
		NodeID:       nl.NodeID,
		Domain:       nl.Domain,
		StartCounter: nl.StartCounter,
		EndCounter:   nl.EndCounter,
		UsedCounter:  nl.UsedCounter,
		ExpiresAt:    nl.ExpiresAt,
		Status:       nonce.LeaseStatus(nl.Status),
	}, nil
}

func hashBaseline(b config.BaselineConfig) []byte {
	h := sha256.New()
	h.Write([]byte(fmt.Sprintf("%v", b)))
	return h.Sum(nil)
}

// hexEncode is a small helper retained for diagnostic output.
func hexEncode(b []byte) string { return hex.EncodeToString(b) }

// _ unused import guard.
var (
	_ = admin.New
	_ = cryptoapi.New
	_ = json.Marshal
)
