// Package crypto implements the Crypto application service.
package crypto

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/kvlt/key-vault/internal/crypto/envelope"
	cryptomac "github.com/kvlt/key-vault/internal/crypto/mac"
	"github.com/kvlt/key-vault/internal/crypto/nonce"
	cryptosuite "github.com/kvlt/key-vault/internal/crypto/suite"
	keystate "github.com/kvlt/key-vault/internal/domain/key/state"
	"github.com/kvlt/key-vault/internal/domain/policy"
	"github.com/kvlt/key-vault/internal/errorsx"
	"github.com/kvlt/key-vault/internal/repository/models"
	"github.com/kvlt/key-vault/internal/resolver/keyresolver"
)

// EncryptCommand is the input for Encrypt.
type EncryptCommand struct {
	TenantID       string
	KeyID          string
	Plaintext      []byte
	AAD            []byte
	NodeID         string
	PrincipalID    string
	EnvelopeFormat string
	Extensions     map[string]any
}

// EncryptResult is the output of Encrypt.
type EncryptResult struct {
	KeyID          string
	KeyVersion     uint32
	SuiteID        string
	ServiceType    cryptosuite.ServiceType
	Ciphertext     []byte // Envelope v1 bytes
	EnvelopeFormat string
}

// DecryptCommand is the input for Decrypt.
type DecryptCommand struct {
	TenantID       string
	Ciphertext     []byte // Envelope v1 bytes
	AAD            []byte
	PrincipalID    string
	EnvelopeFormat string
}

// DecryptResult is the output of Decrypt.
type DecryptResult struct {
	KeyID      string
	KeyVersion uint32
	Plaintext  []byte
}

// Authenticator is a detached, versioned CMAC result. All metadata fields are
// included in the MAC input and therefore cannot be changed independently.
type Authenticator struct {
	Version       uint8
	SuiteID       string
	ServiceType   cryptosuite.ServiceType
	KeyID         string
	KeyVersion    uint32
	PolicyVersion uint32
	Tag           []byte
}

type AuthenticateCommand struct {
	TenantID    string
	KeyID       string
	Message     []byte
	PrincipalID string
}

type AuthenticateResult struct {
	Authenticator Authenticator
}

type VerifyCommand struct {
	TenantID      string
	Message       []byte
	Authenticator Authenticator
	PrincipalID   string
}

type VerifyResult struct {
	Valid bool
}

// ConvertEnvelopeCommand changes only the approved outer representation of an
// existing envelope. It never decrypts, alters core fields, or accepts caller
// supplied replacements for authenticated values.
type ConvertEnvelopeCommand struct {
	TenantID     string
	Ciphertext   []byte
	SourceFormat string
	TargetFormat string
	PrincipalID  string
}

// ConvertEnvelopeResult contains the normalized envelope in its new format.
type ConvertEnvelopeResult struct {
	Ciphertext     []byte
	EnvelopeFormat string
}

type InspectEnvelopeCommand struct {
	TenantID     string
	Ciphertext   []byte
	SourceFormat string
}
type InspectEnvelopeResult struct {
	Format          string                  `json:"format"`
	Version         uint8                   `json:"version"`
	Flags           uint16                  `json:"flags"`
	SuiteID         string                  `json:"suite_id"`
	ServiceType     cryptosuite.ServiceType `json:"service_type"`
	KeyID           string                  `json:"key_id"`
	KeyVersion      uint32                  `json:"key_version"`
	PolicyVersion   uint32                  `json:"policy_version"`
	NonceBytes      int                     `json:"nonce_bytes"`
	TagBytes        int                     `json:"tag_bytes"`
	CiphertextBytes int                     `json:"ciphertext_bytes"`
	AADHash         string                  `json:"aad_hash,omitempty"`
}

// Store is the repository subset used by the crypto service.
type Store interface {
	GetKey(ctx context.Context, tenantID, keyID string) (*models.Key, error)
	GetKeyVersionByNo(ctx context.Context, keyID string, versionNo uint32) (*models.KeyVersion, error)
	GetCurrentKeyVersion(ctx context.Context, keyID string) (*models.KeyVersion, error)
	AllocateNonceRange(ctx context.Context, keyVersionID, nodeID string, domain uint32, size uint64, ttl time.Duration) (*models.NonceLease, error)
	UpdateNonceUsed(ctx context.Context, leaseID string, used uint64) error
	GetNonceLease(ctx context.Context, leaseID string) (*models.NonceLease, error)
	ClusterEpoch(ctx context.Context) (uint64, error)
	GetTenantEnvelopeConfig(ctx context.Context, tenantID string) (*models.TenantEnvelopeConfig, error)
}

// Service is the crypto application service.
type Service struct {
	store       Store
	resolver    *keyresolver.Resolver
	policies    *policy.Engine
	nonceMgr    *nonce.Manager
	maxBodySize int
	auditor     Auditor
}

const maxCallerAADLen = 64 * 1024
const purposeEncryptDecrypt = "encrypt_decrypt"
const purposeAuthenticateVerify = "authenticate_verify"
const defaultTenantID = "t-default"

// Auditor records audit events for crypto operations (design §15.1, EB-FR-09).
type Auditor interface {
	Record(ctx context.Context, req AuditRequest) error
}

// AuditRequest is the audit event input from the crypto service.
type AuditRequest struct {
	Action      string
	TenantID    string
	PrincipalID string
	TargetType  string
	TargetID    string
	Result      string // "success" | "failure"
	ErrorCode   string
	Metadata    map[string]string
}

// noopAuditor discards all audit events. Used when no auditor is wired.
type noopAuditor struct{}

func (noopAuditor) Record(context.Context, AuditRequest) error { return nil }

// New constructs a crypto service.
func New(store Store, resolver *keyresolver.Resolver, policies *policy.Engine,
	nonceMgr *nonce.Manager, maxBodySize int) *Service {
	return &Service{
		store:       store,
		resolver:    resolver,
		policies:    policies,
		nonceMgr:    nonceMgr,
		maxBodySize: maxBodySize,
		auditor:     noopAuditor{},
	}
}

// SetAuditor wires the audit dependency. Must be called before serving requests.
func (s *Service) SetAuditor(a Auditor) {
	if a != nil {
		s.auditor = a
	}
}

// audit records a crypto audit event.
func (s *Service) audit(ctx context.Context, action, tenantID, principalID, keyID, result, errorCode string, metadata map[string]string) {
	_ = s.auditor.Record(ctx, AuditRequest{
		Action:      action,
		TenantID:    tenantID,
		PrincipalID: principalID,
		TargetType:  "key",
		TargetID:    keyID,
		Result:      result,
		ErrorCode:   errorCode,
		Metadata:    metadata,
	})
}

// Encrypt performs server-side encryption per design §9.4.
func (s *Service) Encrypt(ctx context.Context, cmd EncryptCommand) (*EncryptResult, error) {
	if cmd.TenantID == "" {
		cmd.TenantID = defaultTenantID
	}
	if cmd.KeyID == "" {
		return nil, errorsx.New(errorsx.CodeInvalidArgument, "key_id is required", false)
	}
	if len(cmd.Plaintext) > s.maxBodySize {
		return nil, errorsx.New(errorsx.CodeBadRequest, "plaintext exceeds max size", false)
	}
	if len(cmd.AAD) > maxCallerAADLen {
		return nil, errorsx.New(errorsx.CodeBadRequest, "aad exceeds max size", false)
	}
	tenantCfg, _ := s.store.GetTenantEnvelopeConfig(ctx, cmd.TenantID)
	k, err := s.store.GetKey(ctx, cmd.TenantID, cmd.KeyID)
	if err != nil {
		return nil, errorsx.New(errorsx.CodeKeyNotFound, "key not found", false)
	}
	if !genericUsageAllowed(k) {
		return nil, errorsx.New(errorsx.CodePolicyDenied, "protocol-scoped key cannot be used by the generic crypto interface", false)
	}
	if k.Purpose != purposeEncryptDecrypt {
		return nil, errorsx.New(errorsx.CodePolicyDenied, "key purpose does not permit encryption", false)
	}
	if keyExpired(k) {
		return nil, errorsx.New(errorsx.CodeKeyDisabled, "key expired", false)
	}
	if !keystate.CanEncrypt(keystate.KeyStatus(k.Status)) {
		return nil, errorsx.New(errorsx.CodeKeyDisabled, "key not active for encryption", false)
	}
	// Validate suite against policy.
	pol, err := s.policies.Get(k.PolicyID)
	if err != nil {
		return nil, errorsx.New(errorsx.CodePolicyDenied, "policy not found", false)
	}
	suite, err := pol.SuiteByID(k.SuiteID)
	if err != nil {
		return nil, errorsx.New(errorsx.CodePolicyDenied, "suite not in policy", false)
	}
	if !policy.CanCreate(suite.Status) {
		return nil, errorsx.New(errorsx.CodePolicyDenied, "suite not available for encryption", false)
	}
	suiteEnum, err := cryptosuite.Parse(k.SuiteID)
	if err != nil {
		return nil, errorsx.New(errorsx.CodePolicyDenied, "invalid suite_id", false)
	}
	if !suiteEnum.Supports(cryptosuite.OperationEncrypt) {
		return nil, errorsx.New(errorsx.CodePolicyDenied, "suite does not provide encryption", false)
	}
	if suiteEnum.AuthenticatesAAD() {
		if err := validateTenantAADPolicy(tenantCfg, cmd.AAD); err != nil {
			return nil, err
		}
	} else if len(cmd.AAD) != 0 {
		return nil, errorsx.New(errorsx.CodeBadRequest, "aad_b64 is not supported by CTR suites", false)
	}

	// Get current key version.
	kv, err := s.store.GetCurrentKeyVersion(ctx, cmd.KeyID)
	if err != nil {
		return nil, errorsx.Wrap(errorsx.CodeInternal, "version fetch failed", false, err)
	}
	if !keystate.KVCanEncrypt(keystate.KeyVersionStatus(kv.Status)) {
		return nil, errorsx.New(errorsx.CodeKeyDisabled, "key version not active", false)
	}

	// Issue DEK lease (CRK critical section inside resolver).
	lease, err := s.resolver.IssueDEKLease(ctx, kv.ID, k.ID, kv.VersionNo, suiteEnum,
		cmd.TenantID, "", cmd.NodeID)
	if err != nil {
		return nil, errorsx.Wrap(errorsx.CodeTPMUnavailable, "dek lease failed", true, err)
	}

	// GCM and CTR both consume the same durable 96-bit uniqueness lease.
	// CTR expands that unique prefix into a 128-bit initial counter.
	var nonceBytes []byte
	if suiteEnum.NonceLen() > 0 {
		epoch, err := s.store.ClusterEpoch(ctx)
		if err != nil {
			return nil, errorsx.Wrap(errorsx.CodeInternal, "epoch fetch failed", false, err)
		}
		nonceLease, err := s.nonceMgr.GetLeaseForUse(cmd.NodeID, kv.ID, epoch)
		if err != nil {
			if errors.Is(err, nonce.ErrFrozen) {
				return nil, errorsx.New(errorsx.CodeNodeFrozen, "node frozen", false)
			}
			return nil, errorsx.Wrap(errorsx.CodeNonceExhausted, "nonce lease failed", true, err)
		}
		nonceBytes, err = s.nonceMgr.NextNonce(nonceLease.LeaseID)
		if err != nil {
			return nil, errorsx.Wrap(errorsx.CodeNonceExhausted, "nonce exhausted", true, err)
		}
		if suiteEnum.ServiceType() == cryptosuite.ServiceEncryptOnly {
			nonceBytes, err = nonce.CTRInitialCounter(nonceBytes)
			if err != nil {
				return nil, errorsx.Wrap(errorsx.CodeInternal, "ctr initial counter failed", false, err)
			}
		}
	}

	// Seal envelope.
	envBytes, err := envelope.Seal(suiteEnum, lease.DEK, cmd.KeyID, kv.VersionNo,
		pol.Version, nonceBytes, cmd.Plaintext, cmd.AAD)
	// Zeroize DEK lease plaintext copy after use.
	defer zeroize(lease.DEK)
	if err != nil {
		return nil, errorsx.Wrap(errorsx.CodeInternal, "seal failed", false, err)
	}
	format := envelope.FormatID(cmd.EnvelopeFormat)
	if format == "" {
		// Look up tenant's default envelope format (design §8.6).
		if tenantCfg != nil {
			format = envelope.FormatID(tenantCfg.DefaultFormat)
		}
		if format == "" || !envelopeFormatKnown(tenantCfg, format) {
			format = envelope.FormatJSONV1
		}
	} else {
		// Validate requested format against tenant's allowed_formats whitelist.
		if !envelopeFormatAllowed(tenantCfg, format) {
			return nil, errorsx.New(errorsx.CodePolicyDenied, "envelope format not allowed for tenant", false)
		}
	}
	parsed, err := envelope.Parse(envBytes)
	if err != nil {
		return nil, errorsx.Wrap(errorsx.CodeInternal, "envelope parse failed", false, err)
	}
	profile := envelopeProfile(tenantCfg, format)
	envBytes, err = envelope.DefaultRegistry().EncodeWithProfile(profile, parsed, envelope.RenderContext{Extensions: cmd.Extensions})
	if err != nil {
		return nil, errorsx.Wrap(errorsx.CodePolicyDenied, "envelope format not allowed", false, err)
	}
	auditMetadata := map[string]string{
		"key_version": fmt.Sprintf("%d", kv.VersionNo),
		"node_id":     cmd.NodeID,
	}
	if suiteEnum.AuthenticatesAAD() {
		auditMetadata["aad_hash"] = sha256Hex(cmd.AAD)
	}
	s.audit(ctx, "encrypt.success", cmd.TenantID, cmd.PrincipalID, cmd.KeyID, "success", "", auditMetadata)
	return &EncryptResult{
		KeyID:          cmd.KeyID,
		KeyVersion:     kv.VersionNo,
		SuiteID:        k.SuiteID,
		ServiceType:    suiteEnum.ServiceType(),
		Ciphertext:     envBytes,
		EnvelopeFormat: string(format),
	}, nil
}

// Decrypt performs server-side decryption per design §9.5.
func (s *Service) Decrypt(ctx context.Context, cmd DecryptCommand) (*DecryptResult, error) {
	if cmd.TenantID == "" {
		cmd.TenantID = defaultTenantID
	}
	if len(cmd.Ciphertext) > s.maxBodySize*2 {
		return nil, errorsx.New(errorsx.CodeBadRequest, "ciphertext exceeds max size", false)
	}
	if len(cmd.AAD) > maxCallerAADLen {
		return nil, errorsx.New(errorsx.CodeBadRequest, "aad exceeds max size", false)
	}
	registry := envelope.DefaultRegistry()
	format := envelope.FormatID(cmd.EnvelopeFormat)
	tenantCfg, _ := s.store.GetTenantEnvelopeConfig(ctx, cmd.TenantID)
	profile, env, err := detectEnvelopeProfile(registry, tenantCfg, format, cmd.Ciphertext)
	if err != nil {
		return nil, errorsx.New(errorsx.CodeEnvelopeInvalid, "envelope invalid", false)
	}
	// Look up key by env.KeyID, scoped to tenant.
	k, err := s.store.GetKey(ctx, cmd.TenantID, string(env.KeyID))
	if err != nil {
		return nil, errorsx.New(errorsx.CodeKeyNotFound, "key not found", false)
	}
	if !genericUsageAllowed(k) {
		return nil, errorsx.New(errorsx.CodePolicyDenied, "protocol-scoped key cannot be used by the generic crypto interface", false)
	}
	if k.Purpose != purposeEncryptDecrypt {
		return nil, errorsx.New(errorsx.CodePolicyDenied, "key purpose does not permit decryption", false)
	}
	if keyExpired(k) {
		return nil, errorsx.New(errorsx.CodeKeyDisabled, "key expired", false)
	}
	if !keystate.CanDecrypt(keystate.KeyStatus(k.Status)) {
		return nil, errorsx.New(errorsx.CodeKeyDestroyed, "key destroyed", false)
	}
	// Look up exact key version (not current).
	kv, err := s.store.GetKeyVersionByNo(ctx, k.ID, env.KeyVersion)
	if err != nil {
		return nil, errorsx.New(errorsx.CodeKeyNotFound, "key version not found", false)
	}
	if !keystate.KVCanDecrypt(keystate.KeyVersionStatus(kv.Status)) {
		return nil, errorsx.New(errorsx.CodeKeyDestroyed, "key version destroyed", false)
	}
	suiteEnum, suiteErr := cryptosuite.Parse(k.SuiteID)
	if suiteErr != nil || uint16(suiteEnum) != uint16(env.SuiteID) {
		return nil, errorsx.New(errorsx.CodeEnvelopeInvalid, "envelope suite does not match key", false)
	}
	if !suiteEnum.Supports(cryptosuite.OperationDecrypt) {
		return nil, errorsx.New(errorsx.CodeEnvelopeInvalid, "envelope suite does not support decryption", false)
	}
	// Decryption is governed by the exact policy version authenticated in the
	// Envelope, not by whichever version is current when the request arrives.
	// Historical versions remain in the policy catalog for this decision.
	historicalPolicy, err := s.policies.GetVersion(k.PolicyID, env.PolicyVersion)
	if err != nil {
		return nil, errorsx.New(errorsx.CodePolicyDenied, "envelope policy version unavailable", false)
	}
	historicalSuite, err := historicalPolicy.SuiteByID(k.SuiteID)
	if err != nil || !policy.CanConsume(historicalSuite.Status) {
		return nil, errorsx.New(errorsx.CodePolicyDenied, "suite not available for decryption under envelope policy", false)
	}
	if suiteEnum.AuthenticatesAAD() {
		if err := validateTenantAADPolicy(tenantCfg, cmd.AAD); err != nil {
			return nil, err
		}
	} else if len(cmd.AAD) != 0 {
		return nil, errorsx.New(errorsx.CodeBadRequest, "aad_b64 is not supported by CTR suites", false)
	}
	if suiteEnum.AuthenticatesAAD() && !env.VerifyAADHash(cmd.AAD) {
		s.audit(ctx, "decrypt.failure", cmd.TenantID, cmd.PrincipalID, k.ID, "failure", "AAD_MISMATCH", map[string]string{"aad_hash": sha256Hex(cmd.AAD)})
		return nil, errorsx.New(errorsx.CodeAADMismatch, "decrypt failed", false)
	}

	// Issue DEK lease (decrypt path).
	lease, err := s.resolver.IssueDEKLease(ctx, kv.ID, k.ID, kv.VersionNo, suiteEnum,
		cmd.TenantID, "", "")
	if err != nil {
		return nil, errorsx.Wrap(errorsx.CodeTPMUnavailable, "dek lease failed", true, err)
	}
	defer zeroize(lease.DEK)

	// Open envelope.
	_, pt, err := registry.OpenWithProfile(profile, cmd.Ciphertext, lease.DEK, cmd.AAD)
	if err != nil {
		s.audit(ctx, "decrypt.failure", cmd.TenantID, cmd.PrincipalID, k.ID, "failure", "AAD_MISMATCH", map[string]string{
			"aad_hash": sha256Hex(cmd.AAD),
		})
		return nil, errorsx.New(errorsx.CodeAADMismatch, "decrypt failed", false)
	}
	auditMetadata := map[string]string{"key_version": fmt.Sprintf("%d", kv.VersionNo)}
	if suiteEnum.AuthenticatesAAD() {
		auditMetadata["aad_hash"] = sha256Hex(cmd.AAD)
	}
	s.audit(ctx, "decrypt.success", cmd.TenantID, cmd.PrincipalID, k.ID, "success", "", auditMetadata)
	return &DecryptResult{
		KeyID:      k.ID,
		KeyVersion: kv.VersionNo,
		Plaintext:  pt,
	}, nil
}

// Authenticate computes a detached CMAC. The message is returned unchanged by
// definition; only the authenticator and its cryptographically bound metadata
// are produced.
func (s *Service) Authenticate(ctx context.Context, cmd AuthenticateCommand) (*AuthenticateResult, error) {
	if cmd.TenantID == "" {
		cmd.TenantID = defaultTenantID
	}
	if cmd.KeyID == "" {
		return nil, errorsx.New(errorsx.CodeInvalidArgument, "key_id is required", false)
	}
	if len(cmd.Message) > s.maxBodySize {
		return nil, errorsx.New(errorsx.CodeBadRequest, "message exceeds max size", false)
	}
	k, err := s.store.GetKey(ctx, cmd.TenantID, cmd.KeyID)
	if err != nil {
		return nil, errorsx.New(errorsx.CodeKeyNotFound, "key not found", false)
	}
	if !genericUsageAllowed(k) {
		return nil, errorsx.New(errorsx.CodePolicyDenied, "protocol-scoped key cannot be used by the generic crypto interface", false)
	}
	if k.Purpose != purposeAuthenticateVerify {
		return nil, errorsx.New(errorsx.CodePolicyDenied, "key purpose does not permit authentication", false)
	}
	if keyExpired(k) || !keystate.CanEncrypt(keystate.KeyStatus(k.Status)) {
		return nil, errorsx.New(errorsx.CodeKeyDisabled, "key not active for authentication", false)
	}
	pol, err := s.policies.Get(k.PolicyID)
	if err != nil {
		return nil, errorsx.New(errorsx.CodePolicyDenied, "policy not found", false)
	}
	suite, err := pol.SuiteByID(k.SuiteID)
	if err != nil || suite.ServiceType != policy.ServiceAuthOnly || !policy.CanCreate(suite.Status) {
		return nil, errorsx.New(errorsx.CodePolicyDenied, "suite not available for authentication", false)
	}
	suiteEnum, err := cryptosuite.Parse(k.SuiteID)
	if err != nil || !suiteEnum.Supports(cryptosuite.OperationAuthenticate) {
		return nil, errorsx.New(errorsx.CodePolicyDenied, "invalid authentication suite", false)
	}
	kv, err := s.store.GetCurrentKeyVersion(ctx, k.ID)
	if err != nil {
		return nil, errorsx.Wrap(errorsx.CodeInternal, "version fetch failed", false, err)
	}
	if !keystate.KVCanEncrypt(keystate.KeyVersionStatus(kv.Status)) {
		return nil, errorsx.New(errorsx.CodeKeyDisabled, "key version not active for authentication", false)
	}
	lease, err := s.resolver.IssueDEKLease(ctx, kv.ID, k.ID, kv.VersionNo, suiteEnum,
		cmd.TenantID, purposeAuthenticateVerify, "")
	if err != nil {
		return nil, errorsx.Wrap(errorsx.CodeTPMUnavailable, "key lease failed", true, err)
	}
	defer zeroize(lease.DEK)
	metadata := cryptomac.Metadata{
		Version:       cryptomac.TagVersion,
		SuiteID:       suiteEnum,
		TenantID:      cmd.TenantID,
		KeyID:         k.ID,
		KeyVersion:    kv.VersionNo,
		PolicyVersion: pol.Version,
	}
	tag, err := cryptomac.Compute(suiteEnum, lease.DEK, metadata, cmd.Message)
	if err != nil {
		return nil, errorsx.Wrap(errorsx.CodeInternal, "authentication failed", false, err)
	}
	s.audit(ctx, "authenticate.success", cmd.TenantID, cmd.PrincipalID, k.ID, "success", "", map[string]string{
		"key_version": fmt.Sprintf("%d", kv.VersionNo),
		"suite_id":    k.SuiteID,
	})
	return &AuthenticateResult{Authenticator: Authenticator{
		Version:       metadata.Version,
		SuiteID:       k.SuiteID,
		ServiceType:   suiteEnum.ServiceType(),
		KeyID:         k.ID,
		KeyVersion:    kv.VersionNo,
		PolicyVersion: pol.Version,
		Tag:           tag,
	}}, nil
}

// Verify validates a detached CMAC using the exact historical key and policy
// versions recorded in the authenticator.
func (s *Service) Verify(ctx context.Context, cmd VerifyCommand) (*VerifyResult, error) {
	if cmd.TenantID == "" {
		cmd.TenantID = defaultTenantID
	}
	if len(cmd.Message) > s.maxBodySize {
		return nil, errorsx.New(errorsx.CodeBadRequest, "message exceeds max size", false)
	}
	authenticator := cmd.Authenticator
	if authenticator.Version != cryptomac.TagVersion || authenticator.KeyID == "" ||
		authenticator.KeyVersion == 0 || authenticator.PolicyVersion == 0 || len(authenticator.Tag) != 16 {
		return nil, errorsx.New(errorsx.CodeInvalidArgument, "invalid authenticator", false)
	}
	k, err := s.store.GetKey(ctx, cmd.TenantID, authenticator.KeyID)
	if err != nil {
		return nil, errorsx.New(errorsx.CodeKeyNotFound, "key not found", false)
	}
	if !genericUsageAllowed(k) {
		return nil, errorsx.New(errorsx.CodePolicyDenied, "protocol-scoped key cannot be used by the generic crypto interface", false)
	}
	if k.Purpose != purposeAuthenticateVerify {
		return nil, errorsx.New(errorsx.CodePolicyDenied, "key purpose does not permit verification", false)
	}
	if keyExpired(k) || !keystate.CanDecrypt(keystate.KeyStatus(k.Status)) {
		return nil, errorsx.New(errorsx.CodeKeyDestroyed, "key unavailable for verification", false)
	}
	suiteEnum, err := cryptosuite.Parse(k.SuiteID)
	if err != nil || !suiteEnum.Supports(cryptosuite.OperationVerify) || authenticator.SuiteID != k.SuiteID ||
		authenticator.ServiceType != cryptosuite.ServiceAuthOnly {
		return nil, errorsx.New(errorsx.CodeInvalidArgument, "authenticator suite does not match key", false)
	}
	kv, err := s.store.GetKeyVersionByNo(ctx, k.ID, authenticator.KeyVersion)
	if err != nil {
		return nil, errorsx.New(errorsx.CodeKeyNotFound, "key version not found", false)
	}
	if !keystate.KVCanDecrypt(keystate.KeyVersionStatus(kv.Status)) {
		return nil, errorsx.New(errorsx.CodeKeyDestroyed, "key version unavailable for verification", false)
	}
	historicalPolicy, err := s.policies.GetVersion(k.PolicyID, authenticator.PolicyVersion)
	if err != nil {
		return nil, errorsx.New(errorsx.CodePolicyDenied, "authenticator policy version unavailable", false)
	}
	historicalSuite, err := historicalPolicy.SuiteByID(k.SuiteID)
	if err != nil || historicalSuite.ServiceType != policy.ServiceAuthOnly ||
		!policy.CanConsume(historicalSuite.Status) {
		return nil, errorsx.New(errorsx.CodePolicyDenied, "suite unavailable for verification", false)
	}
	lease, err := s.resolver.IssueDEKLease(ctx, kv.ID, k.ID, kv.VersionNo, suiteEnum,
		cmd.TenantID, purposeAuthenticateVerify, "")
	if err != nil {
		return nil, errorsx.Wrap(errorsx.CodeTPMUnavailable, "key lease failed", true, err)
	}
	defer zeroize(lease.DEK)
	valid, err := cryptomac.Verify(suiteEnum, lease.DEK, cryptomac.Metadata{
		Version:       authenticator.Version,
		SuiteID:       suiteEnum,
		TenantID:      cmd.TenantID,
		KeyID:         k.ID,
		KeyVersion:    authenticator.KeyVersion,
		PolicyVersion: authenticator.PolicyVersion,
	}, cmd.Message, authenticator.Tag)
	if err != nil {
		return nil, errorsx.Wrap(errorsx.CodeInternal, "verification failed", false, err)
	}
	result := "success"
	errorCode := ""
	if !valid {
		result = "failure"
		errorCode = "MAC_MISMATCH"
	}
	s.audit(ctx, "verify.result", cmd.TenantID, cmd.PrincipalID, k.ID, result, errorCode, map[string]string{
		"key_version": fmt.Sprintf("%d", kv.VersionNo),
		"suite_id":    k.SuiteID,
	})
	return &VerifyResult{Valid: valid}, nil
}

// ConvertEnvelope parses an allowed source format and emits an allowed target
// format from the server's normalized envelope representation.
func (s *Service) ConvertEnvelope(ctx context.Context, cmd ConvertEnvelopeCommand) (*ConvertEnvelopeResult, error) {
	if len(cmd.Ciphertext) > s.maxBodySize*2 {
		return nil, errorsx.New(errorsx.CodeBadRequest, "ciphertext exceeds max size", false)
	}
	registry := envelope.DefaultRegistry()
	tenantCfg, _ := s.store.GetTenantEnvelopeConfig(ctx, cmd.TenantID)
	_, env, err := detectEnvelopeProfile(registry, tenantCfg, envelope.FormatID(cmd.SourceFormat), cmd.Ciphertext)
	if err != nil {
		return nil, errorsx.New(errorsx.CodeEnvelopeInvalid, "envelope invalid", false)
	}
	target := envelope.FormatID(cmd.TargetFormat)
	if target == "" {
		return nil, errorsx.New(errorsx.CodeBadRequest, "target envelope format is required", false)
	}
	if !envelopeFormatAllowed(tenantCfg, target) {
		return nil, errorsx.New(errorsx.CodePolicyDenied, "envelope format not allowed for tenant", false)
	}
	encoded, err := registry.EncodeWithProfile(envelopeProfile(tenantCfg, target), env, envelope.RenderContext{})
	if err != nil {
		return nil, errorsx.Wrap(errorsx.CodePolicyDenied, "envelope format not allowed", false, err)
	}
	s.audit(ctx, "envelope.convert", cmd.TenantID, cmd.PrincipalID, string(env.KeyID), "success", "", map[string]string{"source_format": cmd.SourceFormat, "target_format": cmd.TargetFormat})
	return &ConvertEnvelopeResult{Ciphertext: encoded, EnvelopeFormat: string(target)}, nil
}

// InspectEnvelope returns non-secret normalized metadata using the same parser
// used by conversion and decryption.
func (s *Service) InspectEnvelope(ctx context.Context, cmd InspectEnvelopeCommand) (*InspectEnvelopeResult, error) {
	if len(cmd.Ciphertext) > s.maxBodySize*2 {
		return nil, errorsx.New(errorsx.CodeBadRequest, "ciphertext exceeds max size", false)
	}
	cfg, _ := s.store.GetTenantEnvelopeConfig(ctx, cmd.TenantID)
	profile, env, err := detectEnvelopeProfile(envelope.DefaultRegistry(), cfg, envelope.FormatID(cmd.SourceFormat), cmd.Ciphertext)
	if err != nil {
		return nil, errorsx.New(errorsx.CodeEnvelopeInvalid, "envelope invalid", false)
	}
	result := &InspectEnvelopeResult{Format: string(profile.FormatID), Version: env.Version, Flags: env.Flags, SuiteID: env.SuiteID.String(), ServiceType: env.SuiteID.ServiceType(), KeyID: string(env.KeyID), KeyVersion: env.KeyVersion, PolicyVersion: env.PolicyVersion, NonceBytes: len(env.Nonce), TagBytes: len(env.Tag), CiphertextBytes: len(env.Ciphertext)}
	if env.SuiteID.AuthenticatesAAD() {
		result.AADHash = fmt.Sprintf("%x", env.AADHash[:])
	}
	return result, nil
}

func zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func validateTenantAADPolicy(cfg *models.TenantEnvelopeConfig, callerAAD []byte) error {
	if cfg != nil && cfg.AADRequired && len(callerAAD) == 0 {
		return errorsx.New(errorsx.CodeBadRequest, "aad_b64 is required by tenant policy", false)
	}
	return nil
}

func keyExpired(k *models.Key) bool {
	return k != nil && !k.ExpiresAt.IsZero() && !time.Now().UTC().Before(k.ExpiresAt)
}

func genericUsageAllowed(k *models.Key) bool {
	return k != nil && k.UsageScope == models.KeyUsageGeneric
}

func envelopeProfile(cfg *models.TenantEnvelopeConfig, format envelope.FormatID) *envelope.FormatProfile {
	if cfg != nil {
		for _, p := range cfg.Profiles {
			if p.FormatID == string(format) {
				return modelProfileToEnvelope(p)
			}
		}
	}
	if p := envelope.BuiltinProfile(format); p != nil {
		return p
	}
	return &envelope.FormatProfile{FormatID: format, Adapter: format}
}

func detectEnvelopeProfile(registry *envelope.Registry, cfg *models.TenantEnvelopeConfig, requested envelope.FormatID, ciphertext []byte) (*envelope.FormatProfile, *envelope.Envelope, error) {
	if requested != "" {
		if !envelopeFormatAllowed(cfg, requested) {
			return nil, nil, errorsx.New(errorsx.CodePolicyDenied, "envelope format not allowed for tenant", false)
		}
		profile := envelopeProfile(cfg, requested)
		env, _, err := registry.ParseWithProfile(profile, ciphertext)
		return profile, env, err
	}
	codec, err := registry.Detect(ciphertext)
	if err != nil {
		return nil, nil, err
	}
	candidates := []*envelope.FormatProfile{}
	if envelopeFormatAllowed(cfg, codec.ID()) {
		candidates = append(candidates, envelopeProfile(cfg, codec.ID()))
	}
	if codec.ID() == envelope.FormatJSONV1 && cfg != nil {
		for _, p := range cfg.Profiles {
			profile := modelProfileToEnvelope(p)
			if profile.Adapter == envelope.FormatConfigurableJSONV1 && envelopeFormatAllowed(cfg, profile.FormatID) {
				candidates = append(candidates, profile)
			}
		}
	}
	var lastErr error
	for _, profile := range candidates {
		env, _, err := registry.ParseWithProfile(profile, ciphertext)
		if err == nil {
			return profile, env, nil
		}
		lastErr = err
	}
	if lastErr != nil {
		return nil, nil, lastErr
	}
	return nil, nil, errorsx.New(errorsx.CodePolicyDenied, "envelope format not allowed for tenant", false)
}

func envelopeFormatAllowed(cfg *models.TenantEnvelopeConfig, format envelope.FormatID) bool {
	if format == "" || cfg == nil || len(cfg.AllowedFormats) == 0 {
		return true
	}
	for _, allowed := range cfg.AllowedFormats {
		if allowed == string(format) {
			return true
		}
	}
	return false
}

func envelopeFormatKnown(cfg *models.TenantEnvelopeConfig, format envelope.FormatID) bool {
	if envelope.BuiltinProfile(format) != nil {
		return true
	}
	if cfg != nil {
		for _, p := range cfg.Profiles {
			if p.FormatID == string(format) {
				adapter := envelope.FormatID(p.Adapter)
				return adapter == envelope.FormatJSONV1 || adapter == envelope.FormatConfigurableJSONV1
			}
		}
	}
	return false
}

func modelProfileToEnvelope(p models.EnvelopeFormatProfile) *envelope.FormatProfile {
	out := &envelope.FormatProfile{
		FormatID:    envelope.FormatID(p.FormatID),
		Adapter:     envelope.FormatID(p.Adapter),
		Description: p.Description,
	}
	for _, m := range p.FieldMappings {
		out.FieldMappings = append(out.FieldMappings, envelope.FieldMapping{
			Path:         m.Path,
			Source:       m.Source,
			Required:     m.Required,
			Encoding:     m.Encoding,
			DefaultValue: m.DefaultValue,
		})
	}
	for _, ext := range p.Extensions {
		out.Extensions = append(out.Extensions, envelope.ExtensionField{
			Name:         ext.Name,
			Type:         ext.Type,
			Required:     ext.Required,
			DefaultValue: ext.DefaultValue,
			Description:  ext.Description,
		})
	}
	return out
}

// Base64Encode is a convenience for the API layer.
func Base64Encode(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

// Base64Decode is a convenience for the API layer.
func Base64Decode(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}
