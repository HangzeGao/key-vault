// Package protection provides protocol-neutral symmetric protection without
// imposing the Key Vault Envelope wire format on callers.
package protection

import (
	"context"
	"errors"
	"time"

	"github.com/kvlt/key-vault/internal/crypto/aead"
	"github.com/kvlt/key-vault/internal/crypto/kdf"
	cryptomac "github.com/kvlt/key-vault/internal/crypto/mac"
	"github.com/kvlt/key-vault/internal/crypto/suite"
	keystate "github.com/kvlt/key-vault/internal/domain/key/state"
	"github.com/kvlt/key-vault/internal/domain/policy"
	"github.com/kvlt/key-vault/internal/errorsx"
	"github.com/kvlt/key-vault/internal/repository/models"
	"github.com/kvlt/key-vault/internal/resolver/keyresolver"
)

const maxAADLen = 64 * 1024

// Store is the key and uniqueness state required by the protection core.
type Store interface {
	GetKey(ctx context.Context, tenantID, keyID string) (*models.Key, error)
	GetKeyVersionByNo(ctx context.Context, keyID string, versionNo uint32) (*models.KeyVersion, error)
}

// KeyLeaser exposes the resolver seam without allowing protocol modules to
// access CRK envelopes or wrapped key material.
type KeyLeaser interface {
	IssueDEKLease(ctx context.Context, keyVersionID, keyID string, keyVersion uint32,
		suiteID suite.ID, tenantID, purpose, nodeID string) (*keyresolver.DEKLease, error)
}

// ProtectRequest contains protocol-canonical bytes. AAD is used only by GCM;
// AuthenticationInput is used only by CMAC; CTR accepts neither.
type ProtectRequest struct {
	TenantID            string
	KeyID               string
	UsageScope          models.KeyUsageScope
	KeyVersion          uint32
	PolicyVersion       uint32
	Data                []byte
	Nonce               []byte
	AAD                 []byte
	AuthenticationInput []byte
	NodeID              string
}

// ProtectResult is raw protection material suitable for a protocol's own wire
// codec. It is deliberately not a Key Vault Envelope.
type ProtectResult struct {
	Data          []byte
	Nonce         []byte
	Tag           []byte
	KeyVersion    uint32
	PolicyVersion uint32
	SuiteID       suite.ID
	ServiceType   suite.ServiceType
}

// Derivation fixes the protocol-owned CMAC counter KDF inputs. The root never
// leaves the protection core; only the derived working key reaches the cipher.
type Derivation struct {
	Label   []byte
	Context []byte
}

// UnprotectRequest identifies the exact historical decision recorded by the
// protocol security context.
type UnprotectRequest struct {
	TenantID            string
	KeyID               string
	UsageScope          models.KeyUsageScope
	KeyVersion          uint32
	PolicyVersion       uint32
	Data                []byte
	Nonce               []byte
	Tag                 []byte
	AAD                 []byte
	AuthenticationInput []byte
	NodeID              string
}

type UnprotectResult struct {
	Data        []byte
	SuiteID     suite.ID
	ServiceType suite.ServiceType
}

// Service is the protocol-neutral raw protection core.
type Service struct {
	store    Store
	leaser   KeyLeaser
	policies *policy.Engine
	maxData  int
}

func New(store Store, leaser KeyLeaser, policies *policy.Engine, maxData int) *Service {
	return &Service{store: store, leaser: leaser, policies: policies, maxData: maxData}
}

func (s *Service) Protect(ctx context.Context, req ProtectRequest) (*ProtectResult, error) {
	return s.protect(ctx, req, nil)
}

// ProtectDerived derives an epoch-bound working key from the protocol-scoped
// root identified by req, then protects the data without persisting or leasing
// the derived key outside this operation.
func (s *Service) ProtectDerived(ctx context.Context, req ProtectRequest, derivation Derivation) (*ProtectResult, error) {
	if len(derivation.Label) == 0 || len(derivation.Context) == 0 {
		return nil, errorsx.New(errorsx.CodeInvalidArgument, "derivation label and context are required", false)
	}
	return s.protect(ctx, req, &derivation)
}

func (s *Service) protect(ctx context.Context, req ProtectRequest, derivation *Derivation) (*ProtectResult, error) {
	if req.TenantID == "" || req.KeyID == "" || req.KeyVersion == 0 || req.PolicyVersion == 0 {
		return nil, errorsx.New(errorsx.CodeInvalidArgument, "tenant_id, key_id, key_version, and policy_version are required", false)
	}
	if len(req.Data) > s.maxData || len(req.AAD) > maxAADLen {
		return nil, errorsx.New(errorsx.CodeBadRequest, "protection input exceeds configured limit", false)
	}
	k, err := s.store.GetKey(ctx, req.TenantID, req.KeyID)
	if err != nil {
		return nil, errorsx.New(errorsx.CodeKeyNotFound, "key not found", false)
	}
	if !usageScopeMatches(k.UsageScope, req.UsageScope) {
		return nil, errorsx.New(errorsx.CodePolicyDenied, "key usage scope does not match caller", false)
	}
	if keyExpired(k) || !keystate.CanEncrypt(keystate.KeyStatus(k.Status)) {
		return nil, errorsx.New(errorsx.CodeKeyDisabled, "key unavailable for protection", false)
	}
	pol, err := s.policies.GetVersion(k.PolicyID, req.PolicyVersion)
	if err != nil {
		return nil, errorsx.New(errorsx.CodePolicyDenied, "policy not found", false)
	}
	policySuite, err := pol.SuiteByID(k.SuiteID)
	if err != nil || !policy.CanCreate(policySuite.Status) {
		return nil, errorsx.New(errorsx.CodePolicyDenied, "suite unavailable for protection", false)
	}
	suiteID, err := suite.Parse(k.SuiteID)
	if err != nil || suiteID.KeyPurpose() != k.Purpose {
		return nil, errorsx.New(errorsx.CodePolicyDenied, "key purpose does not match suite", false)
	}
	if suiteID == suite.SM4HCTR && derivation == nil {
		return nil, errorsx.New(errorsx.CodePolicyDenied, "SM4_HCTR requires protocol-bound key derivation", false)
	}
	kv, err := s.store.GetKeyVersionByNo(ctx, k.ID, req.KeyVersion)
	if err != nil || kv.SuiteID != k.SuiteID {
		return nil, errorsx.Wrap(errorsx.CodeInternal, "key version fetch failed", false, err)
	}
	if !keystate.KVCanEncrypt(keystate.KeyVersionStatus(kv.Status)) {
		return nil, errorsx.New(errorsx.CodeKeyDisabled, "key version unavailable for protection", false)
	}
	lease, err := s.leaser.IssueDEKLease(ctx, kv.ID, k.ID, kv.VersionNo, suiteID,
		req.TenantID, suiteID.KeyPurpose(), req.NodeID)
	if err != nil {
		return nil, errorsx.Wrap(errorsx.CodeTPMUnavailable, "key lease failed", true, err)
	}
	defer zeroize(lease.DEK)
	keyMaterial := lease.DEK
	if derivation != nil {
		keyMaterial, err = kdf.CMACCounter(lease.DEK, suiteID, derivation.Label, derivation.Context)
		if err != nil {
			return nil, errorsx.Wrap(errorsx.CodeInternal, "working key derivation failed", false, err)
		}
		defer zeroize(keyMaterial)
	}

	result := &ProtectResult{
		KeyVersion: req.KeyVersion, PolicyVersion: req.PolicyVersion,
		SuiteID: suiteID, ServiceType: suiteID.ServiceType(),
		Nonce: append([]byte(nil), req.Nonce...),
	}
	if len(req.AAD) > maxAADLen {
		return nil, errorsx.New(errorsx.CodeBadRequest, "protection context exceeds configured limit", false)
	}
	if err := validateInputs(suiteID, req.Nonce, req.AAD, req.AuthenticationInput); err != nil {
		return nil, err
	}
	switch suiteID.ServiceType() {
	case suite.ServiceAuthOnly:
		result.Data = append([]byte(nil), req.Data...)
		result.Tag, err = cryptomac.ComputeRaw(suiteID, keyMaterial, req.AuthenticationInput)
	case suite.ServiceEncryptOnly, suite.ServiceAuthEncrypt:
		var primitive aead.Cipher
		primitive, err = aead.New(suiteID, keyMaterial)
		if err == nil {
			result.Data, result.Tag = primitive.Encrypt(req.Data, result.Nonce, req.AAD)
		}
	default:
		err = errors.New("unsupported protection service")
	}
	if err != nil {
		return nil, errorsx.Wrap(errorsx.CodeInternal, "protection failed", false, err)
	}
	return result, nil
}

func (s *Service) Unprotect(ctx context.Context, req UnprotectRequest) (*UnprotectResult, error) {
	if req.TenantID == "" || req.KeyID == "" || req.KeyVersion == 0 || req.PolicyVersion == 0 {
		return nil, errorsx.New(errorsx.CodeInvalidArgument, "historical key and policy versions are required", false)
	}
	if len(req.Data) > s.maxData || len(req.AAD) > maxAADLen {
		return nil, errorsx.New(errorsx.CodeBadRequest, "unprotection input exceeds configured limit", false)
	}
	k, err := s.store.GetKey(ctx, req.TenantID, req.KeyID)
	if err != nil {
		return nil, errorsx.New(errorsx.CodeKeyNotFound, "key not found", false)
	}
	if !usageScopeMatches(k.UsageScope, req.UsageScope) {
		return nil, errorsx.New(errorsx.CodePolicyDenied, "key usage scope does not match caller", false)
	}
	if keyExpired(k) || !keystate.CanDecrypt(keystate.KeyStatus(k.Status)) {
		return nil, errorsx.New(errorsx.CodeKeyDestroyed, "key unavailable for unprotection", false)
	}
	suiteID, err := suite.Parse(k.SuiteID)
	if err != nil || suiteID.KeyPurpose() != k.Purpose {
		return nil, errorsx.New(errorsx.CodePolicyDenied, "key purpose does not match suite", false)
	}
	if suiteID == suite.SM4HCTR {
		return nil, errorsx.New(errorsx.CodePolicyDenied, "SM4_HCTR receive is owned by the protocol module", false)
	}
	if err := validateInputs(suiteID, req.Nonce, req.AAD, req.AuthenticationInput); err != nil {
		return nil, err
	}
	kv, err := s.store.GetKeyVersionByNo(ctx, k.ID, req.KeyVersion)
	if err != nil || kv.SuiteID != k.SuiteID {
		return nil, errorsx.New(errorsx.CodeKeyNotFound, "key version not found", false)
	}
	if !keystate.KVCanDecrypt(keystate.KeyVersionStatus(kv.Status)) {
		return nil, errorsx.New(errorsx.CodeKeyDestroyed, "key version unavailable for unprotection", false)
	}
	historical, err := s.policies.GetVersion(k.PolicyID, req.PolicyVersion)
	if err != nil {
		return nil, errorsx.New(errorsx.CodePolicyDenied, "historical policy unavailable", false)
	}
	policySuite, err := historical.SuiteByID(k.SuiteID)
	if err != nil || !policy.CanConsume(policySuite.Status) {
		return nil, errorsx.New(errorsx.CodePolicyDenied, "suite unavailable for unprotection", false)
	}
	lease, err := s.leaser.IssueDEKLease(ctx, kv.ID, k.ID, kv.VersionNo, suiteID,
		req.TenantID, suiteID.KeyPurpose(), req.NodeID)
	if err != nil {
		return nil, errorsx.Wrap(errorsx.CodeTPMUnavailable, "key lease failed", true, err)
	}
	defer zeroize(lease.DEK)

	result := &UnprotectResult{SuiteID: suiteID, ServiceType: suiteID.ServiceType()}
	switch suiteID.ServiceType() {
	case suite.ServiceAuthOnly:
		var valid bool
		valid, err = cryptomac.VerifyRaw(suiteID, lease.DEK, req.AuthenticationInput, req.Tag)
		if err == nil && !valid {
			return nil, errorsx.New(errorsx.CodeAADMismatch, "authentication failed", false)
		}
		result.Data = append([]byte(nil), req.Data...)
	case suite.ServiceEncryptOnly, suite.ServiceAuthEncrypt:
		if len(req.Nonce) != suiteID.NonceLen() || len(req.Tag) != suiteID.TagLen() {
			return nil, errorsx.New(errorsx.CodeInvalidArgument, "nonce or tag length mismatch", false)
		}
		var primitive aead.Cipher
		primitive, err = aead.New(suiteID, lease.DEK)
		if err == nil {
			result.Data, err = primitive.Decrypt(req.Data, req.Tag, req.Nonce, req.AAD)
		}
	default:
		err = errors.New("unsupported protection service")
	}
	if err != nil {
		return nil, errorsx.Wrap(errorsx.CodeAADMismatch, "unprotection failed", false, err)
	}
	return result, nil
}

func validateInputs(suiteID suite.ID, nonceBytes, aad, authenticationInput []byte) error {
	if len(nonceBytes) != suiteID.NonceLen() {
		return errorsx.New(errorsx.CodeInvalidArgument, "nonce length does not match suite", false)
	}
	switch suiteID.ServiceType() {
	case suite.ServiceAuthOnly:
		if len(aad) != 0 {
			return errorsx.New(errorsx.CodeInvalidArgument, "CMAC does not accept AEAD AAD", false)
		}
	case suite.ServiceEncryptOnly:
		if len(aad) != 0 || len(authenticationInput) != 0 {
			return errorsx.New(errorsx.CodeInvalidArgument, "confidentiality-only suites do not authenticate data", false)
		}
	case suite.ServiceAuthEncrypt:
		if len(authenticationInput) != 0 {
			return errorsx.New(errorsx.CodeInvalidArgument, "GCM uses AAD, not CMAC input", false)
		}
	default:
		return errorsx.New(errorsx.CodePolicyDenied, "unsupported security service", false)
	}
	return nil
}

func keyExpired(k *models.Key) bool {
	return k != nil && !k.ExpiresAt.IsZero() && !time.Now().UTC().Before(k.ExpiresAt)
}

func usageScopeMatches(actual, required models.KeyUsageScope) bool {
	return actual != "" && required != "" && actual == required
}

func zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
