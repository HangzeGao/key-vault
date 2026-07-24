// Package keys implements the Key application service per design §9.3, §9.6.
package keys

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/kvlt/key-vault/internal/crypto/aead"
	keystate "github.com/kvlt/key-vault/internal/domain/key/state"
	"github.com/kvlt/key-vault/internal/domain/policy"
	"github.com/kvlt/key-vault/internal/errorsx"
	"github.com/kvlt/key-vault/internal/lifecycle"
	"github.com/kvlt/key-vault/internal/repository"
	"github.com/kvlt/key-vault/internal/repository/models"
	"github.com/kvlt/key-vault/internal/resolver/keyresolver"
)

// CreateKeyCommand is the input for CreateKey.
type CreateKeyCommand struct {
	TenantID       string
	KeyID          string
	Name           string
	Purpose        string
	PolicyID       string
	SuiteID        string
	Tags           map[string]string
	ExpiresAt      time.Time
	IdempotencyKey string
	PrincipalID    string
}

// KeyDTO is the public representation of a key. Never includes wrapped_dek.
type KeyDTO struct {
	KeyID          string            `json:"key_id"`
	TenantID       string            `json:"tenant_id"`
	Name           string            `json:"name"`
	Purpose        string            `json:"purpose"`
	PolicyID       string            `json:"policy_id"`
	SuiteID        string            `json:"suite_id"`
	CurrentVersion uint32            `json:"current_version"`
	Status         string            `json:"status"`
	Tags           map[string]string `json:"tags,omitempty"`
	ExpiresAt      *time.Time        `json:"expires_at,omitempty"`
	ArchivedAt     *time.Time        `json:"archived_at,omitempty"`
	CreatedAt      time.Time         `json:"created_at"`
}

type PrepareKeyVersionCommand struct {
	TenantID    string
	KeyID       string
	ExternalKey []byte
	PrincipalID string
}

type KeyVersionDTO struct {
	KeyID     string `json:"key_id"`
	VersionNo uint32 `json:"version"`
	SuiteID   string `json:"suite_id"`
	Status    string `json:"status"`
}

// ImportKeyCommand is the input for ImportKey (controlled import, EB-FR-01).
// Per design §2 and INV-11: ExternalKey is the caller-provided plaintext key
// material (DEK or KEK). It is only used inside the key-plane sealing flow and is never
// persisted, logged, or echoed in the response. The service zeroizes its
// in-memory copy after wrapping.
type ImportKeyCommand struct {
	TenantID       string
	KeyID          string
	Name           string
	Purpose        string
	PolicyID       string
	SuiteID        string
	Tags           map[string]string
	ExpiresAt      time.Time
	ExternalKey    []byte // plaintext key material from caller; zeroized after wrapping
	IdempotencyKey string
	PrincipalID    string
}

// UpdateKeyCommand updates mutable key metadata. It never changes key
// material, algorithm suite, policy, tenant, state, or current version.
type UpdateKeyCommand struct {
	TenantID    string
	KeyID       string
	Name        string
	Tags        map[string]string
	ExpiresAt   time.Time
	PrincipalID string
}

// Service is the key application service.
type Service struct {
	mu       sync.Mutex
	store    Store
	resolver *keyresolver.Resolver
	policies *policy.Engine
	auditor  Auditor
}

const (
	PurposeEncryptDecrypt = "encrypt_decrypt"
	// PurposeKeyWrap identifies a pre-shared KEK. It may wrap data keys for
	// protocol-neutral key upload/download and must never encrypt business data.
	PurposeKeyWrap = "key_wrap"
)

func isSupportedPurpose(purpose string) bool {
	return purpose == PurposeEncryptDecrypt || purpose == PurposeKeyWrap
}

// Auditor records audit events for key lifecycle operations (design §15.1, EB-FR-09).
// For high-risk actions such as key.schedule_destroy, Record is called
// BEFORE the business state change; if Record fails the operation must fail-closed.
type Auditor interface {
	Record(ctx context.Context, req AuditRequest) error
}

// AuditRequest is the audit event input from the key service.
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

// Store is the subset of repository methods used by the key service.
type Store interface {
	GetTenant(ctx context.Context, id string) (*models.Tenant, error)
	CreateKey(ctx context.Context, k *models.Key, kv *models.KeyVersion) error
	GetKey(ctx context.Context, tenantID, keyID string) (*models.Key, error)
	ListKeys(ctx context.Context, tenantID string) ([]*models.Key, error)
	ListKeysIncludingArchived(ctx context.Context, tenantID string) ([]*models.Key, error)
	ListAllKeys(ctx context.Context) ([]*models.Key, error)
	UpdateKeyMetadata(ctx context.Context, tenantID, keyID, name string, tags map[string]string, expiresAt time.Time) (*models.Key, error)
	UpdateKeyStatus(ctx context.Context, keyID, expectedCurrent, newStatus string) error
	ArchiveDestroyedKey(ctx context.Context, tenantID, keyID string) (*models.Key, error)
	DestroyKeyMaterial(ctx context.Context, keyID string) error
	CreatePendingKeyVersion(ctx context.Context, keyID string, newVersion *models.KeyVersion) error
	ActivateKeyVersion(ctx context.Context, keyID string, versionNo uint32) error
	GetCurrentKeyVersion(ctx context.Context, keyID string) (*models.KeyVersion, error)
	GetKeyVersionByNo(ctx context.Context, keyID string, versionNo uint32) (*models.KeyVersion, error)
	CreateLifecycleJob(ctx context.Context, j *models.LifecycleJob) error
	ListLifecycleJobs(ctx context.Context, status string, limit int) ([]*models.LifecycleJob, error)
	// Idempotency support (design §8: POST /ui/api/v1/keys 必须支持幂等键).
	RecordIdempotency(ctx context.Context, ik *models.IdempotencyKey) error
	GetIdempotency(ctx context.Context, key string) (*models.IdempotencyKey, error)
}

// New constructs a key service.
func New(store Store, resolver *keyresolver.Resolver, policies *policy.Engine) *Service {
	return &Service{store: store, resolver: resolver, policies: policies, auditor: noopAuditor{}}
}

// SetAuditor wires the audit dependency. Must be called before serving requests.
func (s *Service) SetAuditor(a Auditor) {
	if a != nil {
		s.auditor = a
	}
}

// audit records an audit event. For high-risk actions, callers must invoke
// this BEFORE changing business state and abort on error (fail-closed).
func (s *Service) audit(ctx context.Context, action, tenantID, principalID, targetType, targetID, result, errorCode string, metadata map[string]string) {
	_ = s.auditor.Record(ctx, AuditRequest{
		Action:      action,
		TenantID:    tenantID,
		PrincipalID: principalID,
		TargetType:  targetType,
		TargetID:    targetID,
		Result:      result,
		ErrorCode:   errorCode,
		Metadata:    metadata,
	})
}

// auditHighRisk records a high-risk audit event and returns the error.
// Callers MUST check the error and abort the operation if non-nil (fail-closed).
func (s *Service) auditHighRisk(ctx context.Context, action, tenantID, principalID, targetType, targetID string) error {
	return s.auditor.Record(ctx, AuditRequest{
		Action:      action,
		TenantID:    tenantID,
		PrincipalID: principalID,
		TargetType:  targetType,
		TargetID:    targetID,
		Result:      "success",
	})
}

// CreateKey creates a new key + initial key version. Per design §9.3:
//   - DEK generated server-side and sealed under CRK.
//   - Database stores only wrapped DEK.
//   - Response contains no DEK material.
//
// Per design §8 ("POST /ui/api/v1/keys 必须支持幂等键"), if cmd.IdempotencyKey
// is set, the request is deduplicated: a second call with the same key returns
// the original result without re-running side effects.
func (s *Service) CreateKey(ctx context.Context, cmd CreateKeyCommand) (*KeyDTO, error) {
	if cmd.TenantID == "" || cmd.Name == "" || cmd.Purpose == "" {
		return nil, errorsx.New(errorsx.CodeInvalidArgument, "missing required field", false)
	}
	if !isSupportedPurpose(cmd.Purpose) {
		return nil, errorsx.New(errorsx.CodeInvalidArgument, "unsupported key purpose", false)
	}
	if cmd.Purpose == PurposeKeyWrap {
		return nil, errorsx.New(errorsx.CodeInvalidArgument, "key_wrap keys must be imported from pre-shared key material", false)
	}

	// Idempotency: if a key is present, replay the cached result.
	if cmd.IdempotencyKey != "" {
		if existing, err := s.store.GetIdempotency(ctx, cmd.IdempotencyKey); err == nil && existing != nil {
			// Replay: fetch the previously created key by stored KeyID.
			if k, gerr := s.store.GetKey(ctx, cmd.TenantID, existing.ResponseHash); gerr == nil && k != nil {
				return toDTO(k), nil
			}
		}
	}

	// Validate policy + suite.
	pol, err := s.policies.Get(cmd.PolicyID)
	if err != nil {
		return nil, errorsx.New(errorsx.CodePolicyDenied, "unknown policy", false)
	}
	suite, err := pol.SuiteByID(cmd.SuiteID)
	if err != nil {
		return nil, errorsx.New(errorsx.CodePolicyDenied, "unknown suite", false)
	}
	if !policy.CanEncrypt(suite.Status) {
		return nil, errorsx.New(errorsx.CodePolicyDenied, "suite not available for encryption", false)
	}
	if suite.Mode != policy.ModeGCM && suite.Mode != policy.ModeECB {
		return nil, errorsx.New(errorsx.CodePolicyDenied, "suite mode is not supported", false)
	}

	// Validate tenant exists.
	if _, err := s.store.GetTenant(ctx, cmd.TenantID); err != nil {
		return nil, errorsx.New(errorsx.CodePermissionDenied, "tenant not found", false)
	}

	suiteEnum, err := suiteIDFromString(cmd.SuiteID)
	if err != nil {
		return nil, errorsx.New(errorsx.CodePolicyDenied, "invalid suite_id", false)
	}

	keyID := cmd.KeyID
	if keyID == "" {
		keyID = newID("key")
	}
	versionID := newID("kv")

	// Generate and wrap DEK via resolver (CRK critical section).
	dm, err := s.resolver.GenerateAndWrapDEK(ctx, suiteEnum, versionID)
	if err != nil {
		return nil, errorsx.Wrap(errorsx.CodeTPMUnavailable, "dek generation failed", true, err)
	}

	now := time.Now().UTC()
	k := &models.Key{
		ID:             keyID,
		TenantID:       cmd.TenantID,
		Name:           cmd.Name,
		Purpose:        cmd.Purpose,
		PolicyID:       cmd.PolicyID,
		SuiteID:        cmd.SuiteID,
		CurrentVersion: 1,
		Status:         string(keystate.KeyActive),
		Tags:           cmd.Tags,
		ExpiresAt:      cmd.ExpiresAt,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	kv := &models.KeyVersion{
		ID:           versionID,
		KeyID:        keyID,
		VersionNo:    1,
		SuiteID:      cmd.SuiteID,
		WrappedDEK:   dm.WrappedDEK,
		WrapMetadata: dm.WrapMetadata,
		Status:       string(keystate.KVActive),
		CreatedAt:    now,
	}
	if err := s.store.CreateKey(ctx, k, kv); err != nil {
		return nil, errorsx.Wrap(errorsx.CodeDBConflict, "create key failed", true, err)
	}

	// Record idempotency AFTER successful creation. We reuse the ResponseHash
	// field to store the created KeyID so a replay can re-fetch the DTO.
	if cmd.IdempotencyKey != "" {
		_ = s.store.RecordIdempotency(ctx, &models.IdempotencyKey{
			Key:            cmd.IdempotencyKey,
			PrincipalID:    cmd.PrincipalID,
			TenantID:       cmd.TenantID,
			Method:         "POST",
			Path:           "/ui/api/v1/keys",
			ResponseHash:   keyID,
			ResponseStatus: 201,
		})
	}

	s.audit(ctx, "key.created", cmd.TenantID, cmd.PrincipalID, "key", keyID, "success", "", nil)
	return toDTO(k), nil
}

// ImportKey performs controlled import of external key material (EB-FR-01,
// design §2 "受控导入"). Per INV-11/INV-12: the external DEK plaintext only
// enters the key-plane sealing flow; it is never persisted, logged, or echoed.
// The in-memory copy is zeroized after wrapping. The response contains no key
// material. Supports idempotency keys like CreateKey.
func (s *Service) ImportKey(ctx context.Context, cmd ImportKeyCommand) (*KeyDTO, error) {
	if cmd.TenantID == "" || cmd.Name == "" || cmd.Purpose == "" {
		return nil, errorsx.New(errorsx.CodeInvalidArgument, "missing required field", false)
	}
	if !isSupportedPurpose(cmd.Purpose) {
		return nil, errorsx.New(errorsx.CodeInvalidArgument, "unsupported key purpose", false)
	}
	if len(cmd.ExternalKey) == 0 {
		return nil, errorsx.New(errorsx.CodeInvalidArgument, "missing external_key", false)
	}

	// Idempotency replay.
	if cmd.IdempotencyKey != "" {
		if existing, err := s.store.GetIdempotency(ctx, cmd.IdempotencyKey); err == nil && existing != nil {
			if k, gerr := s.store.GetKey(ctx, cmd.TenantID, existing.ResponseHash); gerr == nil && k != nil {
				return toDTO(k), nil
			}
		}
	}

	// Validate policy + suite (same rules as CreateKey).
	pol, err := s.policies.Get(cmd.PolicyID)
	if err != nil {
		return nil, errorsx.New(errorsx.CodePolicyDenied, "unknown policy", false)
	}
	suite, err := pol.SuiteByID(cmd.SuiteID)
	if err != nil {
		return nil, errorsx.New(errorsx.CodePolicyDenied, "unknown suite", false)
	}
	if !policy.CanEncrypt(suite.Status) {
		return nil, errorsx.New(errorsx.CodePolicyDenied, "suite not available for encryption", false)
	}
	if suite.Mode != policy.ModeGCM && suite.Mode != policy.ModeECB {
		return nil, errorsx.New(errorsx.CodePolicyDenied, "suite mode is not supported", false)
	}

	if _, err := s.store.GetTenant(ctx, cmd.TenantID); err != nil {
		return nil, errorsx.New(errorsx.CodePermissionDenied, "tenant not found", false)
	}

	suiteEnum, err := suiteIDFromString(cmd.SuiteID)
	if err != nil {
		return nil, errorsx.New(errorsx.CodePolicyDenied, "invalid suite_id", false)
	}

	keyID := cmd.KeyID
	if keyID == "" {
		keyID = newID("key")
	}
	versionID := newID("kv")

	// Wrap the externally-provided DEK under the CRK (key-plane only).
	// WrapExternalKey validates length and zeroizes its in-memory copy.
	dm, err := s.resolver.WrapExternalKey(ctx, suiteEnum, versionID, cmd.ExternalKey)
	if err != nil {
		return nil, errorsx.Wrap(errorsx.CodeTPMUnavailable, "dek wrap failed", true, err)
	}
	// Zeroize the caller's DEK plaintext as soon as wrapping succeeds.
	for i := range cmd.ExternalKey {
		cmd.ExternalKey[i] = 0
	}

	now := time.Now().UTC()
	k := &models.Key{
		ID:             keyID,
		TenantID:       cmd.TenantID,
		Name:           cmd.Name,
		Purpose:        cmd.Purpose,
		PolicyID:       cmd.PolicyID,
		SuiteID:        cmd.SuiteID,
		CurrentVersion: 1,
		Status:         string(keystate.KeyActive),
		Tags:           cmd.Tags,
		ExpiresAt:      cmd.ExpiresAt,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	kv := &models.KeyVersion{
		ID:           versionID,
		KeyID:        keyID,
		VersionNo:    1,
		SuiteID:      cmd.SuiteID,
		WrappedDEK:   dm.WrappedDEK,
		WrapMetadata: dm.WrapMetadata,
		Status:       string(keystate.KVActive),
		CreatedAt:    now,
	}
	if err := s.store.CreateKey(ctx, k, kv); err != nil {
		return nil, errorsx.Wrap(errorsx.CodeDBConflict, "import key failed", true, err)
	}

	if cmd.IdempotencyKey != "" {
		_ = s.store.RecordIdempotency(ctx, &models.IdempotencyKey{
			Key:            cmd.IdempotencyKey,
			PrincipalID:    cmd.PrincipalID,
			TenantID:       cmd.TenantID,
			Method:         "POST",
			Path:           "/ui/api/v1/keys:import",
			ResponseHash:   keyID,
			ResponseStatus: 201,
		})
	}

	s.audit(ctx, "key.imported", cmd.TenantID, cmd.PrincipalID, "key", keyID, "success", "", nil)
	return toDTO(k), nil
}

// GetKey returns a key by ID. Cross-tenant access returns PermissionDenied.
func (s *Service) GetKey(ctx context.Context, tenantID, keyID string) (*KeyDTO, error) {
	k, err := s.store.GetKey(ctx, tenantID, keyID)
	if err != nil {
		return nil, errorsx.New(errorsx.CodeKeyNotFound, "key not found", false)
	}
	return toDTO(k), nil
}

// ListKeys lists keys for a tenant.
func (s *Service) ListKeys(ctx context.Context, tenantID string, includeArchived bool) ([]*KeyDTO, error) {
	var (
		ks  []*models.Key
		err error
	)
	if includeArchived {
		ks, err = s.store.ListKeysIncludingArchived(ctx, tenantID)
	} else {
		ks, err = s.store.ListKeys(ctx, tenantID)
	}
	if err != nil {
		return nil, errorsx.Wrap(errorsx.CodeInternal, "list keys failed", false, err)
	}
	out := make([]*KeyDTO, 0, len(ks))
	for _, k := range ks {
		out = append(out, toDTO(k))
	}
	return out, nil
}

// ArchiveDestroyedKey hides a DESTROYED key from default inventory views while
// preserving the tombstone row, key_id history, and audit evidence.
func (s *Service) ArchiveDestroyedKey(ctx context.Context, tenantID, keyID, principalID string) (*KeyDTO, error) {
	k, err := s.store.GetKey(ctx, tenantID, keyID)
	if err != nil {
		return nil, errorsx.New(errorsx.CodeKeyNotFound, "key not found", false)
	}
	if k.Status != string(keystate.KeyDestroyed) {
		return nil, errorsx.New(errorsx.CodeKeyDisabled, "only destroyed keys can be archived", false)
	}
	if !k.ArchivedAt.IsZero() {
		return toDTO(k), nil
	}
	if err := s.auditHighRisk(ctx, "key.archive_destroyed", tenantID, principalID, "key", keyID); err != nil {
		return nil, errorsx.Wrap(errorsx.CodeAuditUnavailable, "audit failed, operation aborted", false, err)
	}
	archived, err := s.store.ArchiveDestroyedKey(ctx, tenantID, keyID)
	if err != nil {
		return nil, errorsx.Wrap(errorsx.CodeDBConflict, "archive destroyed key failed", true, err)
	}
	return toDTO(archived), nil
}

// CheckExpiry returns active keys whose custom validity window has expired or
// will expire within the warning window.
func (s *Service) CheckExpiry(ctx context.Context, warningWindow time.Duration) ([]lifecycle.ExpiryCandidate, error) {
	ks, err := s.store.ListAllKeys(ctx)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	warnUntil := now.Add(warningWindow)
	out := make([]lifecycle.ExpiryCandidate, 0)
	for _, k := range ks {
		if k.ExpiresAt.IsZero() || k.ExpiresAt.After(warnUntil) {
			continue
		}
		if k.Status != string(keystate.KeyActive) {
			continue
		}
		out = append(out, lifecycle.ExpiryCandidate{
			KeyID:          k.ID,
			TenantID:       k.TenantID,
			CurrentVersion: k.CurrentVersion,
			ExpiresAt:      k.ExpiresAt,
		})
	}
	return out, nil
}

// UpdateKey updates mutable key metadata.
func (s *Service) UpdateKey(ctx context.Context, cmd UpdateKeyCommand) (*KeyDTO, error) {
	if cmd.Name == "" {
		return nil, errorsx.New(errorsx.CodeInvalidArgument, "missing required field", false)
	}
	k, err := s.store.UpdateKeyMetadata(ctx, cmd.TenantID, cmd.KeyID, cmd.Name, cmd.Tags, cmd.ExpiresAt)
	if err != nil {
		return nil, errorsx.New(errorsx.CodeKeyNotFound, "key not found", false)
	}
	s.audit(ctx, "key.updated", cmd.TenantID, cmd.PrincipalID, "key", cmd.KeyID, "success", "", nil)
	return toDTO(k), nil
}

// DisableKey transitions a key from ACTIVE to DISABLED.
func (s *Service) DisableKey(ctx context.Context, tenantID, keyID, principalID string) error {
	k, err := s.store.GetKey(ctx, tenantID, keyID)
	if err != nil {
		return errorsx.New(errorsx.CodeKeyNotFound, "key not found", false)
	}
	newStatus, err := keystate.TransitionKey(keystate.KeyStatus(k.Status), keystate.EvDisable)
	if err != nil {
		return errorsx.New(errorsx.CodeKeyDisabled, "illegal state transition", false)
	}
	if err := s.store.UpdateKeyStatus(ctx, keyID, k.Status, string(newStatus)); err != nil {
		return errorsx.Wrap(errorsx.CodeDBConflict, "update failed", true, err)
	}
	s.audit(ctx, "key.disabled", tenantID, principalID, "key", keyID, "success", "", nil)
	return nil
}

// EnableKey transitions a key from DISABLED to ACTIVE.
func (s *Service) EnableKey(ctx context.Context, tenantID, keyID, principalID string) error {
	k, err := s.store.GetKey(ctx, tenantID, keyID)
	if err != nil {
		return errorsx.New(errorsx.CodeKeyNotFound, "key not found", false)
	}
	newStatus, err := keystate.TransitionKey(keystate.KeyStatus(k.Status), keystate.EvEnable)
	if err != nil {
		return errorsx.New(errorsx.CodeKeyDisabled, "illegal state transition", false)
	}
	if err := s.store.UpdateKeyStatus(ctx, keyID, k.Status, string(newStatus)); err != nil {
		return errorsx.Wrap(errorsx.CodeDBConflict, "update failed", true, err)
	}
	s.audit(ctx, "key.enabled", tenantID, principalID, "key", keyID, "success", "", nil)
	return nil
}

// CancelDestroy transitions a DESTROY_PENDING key back to the state machine's
// recoverable state.
func (s *Service) CancelDestroy(ctx context.Context, tenantID, keyID, principalID string) error {
	k, err := s.store.GetKey(ctx, tenantID, keyID)
	if err != nil {
		return errorsx.New(errorsx.CodeKeyNotFound, "key not found", false)
	}
	newStatus, err := keystate.TransitionKey(keystate.KeyStatus(k.Status), keystate.EvCancelDestroy)
	if err != nil {
		return errorsx.New(errorsx.CodeKeyDisabled, "illegal state transition", false)
	}
	if err := s.store.UpdateKeyStatus(ctx, keyID, k.Status, string(newStatus)); err != nil {
		return errorsx.Wrap(errorsx.CodeDBConflict, "update failed", true, err)
	}
	s.audit(ctx, "key.cancel_destroy", tenantID, principalID, "key", keyID, "success", "", nil)
	return nil
}

// ScheduleDestroy transitions a key to DESTROY_PENDING.
// Per NFR-5, this is a high-risk operation: audit BEFORE state change, fail-closed.
func (s *Service) ScheduleDestroy(ctx context.Context, tenantID, keyID, principalID string) error {
	k, err := s.store.GetKey(ctx, tenantID, keyID)
	if err != nil {
		return errorsx.New(errorsx.CodeKeyNotFound, "key not found", false)
	}
	newStatus, err := keystate.TransitionKey(keystate.KeyStatus(k.Status), keystate.EvScheduleDestroy)
	if err != nil {
		return errorsx.New(errorsx.CodeKeyDisabled, "illegal state transition", false)
	}
	// High-risk: audit before state change (fail-closed per NFR-5).
	if err := s.auditHighRisk(ctx, "key.schedule_destroy", tenantID, principalID, "key", keyID); err != nil {
		return errorsx.Wrap(errorsx.CodeAuditUnavailable, "audit failed, operation aborted", false, err)
	}
	if err := s.store.UpdateKeyStatus(ctx, keyID, k.Status, string(newStatus)); err != nil {
		return errorsx.Wrap(errorsx.CodeDBConflict, "update failed", true, err)
	}
	payload, err := json.Marshal(map[string]string{
		"key_id":      keyID,
		"approved_by": principalID,
	})
	if err != nil {
		return errorsx.Wrap(errorsx.CodeInternal, "encode destroy job", false, err)
	}
	now := time.Now().UTC()
	if err := s.store.CreateLifecycleJob(ctx, &models.LifecycleJob{
		ID:             fmt.Sprintf("job-destroy-%s-%d", keyID, now.UnixNano()),
		Type:           "destroy_due",
		TenantID:       tenantID,
		KeyID:          keyID,
		Payload:        payload,
		Status:         "PENDING",
		NextRunAt:      func() *time.Time { t := now.Add(keystate.DestroyGracePeriod); return &t }(),
		IdempotencyKey: fmt.Sprintf("destroy_due-%s-%d", keyID, now.UnixNano()),
		CreatedAt:      now,
	}); err != nil {
		return errorsx.Wrap(errorsx.CodeDBConflict, "schedule destroy job failed", true, err)
	}
	return nil
}

// DestroyKeyMaterial performs the final post-grace destruction step.
func (s *Service) DestroyKeyMaterial(ctx context.Context, keyID string) error {
	if err := s.store.DestroyKeyMaterial(ctx, keyID); err != nil {
		return errorsx.Wrap(errorsx.CodeDBConflict, "destroy key material failed", true, err)
	}
	return nil
}

// ReconcileDestroyDueJobs repairs historical DESTROY_PENDING keys that predate
// destroy_due job creation or lost their pending lifecycle job. It does not
// bypass FAILED destroy jobs; operators retry those through the Ops plane.
func (s *Service) ReconcileDestroyDueJobs(ctx context.Context) error {
	ks, err := s.store.ListAllKeys(ctx)
	if err != nil {
		return err
	}
	jobs, err := s.store.ListLifecycleJobs(ctx, "", 10000)
	if err != nil {
		return err
	}
	hasActiveDestroyJob := make(map[string]bool, len(jobs))
	hasFailedDestroyJob := make(map[string]bool, len(jobs))
	for _, job := range jobs {
		if job.Type == "destroy_due" && job.KeyID != "" && (job.Status == "PENDING" || job.Status == "RUNNING") {
			hasActiveDestroyJob[job.KeyID] = true
		}
		if job.Type == "destroy_due" && job.KeyID != "" && job.Status == "FAILED" {
			hasFailedDestroyJob[job.KeyID] = true
		}
	}
	for _, k := range ks {
		if k.Status != string(keystate.KeyDestroyPending) || hasActiveDestroyJob[k.ID] || hasFailedDestroyJob[k.ID] {
			continue
		}
		nextRun := k.UpdatedAt.UTC().Add(keystate.DestroyGracePeriod)
		payload, err := json.Marshal(map[string]string{
			"key_id":      k.ID,
			"approved_by": "reconciler",
		})
		if err != nil {
			return err
		}
		if err := s.store.CreateLifecycleJob(ctx, &models.LifecycleJob{
			ID:             fmt.Sprintf("job-destroy-reconcile-%s", k.ID),
			Type:           "destroy_due",
			TenantID:       k.TenantID,
			KeyID:          k.ID,
			Payload:        payload,
			Status:         "PENDING",
			NextRunAt:      &nextRun,
			IdempotencyKey: fmt.Sprintf("destroy_due-reconcile-%s", k.ID),
			CreatedAt:      time.Now().UTC(),
		}); err != nil && !errors.Is(err, repository.ErrConflict) {
			return err
		}
	}
	return nil
}

// PrepareKeyVersion imports externally provisioned static material as a
// PRE_ACTIVE version. It does not change the key's current version.
func (s *Service) PrepareKeyVersion(ctx context.Context, cmd PrepareKeyVersionCommand) (*KeyVersionDTO, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, err := s.store.GetKey(ctx, cmd.TenantID, cmd.KeyID)
	if err != nil {
		return nil, errorsx.New(errorsx.CodeKeyNotFound, "key not found", false)
	}
	if k.Status != string(keystate.KeyActive) {
		return nil, errorsx.New(errorsx.CodeKeyDisabled, "key not active", false)
	}
	suite, err := suiteIDFromString(k.SuiteID)
	if err != nil {
		return nil, errorsx.New(errorsx.CodePolicyDenied, "invalid suite_id", false)
	}
	versionNo := k.CurrentVersion + 1
	versionID := newID("kv")
	dm, err := s.resolver.WrapExternalKey(ctx, suite, versionID, cmd.ExternalKey)
	for i := range cmd.ExternalKey {
		cmd.ExternalKey[i] = 0
	}
	if err != nil {
		return nil, errorsx.Wrap(errorsx.CodeTPMUnavailable, "dek wrap failed", true, err)
	}
	kv := &models.KeyVersion{ID: versionID, KeyID: k.ID, VersionNo: versionNo, SuiteID: k.SuiteID,
		WrappedDEK: dm.WrappedDEK, WrapMetadata: dm.WrapMetadata, Status: string(keystate.KVPreActive), CreatedAt: time.Now().UTC()}
	if err := s.store.CreatePendingKeyVersion(ctx, k.ID, kv); err != nil {
		return nil, errorsx.Wrap(errorsx.CodeDBConflict, "create pending version failed", true, err)
	}
	s.audit(ctx, "key.version_prepared", cmd.TenantID, cmd.PrincipalID, "key", k.ID, "success", "", map[string]string{"version": fmt.Sprintf("%d", versionNo)})
	return &KeyVersionDTO{KeyID: k.ID, VersionNo: versionNo, SuiteID: k.SuiteID, Status: kv.Status}, nil
}

func (s *Service) ActivateKeyVersion(ctx context.Context, tenantID, keyID string, versionNo uint32, principalID string) (*KeyDTO, error) {
	if _, err := s.store.GetKey(ctx, tenantID, keyID); err != nil {
		return nil, errorsx.New(errorsx.CodeKeyNotFound, "key not found", false)
	}
	if err := s.auditHighRisk(ctx, "key.version_activate", tenantID, principalID, "key", keyID); err != nil {
		return nil, errorsx.Wrap(errorsx.CodeAuditUnavailable, "audit failed, operation aborted", false, err)
	}
	if err := s.store.ActivateKeyVersion(ctx, keyID, versionNo); err != nil {
		return nil, errorsx.Wrap(errorsx.CodeDBConflict, "activate version failed", true, err)
	}
	k, err := s.store.GetKey(ctx, tenantID, keyID)
	if err != nil {
		return nil, errorsx.Wrap(errorsx.CodeInternal, "re-fetch failed", false, err)
	}
	return toDTO(k), nil
}

// suiteIDFromString maps a suite string to aead.SuiteID.
func suiteIDFromString(s string) (aead.SuiteID, error) {
	switch s {
	case "AES_256_GCM":
		return aead.SuiteAES256GCM, nil
	case "SM4_GCM":
		return aead.SuiteSM4GCM, nil
	case "AES_256_ECB":
		return aead.SuiteAES256ECB, nil
	case "SM4_ECB":
		return aead.SuiteSM4ECB, nil
	}
	return 0, fmt.Errorf("unknown suite %s", s)
}

func toDTO(k *models.Key) *KeyDTO {
	var expiresAt *time.Time
	if !k.ExpiresAt.IsZero() {
		expiresAt = &k.ExpiresAt
	}
	var archivedAt *time.Time
	if !k.ArchivedAt.IsZero() {
		archivedAt = &k.ArchivedAt
	}
	status := k.Status
	if status == string(keystate.KeyActive) && keyExpired(k) {
		status = "EXPIRED"
	}
	return &KeyDTO{
		KeyID:          k.ID,
		TenantID:       k.TenantID,
		Name:           k.Name,
		Purpose:        k.Purpose,
		PolicyID:       k.PolicyID,
		SuiteID:        k.SuiteID,
		CurrentVersion: k.CurrentVersion,
		Status:         status,
		Tags:           k.Tags,
		ExpiresAt:      expiresAt,
		ArchivedAt:     archivedAt,
		CreatedAt:      k.CreatedAt,
	}
}

func keyExpired(k *models.Key) bool {
	return k != nil && !k.ExpiresAt.IsZero() && !time.Now().UTC().Before(k.ExpiresAt)
}

func newID(prefix string) string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%s_%s", prefix, hex.EncodeToString(b))
}

// ErrInternal is a sentinel for unexpected errors.
var ErrInternal = errors.New("keys: internal")
