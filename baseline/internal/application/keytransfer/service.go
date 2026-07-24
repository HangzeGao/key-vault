// Package keytransfer implements protocol-neutral key upload and download.
package keytransfer

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"time"

	"github.com/kvlt/key-vault/internal/application/keys"
	"github.com/kvlt/key-vault/internal/crypto/aead"
	"github.com/kvlt/key-vault/internal/errorsx"
	"github.com/kvlt/key-vault/internal/repository"
	"github.com/kvlt/key-vault/internal/repository/models"
	"github.com/kvlt/key-vault/internal/resolver/keyresolver"
)

const (
	StatusUploadPending = "UPLOAD_PENDING"
	StatusConfirmed     = "CONFIRMED"
)

type Store interface {
	GetKey(ctx context.Context, tenantID, keyID string) (*models.Key, error)
	GetCurrentKeyVersion(ctx context.Context, keyID string) (*models.KeyVersion, error)
	GetKeyVersionByNo(ctx context.Context, keyID string, versionNo uint32) (*models.KeyVersion, error)
	CreateKeyUpload(ctx context.Context, p *models.KeyUpload) error
	GetKeyUpload(ctx context.Context, tenantID, uploadID string) (*models.KeyUpload, error)
	ConfirmKeyUpload(ctx context.Context, tenantID, uploadID, principalID string, confirmedAt time.Time) error
	CreateKeyDownload(ctx context.Context, d *models.KeyDownload) error
	GetKeyDownload(ctx context.Context, tenantID, downloadID string) (*models.KeyDownload, error)
	CompleteKeyDownload(ctx context.Context, tenantID, downloadID, principalID string, importedAt time.Time) error
	ActivateKeyVersion(ctx context.Context, keyID string, versionNo uint32) error
	GetIdempotency(ctx context.Context, key string) (*models.IdempotencyKey, error)
	RecordIdempotency(ctx context.Context, ik *models.IdempotencyKey) error
}

type Auditor interface {
	Record(ctx context.Context, req keys.AuditRequest) error
}

type noopAuditor struct{}

func (noopAuditor) Record(context.Context, keys.AuditRequest) error { return nil }

type Service struct {
	store    Store
	resolver *keyresolver.Resolver
	keys     *keys.Service
	auditor  Auditor
}

func New(store Store, resolver *keyresolver.Resolver, keyService *keys.Service) *Service {
	return &Service{store: store, resolver: resolver, keys: keyService, auditor: noopAuditor{}}
}

func (s *Service) SetAuditor(a Auditor) {
	if a != nil {
		s.auditor = a
	}
}

type CreateUploadCommand struct {
	TenantID       string
	TargetID       string
	Sequence       uint64
	KEKID          string
	KEKVersion     uint32
	DataKeyID      string
	DataKeyVersion uint32
	PrincipalID    string
	IdempotencyKey string
}

type UploadDTO struct {
	UploadID       string     `json:"upload_id"`
	FormatVersion  uint8      `json:"format_version"`
	TargetID       string     `json:"target_id"`
	Sequence       uint64     `json:"sequence"`
	KEKID          string     `json:"kek_id"`
	KEKVersion     uint32     `json:"kek_version"`
	DataKeyID      string     `json:"data_key_id"`
	DataKeyVersion uint32     `json:"data_key_version"`
	WrapSuiteID    string     `json:"wrap_suite_id"`
	Nonce          string     `json:"nonce"`
	WrappedKey     string     `json:"wrapped_key"`
	Tag            string     `json:"tag"`
	AADB64         string     `json:"aad_b64"`
	Status         string     `json:"status"`
	CreatedAt      time.Time  `json:"created_at"`
	ConfirmedAt    *time.Time `json:"confirmed_at,omitempty"`
}

type uploadAAD struct {
	FormatVersion  uint8  `json:"format_version"`
	UploadID       string `json:"upload_id"`
	TargetID       string `json:"target_id"`
	Sequence       uint64 `json:"sequence"`
	KEKID          string `json:"kek_id"`
	KEKVersion     uint32 `json:"kek_version"`
	DataKeyID      string `json:"data_key_id"`
	DataKeyVersion uint32 `json:"data_key_version"`
	WrapSuiteID    string `json:"wrap_suite_id"`
}

func (s *Service) CreateUpload(ctx context.Context, cmd CreateUploadCommand) (*UploadDTO, error) {
	if cmd.TenantID == "" || cmd.TargetID == "" || cmd.KEKID == "" || cmd.DataKeyID == "" {
		return nil, errorsx.New(errorsx.CodeInvalidArgument, "missing required field", false)
	}
	if cmd.Sequence == 0 || cmd.Sequence > math.MaxInt64 {
		return nil, errorsx.New(errorsx.CodeInvalidArgument, "sequence must be between 1 and 9223372036854775807", false)
	}
	if cmd.KEKID == cmd.DataKeyID {
		return nil, errorsx.New(errorsx.CodeInvalidArgument, "kek and data key must be different keys", false)
	}
	requestHash := createUploadRequestHash(cmd)
	if cmd.IdempotencyKey != "" {
		if existing, err := s.store.GetIdempotency(ctx, cmd.IdempotencyKey); err == nil {
			if existing.TenantID != cmd.TenantID || existing.PrincipalID != cmd.PrincipalID ||
				existing.Path != "/ui/api/v1/key-uploads" || existing.RequestHash != requestHash {
				return nil, errorsx.New(errorsx.CodeDBConflict, "idempotency key belongs to a different request scope", false)
			}
			return s.GetUpload(ctx, cmd.TenantID, existing.ResponseHash)
		}
	}

	kek, err := s.store.GetKey(ctx, cmd.TenantID, cmd.KEKID)
	if err != nil {
		return nil, errorsx.New(errorsx.CodeKeyNotFound, "kek not found", false)
	}
	if kek.Purpose != keys.PurposeKeyWrap || kek.Status != "ACTIVE" {
		return nil, errorsx.New(errorsx.CodePolicyDenied, "kek is not an active key_wrap key", false)
	}
	kekVersion, err := s.selectVersion(ctx, kek, cmd.KEKVersion)
	if err != nil || kekVersion.Status != "ACTIVE" {
		return nil, errorsx.New(errorsx.CodePolicyDenied, "kek version is not active", false)
	}
	wrapSuite, err := wrappingSuite(kekVersion.SuiteID)
	if err != nil {
		return nil, errorsx.New(errorsx.CodePolicyDenied, err.Error(), false)
	}

	dataKey, err := s.store.GetKey(ctx, cmd.TenantID, cmd.DataKeyID)
	if err != nil {
		return nil, errorsx.New(errorsx.CodeKeyNotFound, "data key not found", false)
	}
	if dataKey.Purpose != keys.PurposeEncryptDecrypt || dataKey.SuiteID != "SM4_GCM" || dataKey.Status != "ACTIVE" {
		return nil, errorsx.New(errorsx.CodePolicyDenied, "data key must be an active SM4_GCM encrypt_decrypt key", false)
	}
	dataVersion, err := s.selectVersion(ctx, dataKey, cmd.DataKeyVersion)
	if err != nil {
		return nil, errorsx.New(errorsx.CodeKeyNotFound, "data key version not found", false)
	}
	if dataVersion.Status != "ACTIVE" && dataVersion.Status != "PRE_ACTIVE" {
		return nil, errorsx.New(errorsx.CodePolicyDenied, "data key version is not deliverable", false)
	}

	kekPlain, err := s.resolver.UnwrapDEK(ctx, kekVersion.WrappedDEK, kekVersion.WrapMetadata, kekVersion.ID)
	if err != nil {
		return nil, errorsx.Wrap(errorsx.CodeTPMUnavailable, "kek unwrap failed", true, err)
	}
	defer zeroize(kekPlain)
	dataPlain, err := s.resolver.UnwrapDEK(ctx, dataVersion.WrappedDEK, dataVersion.WrapMetadata, dataVersion.ID)
	if err != nil {
		return nil, errorsx.Wrap(errorsx.CodeTPMUnavailable, "data key unwrap failed", true, err)
	}
	defer zeroize(dataPlain)

	cipherImpl, err := aead.New(wrapSuite, kekPlain)
	if err != nil {
		return nil, errorsx.Wrap(errorsx.CodeInternal, "kek cipher initialization failed", false, err)
	}
	uploadID, err := randomID("kup")
	if err != nil {
		return nil, errorsx.Wrap(errorsx.CodeInternal, "upload id generation failed", false, err)
	}
	aadValue := uploadAAD{
		FormatVersion: 1, UploadID: uploadID, TargetID: cmd.TargetID, Sequence: cmd.Sequence,
		KEKID: kek.ID, KEKVersion: kekVersion.VersionNo, DataKeyID: dataKey.ID,
		DataKeyVersion: dataVersion.VersionNo, WrapSuiteID: kekVersion.SuiteID,
	}
	aadBytes, err := json.Marshal(aadValue)
	if err != nil {
		return nil, errorsx.Wrap(errorsx.CodeInternal, "aad encoding failed", false, err)
	}
	nonce := make([]byte, cipherImpl.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, errorsx.Wrap(errorsx.CodeInternal, "nonce generation failed", false, err)
	}
	wrapped, tag := cipherImpl.Encrypt(dataPlain, nonce, aadBytes)
	now := time.Now().UTC()
	p := &models.KeyUpload{
		ID: uploadID, TenantID: cmd.TenantID, TargetID: cmd.TargetID, Sequence: cmd.Sequence,
		KEKID: kek.ID, KEKVersion: kekVersion.VersionNo, DataKeyID: dataKey.ID,
		DataKeyVersion: dataVersion.VersionNo, WrapSuiteID: kekVersion.SuiteID,
		Nonce: nonce, WrappedKey: wrapped, Tag: tag, AAD: aadBytes,
		Status: StatusUploadPending, CreatedAt: now,
	}
	if err := s.auditor.Record(ctx, keys.AuditRequest{
		Action: "key_upload.create_authorized", TenantID: cmd.TenantID, PrincipalID: cmd.PrincipalID,
		TargetType: "key_upload", TargetID: uploadID, Result: "success",
		Metadata: map[string]string{"target_id": cmd.TargetID, "kek_id": kek.ID, "data_key_id": dataKey.ID},
	}); err != nil {
		return nil, errorsx.Wrap(errorsx.CodeAuditUnavailable, "audit failed, operation aborted", false, err)
	}
	if err := s.store.CreateKeyUpload(ctx, p); err != nil {
		if errors.Is(err, repository.ErrConflict) {
			return nil, errorsx.New(errorsx.CodeDBConflict, "upload id or target sequence already exists", false)
		}
		return nil, errorsx.Wrap(errorsx.CodeInternal, "upload persistence failed", true, err)
	}
	if cmd.IdempotencyKey != "" {
		_ = s.store.RecordIdempotency(ctx, &models.IdempotencyKey{
			Key: cmd.IdempotencyKey, PrincipalID: cmd.PrincipalID, TenantID: cmd.TenantID,
			Method: "POST", Path: "/ui/api/v1/key-uploads",
			RequestHash: requestHash, ResponseStatus: 201, ResponseHash: uploadID, CreatedAt: now,
		})
	}
	return toUploadDTO(p), nil
}

func (s *Service) GetUpload(ctx context.Context, tenantID, uploadID string) (*UploadDTO, error) {
	p, err := s.store.GetKeyUpload(ctx, tenantID, uploadID)
	if err != nil {
		return nil, errorsx.New(errorsx.CodeKeyNotFound, "key upload not found", false)
	}
	return toUploadDTO(p), nil
}

func (s *Service) ConfirmUpload(ctx context.Context, tenantID, uploadID, principalID string) (*UploadDTO, error) {
	p, err := s.store.GetKeyUpload(ctx, tenantID, uploadID)
	if err != nil {
		return nil, errorsx.New(errorsx.CodeKeyNotFound, "key upload not found", false)
	}
	if p.Status == StatusConfirmed {
		return toUploadDTO(p), nil
	}
	if err := s.auditor.Record(ctx, keys.AuditRequest{
		Action: "key_upload.confirmed", TenantID: tenantID, PrincipalID: principalID,
		TargetType: "key_upload", TargetID: uploadID, Result: "success",
		Metadata: map[string]string{"target_id": p.TargetID, "data_key_id": p.DataKeyID},
	}); err != nil {
		return nil, errorsx.Wrap(errorsx.CodeAuditUnavailable, "audit failed, operation aborted", false, err)
	}
	dataVersion, err := s.store.GetKeyVersionByNo(ctx, p.DataKeyID, p.DataKeyVersion)
	if err != nil {
		return nil, errorsx.New(errorsx.CodeKeyNotFound, "data key version not found", false)
	}
	if dataVersion.Status == "PRE_ACTIVE" {
		if err := s.store.ActivateKeyVersion(ctx, p.DataKeyID, p.DataKeyVersion); err != nil {
			return nil, errorsx.Wrap(errorsx.CodeDBConflict, "data key activation failed", true, err)
		}
	} else if dataVersion.Status != "ACTIVE" {
		return nil, errorsx.New(errorsx.CodePolicyDenied, "data key version can no longer be activated", false)
	}
	now := time.Now().UTC()
	if err := s.store.ConfirmKeyUpload(ctx, tenantID, uploadID, principalID, now); err != nil {
		return nil, errorsx.Wrap(errorsx.CodeDBConflict, "upload confirmation failed", true, err)
	}
	return s.GetUpload(ctx, tenantID, uploadID)
}

func (s *Service) selectVersion(ctx context.Context, key *models.Key, version uint32) (*models.KeyVersion, error) {
	if version == 0 {
		return s.store.GetCurrentKeyVersion(ctx, key.ID)
	}
	return s.store.GetKeyVersionByNo(ctx, key.ID, version)
}

func wrappingSuite(id string) (aead.SuiteID, error) {
	switch id {
	case "AES_256_GCM":
		return aead.SuiteAES256GCM, nil
	case "SM4_GCM":
		return aead.SuiteSM4GCM, nil
	default:
		return 0, errors.New("kek must use an authenticated GCM suite")
	}
}

func randomID(prefix string) (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return prefix + "-" + hex.EncodeToString(b[:]), nil
}

func createUploadRequestHash(cmd CreateUploadCommand) string {
	body, _ := json.Marshal(struct {
		TenantID       string `json:"tenant_id"`
		TargetID       string `json:"target_id"`
		Sequence       uint64 `json:"sequence"`
		KEKID          string `json:"kek_id"`
		KEKVersion     uint32 `json:"kek_version"`
		DataKeyID      string `json:"data_key_id"`
		DataKeyVersion uint32 `json:"data_key_version"`
	}{
		TenantID: cmd.TenantID, TargetID: cmd.TargetID, Sequence: cmd.Sequence,
		KEKID: cmd.KEKID, KEKVersion: cmd.KEKVersion,
		DataKeyID: cmd.DataKeyID, DataKeyVersion: cmd.DataKeyVersion,
	})
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func zeroize(v []byte) {
	for i := range v {
		v[i] = 0
	}
}

func toUploadDTO(p *models.KeyUpload) *UploadDTO {
	dto := &UploadDTO{
		UploadID: p.ID, FormatVersion: 1, TargetID: p.TargetID, Sequence: p.Sequence,
		KEKID: p.KEKID, KEKVersion: p.KEKVersion, DataKeyID: p.DataKeyID,
		DataKeyVersion: p.DataKeyVersion, WrapSuiteID: p.WrapSuiteID,
		Nonce:      base64.StdEncoding.EncodeToString(p.Nonce),
		WrappedKey: base64.StdEncoding.EncodeToString(p.WrappedKey),
		Tag:        base64.StdEncoding.EncodeToString(p.Tag),
		AADB64:     base64.StdEncoding.EncodeToString(p.AAD),
		Status:     p.Status, CreatedAt: p.CreatedAt,
	}
	if !p.ConfirmedAt.IsZero() {
		t := p.ConfirmedAt
		dto.ConfirmedAt = &t
	}
	return dto
}
