package keytransfer

import (
	"bytes"
	"context"
	"crypto/sha256"
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
)

const (
	StatusDownloadReceived = "RECEIVED"
	StatusDownloadImported = "IMPORTED"
	OperationCreateKey     = "CREATE_KEY"
	OperationCreateVersion = "CREATE_VERSION"
)

type ImportDownloadCommand struct {
	TenantID       string
	DownloadID     string
	TargetID       string
	Sequence       uint64
	KEKID          string
	KEKVersion     uint32
	DataKeyID      string
	DataKeyVersion uint32
	DataSuiteID    string
	Name           string
	PolicyID       string
	Tags           map[string]string
	Nonce          []byte
	WrappedKey     []byte
	Tag            []byte
	AAD            []byte
	PrincipalID    string
}

type DownloadDTO struct {
	DownloadID     string     `json:"download_id"`
	FormatVersion  uint8      `json:"format_version"`
	TargetID       string     `json:"target_id"`
	Sequence       uint64     `json:"sequence"`
	KEKID          string     `json:"kek_id"`
	KEKVersion     uint32     `json:"kek_version"`
	DataKeyID      string     `json:"data_key_id"`
	DataKeyVersion uint32     `json:"data_key_version"`
	DataSuiteID    string     `json:"data_suite_id"`
	Operation      string     `json:"operation"`
	Status         string     `json:"status"`
	CreatedAt      time.Time  `json:"created_at"`
	ImportedAt     *time.Time `json:"imported_at,omitempty"`
}

type downloadAAD struct {
	FormatVersion  uint8  `json:"format_version"`
	DownloadID     string `json:"download_id"`
	TargetID       string `json:"target_id"`
	Sequence       uint64 `json:"sequence"`
	KEKID          string `json:"kek_id"`
	KEKVersion     uint32 `json:"kek_version"`
	DataKeyID      string `json:"data_key_id"`
	DataKeyVersion uint32 `json:"data_key_version"`
	DataSuiteID    string `json:"data_suite_id"`
	WrapSuiteID    string `json:"wrap_suite_id"`
}

func (s *Service) ImportDownload(ctx context.Context, cmd ImportDownloadCommand) (*DownloadDTO, error) {
	if cmd.TenantID == "" || cmd.DownloadID == "" || cmd.TargetID == "" ||
		cmd.KEKID == "" || cmd.KEKVersion == 0 || cmd.DataKeyID == "" ||
		cmd.DataKeyVersion == 0 || cmd.DataSuiteID == "" {
		return nil, errorsx.New(errorsx.CodeInvalidArgument, "missing required field", false)
	}
	if cmd.Sequence == 0 || cmd.Sequence > math.MaxInt64 {
		return nil, errorsx.New(errorsx.CodeInvalidArgument, "sequence must be between 1 and 9223372036854775807", false)
	}
	if cmd.KEKID == cmd.DataKeyID {
		return nil, errorsx.New(errorsx.CodeInvalidArgument, "kek and data key must be different keys", false)
	}
	if cmd.DataSuiteID != "SM4_GCM" {
		return nil, errorsx.New(errorsx.CodePolicyDenied, "downloaded data key must use SM4_GCM", false)
	}

	kek, err := s.store.GetKey(ctx, cmd.TenantID, cmd.KEKID)
	if err != nil || kek.Purpose != keys.PurposeKeyWrap || kek.Status != "ACTIVE" {
		return nil, errorsx.New(errorsx.CodePolicyDenied, "kek is not an active key_wrap key", false)
	}
	kekVersion, err := s.store.GetKeyVersionByNo(ctx, kek.ID, cmd.KEKVersion)
	if err != nil || kekVersion.Status != "ACTIVE" {
		return nil, errorsx.New(errorsx.CodePolicyDenied, "kek version is not active", false)
	}
	wrapSuite, err := wrappingSuite(kekVersion.SuiteID)
	if err != nil {
		return nil, errorsx.New(errorsx.CodePolicyDenied, err.Error(), false)
	}

	expectedAAD, err := json.Marshal(downloadAAD{
		FormatVersion: 1, DownloadID: cmd.DownloadID, TargetID: cmd.TargetID,
		Sequence: cmd.Sequence, KEKID: cmd.KEKID, KEKVersion: cmd.KEKVersion,
		DataKeyID: cmd.DataKeyID, DataKeyVersion: cmd.DataKeyVersion,
		DataSuiteID: cmd.DataSuiteID, WrapSuiteID: kekVersion.SuiteID,
	})
	if err != nil {
		return nil, errorsx.Wrap(errorsx.CodeInternal, "aad encoding failed", false, err)
	}
	if !bytes.Equal(cmd.AAD, expectedAAD) {
		return nil, errorsx.New(errorsx.CodeInvalidArgument, "aad does not match download metadata", false)
	}
	requestDigest := downloadRequestDigest(cmd)
	var operation string
	var newRecord *models.KeyDownload

	if existing, err := s.store.GetKeyDownload(ctx, cmd.TenantID, cmd.DownloadID); err == nil {
		if existing.RequestDigest != requestDigest {
			return nil, errorsx.New(errorsx.CodeDBConflict, "download_id was already used for different content", false)
		}
		if existing.Status == StatusDownloadImported {
			return toDownloadDTO(existing), nil
		}
		if s.downloadMaterialExists(ctx, existing) {
			if err := s.store.CompleteKeyDownload(ctx, cmd.TenantID, cmd.DownloadID, cmd.PrincipalID, time.Now().UTC()); err != nil {
				return nil, errorsx.Wrap(errorsx.CodeDBConflict, "download recovery failed", true, err)
			}
			return s.GetDownload(ctx, cmd.TenantID, cmd.DownloadID)
		}
		operation = existing.Operation
	} else if !errors.Is(err, repository.ErrNotFound) {
		return nil, errorsx.Wrap(errorsx.CodeInternal, "download lookup failed", true, err)
	} else {
		operation, err = s.downloadOperation(ctx, cmd)
		if err != nil {
			return nil, err
		}
		newRecord = &models.KeyDownload{
			ID: cmd.DownloadID, TenantID: cmd.TenantID, TargetID: cmd.TargetID,
			Sequence: cmd.Sequence, KEKID: cmd.KEKID, KEKVersion: cmd.KEKVersion,
			DataKeyID: cmd.DataKeyID, DataKeyVersion: cmd.DataKeyVersion,
			DataSuiteID: cmd.DataSuiteID, RequestDigest: requestDigest,
			Operation: operation, Status: StatusDownloadReceived, CreatedAt: time.Now().UTC(),
		}
	}

	kekPlain, err := s.resolver.UnwrapDEK(ctx, kekVersion.WrappedDEK, kekVersion.WrapMetadata, kekVersion.ID)
	if err != nil {
		return nil, errorsx.Wrap(errorsx.CodeTPMUnavailable, "kek unwrap failed", true, err)
	}
	defer zeroize(kekPlain)
	cipherImpl, err := aead.New(wrapSuite, kekPlain)
	if err != nil {
		return nil, errorsx.Wrap(errorsx.CodeInternal, "kek cipher initialization failed", false, err)
	}
	if len(cmd.Nonce) != cipherImpl.NonceSize() || len(cmd.Tag) != cipherImpl.TagSize() {
		return nil, errorsx.New(errorsx.CodeInvalidArgument, "invalid nonce or tag length", false)
	}
	dataPlain, err := cipherImpl.Decrypt(cmd.WrappedKey, cmd.Tag, cmd.Nonce, cmd.AAD)
	if err != nil {
		return nil, errorsx.New(errorsx.CodeInvalidArgument, "download authentication failed", false)
	}
	defer zeroize(dataPlain)
	if len(dataPlain) != aead.SuiteSM4GCM.KeyBytes() {
		return nil, errorsx.New(errorsx.CodeInvalidArgument, "downloaded key length does not match SM4_GCM", false)
	}

	if err := s.auditor.Record(ctx, keys.AuditRequest{
		Action: "key_download.import_authorized", TenantID: cmd.TenantID, PrincipalID: cmd.PrincipalID,
		TargetType: "key_download", TargetID: cmd.DownloadID, Result: "success",
		Metadata: map[string]string{"target_id": cmd.TargetID, "kek_id": cmd.KEKID, "data_key_id": cmd.DataKeyID},
	}); err != nil {
		return nil, errorsx.Wrap(errorsx.CodeAuditUnavailable, "audit failed, operation aborted", false, err)
	}
	if newRecord != nil {
		if err := s.store.CreateKeyDownload(ctx, newRecord); err != nil {
			if errors.Is(err, repository.ErrConflict) {
				return nil, errorsx.New(errorsx.CodeDBConflict, "download id or target sequence already exists", false)
			}
			return nil, errorsx.Wrap(errorsx.CodeInternal, "download persistence failed", true, err)
		}
	}

	switch operation {
	case OperationCreateKey:
		_, err = s.keys.ImportKey(ctx, keys.ImportKeyCommand{
			TenantID: cmd.TenantID, KeyID: cmd.DataKeyID, Name: cmd.Name,
			Purpose: keys.PurposeEncryptDecrypt, PolicyID: cmd.PolicyID,
			SuiteID: cmd.DataSuiteID, Tags: cmd.Tags, ExternalKey: dataPlain,
			PrincipalID: cmd.PrincipalID,
		})
	case OperationCreateVersion:
		var version *keys.KeyVersionDTO
		version, err = s.keys.PrepareKeyVersion(ctx, keys.PrepareKeyVersionCommand{
			TenantID: cmd.TenantID, KeyID: cmd.DataKeyID,
			ExternalKey: dataPlain, PrincipalID: cmd.PrincipalID,
		})
		if err == nil && version.VersionNo != cmd.DataKeyVersion {
			err = errors.New("prepared key version does not match download metadata")
		}
	default:
		err = errors.New("unsupported download operation")
	}
	if err != nil {
		return nil, errorsx.Wrap(errorsx.CodeDBConflict, "downloaded key import failed", true, err)
	}
	if err := s.store.CompleteKeyDownload(ctx, cmd.TenantID, cmd.DownloadID, cmd.PrincipalID, time.Now().UTC()); err != nil {
		return nil, errorsx.Wrap(errorsx.CodeDBConflict, "download completion failed", true, err)
	}
	return s.GetDownload(ctx, cmd.TenantID, cmd.DownloadID)
}

func (s *Service) GetDownload(ctx context.Context, tenantID, downloadID string) (*DownloadDTO, error) {
	d, err := s.store.GetKeyDownload(ctx, tenantID, downloadID)
	if err != nil {
		return nil, errorsx.New(errorsx.CodeKeyNotFound, "key download not found", false)
	}
	return toDownloadDTO(d), nil
}

func (s *Service) downloadOperation(ctx context.Context, cmd ImportDownloadCommand) (string, error) {
	k, err := s.store.GetKey(ctx, cmd.TenantID, cmd.DataKeyID)
	if errors.Is(err, repository.ErrNotFound) {
		if cmd.DataKeyVersion != 1 || cmd.Name == "" || cmd.PolicyID == "" {
			return "", errorsx.New(errorsx.CodeInvalidArgument, "new data key requires version 1, name and policy_id", false)
		}
		return OperationCreateKey, nil
	}
	if err != nil {
		return "", errorsx.Wrap(errorsx.CodeInternal, "data key lookup failed", true, err)
	}
	if k.Purpose != keys.PurposeEncryptDecrypt || k.SuiteID != cmd.DataSuiteID || k.Status != "ACTIVE" {
		return "", errorsx.New(errorsx.CodePolicyDenied, "existing data key is not eligible for download import", false)
	}
	if cmd.DataKeyVersion != k.CurrentVersion+1 {
		return "", errorsx.New(errorsx.CodeInvalidArgument, "data_key_version must be the next version", false)
	}
	return OperationCreateVersion, nil
}

func (s *Service) downloadMaterialExists(ctx context.Context, d *models.KeyDownload) bool {
	k, err := s.store.GetKey(ctx, d.TenantID, d.DataKeyID)
	if err != nil || k.SuiteID != d.DataSuiteID {
		return false
	}
	v, err := s.store.GetKeyVersionByNo(ctx, d.DataKeyID, d.DataKeyVersion)
	return err == nil && (v.Status == "PRE_ACTIVE" || v.Status == "ACTIVE")
}

func downloadRequestDigest(cmd ImportDownloadCommand) string {
	body, _ := json.Marshal(struct {
		TenantID       string            `json:"tenant_id"`
		DownloadID     string            `json:"download_id"`
		TargetID       string            `json:"target_id"`
		Sequence       uint64            `json:"sequence"`
		KEKID          string            `json:"kek_id"`
		KEKVersion     uint32            `json:"kek_version"`
		DataKeyID      string            `json:"data_key_id"`
		DataKeyVersion uint32            `json:"data_key_version"`
		DataSuiteID    string            `json:"data_suite_id"`
		Name           string            `json:"name"`
		PolicyID       string            `json:"policy_id"`
		Tags           map[string]string `json:"tags"`
		Nonce          []byte            `json:"nonce"`
		WrappedKey     []byte            `json:"wrapped_key"`
		Tag            []byte            `json:"tag"`
		AAD            []byte            `json:"aad"`
	}{
		TenantID: cmd.TenantID, DownloadID: cmd.DownloadID, TargetID: cmd.TargetID,
		Sequence: cmd.Sequence, KEKID: cmd.KEKID, KEKVersion: cmd.KEKVersion,
		DataKeyID: cmd.DataKeyID, DataKeyVersion: cmd.DataKeyVersion,
		DataSuiteID: cmd.DataSuiteID, Name: cmd.Name, PolicyID: cmd.PolicyID,
		Tags: cmd.Tags, Nonce: cmd.Nonce, WrappedKey: cmd.WrappedKey, Tag: cmd.Tag, AAD: cmd.AAD,
	})
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func toDownloadDTO(d *models.KeyDownload) *DownloadDTO {
	dto := &DownloadDTO{
		DownloadID: d.ID, FormatVersion: 1, TargetID: d.TargetID, Sequence: d.Sequence,
		KEKID: d.KEKID, KEKVersion: d.KEKVersion, DataKeyID: d.DataKeyID,
		DataKeyVersion: d.DataKeyVersion, DataSuiteID: d.DataSuiteID,
		Operation: d.Operation, Status: d.Status, CreatedAt: d.CreatedAt,
	}
	if !d.ImportedAt.IsZero() {
		t := d.ImportedAt
		dto.ImportedAt = &t
	}
	return dto
}
