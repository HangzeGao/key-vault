package keytransfer

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	appkeys "github.com/kvlt/key-vault/internal/application/keys"
	"github.com/kvlt/key-vault/internal/crypto/aad"
	"github.com/kvlt/key-vault/internal/crypto/aead"
	"github.com/kvlt/key-vault/internal/domain/policy"
	"github.com/kvlt/key-vault/internal/repository/memory"
	"github.com/kvlt/key-vault/internal/repository/models"
	"github.com/kvlt/key-vault/internal/resolver/keyresolver"
	"github.com/kvlt/key-vault/internal/tpm/provider"
)

func TestCreateUploadWrapsDataKeyAndConfirmActivatesPendingVersion(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	resolver := testResolver(t, ctx)
	now := time.Now().UTC()
	if err := store.UpsertTenant(ctx, &models.Tenant{ID: "tenant-1", Name: "tenant"}); err != nil {
		t.Fatal(err)
	}

	kekPlain := bytes.Repeat([]byte{0x11}, 16)
	kekMaterial, err := resolver.WrapExternalKey(ctx, aead.SuiteSM4GCM, "kek-v1", kekPlain)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CreateKey(ctx, &models.Key{
		ID: "kek", TenantID: "tenant-1", Name: "device kek", Purpose: "key_wrap",
		PolicyID: "default-v1", SuiteID: "SM4_GCM", CurrentVersion: 1, Status: "ACTIVE",
	}, &models.KeyVersion{
		ID: "kek-v1", KeyID: "kek", VersionNo: 1, SuiteID: "SM4_GCM",
		WrappedDEK: kekMaterial.WrappedDEK, WrapMetadata: kekMaterial.WrapMetadata,
		Status: "ACTIVE", CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	oldData := bytes.Repeat([]byte{0x22}, 16)
	oldMaterial, err := resolver.WrapExternalKey(ctx, aead.SuiteSM4GCM, "data-v1", oldData)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CreateKey(ctx, &models.Key{
		ID: "data", TenantID: "tenant-1", Name: "data key", Purpose: "encrypt_decrypt",
		PolicyID: "default-v1", SuiteID: "SM4_GCM", CurrentVersion: 1, Status: "ACTIVE",
	}, &models.KeyVersion{
		ID: "data-v1", KeyID: "data", VersionNo: 1, SuiteID: "SM4_GCM",
		WrappedDEK: oldMaterial.WrappedDEK, WrapMetadata: oldMaterial.WrapMetadata,
		Status: "ACTIVE", CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	newData := bytes.Repeat([]byte{0x33}, 16)
	newMaterial, err := resolver.WrapExternalKey(ctx, aead.SuiteSM4GCM, "data-v2", newData)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CreatePendingKeyVersion(ctx, "data", &models.KeyVersion{
		ID: "data-v2", KeyID: "data", VersionNo: 2, SuiteID: "SM4_GCM",
		WrappedDEK: newMaterial.WrappedDEK, WrapMetadata: newMaterial.WrapMetadata,
		Status: "PRE_ACTIVE", CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	svc := New(store, resolver, nil)
	dto, err := svc.CreateUpload(ctx, CreateUploadCommand{
		TenantID: "tenant-1", TargetID: "device-01", Sequence: 7,
		KEKID: "kek", DataKeyID: "data", DataKeyVersion: 2, PrincipalID: "admin",
		IdempotencyKey: "delivery-request-1",
	})
	if err != nil {
		t.Fatalf("CreateUpload: %v", err)
	}
	if dto.Status != StatusUploadPending || dto.DataKeyVersion != 2 {
		t.Fatalf("unexpected upload: %+v", dto)
	}
	wrapped, _ := base64.StdEncoding.DecodeString(dto.WrappedKey)
	nonce, _ := base64.StdEncoding.DecodeString(dto.Nonce)
	tag, _ := base64.StdEncoding.DecodeString(dto.Tag)
	aadBytes, _ := base64.StdEncoding.DecodeString(dto.AADB64)
	cipherImpl, err := aead.New(aead.SuiteSM4GCM, kekPlain)
	if err != nil {
		t.Fatal(err)
	}
	got, err := cipherImpl.Decrypt(wrapped, tag, nonce, aadBytes)
	if err != nil {
		t.Fatalf("unwrap delivery package: %v", err)
	}
	if !bytes.Equal(got, newData) {
		t.Fatal("delivery package did not contain the selected data key")
	}
	replayed, err := svc.CreateUpload(ctx, CreateUploadCommand{
		TenantID: "tenant-1", TargetID: "device-01", Sequence: 7,
		KEKID: "kek", DataKeyID: "data", DataKeyVersion: 2, PrincipalID: "admin",
		IdempotencyKey: "delivery-request-1",
	})
	if err != nil || replayed.UploadID != dto.UploadID {
		t.Fatalf("idempotent replay = %+v, %v", replayed, err)
	}

	if _, err := svc.CreateUpload(ctx, CreateUploadCommand{
		TenantID: "tenant-1", TargetID: "device-01", Sequence: 7,
		KEKID: "kek", DataKeyID: "data", DataKeyVersion: 2,
	}); err == nil {
		t.Fatal("duplicate target sequence was accepted")
	}

	confirmed, err := svc.ConfirmUpload(ctx, "tenant-1", dto.UploadID, "confirmer")
	if err != nil {
		t.Fatalf("Confirm: %v", err)
	}
	if confirmed.Status != StatusConfirmed {
		t.Fatalf("status = %s, want CONFIRMED", confirmed.Status)
	}
	key, err := store.GetKey(ctx, "tenant-1", "data")
	if err != nil {
		t.Fatal(err)
	}
	if key.CurrentVersion != 2 {
		t.Fatalf("current version = %d, want 2", key.CurrentVersion)
	}
}

func TestImportDownloadCreatesKeyThenPendingVersion(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	resolver := testResolver(t, ctx)
	if err := store.UpsertTenant(ctx, &models.Tenant{ID: "tenant-1", Name: "tenant"}); err != nil {
		t.Fatal(err)
	}
	kekPlain := bytes.Repeat([]byte{0x51}, 16)
	kekMaterial, err := resolver.WrapExternalKey(ctx, aead.SuiteSM4GCM, "download-kek-v1", kekPlain)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CreateKey(ctx, &models.Key{
		ID: "download-kek", TenantID: "tenant-1", Name: "device kek", Purpose: "key_wrap",
		PolicyID: "default-v1", SuiteID: "SM4_GCM", CurrentVersion: 1, Status: "ACTIVE",
	}, &models.KeyVersion{
		ID: "download-kek-v1", KeyID: "download-kek", VersionNo: 1, SuiteID: "SM4_GCM",
		WrappedDEK: kekMaterial.WrappedDEK, WrapMetadata: kekMaterial.WrapMetadata, Status: "ACTIVE",
	}); err != nil {
		t.Fatal(err)
	}
	policies := policy.NewEngine()
	if err := policies.Load(policy.DefaultPolicy()); err != nil {
		t.Fatal(err)
	}
	keySvc := appkeys.New(store, resolver, policies)
	svc := New(store, resolver, keySvc)

	importOne := func(downloadID string, sequence uint64, version uint32, plaintext []byte, name, policyID string) *DownloadDTO {
		t.Helper()
		aadBytes, err := json.Marshal(downloadAAD{
			FormatVersion: 1, DownloadID: downloadID, TargetID: "device-01",
			Sequence: sequence, KEKID: "download-kek", KEKVersion: 1,
			DataKeyID: "downloaded-data", DataKeyVersion: version,
			DataSuiteID: "SM4_GCM", WrapSuiteID: "SM4_GCM",
		})
		if err != nil {
			t.Fatal(err)
		}
		cipherImpl, err := aead.New(aead.SuiteSM4GCM, kekPlain)
		if err != nil {
			t.Fatal(err)
		}
		nonce := bytes.Repeat([]byte{byte(sequence)}, cipherImpl.NonceSize())
		wrapped, tag := cipherImpl.Encrypt(plaintext, nonce, aadBytes)
		dto, err := svc.ImportDownload(ctx, ImportDownloadCommand{
			TenantID: "tenant-1", DownloadID: downloadID, TargetID: "device-01",
			Sequence: sequence, KEKID: "download-kek", KEKVersion: 1,
			DataKeyID: "downloaded-data", DataKeyVersion: version, DataSuiteID: "SM4_GCM",
			Name: name, PolicyID: policyID, Nonce: nonce, WrappedKey: wrapped,
			Tag: tag, AAD: aadBytes, PrincipalID: "admin",
		})
		if err != nil {
			t.Fatalf("ImportDownload(%s): %v", downloadID, err)
		}
		return dto
	}

	v1Plain := bytes.Repeat([]byte{0x61}, 16)
	first := importOne("download-1", 1, 1, v1Plain, "downloaded data key", "default-v1")
	if first.Status != StatusDownloadImported || first.Operation != OperationCreateKey {
		t.Fatalf("first download = %+v", first)
	}
	replayed := importOne("download-1", 1, 1, v1Plain, "downloaded data key", "default-v1")
	if replayed.DownloadID != first.DownloadID || replayed.Status != StatusDownloadImported {
		t.Fatalf("download replay = %+v", replayed)
	}
	v1, err := store.GetKeyVersionByNo(ctx, "downloaded-data", 1)
	if err != nil {
		t.Fatal(err)
	}
	gotV1, err := resolver.UnwrapDEK(ctx, v1.WrappedDEK, v1.WrapMetadata, v1.ID)
	if err != nil || !bytes.Equal(gotV1, v1Plain) {
		t.Fatalf("downloaded v1 mismatch: %v", err)
	}
	zeroize(gotV1)

	v2Plain := bytes.Repeat([]byte{0x62}, 16)
	second := importOne("download-2", 2, 2, v2Plain, "", "")
	if second.Status != StatusDownloadImported || second.Operation != OperationCreateVersion {
		t.Fatalf("second download = %+v", second)
	}
	v2, err := store.GetKeyVersionByNo(ctx, "downloaded-data", 2)
	if err != nil {
		t.Fatal(err)
	}
	if v2.Status != "PRE_ACTIVE" {
		t.Fatalf("downloaded v2 status = %s, want PRE_ACTIVE", v2.Status)
	}
}

func testResolver(t *testing.T, ctx context.Context) *keyresolver.Resolver {
	t.Helper()
	p, err := provider.NewSoftwareProvider(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	resolver := keyresolver.New(p, "test-nrwk", time.Minute)
	baselineDigest := []byte("baseline")
	policyDigest := []byte("policy")
	if err := resolver.Init(ctx, "cluster-1", "node-1", "key", baselineDigest, policyDigest); err != nil {
		t.Fatal(err)
	}
	nrwk, err := p.EnsureNRWK(ctx, "test-nrwk")
	if err != nil {
		t.Fatal(err)
	}
	env, err := p.SealCRK(ctx, nrwk, bytes.Repeat([]byte{0x42}, 32), aad.CRKAAD{
		ClusterID: "cluster-1", NodeID: "node-1", PlaneRole: "key", CRKVersion: 1,
		NRWKName: "test-nrwk", BaselineDigest: baselineDigest, PolicyDigest: policyDigest,
	})
	if err != nil {
		t.Fatal(err)
	}
	resolver.SetCRKEnvelope(env)
	return resolver
}
