package ccsds_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	ccsdsapi "github.com/kvlt/key-vault/internal/api/ccsds"
	"github.com/kvlt/key-vault/internal/api/middleware"
	"github.com/kvlt/key-vault/internal/auth/access"
	"github.com/kvlt/key-vault/internal/crypto/aead"
	"github.com/kvlt/key-vault/internal/crypto/suite"
	"github.com/kvlt/key-vault/internal/downlink"
	"github.com/kvlt/key-vault/internal/securitystate"
	"github.com/kvlt/key-vault/internal/tpm/provider"
)

func TestDownlinkBatchToAuthenticatedHTTPPlaintext(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	store, err := securitystate.Open(ctx, filepath.Join(root, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	testTPM, err := provider.NewSoftwareProvider(filepath.Join(root, "tpm"))
	if err != nil {
		t.Fatal(err)
	}
	defer testTPM.Close()
	sealer, err := downlink.NewTPMSealer(ctx, testTPM, "test-storage", "test-node", []byte("baseline"), []byte("policy"))
	if err != nil {
		t.Fatal(err)
	}
	service := downlink.NewService(store, sealer)
	defer service.Close()
	kekSet := make([]byte, downlink.KEKSetBytes)
	for index := range kekSet {
		kekSet[index] = byte(index)
	}
	if err := service.Provision(ctx, kekSet, 6); err != nil {
		t.Fatal(err)
	}
	uploadPackage, err := service.GenerateNext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := downlink.ParsePackage(uploadPackage)
	if err != nil {
		t.Fatal(err)
	}
	deks, err := parsed.Decrypt(kekSet)
	if err != nil {
		t.Fatal(err)
	}
	defer clearBytes(deks)
	if err := service.Load(ctx); err != nil {
		t.Fatal(err)
	}

	const serial = uint16(1023)
	keyOffset := int(serial) * downlink.DEKBytes
	primitive, err := aead.New(suite.SM4GCM, deks[keyOffset:keyOffset+downlink.DEKBytes])
	if err != nil {
		t.Fatal(err)
	}
	nonce := bytes.Repeat([]byte{0xa5}, downlink.UploadNonceBytes)
	want := []byte("authenticated hardware downlink")
	ciphertext, tag := primitive.Encrypt(want, nonce, nil)
	raw := make([]byte, 2)
	binary.BigEndian.PutUint16(raw, serial)
	raw = append(raw, nonce...)
	raw = append(raw, ciphertext...)
	raw = append(raw, tag...)

	mux := http.NewServeMux()
	ccsdsapi.New(&fakeService{}, service).Routes(mux)
	verifier, _ := access.NewVerifier("tenant-1", testDataToken(), testOpsToken())
	auth := middleware.Auth(middleware.AuthConfig{Verifier: verifier})
	handler := middleware.ReadBody(auth(middleware.APIAccess(mux)))
	body, _ := json.Marshal(map[string]string{"package": base64.StdEncoding.EncodeToString(raw)})
	request := httptest.NewRequest(http.MethodPost, "/api/v1/downlink:unprotect", bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+testDataToken())
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var result struct {
		Plaintext string `json:"plaintext"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	got, err := base64.StdEncoding.DecodeString(result.Plaintext)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("plaintext=%q err=%v", got, err)
	}
	status, err := service.Status(ctx)
	if err != nil || !status.CurrentObserved || status.CurrentGeneration != 1 || status.ActiveKEKSlot != 6 {
		t.Fatalf("status=%+v err=%v", status, err)
	}

	raw[len(raw)-1] ^= 1
	body, _ = json.Marshal(map[string]string{"package": base64.StdEncoding.EncodeToString(raw)})
	request = httptest.NewRequest(http.MethodPost, "/api/v1/downlink:unprotect", bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+testDataToken())
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnprocessableEntity || bytes.Contains(response.Body.Bytes(), want) {
		t.Fatalf("tampered status=%d body=%s", response.Code, response.Body.String())
	}
}

func clearBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
