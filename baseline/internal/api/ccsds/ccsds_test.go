package ccsds_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	ccsdsapi "github.com/kvlt/key-vault/internal/api/ccsds"
	"github.com/kvlt/key-vault/internal/api/middleware"
	"github.com/kvlt/key-vault/internal/auth/principal"
	"github.com/kvlt/key-vault/internal/crypto/suite"
	protocol "github.com/kvlt/key-vault/internal/protocol/ccsds"
)

type fakeService struct {
	tenant string
	input  []byte
}

func (service *fakeService) ProtectTCFrame(_ context.Context, tenantID string, frame []byte) (*protocol.ProtectedTCFrame, error) {
	service.tenant, service.input = tenantID, append([]byte(nil), frame...)
	return &protocol.ProtectedTCFrame{Frame: []byte{0x20, 0x01, 0, 0, 7, 0x10, 0x01, 0, 0, 0, 7, 0xaa, 0, 0},
		Metadata: protocol.OperationMetadata{SPI: 0x1001, Counter: 7, KeyVersion: 3,
			PolicyVersion: 2, SuiteID: suite.SM4HCTR.String(), ServiceType: suite.ServiceEncryptOnly}}, nil
}

func (service *fakeService) UnprotectAOS(_ context.Context, tenantID string, frame []byte) (*protocol.PlainAOSFrame, error) {
	service.tenant, service.input = tenantID, append([]byte(nil), frame...)
	return &protocol.PlainAOSFrame{Frame: []byte{1, 2, 3}, Metadata: protocol.OperationMetadata{
		SPI: 0x2001, Counter: 9, KeyVersion: 4, PolicyVersion: 2,
		SuiteID: suite.SM4GCM.String(), ServiceType: suite.ServiceAuthEncrypt}}, nil
}

func (service *fakeService) OperationsStatus(_ context.Context, tenantID string) (*protocol.OperationsStatus, error) {
	service.tenant = tenantID
	counter := uint64(42)
	return &protocol.OperationsStatus{
		Status: "READY", Ready: true, AOSFormat: "NOT_FROZEN",
		TCRotation: &protocol.TCRotationState{Phase: protocol.TCRotationPrepared, TransactionID: ^uint64(0),
			CurrentSPI: 0x1001, NextSPI: 0x1002, CurrentRootVersion: 4, NextRootVersion: 5},
		TCCurrent: &protocol.AssociationRuntimeState{ID: "tc-current", SPI: 0x1001, Direction: protocol.DirectionTCTx,
			State: protocol.AssociationCurrent, SuiteID: suite.SM4HCTR.String(), SecurityEpoch: 3,
			KeyVersion: 4, PolicyVersion: 2, TransmittedIVLength: 4, NextIVCounter: &counter},
		AOSActive: []protocol.AssociationRuntimeState{}, Warnings: []string{},
	}, nil
}

func TestTCAPIConsumesAndReturnsCompleteFrames(t *testing.T) {
	service := &fakeService{}
	handler := authenticatedHandler(service, "ccsds:tc:protect")
	plainFrame := []byte{0x20, 0x01, 0, 0, 7, 0xca, 0xfe, 0, 0}
	body := []byte(`{"frame":"` + base64.StdEncoding.EncodeToString(plainFrame) + `"}`)
	request := httptest.NewRequest(http.MethodPost, "/ui/api/v1/ccsds/tc:protect", bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer test-token")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || service.tenant != "tenant-1" || !bytes.Equal(service.input, plainFrame) {
		t.Fatalf("status=%d tenant=%q input=%x body=%s", response.Code, service.tenant, service.input, response.Body.String())
	}
	var result struct {
		ProtectedFrame string `json:"protected_frame"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.ProtectedFrame != base64.StdEncoding.EncodeToString([]byte{0x20, 0x01, 0, 0, 7, 0x10, 0x01, 0, 0, 0, 7, 0xaa, 0, 0}) {
		t.Fatalf("response = %+v", result)
	}
}

func TestTCAPIRejectsObsoleteDataOnlyContract(t *testing.T) {
	service := &fakeService{}
	handler := authenticatedHandler(service, "ccsds:tc:protect")
	request := httptest.NewRequest(http.MethodPost, "/ui/api/v1/ccsds/tc:protect",
		bytes.NewReader([]byte(`{"data":"AQID"}`)))
	request.Header.Set("Authorization", "Bearer test-token")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || len(service.input) != 0 {
		t.Fatalf("obsolete data-only request accepted: status=%d input=%x", response.Code, service.input)
	}
}

func TestAOSAPIHasSeparateLeastPrivilegeScope(t *testing.T) {
	service := &fakeService{}
	handler := authenticatedHandler(service, "ccsds:tc:protect")
	body := []byte(`{"frame":"AQID"}`)
	request := httptest.NewRequest(http.MethodPost, "/ui/api/v1/ccsds/aos:unprotect", bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer test-token")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden || len(service.input) != 0 {
		t.Fatalf("status=%d input=%x", response.Code, service.input)
	}
}

func TestOperationsStatusExposesOnlyNonSecretRuntimeState(t *testing.T) {
	service := &fakeService{}
	mux := http.NewServeMux()
	ccsdsapi.New(service).OpsRoutes(mux)
	auth := middleware.Auth(middleware.AuthConfig{AccessTokens: map[string]*principal.Principal{
		"test-token": {ID: "operator", TenantID: "tenant-1", Plane: principal.PlaneOps, Scopes: []string{"ops:read"}},
	}})
	handler := middleware.ReadBody(auth(middleware.APIAccess(mux)))
	request := httptest.NewRequest(http.MethodGet, "/ui/api/v1/ops/ccsds/status", nil)
	request.Header.Set("Authorization", "Bearer test-token")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || service.tenant != "tenant-1" {
		t.Fatalf("status=%d tenant=%q body=%s", response.Code, service.tenant, response.Body.String())
	}
	body := response.Body.String()
	if bytes.Contains([]byte(body), []byte("key_id")) || bytes.Contains([]byte(body), []byte("nonce_prefix")) ||
		bytes.Contains([]byte(body), []byte("bitmap")) || bytes.Contains([]byte(body), []byte(`"root":`)) {
		t.Fatalf("operations response exposed secret or internal state: %s", body)
	}
	if !bytes.Contains([]byte(body), []byte(`"warnings":[]`)) || !bytes.Contains([]byte(body), []byte(`"aos":[]`)) {
		t.Fatalf("empty collections must use the strict JSON array contract: %s", body)
	}
	if !bytes.Contains([]byte(body), []byte(`"aos_format":"NOT_FROZEN"`)) {
		t.Fatalf("AOS format status missing: %s", body)
	}
	if !bytes.Contains([]byte(body), []byte(`"phase":"PREPARED"`)) ||
		!bytes.Contains([]byte(body), []byte(`"evidence":"RECOVERY_FRAME_PRODUCED"`)) ||
		!bytes.Contains([]byte(body), []byte(`"transaction_id":"18446744073709551615"`)) {
		t.Fatalf("rotation evidence missing: %s", body)
	}
}

func authenticatedHandler(service ccsdsapi.Service, scopes ...string) http.Handler {
	mux := http.NewServeMux()
	ccsdsapi.New(service).Routes(mux)
	auth := middleware.Auth(middleware.AuthConfig{AccessTokens: map[string]*principal.Principal{
		"test-token": {ID: "measurement", TenantID: "tenant-1", Plane: principal.PlaneData, Scopes: scopes},
	}})
	return middleware.ReadBody(auth(middleware.APIAccess(mux)))
}
