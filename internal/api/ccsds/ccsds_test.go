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
	"github.com/kvlt/key-vault/internal/auth/access"
	"github.com/kvlt/key-vault/internal/crypto/suite"
	protocol "github.com/kvlt/key-vault/internal/protocol/ccsds"
)

type fakeService struct {
	tenant string
	input  []byte
	flight protocol.FlightSecurityStatus
}

func (service *fakeService) ObserveFlightSecurityStatus(_ context.Context, tenantID string, status protocol.FlightSecurityStatus) error {
	service.tenant, service.flight = tenantID, status
	return nil
}

func (service *fakeService) ProtectTCFrame(_ context.Context, tenantID string, frame []byte) (*protocol.ProtectedTCFrame, error) {
	service.tenant, service.input = tenantID, append([]byte(nil), frame...)
	return &protocol.ProtectedTCFrame{Frame: []byte{0x20, 0x01, 0, 0, 7, 0x10, 0x01, 0, 0, 0, 7, 0xaa, 0, 0},
		Metadata: protocol.OperationMetadata{SPI: 0x1001, Counter: 7, KeyVersion: 3,
			PolicyVersion: 2, SuiteID: suite.SM4HCTR.String(), ServiceType: suite.ServiceEncryptOnly}}, nil
}

func (service *fakeService) OperationsStatus(_ context.Context, tenantID string) (*protocol.OperationsStatus, error) {
	service.tenant = tenantID
	counter := uint64(42)
	return &protocol.OperationsStatus{
		Status: "READY", Ready: true,
		TCRotation: &protocol.TCRotationState{Phase: protocol.TCRotationPrepared, TransactionID: ^uint64(0),
			CurrentSPI: 0x1001, NextSPI: 0x1002, CurrentRootVersion: 4, NextRootVersion: 5},
		TCCurrent: &protocol.AssociationRuntimeState{ID: "tc-current", SPI: 0x1001, Direction: protocol.DirectionTCTx,
			State: protocol.AssociationCurrent, SuiteID: suite.SM4HCTR.String(), SecurityEpoch: 3,
			KeyVersion: 4, PolicyVersion: 2, TransmittedIVLength: 4, NextIVCounter: &counter},
		Warnings: []string{},
	}, nil
}

func TestTCAPIConsumesAndReturnsCompleteFrames(t *testing.T) {
	service := &fakeService{}
	handler := authenticatedHandler(service)
	plainFrame := []byte{0x20, 0x01, 0, 0, 7, 0xca, 0xfe, 0, 0}
	body := []byte(`{"frame":"` + base64.StdEncoding.EncodeToString(plainFrame) + `"}`)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/tc:protect", bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+testDataToken())
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
	handler := authenticatedHandler(service)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/tc:protect",
		bytes.NewReader([]byte(`{"data":"AQID"}`)))
	request.Header.Set("Authorization", "Bearer "+testDataToken())
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || len(service.input) != 0 {
		t.Fatalf("obsolete data-only request accepted: status=%d input=%x", response.Code, service.input)
	}
}

func TestCCSDSRoutesDoNotExposeHardwareDownlink(t *testing.T) {
	mux := http.NewServeMux()
	ccsdsapi.New(&fakeService{}).Routes(mux)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/downlink:unprotect", nil)
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("unsupported hardware route status=%d", response.Code)
	}
}

func TestFlightStatusObservationUsesDedicatedScopeAndStrictSemantic(t *testing.T) {
	service := &fakeService{}
	handler := authenticatedHandler(service)
	body := []byte(`{"format_version":1,"profile_digest":"` + string(bytes.Repeat([]byte("01"), 32)) +
		`","self_test":"PASSED","crypto_backend":"ARMV7_NEON","current_spi":4097,"next_spi":4098,` +
		`"recovery_spi":28673,"security_epoch":5,"root_version":2,"pending_root_present":false,` +
		`"receive_count":10,"last_receive_us":20,"max_receive_us":30,"cycle_limit_exceeded_count":0,"clock_anomaly_count":0}`)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/flight-status:observe", bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+testDataToken())
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent || service.flight.CurrentSPI != 4097 || service.flight.ProfileDigest[0] != 1 {
		t.Fatalf("status=%d flight=%+v body=%s", response.Code, service.flight, response.Body.String())
	}
}

func authenticatedHandler(service ccsdsapi.Service) http.Handler {
	mux := http.NewServeMux()
	handler := ccsdsapi.New(service)
	handler.Routes(mux)
	verifier, _ := access.NewVerifier("tenant-1", testDataToken(), testOpsToken())
	auth := middleware.Auth(middleware.AuthConfig{Verifier: verifier})
	return middleware.ReadBody(auth(middleware.APIAccess(mux)))
}

func testDataToken() string {
	return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, access.TokenBytes))
}
func testOpsToken() string {
	return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{2}, access.TokenBytes))
}
