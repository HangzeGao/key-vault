//go:build downlink

package ccsds_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kvlt/key-vault/internal/api/ccsds"
	"github.com/kvlt/key-vault/internal/api/middleware"
	"github.com/kvlt/key-vault/internal/auth/access"
	"github.com/kvlt/key-vault/internal/downlink"
)

func (service *fakeService) UnprotectRaw(_ context.Context, frame []byte) ([]byte, error) {
	service.input = append([]byte(nil), frame...)
	return []byte{1, 2, 3}, service.downlinkErr
}

func TestDownlinkAPIConsumesRawPackageAndReturnsPlaintext(t *testing.T) {
	service := &fakeService{}
	handler := authenticatedHandler(service)
	raw := append([]byte{0, 17}, bytes.Repeat([]byte{1}, 12+16)...)
	body := []byte(`{"package":"` + base64.StdEncoding.EncodeToString(raw) + `"}`)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/downlink:unprotect", bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+testDataToken())
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !bytes.Equal(service.input, raw) ||
		!bytes.Contains(response.Body.Bytes(), []byte(`"plaintext":"AQID"`)) {
		t.Fatalf("status=%d input=%x body=%s", response.Code, service.input, response.Body.String())
	}
}

func TestDownlinkAPIErrorsFailClosed(t *testing.T) {
	for _, tc := range []struct {
		err    error
		status int
		code   string
	}{
		{downlink.ErrInvalid, http.StatusBadRequest, "DOWNLINK_INVALID"},
		{downlink.ErrAuthentication, http.StatusUnprocessableEntity, "DOWNLINK_AUTHENTICATION_FAILED"},
		{downlink.ErrNotProvisioned, http.StatusConflict, "DOWNLINK_STATE_REJECTED"},
	} {
		service := &fakeService{downlinkErr: tc.err}
		handler := authenticatedHandler(service)
		request := httptest.NewRequest(http.MethodPost, "/api/v1/downlink:unprotect",
			bytes.NewReader([]byte(`{"package":"AQID"}`)))
		request.Header.Set("Authorization", "Bearer "+testDataToken())
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != tc.status || !bytes.Contains(response.Body.Bytes(), []byte(tc.code)) {
			t.Fatalf("err=%v status=%d body=%s", tc.err, response.Code, response.Body.String())
		}
	}
}

func TestDownlinkRouteFailsClosedWithoutWiredService(t *testing.T) {
	mux := http.NewServeMux()
	ccsds.New(&fakeService{}).Routes(mux)
	verifier, err := access.NewVerifier("tenant-1", testDataToken(), testOpsToken())
	if err != nil {
		t.Fatal(err)
	}
	handler := middleware.ReadBody(middleware.Auth(middleware.AuthConfig{Verifier: verifier})(middleware.APIAccess(mux)))
	request := httptest.NewRequest(http.MethodPost, "/api/v1/downlink:unprotect", bytes.NewReader([]byte(`{"package":"AQID"}`)))
	request.Header.Set("Authorization", "Bearer "+testDataToken())
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("unwired downlink status=%d body=%s", response.Code, response.Body.String())
	}
}

func attachTestDownlink(handler *ccsds.Handler, service ccsds.Service) {
	if downlinkService, ok := service.(ccsds.RawDownlinkService); ok {
		handler.SetDownlink(downlinkService)
	}
}
