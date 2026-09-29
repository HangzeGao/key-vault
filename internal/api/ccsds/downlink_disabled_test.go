//go:build !downlink

package ccsds_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kvlt/key-vault/internal/api/ccsds"
)

func TestTCOnlyBuildRejectsDownlinkRoute(t *testing.T) {
	service := &fakeService{}
	handler := authenticatedHandler(service)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/downlink:unprotect", bytes.NewReader([]byte(`{"package":"AQID"}`)))
	request.Header.Set("Authorization", "Bearer "+testDataToken())
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden || len(service.input) != 0 {
		t.Fatalf("disabled downlink route accepted: status=%d input=%x", response.Code, service.input)
	}
}

func attachTestDownlink(*ccsds.Handler, ccsds.Service) {}
