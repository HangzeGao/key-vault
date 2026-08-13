package server

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kvlt/key-vault/internal/auth/principal"
	"github.com/kvlt/key-vault/internal/config"
)

func TestServerAppliesTransportSecurityWithoutBrowserPolicy(t *testing.T) {
	value, err := New(Deps{Cfg: config.Default()})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	request.TLS = &tls.ConnectionState{}
	response := httptest.NewRecorder()
	value.OpsHTTPServer().Handler.ServeHTTP(response, request)
	if response.Code != 200 || response.Header().Get("X-Content-Type-Options") != "nosniff" || response.Header().Get("Strict-Transport-Security") == "" {
		t.Fatalf("status=%d headers=%v", response.Code, response.Header())
	}
	if response.Header().Get("Content-Security-Policy") != "" || response.Header().Get("X-Frame-Options") != "" {
		t.Fatal("browser-only headers remain")
	}
	if value.OpsHTTPServer().TLSConfig.MinVersion != tls.VersionTLS13 {
		t.Fatal("TLS 1.3 minimum not enforced")
	}
}

func TestServerHasNoWebConsoleAndSeparatesPlanes(t *testing.T) {
	value, err := New(Deps{Cfg: config.Default(), AccessTokens: map[string]*principal.Principal{
		"data-token": {ID: "data", TenantID: "t-default", Plane: principal.PlaneData, Scopes: []string{"ccsds:tc:protect"}},
		"ops-token":  {ID: "ops", TenantID: "t-default", Plane: principal.PlaneOps, Scopes: []string{"ops:read"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	for _, server := range []*http.Server{value.DataHTTPServer(), value.OpsHTTPServer()} {
		response := httptest.NewRecorder()
		server.Handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/ui/", nil))
		if response.Code != 401 {
			t.Fatalf("web route status=%d", response.Code)
		}
	}
	for _, test := range []struct {
		server      *http.Server
		path, token string
	}{
		{value.DataHTTPServer(), "/api/v1/tc:protect", "ops-token"},
		{value.OpsHTTPServer(), "/ops/v1/status", "data-token"},
	} {
		request := httptest.NewRequest(http.MethodGet, test.path, nil)
		request.Header.Set("Authorization", "Bearer "+test.token)
		response := httptest.NewRecorder()
		test.server.Handler.ServeHTTP(response, request)
		if response.Code != 403 {
			t.Fatalf("cross-plane status=%d", response.Code)
		}
	}
}

func TestServerRejectsPartialTLSConfiguration(t *testing.T) {
	cfg := config.Default()
	cfg.Server.TLSCertFile = "server.crt"
	if _, err := New(Deps{Cfg: cfg}); err == nil {
		t.Fatal("partial TLS accepted")
	}
}

func TestAPIResponsesDisableCaching(t *testing.T) {
	value, err := New(Deps{Cfg: config.Default()})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/ops/v1/status", nil)
	response := httptest.NewRecorder()
	value.OpsHTTPServer().Handler.ServeHTTP(response, request)
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("cache=%q", response.Header().Get("Cache-Control"))
	}
}
