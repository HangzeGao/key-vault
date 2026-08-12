package server

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kvlt/key-vault/internal/auth/principal"
	"github.com/kvlt/key-vault/internal/config"
)

func TestServerAppliesBrowserSecurityAndExactCORS(t *testing.T) {
	cfg := config.Default()
	value, err := New(Deps{Cfg: cfg})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	request := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	request.TLS = &tls.ConnectionState{}
	response := httptest.NewRecorder()
	value.OpsHTTPServer().Handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("health status = %d", response.Code)
	}
	for _, header := range []string{"Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy", "Permissions-Policy", "Strict-Transport-Security"} {
		if response.Header().Get(header) == "" {
			t.Errorf("missing security header %s", header)
		}
	}

	disallowed := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	disallowed.Header.Set("Origin", "https://evil.example.test")
	disallowedResponse := httptest.NewRecorder()
	value.OpsHTTPServer().Handler.ServeHTTP(disallowedResponse, disallowed)
	if disallowedResponse.Code != http.StatusForbidden {
		t.Fatalf("disallowed origin status = %d", disallowedResponse.Code)
	}
	if value.OpsHTTPServer().TLSConfig.MinVersion != tls.VersionTLS13 {
		t.Fatal("TLS 1.3 minimum not enforced")
	}
}

func TestServerSeparatesDataAndOperationsListeners(t *testing.T) {
	cfg := config.Default()
	value, err := New(Deps{Cfg: cfg, AccessTokens: map[string]*principal.Principal{
		"data-token": {ID: "data", TenantID: "t-default", Plane: principal.PlaneData, Scopes: []string{"ccsds:tc:protect"}},
		"ops-token":  {ID: "ops", TenantID: "t-default", Plane: principal.PlaneOps, Scopes: []string{"ops:read"}},
	}})
	if err != nil {
		t.Fatal(err)
	}

	console := httptest.NewRecorder()
	value.OpsHTTPServer().Handler.ServeHTTP(console, httptest.NewRequest(http.MethodGet, "/ui/", nil))
	if console.Code == http.StatusNotFound {
		t.Fatal("ops listener did not expose console")
	}
	dataConsole := httptest.NewRecorder()
	value.DataHTTPServer().Handler.ServeHTTP(dataConsole, httptest.NewRequest(http.MethodGet, "/ui/", nil))
	if dataConsole.Code != http.StatusUnauthorized {
		t.Fatalf("data listener exposed console: %d", dataConsole.Code)
	}

	wrongIdentity := httptest.NewRequest(http.MethodGet, "/ui/api/v1/ops/health", nil)
	wrongIdentity.Header.Set("Authorization", "Bearer data-token")
	wrongResponse := httptest.NewRecorder()
	value.OpsHTTPServer().Handler.ServeHTTP(wrongResponse, wrongIdentity)
	if wrongResponse.Code != http.StatusForbidden {
		t.Fatalf("data token crossed into ops listener: %d", wrongResponse.Code)
	}
}

func TestServerRejectsPartialTLSConfiguration(t *testing.T) {
	cfg := config.Default()
	cfg.Server.TLSCertFile = "server.crt"
	if _, err := New(Deps{Cfg: cfg}); err == nil {
		t.Fatal("partial TLS configuration accepted")
	}
}

func TestListenerHandlersRejectCrossPlaneTokensBeforeRouting(t *testing.T) {
	cfg := config.Default()
	value, err := New(Deps{Cfg: cfg, AccessTokens: map[string]*principal.Principal{
		"data-token": {ID: "data", TenantID: "t-default", Plane: principal.PlaneData, Scopes: []string{"ccsds:tc:protect"}},
		"ops-token":  {ID: "ops", TenantID: "t-default", Plane: principal.PlaneOps, Scopes: []string{"ops:read"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		server      *http.Server
		path, token string
	}{
		{value.DataHTTPServer(), "/ui/api/v1/ccsds/tc:protect", "ops-token"},
		{value.OpsHTTPServer(), "/ui/api/v1/ops/health", "data-token"},
	} {
		request := httptest.NewRequest(http.MethodGet, test.path, nil)
		request.Header.Set("Authorization", "Bearer "+test.token)
		response := httptest.NewRecorder()
		test.server.Handler.ServeHTTP(response, request)
		if response.Code != http.StatusForbidden {
			t.Fatalf("cross-plane status = %d", response.Code)
		}
	}
}

func TestEmptyCORSAllowlistPermitsSameOriginOnly(t *testing.T) {
	value, err := New(Deps{Cfg: config.Default()})
	if err != nil {
		t.Fatal(err)
	}
	sameOrigin := httptest.NewRequest(http.MethodPost, "http://vault.example.test/not-found", nil)
	sameOrigin.Header.Set("Origin", "http://vault.example.test")
	sameOriginResponse := httptest.NewRecorder()
	value.DataHTTPServer().Handler.ServeHTTP(sameOriginResponse, sameOrigin)
	if sameOriginResponse.Code == http.StatusForbidden {
		t.Fatal("same-origin request rejected")
	}
	crossOrigin := httptest.NewRequest(http.MethodPost, "http://vault.example.test/not-found", nil)
	crossOrigin.Header.Set("Origin", "https://other.example.test")
	crossOriginResponse := httptest.NewRecorder()
	value.DataHTTPServer().Handler.ServeHTTP(crossOriginResponse, crossOrigin)
	if crossOriginResponse.Code != http.StatusForbidden {
		t.Fatalf("cross-origin status = %d", crossOriginResponse.Code)
	}
}
