package server

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kvlt/key-vault/internal/config"
)

func TestServerAppliesBrowserSecurityAndExactCORS(t *testing.T) {
	cfg := config.Default()
	cfg.Server.ActivePlane = "management"
	cfg.Server.AllowedOrigins = []string{"https://console.example.test"}
	server, err := New(Deps{Cfg: cfg})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	request := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	request.TLS = &tls.ConnectionState{}
	response := httptest.NewRecorder()
	server.HTTPServer().Handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("health status = %d", response.Code)
	}
	for _, header := range []string{
		"Content-Security-Policy", "X-Content-Type-Options",
		"X-Frame-Options", "Referrer-Policy", "Permissions-Policy",
		"Strict-Transport-Security",
	} {
		if response.Header().Get(header) == "" {
			t.Errorf("missing security header %s", header)
		}
	}

	disallowed := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	disallowed.Header.Set("Origin", "https://evil.example.test")
	disallowedResponse := httptest.NewRecorder()
	server.HTTPServer().Handler.ServeHTTP(disallowedResponse, disallowed)
	if disallowedResponse.Code != http.StatusForbidden {
		t.Fatalf("disallowed origin status = %d, want 403", disallowedResponse.Code)
	}

	preflight := httptest.NewRequest(http.MethodOptions, "/ui/api/v1/keys", nil)
	preflight.Header.Set("Origin", "https://console.example.test")
	preflightResponse := httptest.NewRecorder()
	server.HTTPServer().Handler.ServeHTTP(preflightResponse, preflight)
	if preflightResponse.Code != http.StatusNoContent {
		t.Fatalf("preflight status = %d", preflightResponse.Code)
	}
	if got := preflightResponse.Header().Get("Access-Control-Allow-Origin"); got != "https://console.example.test" {
		t.Fatalf("allow origin = %q", got)
	}
	if server.HTTPServer().TLSConfig.MinVersion != tls.VersionTLS13 {
		t.Fatalf("minimum TLS version = %x", server.HTTPServer().TLSConfig.MinVersion)
	}
}

func TestServerExposesOnlyActivePlane(t *testing.T) {
	management := config.Default()
	management.Server.ActivePlane = "management"
	managementServer, err := New(Deps{Cfg: management})
	if err != nil {
		t.Fatal(err)
	}
	managementResponse := httptest.NewRecorder()
	managementServer.HTTPServer().Handler.ServeHTTP(
		managementResponse,
		httptest.NewRequest(http.MethodGet, "/ui/", nil),
	)
	if managementResponse.Code == http.StatusNotFound {
		t.Fatal("management plane did not expose the embedded console")
	}

	data := config.Default()
	data.Server.ActivePlane = "data"
	dataServer, err := New(Deps{Cfg: data})
	if err != nil {
		t.Fatal(err)
	}
	dataResponse := httptest.NewRecorder()
	dataServer.HTTPServer().Handler.ServeHTTP(
		dataResponse,
		httptest.NewRequest(http.MethodGet, "/ui/", nil),
	)
	if dataResponse.Code != http.StatusNotFound {
		t.Fatalf("data plane exposed management console: status=%d", dataResponse.Code)
	}
}

func TestEmptyCORSAllowlistPermitsSameOriginOnly(t *testing.T) {
	cfg := config.Default()
	cfg.Server.ActivePlane = "management"
	server, err := New(Deps{Cfg: cfg})
	if err != nil {
		t.Fatal(err)
	}
	sameOrigin := httptest.NewRequest(http.MethodPost, "http://vault.example.test/not-found", nil)
	sameOrigin.Header.Set("Origin", "http://vault.example.test")
	sameOriginResponse := httptest.NewRecorder()
	server.HTTPServer().Handler.ServeHTTP(sameOriginResponse, sameOrigin)
	if sameOriginResponse.Code == http.StatusForbidden {
		t.Fatal("same-origin request was rejected by an empty CORS allowlist")
	}

	crossOrigin := httptest.NewRequest(http.MethodPost, "http://vault.example.test/not-found", nil)
	crossOrigin.Header.Set("Origin", "https://other.example.test")
	crossOriginResponse := httptest.NewRecorder()
	server.HTTPServer().Handler.ServeHTTP(crossOriginResponse, crossOrigin)
	if crossOriginResponse.Code != http.StatusForbidden {
		t.Fatalf("cross-origin status = %d, want 403", crossOriginResponse.Code)
	}
}

func TestServerRejectsAllPlaneProductionListener(t *testing.T) {
	cfg := config.Default()
	cfg.Environment = "production"
	cfg.Server.ActivePlane = "all"
	if _, err := New(Deps{Cfg: cfg}); err == nil {
		t.Fatal("production all-plane server was accepted")
	}
}
