package server

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kvlt/key-vault/internal/auth/access"
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
	if response.Code != 200 || response.Header().Get("X-Content-Type-Options") != "nosniff" || response.Header().Get("Strict-Transport-Security") != "" {
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
	cfg := config.Default()
	cfg.Auth.DataSourceIP = "192.0.2.1"
	verifier, dataToken, opsToken := testAccess(t)
	value, err := New(Deps{Cfg: cfg, AccessVerifier: verifier})
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
		{value.DataHTTPServer(), "/api/v1/tc:protect", opsToken},
		{value.OpsHTTPServer(), "/ops/v1/status", dataToken},
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

func TestTLSHandshakeRejectsTLS12AndAcceptsTLS13(t *testing.T) {
	value, err := New(Deps{Cfg: config.Default()})
	if err != nil {
		t.Fatal(err)
	}
	tlsServer := httptest.NewUnstartedServer(value.OpsHTTPServer().Handler)
	tlsServer.TLS = serverTLSConfig()
	tlsServer.StartTLS()
	defer tlsServer.Close()
	certificate := tlsServer.Certificate()
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	serverName := ""
	if len(certificate.DNSNames) != 0 {
		serverName = certificate.DNSNames[0]
	} else if len(certificate.IPAddresses) != 0 {
		serverName = certificate.IPAddresses[0].String()
	} else {
		t.Fatal("test TLS certificate has no usable subject alternative name")
	}
	address := strings.TrimPrefix(tlsServer.URL, "https://")
	if connection, err := tls.Dial("tcp", address, &tls.Config{RootCAs: roots, ServerName: serverName, MaxVersion: tls.VersionTLS12}); err == nil {
		connection.Close()
		t.Fatal("TLS 1.2 handshake succeeded")
	}
	connection, err := tls.Dial("tcp", address, &tls.Config{RootCAs: roots, ServerName: serverName, MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatalf("TLS 1.3 handshake failed: %v", err)
	}
	connection.Close()
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

func TestAuthenticationAndAuthorizationPrecedeBodyRead(t *testing.T) {
	cfg := config.Default()
	cfg.Server.MaxRequestBody = 8
	cfg.Auth.DataSourceIP = "192.0.2.1"
	verifier, dataToken, opsToken := testAccess(t)
	value, err := New(Deps{Cfg: cfg, AccessVerifier: verifier})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, token string
		want        int
	}{
		{name: "missing token", want: http.StatusUnauthorized},
		{name: "invalid token", token: "invalid", want: http.StatusUnauthorized},
		{name: "wrong plane", token: opsToken, want: http.StatusForbidden},
		{name: "authorized", token: dataToken, want: http.StatusBadRequest},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/api/v1/tc:protect", strings.NewReader("body larger than eight bytes"))
			if test.token != "" {
				request.Header.Set("Authorization", "Bearer "+test.token)
			}
			response := httptest.NewRecorder()
			value.DataHTTPServer().Handler.ServeHTTP(response, request)
			if response.Code != test.want {
				t.Fatalf("status=%d want=%d body=%s", response.Code, test.want, response.Body.String())
			}
		})
	}
}

func TestInvalidCredentialsAreRateLimitedBeforeBodyRead(t *testing.T) {
	cfg := config.Default()
	cfg.TrafficGuard.Burst = 1
	cfg.Auth.DataSourceIP = "192.0.2.10"
	value, err := New(Deps{Cfg: cfg})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 121; i++ {
		request := httptest.NewRequest(http.MethodPost, "/api/v1/tc:protect", strings.NewReader("ignored"))
		request.RemoteAddr = "192.0.2.10:1234"
		response := httptest.NewRecorder()
		value.DataHTTPServer().Handler.ServeHTTP(response, request)
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("request %d status=%d", i, response.Code)
		}
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/tc:protect", strings.NewReader("ignored"))
	request.RemoteAddr = "192.0.2.10:5678"
	response := httptest.NewRecorder()
	value.DataHTTPServer().Handler.ServeHTTP(response, request)
	if response.Code != http.StatusTooManyRequests {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestDataSourceIsRejectedBeforeCredentialsAndHealthIsOpsOnly(t *testing.T) {
	cfg := config.Default()
	cfg.Auth.DataSourceIP = "192.0.2.10"
	verifier, dataToken, _ := testAccess(t)
	counters := &access.Counters{}
	value, err := New(Deps{Cfg: cfg, AccessVerifier: verifier, AccessCounters: counters})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/tc:protect", strings.NewReader("ignored"))
	body := &trackingBody{}
	request.Body = body
	request.RemoteAddr = "192.0.2.11:1234"
	request.Header.Set("Authorization", "Bearer "+dataToken)
	response := httptest.NewRecorder()
	value.DataHTTPServer().Handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden || counters.Snapshot().SourceIPRejected != 1 || counters.Snapshot().TokenRejected != 0 {
		t.Fatalf("status=%d counters=%+v", response.Code, counters.Snapshot())
	}
	if body.read {
		t.Fatal("source-IP rejection read the request body")
	}

	health := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	health.RemoteAddr = "192.0.2.10:1234"
	health.Header.Set("Authorization", "Bearer "+dataToken)
	healthResponse := httptest.NewRecorder()
	value.DataHTTPServer().Handler.ServeHTTP(healthResponse, health)
	if healthResponse.Code != http.StatusNotFound {
		t.Fatalf("Data health status=%d", healthResponse.Code)
	}
}

type trackingBody struct{ read bool }

func (b *trackingBody) Read([]byte) (int, error) {
	b.read = true
	return 0, errors.New("body must not be read")
}

func (*trackingBody) Close() error { return nil }

var _ io.ReadCloser = (*trackingBody)(nil)

func testAccess(t *testing.T) (*access.Verifier, string, string) {
	t.Helper()
	dataToken := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, access.TokenBytes))
	opsToken := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{2}, access.TokenBytes))
	verifier, err := access.NewVerifier("t-default", dataToken, opsToken)
	if err != nil {
		t.Fatal(err)
	}
	return verifier, dataToken, opsToken
}
