// Package server wires the HTTP server with all middleware and routes.
package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/kvlt/key-vault/internal/api/admin"
	"github.com/kvlt/key-vault/internal/api/baselineapi"
	cryptoapi "github.com/kvlt/key-vault/internal/api/crypto"
	keytransferapi "github.com/kvlt/key-vault/internal/api/keytransfer"
	"github.com/kvlt/key-vault/internal/api/middleware"
	"github.com/kvlt/key-vault/internal/api/ops"
	tenantapi "github.com/kvlt/key-vault/internal/api/tenant"
	"github.com/kvlt/key-vault/internal/auth/hmacsign"
	"github.com/kvlt/key-vault/internal/auth/jwt"
	"github.com/kvlt/key-vault/internal/auth/principal"
	"github.com/kvlt/key-vault/internal/config"
	"github.com/kvlt/key-vault/internal/web"
)

// Server is the HTTP server.
type Server struct {
	http       *http.Server
	tlsEnabled bool
}

// Deps bundles the server dependencies.
type Deps struct {
	Cfg                *config.Config
	AdminHandler       *admin.Handler
	CryptoHandler      *cryptoapi.Handler
	BaselineHandler    *baselineapi.Handler
	OpsHandler         *ops.Handler
	TenantHandler      *tenantapi.Handler
	KeyTransferHandler *keytransferapi.Handler
	JWTVerifier        *jwt.Verifier
	HMACVerifier       *hmacsign.Verifier
	StaticTokens       map[string]*principal.Principal
}

// New constructs one plane-scoped server with all transport and request
// protections applied.
func New(deps Deps) (*Server, error) {
	if deps.Cfg == nil {
		return nil, fmt.Errorf("server: missing config")
	}
	mux := http.NewServeMux()

	switch deps.Cfg.Server.ActivePlane {
	case "management":
		registerManagementRoutes(mux, deps)
	case "data":
		registerDataRoutes(mux, deps)
	case "ops":
		if deps.OpsHandler != nil {
			deps.OpsHandler.Routes(mux)
		}
	case "all":
		if deps.Cfg.Environment == "production" {
			return nil, fmt.Errorf("server: all-plane listener is forbidden in production")
		}
		registerManagementRoutes(mux, deps)
		registerDataRoutes(mux, deps)
		if deps.OpsHandler != nil {
			deps.OpsHandler.Routes(mux)
		}
	default:
		return nil, fmt.Errorf("server: unsupported active plane %q", deps.Cfg.Server.ActivePlane)
	}

	// Health check.
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	// Auth config.
	authCfg := middleware.AuthConfig{
		JWTVerifier:  deps.JWTVerifier,
		HMACVerifier: deps.HMACVerifier,
		HMACEnabled:  deps.Cfg.Auth.HMACEnabled,
		StaticTokens: deps.StaticTokens,
	}

	// Build the middleware chain. Order (outer -> inner):
	//   CORS -> RequestID -> BodyLimit -> ReadBody -> Auth -> mux
	// ReadBody MUST run before Auth so the body is in context for HMAC verification.
	var handler http.Handler = mux
	authMiddleware := middleware.Auth(authCfg)
	admitted := middleware.CapacityGuard(middleware.CapacityConfig{
		Window: deps.Cfg.Nonce.RateWindow, SigmaThreshold: deps.Cfg.Nonce.RateSigmaThreshold,
	})(handler)
	// Wrap auth so healthz and /ui/ static assets bypass authentication.
	// /ui/api/ paths must still go through auth.
	authWrapper := func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/healthz" || (strings.HasPrefix(r.URL.Path, "/ui/") && !strings.HasPrefix(r.URL.Path, "/ui/api/")) {
				h.ServeHTTP(w, r)
				return
			}
			authMiddleware(middleware.APIAccess(admitted)).ServeHTTP(w, r)
		})
	}
	handler = authWrapper(handler)
	handler = middleware.ReadBody(handler)
	handler = middleware.BodyLimit(deps.Cfg.Server.MaxRequestBody)(handler)
	handler = middleware.RequestID(handler)
	handler = browserSecurity(deps.Cfg.Server.AllowedOrigins, handler)

	addr := deps.Cfg.Server.HTTPListenAddr
	tlsConfig, err := serverTLSConfig(deps.Cfg.Server.TLSClientCAFile)
	if err != nil {
		return nil, err
	}
	if deps.Cfg.Server.TLSCertFile != "" || deps.Cfg.Server.TLSKeyFile != "" {
		if deps.Cfg.Server.TLSCertFile == "" || deps.Cfg.Server.TLSKeyFile == "" {
			return nil, fmt.Errorf("server: both TLS certificate and key are required")
		}
		addr = deps.Cfg.Server.HTTPSListenAddr
		if addr == "" {
			return nil, fmt.Errorf("server: https listen address is required when TLS is configured")
		}
		certificate, err := tls.LoadX509KeyPair(deps.Cfg.Server.TLSCertFile, deps.Cfg.Server.TLSKeyFile)
		if err != nil {
			return nil, fmt.Errorf("server: load TLS certificate: %w", err)
		}
		leaf, err := x509.ParseCertificate(certificate.Certificate[0])
		if err != nil {
			return nil, fmt.Errorf("server: parse TLS leaf certificate: %w", err)
		}
		now := time.Now()
		if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
			return nil, fmt.Errorf("server: TLS certificate is not currently valid")
		}
		certificate.Leaf = leaf
		tlsConfig.Certificates = []tls.Certificate{certificate}
	}
	srv := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: deps.Cfg.Server.ReadHeaderTimeout,
		ReadTimeout:       deps.Cfg.Server.ReadTimeout,
		WriteTimeout:      deps.Cfg.Server.WriteTimeout,
		IdleTimeout:       deps.Cfg.Server.IdleTimeout,
		MaxHeaderBytes:    deps.Cfg.Server.MaxHeaderBytes,
		TLSConfig:         tlsConfig,
	}
	return &Server{
		http:       srv,
		tlsEnabled: deps.Cfg.Server.TLSCertFile != "",
	}, nil
}

func registerManagementRoutes(mux *http.ServeMux, deps Deps) {
	if deps.AdminHandler != nil {
		deps.AdminHandler.Routes(mux)
	}
	if deps.BaselineHandler != nil {
		deps.BaselineHandler.ManagementRoutes(mux)
	}
	if deps.TenantHandler != nil {
		deps.TenantHandler.ManagementRoutes(mux)
	}
	if deps.KeyTransferHandler != nil {
		deps.KeyTransferHandler.Routes(mux)
	}
	mux.Handle("GET /ui/", http.StripPrefix("/ui", web.Handler()))
}

func registerDataRoutes(mux *http.ServeMux, deps Deps) {
	if deps.CryptoHandler != nil {
		deps.CryptoHandler.Routes(mux)
	}
	if deps.BaselineHandler != nil {
		deps.BaselineHandler.DataRoutes(mux)
	}
	if deps.TenantHandler != nil {
		deps.TenantHandler.DataRoutes(mux)
	}
}

// Start begins listening.
func (s *Server) Start() error {
	var err error
	if s.tlsEnabled {
		// The key pair was parsed and pinned during New, so startup cannot race
		// a file replacement between validation and listener creation.
		err = s.http.ListenAndServeTLS("", "")
	} else {
		err = s.http.ListenAndServe()
	}
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// Shutdown gracefully stops the server.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.http.Shutdown(ctx)
}

// HTTPServer returns the underlying *http.Server (for testing).
func (s *Server) HTTPServer() *http.Server { return s.http }

func serverTLSConfig(clientCAFile string) (*tls.Config, error) {
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
	}
	if clientCAFile == "" {
		return cfg, nil
	}
	pemBytes, err := os.ReadFile(clientCAFile)
	if err != nil {
		return nil, fmt.Errorf("server: read client CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, fmt.Errorf("server: client CA contains no certificates")
	}
	cfg.ClientCAs = pool
	cfg.ClientAuth = tls.RequireAndVerifyClientCert
	return cfg, nil
}

// browserSecurity centralizes browser response hardening and implements
// least-privilege CORS. An empty allowlist means same-origin only.
func browserSecurity(allowedOrigins []string, next http.Handler) http.Handler {
	allowed := make(map[string]struct{}, len(allowedOrigins))
	for _, origin := range allowedOrigins {
		allowed[origin] = struct{}{}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
		if r.TLS != nil {
			h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		if strings.HasPrefix(r.URL.Path, "/ui/api/") {
			h.Set("Cache-Control", "no-store")
		}

		origin := r.Header.Get("Origin")
		if origin != "" {
			_, explicitlyAllowed := allowed[origin]
			if !explicitlyAllowed && !requestIsSameOrigin(r, origin) {
				http.Error(w, "origin not allowed", http.StatusForbidden)
				return
			}
			if explicitlyAllowed {
				h.Set("Access-Control-Allow-Origin", origin)
				h.Add("Vary", "Origin")
				h.Set("Access-Control-Allow-Methods", "GET, POST, PATCH, PUT, DELETE, OPTIONS")
				h.Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Idempotency-Key")
				h.Set("Access-Control-Max-Age", "600")
			}
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func requestIsSameOrigin(r *http.Request, rawOrigin string) bool {
	origin, err := url.Parse(rawOrigin)
	if err != nil || origin.User != nil || origin.Path != "" ||
		origin.RawQuery != "" || origin.Fragment != "" {
		return false
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return origin.Scheme == scheme && strings.EqualFold(origin.Host, r.Host)
}
