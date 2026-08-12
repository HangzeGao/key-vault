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
	"strings"
	"time"

	"github.com/kvlt/key-vault/internal/api/auditapi"
	ccsdsapi "github.com/kvlt/key-vault/internal/api/ccsds"
	"github.com/kvlt/key-vault/internal/api/middleware"
	"github.com/kvlt/key-vault/internal/api/ops"
	"github.com/kvlt/key-vault/internal/auth/principal"
	"github.com/kvlt/key-vault/internal/config"
	"github.com/kvlt/key-vault/internal/web"
)

// Server is the HTTP server.
type Server struct {
	data       *http.Server
	ops        *http.Server
	tlsEnabled bool
}

// Deps bundles the server dependencies.
type Deps struct {
	Cfg          *config.Config
	CCSDSHandler *ccsdsapi.Handler
	AuditHandler *auditapi.Handler
	OpsHandler   *ops.Handler
	AccessTokens map[string]*principal.Principal
}

// New constructs one process with separate data and read-only operations
// listeners. Both listeners share one application core and SecurityState.
func New(deps Deps) (*Server, error) {
	if deps.Cfg == nil {
		return nil, fmt.Errorf("server: missing config")
	}
	tlsConfig := serverTLSConfig()
	tlsEnabled := deps.Cfg.Server.TLSCertFile != "" || deps.Cfg.Server.TLSKeyFile != ""
	if deps.Cfg.Server.TLSCertFile != "" || deps.Cfg.Server.TLSKeyFile != "" {
		if deps.Cfg.Server.TLSCertFile == "" || deps.Cfg.Server.TLSKeyFile == "" {
			return nil, fmt.Errorf("server: both TLS certificate and key are required")
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
	dataMux := http.NewServeMux()
	registerDataRoutes(dataMux, deps)
	dataServer := buildHTTPServer(deps.Cfg, deps.Cfg.Server.DataListenAddr,
		listenerHandler(dataMux, deps, principal.PlaneData, false), tlsConfig)
	opsMux := http.NewServeMux()
	registerOpsRoutes(opsMux, deps)
	registerConsoleRoutes(opsMux, deps)
	opsServer := buildHTTPServer(deps.Cfg, deps.Cfg.Server.OpsListenAddr,
		listenerHandler(opsMux, deps, principal.PlaneOps, true), tlsConfig.Clone())
	return &Server{data: dataServer, ops: opsServer, tlsEnabled: tlsEnabled}, nil
}

func buildHTTPServer(cfg *config.Config, addr string, handler http.Handler, tlsConfig *tls.Config) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: cfg.Server.ReadHeaderTimeout,
		ReadTimeout:       cfg.Server.ReadTimeout,
		WriteTimeout:      cfg.Server.WriteTimeout,
		IdleTimeout:       cfg.Server.IdleTimeout,
		MaxHeaderBytes:    cfg.Server.MaxHeaderBytes,
		TLSConfig:         tlsConfig,
	}
}

func registerConsoleRoutes(mux *http.ServeMux, deps Deps) {
	if deps.AuditHandler != nil {
		deps.AuditHandler.Routes(mux)
	}
	mux.Handle("GET /ui/", http.StripPrefix("/ui", web.Handler()))
}

func listenerHandler(mux *http.ServeMux, deps Deps, plane principal.Plane, console bool) http.Handler {
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	auth := middleware.Auth(middleware.AuthConfig{AccessTokens: deps.AccessTokens})
	admitted := middleware.CapacityGuard(middleware.CapacityConfig{Window: deps.Cfg.TrafficGuard.RateWindow,
		SigmaThreshold: deps.Cfg.TrafficGuard.RateSigmaThreshold})(mux)
	protected := middleware.APIAccess(middleware.RequirePlane(plane)(admitted))
	var handler http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" || (console && strings.HasPrefix(r.URL.Path, "/ui/") && !strings.HasPrefix(r.URL.Path, "/ui/api/")) {
			mux.ServeHTTP(w, r)
			return
		}
		auth(protected).ServeHTTP(w, r)
	})
	handler = middleware.ReadBody(handler)
	handler = middleware.BodyLimit(deps.Cfg.Server.MaxRequestBody)(handler)
	handler = middleware.RequestID(handler)
	return browserSecurity(handler)
}

func registerDataRoutes(mux *http.ServeMux, deps Deps) {
	if deps.CCSDSHandler != nil {
		deps.CCSDSHandler.Routes(mux)
	}
}

func registerOpsRoutes(mux *http.ServeMux, deps Deps) {
	if deps.OpsHandler != nil {
		deps.OpsHandler.Routes(mux)
	}
	if deps.CCSDSHandler != nil {
		deps.CCSDSHandler.OpsRoutes(mux)
	}
}

// Start begins listening.
func (s *Server) Start() error {
	errorsCh := make(chan error, 2)
	start := func(value *http.Server) {
		var err error
		if s.tlsEnabled {
			err = value.ListenAndServeTLS("", "")
		} else {
			err = value.ListenAndServe()
		}
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		errorsCh <- err
	}
	go start(s.data)
	go start(s.ops)
	err := <-errorsCh
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = s.data.Shutdown(shutdownCtx)
	_ = s.ops.Shutdown(shutdownCtx)
	return err
}

// Shutdown gracefully stops the server.
func (s *Server) Shutdown(ctx context.Context) error {
	return errors.Join(s.data.Shutdown(ctx), s.ops.Shutdown(ctx))
}

func (s *Server) DataHTTPServer() *http.Server { return s.data }
func (s *Server) OpsHTTPServer() *http.Server  { return s.ops }

func serverTLSConfig() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS13}
}

// browserSecurity centralizes browser response hardening and implements
// least-privilege CORS. An empty allowlist means same-origin only.
func browserSecurity(next http.Handler) http.Handler {
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
		if origin != "" && !requestIsSameOrigin(r, origin) {
			http.Error(w, "origin not allowed", http.StatusForbidden)
			return
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
