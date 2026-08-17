// Package server wires the HTTP server with all middleware and routes.
package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/kvlt/key-vault/internal/api/auditapi"
	ccsdsapi "github.com/kvlt/key-vault/internal/api/ccsds"
	"github.com/kvlt/key-vault/internal/api/middleware"
	"github.com/kvlt/key-vault/internal/api/ops"
	"github.com/kvlt/key-vault/internal/auth/access"
	"github.com/kvlt/key-vault/internal/auth/principal"
	"github.com/kvlt/key-vault/internal/config"
)

// Server is the HTTP server.
type Server struct {
	data       *http.Server
	ops        *http.Server
	tlsEnabled bool
}

// Deps bundles the server dependencies.
type Deps struct {
	Cfg            *config.Config
	CCSDSHandler   *ccsdsapi.Handler
	AuditHandler   *auditapi.Handler
	OpsHandler     *ops.Handler
	AccessVerifier *access.Verifier
	AccessCounters *access.Counters
}

// New constructs one process with separate data and read-only operations
// listeners. Both listeners share one application core and SecurityState.
func New(deps Deps) (*Server, error) {
	if deps.Cfg == nil {
		return nil, fmt.Errorf("server: missing config")
	}
	dataSource, err := netip.ParseAddr(deps.Cfg.Auth.DataSourceIP)
	if err != nil {
		return nil, fmt.Errorf("server: invalid Data source IP: %w", err)
	}
	if dataSource.Zone() != "" || dataSource.IsUnspecified() || dataSource.IsMulticast() {
		return nil, errors.New("server: Data source IP must be one unicast address without a zone")
	}
	if deps.Cfg.Environment == "production" && deps.AccessVerifier == nil {
		return nil, fmt.Errorf("server: production access verifier is required")
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
		listenerHandler(dataMux, deps, principal.PlaneData), tlsConfig)
	opsMux := http.NewServeMux()
	registerOpsRoutes(opsMux, deps)
	opsServer := buildHTTPServer(deps.Cfg, deps.Cfg.Server.OpsListenAddr,
		listenerHandler(opsMux, deps, principal.PlaneOps), tlsConfig.Clone())
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

func listenerHandler(mux *http.ServeMux, deps Deps, plane principal.Plane) http.Handler {
	auth := middleware.Auth(middleware.AuthConfig{Verifier: deps.AccessVerifier, Counters: deps.AccessCounters})
	capacityCfg := middleware.CapacityConfig{Window: deps.Cfg.TrafficGuard.RateWindow,
		Burst: deps.Cfg.TrafficGuard.Burst, Counters: deps.AccessCounters}
	var endpoint http.Handler = mux
	endpoint = middleware.ReadBody(endpoint)
	endpoint = middleware.BodyLimit(deps.Cfg.Server.MaxRequestBody)(endpoint)
	admitted := middleware.CapacityGuard(capacityCfg)(endpoint)
	protected := middleware.APIAccess(middleware.RequirePlane(plane, deps.AccessCounters)(admitted))
	authenticated := auth(protected)
	preAuthenticated := middleware.PreAuthCapacityGuard(capacityCfg)(authenticated)
	var handler http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if plane == principal.PlaneOps && r.URL.Path == "/healthz" {
			mux.ServeHTTP(w, r)
			return
		}
		preAuthenticated.ServeHTTP(w, r)
	})
	handler = middleware.RequestID(handler)
	if plane == principal.PlaneData {
		allowed, _ := netip.ParseAddr(deps.Cfg.Auth.DataSourceIP)
		handler = middleware.SourceIP(allowed, deps.AccessCounters)(handler)
	}
	return transportSecurity(handler)
}

func registerDataRoutes(mux *http.ServeMux, deps Deps) {
	if deps.CCSDSHandler != nil {
		deps.CCSDSHandler.Routes(mux)
	}
}

func registerOpsRoutes(mux *http.ServeMux, deps Deps) {
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	if deps.OpsHandler != nil {
		deps.OpsHandler.Routes(mux)
	}
	if deps.AuditHandler != nil {
		deps.AuditHandler.Routes(mux)
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

// transportSecurity contains only protocol-level response protections. The
// service no longer hosts browser assets or implements browser CORS policy.
func transportSecurity(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		if strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/ops/") {
			h.Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}
