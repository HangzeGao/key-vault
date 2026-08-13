// Package ops exposes read-only health for the single-node CCSDS ground
// system. It intentionally contains no generic database repair, lifecycle,
// outbox, key mutation, or break-glass endpoints.
package ops

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/kvlt/key-vault/internal/api/middleware"
	"github.com/kvlt/key-vault/internal/domain/policy"
	"github.com/kvlt/key-vault/internal/resolver/keyresolver"
	"github.com/kvlt/key-vault/internal/securitystate"
)

type stateStore interface {
	Ping(context.Context) error
	Diagnostics(context.Context) (*securitystate.Diagnostics, error)
}

type Handler struct {
	store     stateStore
	resolver  *keyresolver.Resolver
	policies  *policy.Engine
	startTime time.Time
}

type Deps struct {
	Store    stateStore
	Resolver *keyresolver.Resolver
	Policies *policy.Engine
}

func New(deps Deps) *Handler {
	return &Handler{store: deps.Store, resolver: deps.Resolver, policies: deps.Policies, startTime: time.Now()}
}

func (h *Handler) Routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /ui/api/v1/ops/health", h.health)
	mux.HandleFunc("GET /ui/api/v1/ops/db/status", h.databaseStatus)
}

func (h *Handler) health(w http.ResponseWriter, request *http.Request) {
	if !requireScope(w, request, "ops:read") {
		return
	}
	checks := map[string]any{}
	overall := "ok"
	if h.store == nil || h.store.Ping(request.Context()) != nil {
		checks["state"] = map[string]any{"status": "degraded", "summary": "SQLite security state unavailable"}
		overall = "degraded"
	} else {
		checks["state"] = map[string]any{"status": "ok", "summary": "SQLite security state available"}
	}
	if h.resolver == nil || !h.resolver.Ready() {
		checks["tpm_storage"] = map[string]any{"status": "degraded", "summary": "TPM sealed-object storage unavailable"}
		overall = "degraded"
	} else {
		checks["tpm_storage"] = map[string]any{"status": "ok", "summary": "TPM sealed-object storage available"}
	}
	policyReady := false
	if h.policies != nil {
		_, policyErr := h.policies.Get("default-v1")
		policyReady = policyErr == nil
	}
	if !policyReady {
		checks["policy"] = map[string]any{"status": "degraded", "summary": "CCSDS policy unavailable"}
		overall = "degraded"
	} else {
		checks["policy"] = map[string]any{"status": "ok", "summary": "CCSDS policy loaded"}
	}
	writeJSON(w, http.StatusOK, map[string]any{"overall": overall,
		"uptime_seconds": int(time.Since(h.startTime).Seconds()), "checks": checks})
}

func (h *Handler) databaseStatus(w http.ResponseWriter, request *http.Request) {
	if !requireScope(w, request, "ops:read") {
		return
	}
	started := time.Now()
	if h.store == nil {
		writeJSON(w, http.StatusServiceUnavailable, unavailableResponse("state store is not configured", time.Since(started)))
		return
	}
	diagnostics, err := h.store.Diagnostics(request.Context())
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, unavailableResponse("security state is unavailable", time.Since(started)))
		return
	}
	status := "ok"
	if !diagnostics.IntegrityOK {
		status = "degraded"
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"driver": "sqlite", "status": status, "observed_at": diagnostics.ObservedAt,
		"connected":  true,
		"connection": map[string]any{"status": status, "latency_ms": time.Since(started).Milliseconds()},
		"schema": map[string]any{"status": map[bool]string{true: "ok", false: "degraded"}[diagnostics.Schema == 3],
			"current": diagnostics.Schema, "expected": 3},
		"storage": map[string]any{"database_bytes": diagnostics.DatabaseSize, "wal_bytes": diagnostics.WALSize,
			"journal_mode": "WAL", "synchronous": "FULL"},
		"records":   map[string]any{"security_associations": diagnostics.Associations, "audit_events": diagnostics.AuditEvents},
		"backup":    map[string]any{"status": "operator_managed", "rule": "restore only with a new operational SPI/epoch"},
		"integrity": map[string]any{"status": map[bool]string{true: "ok", false: "degraded"}[diagnostics.IntegrityOK]},
	})
}

func unavailableResponse(reason string, latency time.Duration) map[string]any {
	return map[string]any{
		"driver": "sqlite", "status": "degraded", "observed_at": time.Now().UTC(), "connected": false,
		"connection": map[string]any{"status": "degraded", "reason": reason, "latency_ms": latency.Milliseconds()},
		"schema":     map[string]any{"status": "degraded", "current": 0, "expected": 1},
		"storage":    map[string]any{"database_bytes": 0, "wal_bytes": 0, "journal_mode": "WAL", "synchronous": "FULL"},
		"records":    map[string]int{"security_associations": 0, "audit_events": 0},
		"backup":     map[string]string{"status": "unavailable"},
		"integrity":  map[string]string{"status": "degraded"},
	}
}

func requireScope(w http.ResponseWriter, request *http.Request, scope string) bool {
	actor := middleware.PrincipalFromContext(request.Context())
	if actor == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": map[string]string{"code": "AUTH_FAILED", "message": "no principal"}})
		return false
	}
	if !actor.HasScope(scope) {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": map[string]string{"code": "PERMISSION_DENIED", "message": "missing required scope"}})
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
