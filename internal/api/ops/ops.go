// Package ops is the thin HTTP adapter for the read-only operations snapshot.
package ops

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/kvlt/key-vault/internal/api/middleware"
	"github.com/kvlt/key-vault/internal/operations"
)

type snapshotService interface {
	Snapshot(context.Context, string) (*operations.Snapshot, error)
}

type Handler struct{ service snapshotService }

func New(service snapshotService) *Handler { return &Handler{service: service} }

func (h *Handler) Routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /ops/v1/status", h.status)
}

func (h *Handler) status(w http.ResponseWriter, request *http.Request) {
	actor := middleware.PrincipalFromContext(request.Context())
	if actor == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": map[string]string{"code": "AUTH_FAILED", "message": "no principal"}})
		return
	}
	if !actor.HasScope("ops:read") {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": map[string]string{"code": "PERMISSION_DENIED", "message": "missing required scope"}})
		return
	}
	if actor.TenantID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": map[string]string{"code": "TENANT_REQUIRED", "message": "tenant-bound operations identity required"}})
		return
	}
	if h.service == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": map[string]string{"code": "OPS_UNAVAILABLE", "message": "operations snapshot unavailable"}})
		return
	}
	value, err := h.service.Snapshot(request.Context(), actor.TenantID)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": map[string]string{"code": "OPS_UNAVAILABLE", "message": "operations snapshot unavailable"}})
		return
	}
	writeJSON(w, http.StatusOK, value)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
