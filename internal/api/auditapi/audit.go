// Package auditapi exposes the read-only security audit projection.
package auditapi

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/kvlt/key-vault/internal/api/middleware"
	"github.com/kvlt/key-vault/internal/auditchain"
	"github.com/kvlt/key-vault/internal/auth/principal"
)

type Handler struct{ audit *auditchain.Service }

func New(audit *auditchain.Service) *Handler { return &Handler{audit: audit} }

func (h *Handler) Routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /ops/v1/audit/events", h.events)
	mux.HandleFunc("GET /ops/v1/audit/verify", h.verify)
	mux.HandleFunc("GET /ops/v1/audit/heads", h.heads)
}

func (h *Handler) events(w http.ResponseWriter, request *http.Request) {
	actor, ok := authorize(w, request)
	if !ok {
		return
	}
	query := request.URL.Query()
	if query.Has("chain") {
		writeInvalidQuery(w, "chain is derived from the authenticated tenant")
		return
	}
	limit := parseBounded(query.Get("limit"), 100, 1, 500)
	offset := parseBounded(query.Get("cursor"), 0, 0, 1_000_000)
	values, err := h.audit.ListTenantEvents(request.Context(), actor.TenantID, 500)
	if err != nil {
		writeError(w)
		return
	}
	from, _ := time.Parse(time.RFC3339, query.Get("from"))
	to, _ := time.Parse(time.RFC3339, query.Get("to"))
	filtered := values[:0]
	for _, event := range values {
		if !contains(event.Action, query.Get("action")) || !contains(event.Result, query.Get("result")) ||
			!contains(event.ActorHash, query.Get("actor")) || !contains(event.TargetIDHash, query.Get("target")) ||
			(!from.IsZero() && event.Timestamp.Before(from)) || (!to.IsZero() && event.Timestamp.After(to)) {
			continue
		}
		filtered = append(filtered, event)
	}
	if offset > len(filtered) {
		offset = len(filtered)
	}
	end := offset + limit
	if end > len(filtered) {
		end = len(filtered)
	}
	var next any
	if end < len(filtered) {
		next = strconv.Itoa(end)
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": filtered[offset:end], "next_cursor": next, "total": len(filtered)})
}

func (h *Handler) verify(w http.ResponseWriter, request *http.Request) {
	actor, ok := authorize(w, request)
	if !ok {
		return
	}
	if request.URL.Query().Has("chain") {
		writeInvalidQuery(w, "chain is derived from the authenticated tenant")
		return
	}
	result, err := h.audit.VerifyTenantChain(request.Context(), actor.TenantID)
	if err != nil {
		writeError(w)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"results": []*auditchain.VerifyResult{result}})
}

func (h *Handler) heads(w http.ResponseWriter, request *http.Request) {
	actor, ok := authorize(w, request)
	if !ok {
		return
	}
	if request.URL.Query().Has("chain") {
		writeInvalidQuery(w, "chain is derived from the authenticated tenant")
		return
	}
	head, err := h.audit.GetTenantChainHead(request.Context(), actor.TenantID)
	if err != nil {
		writeError(w)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"heads": []any{head}})
}

func authorize(w http.ResponseWriter, request *http.Request) (*principal.Principal, bool) {
	actor := middleware.PrincipalFromContext(request.Context())
	if actor == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": map[string]string{"code": "AUTH_FAILED", "message": "no principal"}})
		return nil, false
	}
	if !actor.HasScope("audit:read") && !actor.HasScope("audit:manage") && !actor.HasScope("ops:read") {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": map[string]string{"code": "PERMISSION_DENIED", "message": "missing audit scope"}})
		return nil, false
	}
	if actor.TenantID == "" {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": map[string]string{"code": "PERMISSION_DENIED", "message": "missing tenant identity"}})
		return nil, false
	}
	return actor, true
}

func contains(value, filter string) bool {
	return filter == "" || strings.Contains(strings.ToLower(value), strings.ToLower(filter))
}

func parseBounded(raw string, fallback, minimum, maximum int) int {
	value, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	if value < minimum {
		return minimum
	}
	if value > maximum {
		return maximum
	}
	return value
}

func writeError(w http.ResponseWriter) {
	writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": map[string]string{"code": "AUDIT_UNAVAILABLE", "message": "audit state unavailable"}})
}

func writeInvalidQuery(w http.ResponseWriter, message string) {
	writeJSON(w, http.StatusBadRequest, map[string]any{"error": map[string]string{"code": "INVALID_ARGUMENT", "message": message}})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
