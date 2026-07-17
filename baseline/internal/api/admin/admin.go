// Package admin implements the management API.
package admin

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/kvlt/key-vault/internal/api/middleware"
	"github.com/kvlt/key-vault/internal/application/keys"
	"github.com/kvlt/key-vault/internal/auth/principal"
	"github.com/kvlt/key-vault/internal/errorsx"
)

// Handler is the management API HTTP handler.
type Handler struct {
	keys *keys.Service
}

// New constructs a management handler.
func New(keys *keys.Service) *Handler {
	return &Handler{keys: keys}
}

// Routes registers the management routes.
func (h *Handler) Routes(mux *http.ServeMux) {
	mux.HandleFunc("POST /ui/api/v1/keys", h.createKey)
	mux.HandleFunc("POST /ui/api/v1/keys:import", h.importKey)
	mux.HandleFunc("POST /ui/api/v1/keys:import-batch", h.importKeyBatch)
	mux.HandleFunc("GET /ui/api/v1/keys", h.listKeys)
	mux.HandleFunc("GET /ui/api/v1/keys/{key_id}", h.getKey)
	mux.HandleFunc("PATCH /ui/api/v1/keys/{key_id}", h.updateKey)
	mux.HandleFunc("DELETE /ui/api/v1/keys/{key_id}", h.deleteKey)
	mux.HandleFunc("POST /ui/api/v1/keys/{key_id}/enable", h.enableKey)
	mux.HandleFunc("POST /ui/api/v1/keys/{key_id}/disable", h.disableKey)
	mux.HandleFunc("POST /ui/api/v1/keys/{key_id}/rotate", h.rotateKey)
	mux.HandleFunc("POST /ui/api/v1/keys/{key_id}/schedule-destroy", h.scheduleDestroy)
	mux.HandleFunc("POST /ui/api/v1/keys/{key_id}/cancel-destroy", h.cancelDestroy)
	mux.HandleFunc("POST /ui/api/v1/keys/{key_id}/archive", h.archiveDestroyedKey)
}

type createKeyReq struct {
	TenantID  string            `json:"tenant_id"`
	KeyID     string            `json:"key_id,omitempty"`
	Name      string            `json:"name"`
	Purpose   string            `json:"purpose"`
	PolicyID  string            `json:"policy_id"`
	SuiteID   string            `json:"suite_id"`
	Tags      map[string]string `json:"tags,omitempty"`
	ExpiresAt string            `json:"expires_at,omitempty"`
}

// importKeyReq is the request body for POST /ui/api/v1/keys:import (EB-FR-01).
// Per design §2 and INV-11: external_dek is the caller-provided plaintext DEK
// (base64). It only enters the key-plane sealing flow; it is never persisted,
// logged, or echoed in the response.
type importKeyReq struct {
	TenantID    string            `json:"tenant_id"`
	KeyID       string            `json:"key_id,omitempty"`
	Name        string            `json:"name"`
	Purpose     string            `json:"purpose"`
	PolicyID    string            `json:"policy_id"`
	SuiteID     string            `json:"suite_id"`
	Tags        map[string]string `json:"tags,omitempty"`
	ExpiresAt   string            `json:"expires_at,omitempty"`
	ExternalDEK string            `json:"external_dek"` // base64-encoded plaintext DEK
}

type batchImportKeyReq struct {
	TenantID string         `json:"tenant_id"`
	Entries  []importKeyReq `json:"entries"`
}

type batchImportKeyResult struct {
	Index     int          `json:"index"`
	Success   bool         `json:"success"`
	Key       *keys.KeyDTO `json:"key,omitempty"`
	ErrorCode string       `json:"error_code,omitempty"`
	Message   string       `json:"message,omitempty"`
}

type updateKeyReq struct {
	Name      string            `json:"name"`
	Tags      map[string]string `json:"tags,omitempty"`
	ExpiresAt string            `json:"expires_at,omitempty"`
}

func (h *Handler) createKey(w http.ResponseWriter, r *http.Request) {
	p := middleware.PrincipalFromContext(r.Context())
	if p == nil {
		writeErr(w, 401, "AUTH_FAILED", "no principal")
		return
	}
	if !hasAnyScope(p, "keys:create", "keys:manage") {
		writeErr(w, 403, "PERMISSION_DENIED", "missing scope keys:create")
		return
	}
	body := middleware.BodyFromContext(r.Context())
	var req createKeyReq
	if err := middleware.DecodeJSONStrict(body, &req); err != nil {
		writeErr(w, 400, "BAD_REQUEST", "invalid json")
		return
	}
	// Default tenant_id to the principal's tenant when omitted.
	if req.TenantID == "" {
		req.TenantID = p.TenantID
	}
	if p.TenantID != "" && req.TenantID != p.TenantID {
		writeErr(w, 403, "PERMISSION_DENIED", "tenant mismatch")
		return
	}
	expiresAt, ok := parseOptionalTime(w, req.ExpiresAt)
	if !ok {
		return
	}
	dto, err := h.keys.CreateKey(r.Context(), keys.CreateKeyCommand{
		TenantID:       req.TenantID,
		KeyID:          req.KeyID,
		Name:           req.Name,
		Purpose:        req.Purpose,
		PolicyID:       req.PolicyID,
		SuiteID:        req.SuiteID,
		Tags:           req.Tags,
		ExpiresAt:      expiresAt,
		IdempotencyKey: r.Header.Get("Idempotency-Key"),
		PrincipalID:    p.ID,
	})
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, 201, dto)
}

// importKey handles POST /ui/api/v1/keys:import (EB-FR-01 controlled import).
// Required scope: keys:manage (per requirements §9: keys:create or keys:manage).
func (h *Handler) importKey(w http.ResponseWriter, r *http.Request) {
	p := middleware.PrincipalFromContext(r.Context())
	if p == nil {
		writeErr(w, 401, "AUTH_FAILED", "no principal")
		return
	}
	if !hasAnyScope(p, "keys:create", "keys:manage") {
		writeErr(w, 403, "PERMISSION_DENIED", "missing scope keys:create")
		return
	}
	body := middleware.BodyFromContext(r.Context())
	var req importKeyReq
	if err := middleware.DecodeJSONStrict(body, &req); err != nil {
		writeErr(w, 400, "BAD_REQUEST", "invalid json")
		return
	}
	// Default tenant_id to the principal's tenant when omitted.
	if req.TenantID == "" {
		req.TenantID = p.TenantID
	}
	if p.TenantID != "" && req.TenantID != p.TenantID {
		writeErr(w, 403, "PERMISSION_DENIED", "tenant mismatch")
		return
	}
	expiresAt, ok := parseOptionalTime(w, req.ExpiresAt)
	if !ok {
		return
	}
	// Decode base64 DEK plaintext. Per INV-11, this only enters the key-plane
	// sealing flow inside the resolver; the service zeroizes it after wrapping.
	dek, err := base64.StdEncoding.DecodeString(req.ExternalDEK)
	if err != nil {
		writeErr(w, 400, "BAD_REQUEST", "external_dek is not valid base64")
		return
	}
	dto, err := h.keys.ImportKey(r.Context(), keys.ImportKeyCommand{
		TenantID:       req.TenantID,
		KeyID:          req.KeyID,
		Name:           req.Name,
		Purpose:        req.Purpose,
		PolicyID:       req.PolicyID,
		SuiteID:        req.SuiteID,
		Tags:           req.Tags,
		ExpiresAt:      expiresAt,
		ExternalDEK:    dek,
		IdempotencyKey: r.Header.Get("Idempotency-Key"),
		PrincipalID:    p.ID,
	})
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, 201, dto)
}

// importKeyBatch handles controlled import of up to 100 symmetric DEKs. Each
// entry is independently validated and sealed; raw key material is never
// returned in results, errors, audit records, or logs.
func (h *Handler) importKeyBatch(w http.ResponseWriter, r *http.Request) {
	p := middleware.PrincipalFromContext(r.Context())
	if p == nil {
		writeErr(w, 401, "AUTH_FAILED", "no principal")
		return
	}
	if !hasAnyScope(p, "keys:create", "keys:manage") {
		writeErr(w, 403, "PERMISSION_DENIED", "missing scope keys:create")
		return
	}
	var req batchImportKeyReq
	if err := middleware.DecodeJSONStrict(middleware.BodyFromContext(r.Context()), &req); err != nil {
		writeErr(w, 400, "BAD_REQUEST", "invalid json")
		return
	}
	if len(req.Entries) == 0 || len(req.Entries) > 100 {
		writeErr(w, 400, "BAD_REQUEST", "batch must contain 1-100 entries")
		return
	}
	if req.TenantID == "" {
		req.TenantID = p.TenantID
	}
	if req.TenantID == "" || (p.TenantID != "" && req.TenantID != p.TenantID) {
		writeErr(w, 403, "PERMISSION_DENIED", "tenant mismatch")
		return
	}
	results := make([]batchImportKeyResult, len(req.Entries))
	batchKey := r.Header.Get("Idempotency-Key")
	for i, entry := range req.Entries {
		if entry.TenantID != "" && entry.TenantID != req.TenantID {
			results[i] = batchImportKeyResult{Index: i, ErrorCode: "PERMISSION_DENIED", Message: "tenant mismatch"}
			continue
		}
		expiresAt, err := parseOptionalTimeValue(entry.ExpiresAt)
		if err != nil {
			results[i] = batchImportKeyResult{Index: i, ErrorCode: "BAD_REQUEST", Message: "invalid expires_at"}
			continue
		}
		dek, err := base64.StdEncoding.DecodeString(entry.ExternalDEK)
		if err != nil {
			results[i] = batchImportKeyResult{Index: i, ErrorCode: "BAD_REQUEST", Message: "external_dek is not valid base64"}
			continue
		}
		idempotencyKey := ""
		if batchKey != "" {
			idempotencyKey = batchKey + ":" + strconv.Itoa(i)
		}
		dto, err := h.keys.ImportKey(r.Context(), keys.ImportKeyCommand{
			TenantID: req.TenantID, KeyID: entry.KeyID, Name: entry.Name, Purpose: entry.Purpose,
			PolicyID: entry.PolicyID, SuiteID: entry.SuiteID, Tags: entry.Tags, ExpiresAt: expiresAt,
			ExternalDEK: dek, IdempotencyKey: idempotencyKey, PrincipalID: p.ID,
		})
		if err != nil {
			results[i] = batchImportKeyResult{Index: i, ErrorCode: string(errorsx.AsCode(err)), Message: "key import failed"}
			continue
		}
		results[i] = batchImportKeyResult{Index: i, Success: true, Key: dto}
	}
	writeJSON(w, http.StatusOK, map[string]any{"results": results})
}

func (h *Handler) getKey(w http.ResponseWriter, r *http.Request) {
	p := middleware.PrincipalFromContext(r.Context())
	keyID := r.PathValue("key_id")
	tenantID := tenantFromQueryOrPrincipal(r, p)
	dto, err := h.keys.GetKey(r.Context(), tenantID, keyID)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, 200, dto)
}

func (h *Handler) listKeys(w http.ResponseWriter, r *http.Request) {
	p := middleware.PrincipalFromContext(r.Context())
	tenantID := tenantFromQueryOrPrincipal(r, p)
	includeArchived := r.URL.Query().Get("include_archived") == "true"
	dtos, err := h.keys.ListKeys(r.Context(), tenantID, includeArchived)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"keys": dtos})
}

func (h *Handler) updateKey(w http.ResponseWriter, r *http.Request) {
	p := middleware.PrincipalFromContext(r.Context())
	if p == nil {
		writeErr(w, 401, "AUTH_FAILED", "no principal")
		return
	}
	if !p.HasScope("keys:manage") {
		writeErr(w, 403, "PERMISSION_DENIED", "missing scope keys:manage")
		return
	}
	body := middleware.BodyFromContext(r.Context())
	var req updateKeyReq
	if err := middleware.DecodeJSONStrict(body, &req); err != nil {
		writeErr(w, 400, "BAD_REQUEST", "invalid json")
		return
	}
	expiresAt, ok := parseOptionalTime(w, req.ExpiresAt)
	if !ok {
		return
	}
	tenantID := tenantFromQueryOrPrincipal(r, p)
	dto, err := h.keys.UpdateKey(r.Context(), keys.UpdateKeyCommand{
		TenantID: tenantID, KeyID: r.PathValue("key_id"), Name: req.Name, Tags: req.Tags, ExpiresAt: expiresAt, PrincipalID: p.ID,
	})
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, 200, dto)
}

func (h *Handler) enableKey(w http.ResponseWriter, r *http.Request) {
	p := middleware.PrincipalFromContext(r.Context())
	if !requireAnyScope(w, p, "keys:manage") {
		return
	}
	keyID := r.PathValue("key_id")
	tenantID := tenantFromQueryOrPrincipal(r, p)
	if err := h.keys.EnableKey(r.Context(), tenantID, keyID, p.ID); err != nil {
		writeServiceError(w, err)
		return
	}
	w.WriteHeader(204)
}

func (h *Handler) disableKey(w http.ResponseWriter, r *http.Request) {
	p := middleware.PrincipalFromContext(r.Context())
	if !requireAnyScope(w, p, "keys:manage") {
		return
	}
	keyID := r.PathValue("key_id")
	tenantID := tenantFromQueryOrPrincipal(r, p)
	if err := h.keys.DisableKey(r.Context(), tenantID, keyID, p.ID); err != nil {
		writeServiceError(w, err)
		return
	}
	w.WriteHeader(204)
}

func (h *Handler) rotateKey(w http.ResponseWriter, r *http.Request) {
	p := middleware.PrincipalFromContext(r.Context())
	if !requireAnyScope(w, p, "keys:manage") {
		return
	}
	keyID := r.PathValue("key_id")
	tenantID := tenantFromQueryOrPrincipal(r, p)
	dto, err := h.keys.RotateKey(r.Context(), keys.RotateKeyCommand{
		TenantID: tenantID, KeyID: keyID, PrincipalID: p.ID,
	})
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, 200, dto)
}

func (h *Handler) cancelDestroy(w http.ResponseWriter, r *http.Request) {
	p := middleware.PrincipalFromContext(r.Context())
	if !requireAnyScope(w, p, "keys:manage") {
		return
	}
	keyID := r.PathValue("key_id")
	tenantID := tenantFromQueryOrPrincipal(r, p)
	if err := h.keys.CancelDestroy(r.Context(), tenantID, keyID, p.ID); err != nil {
		writeServiceError(w, err)
		return
	}
	w.WriteHeader(204)
}

func (h *Handler) scheduleDestroy(w http.ResponseWriter, r *http.Request) {
	p := middleware.PrincipalFromContext(r.Context())
	if !requireAnyScope(w, p, "keys:destroy", "keys:manage") {
		return
	}
	keyID := r.PathValue("key_id")
	tenantID := tenantFromQueryOrPrincipal(r, p)
	if err := h.keys.ScheduleDestroy(r.Context(), tenantID, keyID, p.ID); err != nil {
		writeServiceError(w, err)
		return
	}
	w.WriteHeader(204)
}

func (h *Handler) archiveDestroyedKey(w http.ResponseWriter, r *http.Request) {
	p := middleware.PrincipalFromContext(r.Context())
	if !requireAnyScope(w, p, "keys:destroy", "keys:manage") {
		return
	}
	keyID := r.PathValue("key_id")
	tenantID := tenantFromQueryOrPrincipal(r, p)
	dto, err := h.keys.ArchiveDestroyedKey(r.Context(), tenantID, keyID, p.ID)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, dto)
}

func (h *Handler) deleteKey(w http.ResponseWriter, r *http.Request) {
	h.scheduleDestroy(w, r)
}

func tenantFromQueryOrPrincipal(r *http.Request, p *principal.Principal) string {
	if p != nil && p.TenantID != "" {
		return p.TenantID
	}
	return r.URL.Query().Get("tenant_id")
}

func requireAnyScope(w http.ResponseWriter, p *principal.Principal, scopes ...string) bool {
	if p == nil {
		writeErr(w, 401, "AUTH_FAILED", "no principal")
		return false
	}
	if !hasAnyScope(p, scopes...) {
		writeErr(w, 403, "PERMISSION_DENIED", "missing required scope")
		return false
	}
	return true
}

func hasAnyScope(p *principal.Principal, scopes ...string) bool {
	if p == nil {
		return false
	}
	return p.HasAnyScope(scopes...)
}

func parseOptionalTime(w http.ResponseWriter, raw string) (time.Time, bool) {
	if raw == "" {
		return time.Time{}, true
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		writeErr(w, 400, "BAD_REQUEST", "expires_at must be RFC3339")
		return time.Time{}, false
	}
	return t.UTC(), true
}

func parseOptionalTimeValue(raw string) (time.Time, error) {
	if raw == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}, err
	}
	return t.UTC(), nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	b, _ := json.Marshal(v)
	w.Write(b)
}

func writeErr(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	b, _ := json.Marshal(map[string]any{
		"error": map[string]any{
			"code":    code,
			"message": msg,
		},
	})
	w.Write(b)
}

func writeServiceError(w http.ResponseWriter, err error) {
	code := errorsx.AsCode(err)
	status := errorsx.HTTPStatus(code)
	msg := errorsx.AsMessage(err)
	if msg == "" {
		msg = "request failed"
		if code == errorsx.CodeInternal {
			msg = "internal error"
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	b, _ := json.Marshal(map[string]any{
		"error": map[string]any{
			"code":      string(code),
			"message":   msg,
			"retryable": errorsx.AsRetryable(err),
		},
	})
	w.Write(b)
}
