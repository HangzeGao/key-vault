// Package tenant implements the tenant envelope config management API per design §8.6.
package tenant

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/kvlt/key-vault/internal/api/middleware"
	"github.com/kvlt/key-vault/internal/crypto/envelope"
	"github.com/kvlt/key-vault/internal/repository/models"
)

// Store is the repository subset for tenant envelope config.
type Store interface {
	GetTenantEnvelopeConfig(ctx context.Context, tenantID string) (*models.TenantEnvelopeConfig, error)
	UpsertTenantEnvelopeConfig(ctx context.Context, cfg *models.TenantEnvelopeConfig) error
}

// Handler is the tenant envelope config API handler.
type Handler struct {
	store    Store
	registry *envelope.Registry
}

// New constructs a tenant handler.
func New(store Store, registry *envelope.Registry) *Handler {
	return &Handler{store: store, registry: registry}
}

// Routes registers the tenant envelope config routes.
func (h *Handler) Routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /ui/api/v1/tenants/{tenant_id}/envelope-config", h.getEnvelopeConfig)
	mux.HandleFunc("PUT /ui/api/v1/tenants/{tenant_id}/envelope-config", h.updateEnvelopeConfig)
	mux.HandleFunc("GET /ui/api/v1/envelope/formats", h.listFormats)
}

type envelopeConfigResp struct {
	TenantID       string                         `json:"tenant_id"`
	DefaultFormat  string                         `json:"default_format"`
	AllowedFormats []string                       `json:"allowed_formats"`
	Profiles       []models.EnvelopeFormatProfile `json:"profiles"`
	AADRequired    bool                           `json:"aad_required"`
	Version        int                            `json:"version"`
	CreatedAt      string                         `json:"created_at"`
	UpdatedAt      string                         `json:"updated_at"`
	UpdatedBy      string                         `json:"updated_by"`
}

type updateEnvelopeConfigReq struct {
	DefaultFormat  string                         `json:"default_format"`
	AllowedFormats []string                       `json:"allowed_formats"`
	Profiles       []models.EnvelopeFormatProfile `json:"profiles,omitempty"`
	AADRequired    bool                           `json:"aad_required"`
	Version        int                            `json:"version"`
}

func (h *Handler) getEnvelopeConfig(w http.ResponseWriter, r *http.Request) {
	p := middleware.PrincipalFromContext(r.Context())
	if p == nil {
		writeErr(w, http.StatusUnauthorized, "AUTH_FAILED", "no principal")
		return
	}
	if !p.HasAnyScope("tenant:read", "tenant:manage") {
		writeErr(w, http.StatusForbidden, "PERMISSION_DENIED", "missing scope tenant:read")
		return
	}
	tenantID := r.PathValue("tenant_id")
	if p.TenantID != "" && tenantID != "" && p.TenantID != tenantID {
		writeErr(w, http.StatusForbidden, "AUTH_FAILED", "tenant mismatch")
		return
	}

	cfg, err := h.store.GetTenantEnvelopeConfig(r.Context(), tenantID)
	if err != nil {
		writeErr(w, http.StatusNotFound, "NOT_FOUND", "envelope config not found")
		return
	}
	writeJSON(w, http.StatusOK, toResp(cfg))
}

func (h *Handler) updateEnvelopeConfig(w http.ResponseWriter, r *http.Request) {
	p := middleware.PrincipalFromContext(r.Context())
	if p == nil {
		writeErr(w, http.StatusUnauthorized, "AUTH_FAILED", "no principal")
		return
	}
	if !p.HasScope("tenant:manage") {
		writeErr(w, http.StatusForbidden, "PERMISSION_DENIED", "missing scope tenant:manage")
		return
	}
	tenantID := r.PathValue("tenant_id")
	if p.TenantID != "" && tenantID != "" && p.TenantID != tenantID {
		writeErr(w, http.StatusForbidden, "AUTH_FAILED", "tenant mismatch")
		return
	}

	var req updateEnvelopeConfigReq
	body := middleware.BodyFromContext(r.Context())
	if err := middleware.DecodeJSONStrict(body, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "BAD_REQUEST", "invalid JSON")
		return
	}

	profileSet := make(map[string]models.EnvelopeFormatProfile, len(req.Profiles))
	for _, p := range req.Profiles {
		if strings.TrimSpace(p.FormatID) == "" {
			writeErr(w, http.StatusBadRequest, "BAD_REQUEST", "profile format_id is required")
			return
		}
		if strings.TrimSpace(p.Adapter) == "" {
			writeErr(w, http.StatusBadRequest, "BAD_REQUEST", "profile adapter is required")
			return
		}
		if _, err := h.registry.Codec(envelope.FormatID(p.Adapter)); err != nil {
			writeErr(w, http.StatusBadRequest, "BAD_REQUEST", "profile adapter "+p.Adapter+" is not registered")
			return
		}
		if _, exists := profileSet[p.FormatID]; exists {
			writeErr(w, http.StatusBadRequest, "BAD_REQUEST", "duplicate profile "+p.FormatID)
			return
		}
		if err := validateProfile(p); err != nil {
			writeErr(w, http.StatusBadRequest, "BAD_REQUEST", err.Error())
			return
		}
		profileSet[p.FormatID] = p
	}

	// Validate default_format is a registered format or tenant profile.
	if req.DefaultFormat == "" {
		writeErr(w, http.StatusBadRequest, "BAD_REQUEST", "default_format is required")
		return
	}
	if !h.formatKnown(envelope.FormatID(req.DefaultFormat), profileSet) {
		writeErr(w, http.StatusBadRequest, "BAD_REQUEST", "default_format is not a registered format")
		return
	}

	// Validate all allowed_formats are registered.
	if len(req.AllowedFormats) == 0 {
		writeErr(w, http.StatusBadRequest, "BAD_REQUEST", "allowed_formats must not be empty")
		return
	}
	allowedSet := make(map[string]bool)
	for _, f := range req.AllowedFormats {
		if !h.formatKnown(envelope.FormatID(f), profileSet) {
			writeErr(w, http.StatusBadRequest, "BAD_REQUEST", "allowed_format "+f+" is not registered")
			return
		}
		allowedSet[f] = true
	}

	// Validate default_format is in allowed_formats.
	if !allowedSet[req.DefaultFormat] {
		writeErr(w, http.StatusBadRequest, "BAD_REQUEST", "default_format must be in allowed_formats")
		return
	}
	cfg := &models.TenantEnvelopeConfig{
		TenantID:       tenantID,
		DefaultFormat:  req.DefaultFormat,
		AllowedFormats: req.AllowedFormats,
		Profiles:       req.Profiles,
		AADRequired:    req.AADRequired,
		Version:        req.Version,
		UpdatedBy:      p.ID,
	}
	if err := h.store.UpsertTenantEnvelopeConfig(r.Context(), cfg); err != nil {
		// Check if it's a conflict error (version mismatch)
		errMsg := err.Error()
		if contains(errMsg, "version mismatch") || contains(errMsg, "does not exist but version") {
			writeErr(w, http.StatusConflict, "CONFLICT", "version mismatch, please re-fetch and retry")
			return
		}
		writeErr(w, http.StatusInternalServerError, "INTERNAL", "update failed")
		return
	}
	writeJSON(w, http.StatusOK, toResp(cfg))
}

func (h *Handler) listFormats(w http.ResponseWriter, r *http.Request) {
	formats := h.registry.ListFormats()
	writeJSON(w, http.StatusOK, map[string]any{"formats": formats})
}

func toResp(cfg *models.TenantEnvelopeConfig) envelopeConfigResp {
	allowed := cfg.AllowedFormats
	if allowed == nil {
		allowed = []string{}
	}
	return envelopeConfigResp{
		TenantID:       cfg.TenantID,
		DefaultFormat:  cfg.DefaultFormat,
		AllowedFormats: allowed,
		Profiles:       cfg.Profiles,
		AADRequired:    cfg.AADRequired,
		Version:        cfg.Version,
		CreatedAt:      cfg.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		UpdatedAt:      cfg.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
		UpdatedBy:      cfg.UpdatedBy,
	}
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

func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}

func (h *Handler) formatKnown(id envelope.FormatID, profiles map[string]models.EnvelopeFormatProfile) bool {
	if _, ok := profiles[string(id)]; ok {
		return true
	}
	_, err := h.registry.Codec(id)
	return err == nil
}

func validateProfile(p models.EnvelopeFormatProfile) error {
	for _, m := range p.FieldMappings {
		if !strings.HasPrefix(strings.TrimSpace(m.Path), "$.") {
			return errors.New("invalid field mapping path")
		}
		source := strings.TrimSpace(m.Source)
		if source == "" {
			return errors.New("field mapping source is required")
		}
		if strings.HasPrefix(source, "core.") {
			switch source {
			case "core.version", "core.flags", "core.suite_id", "core.key_id", "core.key_version", "core.policy_version", "core.nonce", "core.ciphertext", "core.tag", "core.aad_hash":
			default:
				return errors.New("unsupported core mapping source " + source)
			}
			continue
		}
		if strings.HasPrefix(source, "derived.") || strings.HasPrefix(source, "extension.") {
			continue
		}
		return errors.New("unsupported mapping source " + source)
	}
	for _, ext := range p.Extensions {
		switch ext.Type {
		case "", "string", "number", "boolean", "base64", "json":
		default:
			return errors.New("extension " + ext.Name + " has invalid type")
		}
	}
	return nil
}
