//go:build downlink

package ccsds

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"

	"github.com/kvlt/key-vault/internal/api/middleware"
	downlinkcrypto "github.com/kvlt/key-vault/internal/downlink"
)

type RawDownlinkService interface {
	UnprotectRaw(context.Context, []byte) ([]byte, error)
}

type downlinkHandler struct{ downlink RawDownlinkService }

func (h *Handler) SetDownlink(service RawDownlinkService) { h.downlink = service }

func (h *Handler) registerDownlink(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/downlink:unprotect", h.unprotectDownlink)
}

type unprotectDownlinkRequest struct {
	TenantID string `json:"tenant_id,omitempty"`
	Package  string `json:"package"`
}

func (h *Handler) unprotectDownlink(w http.ResponseWriter, r *http.Request) {
	principal, tenantID, ok := authorize(w, r, "ccsds:downlink:unprotect")
	if !ok {
		return
	}
	if h.downlink == nil {
		writeError(w, http.StatusServiceUnavailable, "DOWNLINK_UNAVAILABLE", "downlink service unavailable")
		return
	}
	var request unprotectDownlinkRequest
	if err := middleware.DecodeJSONStrict(middleware.BodyFromContext(r.Context()), &request); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "invalid json")
		return
	}
	if request.TenantID != "" {
		tenantID = request.TenantID
	}
	if principal.TenantID != "" && tenantID != principal.TenantID {
		writeError(w, http.StatusForbidden, "PERMISSION_DENIED", "tenant mismatch")
		return
	}
	frame, err := base64.StdEncoding.DecodeString(request.Package)
	if err != nil || len(frame) == 0 {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "package must be non-empty base64")
		return
	}
	result, err := h.downlink.UnprotectRaw(r.Context(), frame)
	if err != nil {
		writeProtocolError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"plaintext": base64.StdEncoding.EncodeToString(result)})
}

func writeDownlinkError(w http.ResponseWriter, err error) bool {
	switch {
	case errors.Is(err, downlinkcrypto.ErrInvalid):
		writeError(w, http.StatusBadRequest, "DOWNLINK_INVALID", "invalid raw downlink package")
	case errors.Is(err, downlinkcrypto.ErrAuthentication):
		writeError(w, http.StatusUnprocessableEntity, "DOWNLINK_AUTHENTICATION_FAILED", "raw downlink authentication failed")
	case errors.Is(err, downlinkcrypto.ErrNotProvisioned), errors.Is(err, downlinkcrypto.ErrNotObserved):
		writeError(w, http.StatusConflict, "DOWNLINK_STATE_REJECTED", "downlink key state rejected operation")
	default:
		return false
	}
	return true
}
