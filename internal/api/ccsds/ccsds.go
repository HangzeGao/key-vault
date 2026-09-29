// Package ccsds exposes the mission CCSDS data-plane contract. TC callers
// submit complete plaintext transfer frames; they never select a key, suite,
// SPI, IV, key epoch, or construct the protected frame.
package ccsds

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/kvlt/key-vault/internal/api/middleware"
	"github.com/kvlt/key-vault/internal/auth/principal"
	"github.com/kvlt/key-vault/internal/errorsx"
	protocol "github.com/kvlt/key-vault/internal/protocol/ccsds"
)

type Service interface {
	ProtectTCFrame(ctx context.Context, tenantID string, frame []byte) (*protocol.ProtectedTCFrame, error)
	ObserveFlightSecurityStatus(ctx context.Context, tenantID string, status protocol.FlightSecurityStatus) error
}

type Handler struct {
	service Service
}

func New(service Service) *Handler {
	return &Handler{service: service}
}

func (h *Handler) Routes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/tc:protect", h.protectTC)
	mux.HandleFunc("POST /api/v1/flight-status:observe", h.observeFlightStatus)
}

type observeFlightStatusRequest struct {
	FormatVersion           uint16                       `json:"format_version"`
	ProfileDigest           string                       `json:"profile_digest"`
	SelfTest                protocol.FlightSelfTestState `json:"self_test"`
	CryptoBackend           protocol.FlightCryptoBackend `json:"crypto_backend"`
	CurrentSPI              uint16                       `json:"current_spi"`
	NextSPI                 uint16                       `json:"next_spi"`
	RecoverySPI             uint16                       `json:"recovery_spi"`
	SecurityEpoch           uint32                       `json:"security_epoch"`
	RootVersion             uint32                       `json:"root_version"`
	PendingRootPresent      bool                         `json:"pending_root_present"`
	ReceiveCount            uint64                       `json:"receive_count"`
	LastReceiveUS           uint64                       `json:"last_receive_us"`
	MaxReceiveUS            uint64                       `json:"max_receive_us"`
	CycleLimitExceededCount uint64                       `json:"cycle_limit_exceeded_count"`
	ClockAnomalyCount       uint64                       `json:"clock_anomaly_count"`
}

func (h *Handler) observeFlightStatus(w http.ResponseWriter, r *http.Request) {
	_, tenantID, ok := authorize(w, r, "ccsds:flight-status:observe")
	if !ok {
		return
	}
	var request observeFlightStatusRequest
	if err := middleware.DecodeJSONStrict(middleware.BodyFromContext(r.Context()), &request); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "invalid json")
		return
	}
	digest, err := hex.DecodeString(request.ProfileDigest)
	if err != nil || len(digest) != 32 {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "profile_digest must be 32-byte hexadecimal")
		return
	}
	status := protocol.FlightSecurityStatus{FormatVersion: request.FormatVersion, SelfTest: request.SelfTest,
		CryptoBackend: request.CryptoBackend, CurrentSPI: request.CurrentSPI, NextSPI: request.NextSPI,
		RecoverySPI: request.RecoverySPI, SecurityEpoch: request.SecurityEpoch, RootVersion: request.RootVersion,
		PendingRootPresent: request.PendingRootPresent, ReceiveCount: request.ReceiveCount,
		LastReceiveUS: request.LastReceiveUS, MaxReceiveUS: request.MaxReceiveUS,
		CycleLimitExceededCount: request.CycleLimitExceededCount, ClockAnomalyCount: request.ClockAnomalyCount}
	copy(status.ProfileDigest[:], digest)
	if err := h.service.ObserveFlightSecurityStatus(r.Context(), tenantID, status); err != nil {
		writeProtocolError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type protectTCRequest struct {
	TenantID string `json:"tenant_id,omitempty"`
	Frame    string `json:"frame"`
}

func (h *Handler) protectTC(w http.ResponseWriter, r *http.Request) {
	principal, tenantID, ok := authorize(w, r, "ccsds:tc:protect")
	if !ok {
		return
	}
	var request protectTCRequest
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
	frame, err := base64.StdEncoding.DecodeString(request.Frame)
	if err != nil || len(frame) == 0 {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "frame must be non-empty base64")
		return
	}
	result, err := h.service.ProtectTCFrame(r.Context(), tenantID, frame)
	if err != nil {
		writeProtocolError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"protected_frame": base64.StdEncoding.EncodeToString(result.Frame),
	})
}

func authorize(w http.ResponseWriter, r *http.Request, scope string) (*principal.Principal, string, bool) {
	caller := middleware.PrincipalFromContext(r.Context())
	if caller == nil {
		writeError(w, http.StatusUnauthorized, "AUTH_FAILED", "no principal")
		return nil, "", false
	}
	if !caller.HasScope(scope) {
		writeError(w, http.StatusForbidden, "PERMISSION_DENIED", "missing scope "+scope)
		return nil, "", false
	}
	return caller, caller.TenantID, true
}

func writeProtocolError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, protocol.ErrFrameInvalid):
		writeError(w, http.StatusBadRequest, "FRAME_INVALID", "invalid CCSDS frame data")
	case errors.Is(err, protocol.ErrAssociationNotFound):
		writeError(w, http.StatusNotFound, "ASSOCIATION_NOT_FOUND", "CCSDS association not found")
	case errors.Is(err, protocol.ErrAssociationState), errors.Is(err, protocol.ErrCounterExhausted):
		writeError(w, http.StatusConflict, "CCSDS_STATE_REJECTED", "CCSDS security state rejected operation")
	default:
		code := errorsx.AsCode(err)
		if code != errorsx.CodeInternal {
			writeError(w, errorsx.HTTPStatus(code), string(code), errorsx.AsMessage(err))
			return
		}
		writeError(w, http.StatusInternalServerError, "INTERNAL", "internal error")
	}
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]any{"error": map[string]any{"code": code, "message": message}})
}
