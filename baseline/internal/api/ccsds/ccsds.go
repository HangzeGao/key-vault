// Package ccsds exposes the mission CCSDS data-plane contract. Callers submit
// payload bytes; they never select a key, suite, SPI, IV, or key epoch.
package ccsds

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/kvlt/key-vault/internal/api/middleware"
	"github.com/kvlt/key-vault/internal/auth/principal"
	"github.com/kvlt/key-vault/internal/errorsx"
	protocol "github.com/kvlt/key-vault/internal/protocol/ccsds"
)

type Service interface {
	ProtectTCData(ctx context.Context, tenantID string, data []byte) (*protocol.ProtectedTCData, error)
	UnprotectAOS(ctx context.Context, tenantID string, frame []byte) (*protocol.PlainAOSFrame, error)
	OperationsStatus(ctx context.Context, tenantID string) (*protocol.OperationsStatus, error)
}

type Handler struct {
	service Service
}

func New(service Service) *Handler { return &Handler{service: service} }

func (h *Handler) Routes(mux *http.ServeMux) {
	mux.HandleFunc("POST /ui/api/v1/ccsds/tc:protect", h.protectTC)
	mux.HandleFunc("POST /ui/api/v1/ccsds/aos:unprotect", h.unprotectAOS)
}

// OpsRoutes exposes a read-only operational projection. It intentionally has
// no association, root, key, counter, or replay mutation endpoints.
func (h *Handler) OpsRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /ui/api/v1/ops/ccsds/status", h.operationsStatus)
}

type associationStatusResponse struct {
	ID                   string                    `json:"id"`
	SPI                  uint16                    `json:"spi"`
	Direction            protocol.Direction        `json:"direction"`
	State                protocol.AssociationState `json:"state"`
	SuiteID              string                    `json:"suite_id"`
	SecurityEpoch        uint32                    `json:"security_epoch"`
	KeyVersion           uint32                    `json:"key_version"`
	PolicyVersion        uint32                    `json:"policy_version"`
	SequenceNumberLength int                       `json:"sequence_number_length"`
	TransmittedIVLength  int                       `json:"transmitted_iv_length"`
	TagLength            int                       `json:"tag_length"`
	ReplayWindow         uint8                     `json:"replay_window"`
	NextIVCounter        *uint64                   `json:"next_iv_counter,omitempty"`
	ReplayHighest        *uint64                   `json:"replay_highest,omitempty"`
	ReplaySeen           bool                      `json:"replay_seen"`
}

type operationsStatusResponse struct {
	ObservedAt string `json:"observed_at"`
	Status     string `json:"status"`
	Ready      bool   `json:"ready"`
	TC         struct {
		Current  *associationStatusResponse `json:"current"`
		Next     *associationStatusResponse `json:"next"`
		Recovery *associationStatusResponse `json:"recovery"`
	} `json:"tc"`
	AOS      []associationStatusResponse `json:"aos"`
	Warnings []string                    `json:"warnings"`
}

func (h *Handler) operationsStatus(w http.ResponseWriter, r *http.Request) {
	_, tenantID, ok := authorize(w, r, "ops:read")
	if !ok {
		return
	}
	if tenantID == "" {
		writeError(w, http.StatusBadRequest, "TENANT_REQUIRED", "tenant-bound operations identity required")
		return
	}
	status, err := h.service.OperationsStatus(r.Context(), tenantID)
	if err != nil {
		writeProtocolError(w, err)
		return
	}
	response := operationsStatusResponse{
		ObservedAt: time.Now().UTC().Format(time.RFC3339Nano), Status: status.Status,
		Ready: status.Ready, AOS: make([]associationStatusResponse, 0, len(status.AOSActive)),
		Warnings: append([]string{}, status.Warnings...),
	}
	response.TC.Current = mapAssociationStatus(status.TCCurrent)
	response.TC.Next = mapAssociationStatus(status.TCNext)
	response.TC.Recovery = mapAssociationStatus(status.TCRecovery)
	for i := range status.AOSActive {
		response.AOS = append(response.AOS, *mapAssociationStatus(&status.AOSActive[i]))
	}
	writeJSON(w, http.StatusOK, response)
}

func mapAssociationStatus(state *protocol.AssociationRuntimeState) *associationStatusResponse {
	if state == nil {
		return nil
	}
	return &associationStatusResponse{
		ID: state.ID, SPI: state.SPI, Direction: state.Direction, State: state.State,
		SuiteID: state.SuiteID, SecurityEpoch: state.SecurityEpoch, KeyVersion: state.KeyVersion,
		PolicyVersion: state.PolicyVersion, SequenceNumberLength: state.SequenceNumberLength,
		TransmittedIVLength: state.TransmittedIVLength, TagLength: state.TagLength,
		ReplayWindow: state.ReplayWindow, NextIVCounter: state.NextIVCounter,
		ReplayHighest: state.ReplayHighest, ReplaySeen: state.ReplaySeen,
	}
}

type protectTCRequest struct {
	TenantID string `json:"tenant_id,omitempty"`
	Data     string `json:"data"`
}

type unprotectAOSRequest struct {
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
	data, err := base64.StdEncoding.DecodeString(request.Data)
	if err != nil || len(data) == 0 {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "data must be non-empty base64")
		return
	}
	result, err := h.service.ProtectTCData(r.Context(), tenantID, data)
	if err != nil {
		writeProtocolError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"security_data": base64.StdEncoding.EncodeToString(result.Data),
	})
}

func (h *Handler) unprotectAOS(w http.ResponseWriter, r *http.Request) {
	principal, tenantID, ok := authorize(w, r, "ccsds:aos:unprotect")
	if !ok {
		return
	}
	var request unprotectAOSRequest
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
	result, err := h.service.UnprotectAOS(r.Context(), tenantID, frame)
	if err != nil {
		writeProtocolError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"plain_frame": base64.StdEncoding.EncodeToString(result.Frame),
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
	case errors.Is(err, protocol.ErrAssociationState), errors.Is(err, protocol.ErrCounterExhausted),
		errors.Is(err, protocol.ErrSequenceExhausted), errors.Is(err, protocol.ErrReplay):
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
