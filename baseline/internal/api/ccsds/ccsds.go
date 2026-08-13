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
	"strconv"
	"time"

	"github.com/kvlt/key-vault/internal/api/middleware"
	"github.com/kvlt/key-vault/internal/auth/principal"
	downlinkcrypto "github.com/kvlt/key-vault/internal/downlink"
	"github.com/kvlt/key-vault/internal/errorsx"
	protocol "github.com/kvlt/key-vault/internal/protocol/ccsds"
)

type Service interface {
	ProtectTCFrame(ctx context.Context, tenantID string, frame []byte) (*protocol.ProtectedTCFrame, error)
	OperationsStatus(ctx context.Context, tenantID string) (*protocol.OperationsStatus, error)
	ObserveFlightSecurityStatus(ctx context.Context, tenantID string, status protocol.FlightSecurityStatus) error
}

type RawDownlinkService interface {
	UnprotectRaw(context.Context, []byte) ([]byte, error)
	Status(context.Context) (downlinkcrypto.Status, error)
}

type Handler struct {
	service  Service
	downlink RawDownlinkService
}

func New(service Service, downlink RawDownlinkService) *Handler {
	return &Handler{service: service, downlink: downlink}
}

func (h *Handler) Routes(mux *http.ServeMux) {
	mux.HandleFunc("POST /ui/api/v1/ccsds/tc:protect", h.protectTC)
	mux.HandleFunc("POST /ui/api/v1/ccsds/downlink:unprotect", h.unprotectDownlink)
	mux.HandleFunc("POST /ui/api/v1/ccsds/flight-status:observe", h.observeFlightStatus)
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
	TCRotation           *tcRotationStatusResponse `json:"tc_rotation"`
	DownlinkFormat       string                    `json:"downlink_format"`
	Downlink             downlinkStatusResponse    `json:"downlink"`
	ProfileDigest        string                    `json:"profile_digest"`
	Flight               *flightStatusResponse     `json:"flight"`
	FlightReconciliation string                    `json:"flight_reconciliation"`
	Warnings             []string                  `json:"warnings"`
}

type downlinkStatusResponse struct {
	Provisioned        bool   `json:"provisioned"`
	ActiveKEKSlot      uint8  `json:"active_kek_slot"`
	CurrentGeneration  uint32 `json:"current_generation"`
	CurrentObserved    bool   `json:"current_observed"`
	PreviousGeneration uint32 `json:"previous_generation"`
}

type flightStatusResponse struct {
	ObservedAt              string                       `json:"observed_at"`
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

type tcRotationStatusResponse struct {
	Phase              protocol.TCRotationPhase `json:"phase"`
	TransactionID      string                   `json:"transaction_id"`
	CurrentSPI         uint16                   `json:"current_spi"`
	NextSPI            uint16                   `json:"next_spi"`
	CurrentRootVersion uint32                   `json:"current_root_version"`
	NextRootVersion    uint32                   `json:"next_root_version"`
	Evidence           string                   `json:"evidence"`
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
	downlinkStatus, err := h.downlink.Status(r.Context())
	if err != nil {
		writeProtocolError(w, err)
		return
	}
	response := operationsStatusResponse{
		ObservedAt: time.Now().UTC().Format(time.RFC3339Nano), Status: status.Status,
		Ready: status.Ready, DownlinkFormat: status.DownlinkFormat,
		Warnings:      append([]string{}, status.Warnings...),
		ProfileDigest: status.ProfileDigest, FlightReconciliation: status.FlightReconciliation,
	}
	response.Downlink = downlinkStatusResponse{
		Provisioned: downlinkStatus.Provisioned, ActiveKEKSlot: downlinkStatus.ActiveKEKSlot,
		CurrentGeneration: downlinkStatus.CurrentGeneration, CurrentObserved: downlinkStatus.CurrentObserved,
		PreviousGeneration: downlinkStatus.PreviousGeneration,
	}
	if !downlinkStatus.Provisioned {
		response.Ready = false
		response.Status = "UNCONFIGURED"
		response.Warnings = append(response.Warnings, "Raw downlink KEK set is not provisioned.")
	} else if downlinkStatus.CurrentGeneration == 0 {
		response.Ready = false
		response.Status = "DEGRADED"
		response.Warnings = append(response.Warnings, "Raw downlink has no Current DEK batch.")
	} else if !downlinkStatus.CurrentObserved {
		response.Warnings = append(response.Warnings, "Current downlink DEK batch has not been observed; next generation is blocked.")
	}
	if status.FlightStatus != nil {
		flight := status.FlightStatus
		response.Flight = &flightStatusResponse{ObservedAt: flight.ObservedAt.UTC().Format(time.RFC3339Nano),
			SelfTest: flight.SelfTest, CryptoBackend: flight.CryptoBackend, CurrentSPI: flight.CurrentSPI,
			NextSPI: flight.NextSPI, RecoverySPI: flight.RecoverySPI, SecurityEpoch: flight.SecurityEpoch,
			RootVersion: flight.RootVersion, PendingRootPresent: flight.PendingRootPresent,
			ReceiveCount: flight.ReceiveCount, LastReceiveUS: flight.LastReceiveUS, MaxReceiveUS: flight.MaxReceiveUS,
			CycleLimitExceededCount: flight.CycleLimitExceededCount, ClockAnomalyCount: flight.ClockAnomalyCount}
	}
	response.TC.Current = mapAssociationStatus(status.TCCurrent)
	response.TC.Next = mapAssociationStatus(status.TCNext)
	response.TC.Recovery = mapAssociationStatus(status.TCRecovery)
	if status.TCRotation != nil {
		evidence := "RECOVERY_FRAME_PRODUCED"
		if status.TCRotation.Phase == protocol.TCRotationSwitching {
			evidence = "GROUND_PROMOTED"
		}
		if status.TCRotation.Phase == protocol.TCRotationActive {
			evidence = "FIRST_NEXT_FRAME_PRODUCED"
		}
		response.TCRotation = &tcRotationStatusResponse{Phase: status.TCRotation.Phase,
			TransactionID: strconv.FormatUint(status.TCRotation.TransactionID, 10), CurrentSPI: status.TCRotation.CurrentSPI,
			NextSPI: status.TCRotation.NextSPI, CurrentRootVersion: status.TCRotation.CurrentRootVersion,
			NextRootVersion: status.TCRotation.NextRootVersion, Evidence: evidence}
	}
	writeJSON(w, http.StatusOK, response)
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
	_, tenantID, ok := authorize(w, r, "ccsds:downlink:unprotect")
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
	Frame    string `json:"frame"`
}

type unprotectDownlinkRequest struct {
	TenantID string `json:"tenant_id,omitempty"`
	Package  string `json:"package"`
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

func (h *Handler) unprotectDownlink(w http.ResponseWriter, r *http.Request) {
	principal, tenantID, ok := authorize(w, r, "ccsds:downlink:unprotect")
	if !ok {
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
	writeJSON(w, http.StatusOK, map[string]any{
		"plaintext": base64.StdEncoding.EncodeToString(result),
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
	case errors.Is(err, downlinkcrypto.ErrInvalid):
		writeError(w, http.StatusBadRequest, "DOWNLINK_INVALID", "invalid raw downlink package")
	case errors.Is(err, downlinkcrypto.ErrAuthentication):
		writeError(w, http.StatusUnprocessableEntity, "DOWNLINK_AUTHENTICATION_FAILED", "raw downlink authentication failed")
	case errors.Is(err, downlinkcrypto.ErrNotProvisioned), errors.Is(err, downlinkcrypto.ErrNotObserved):
		writeError(w, http.StatusConflict, "DOWNLINK_STATE_REJECTED", "downlink key state rejected operation")
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
