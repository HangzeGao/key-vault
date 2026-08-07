// Package crypto implements the Crypto API per design §12.3.
package crypto

import (
	"encoding/base64"
	"encoding/json"
	"net/http"

	"github.com/kvlt/key-vault/internal/api/middleware"
	"github.com/kvlt/key-vault/internal/application/crypto"
	cryptosuite "github.com/kvlt/key-vault/internal/crypto/suite"
	apperrors "github.com/kvlt/key-vault/internal/errorsx"
)

// Handler is the crypto API HTTP handler.
type Handler struct {
	svc *crypto.Service
}

// New constructs a crypto handler.
func New(svc *crypto.Service) *Handler {
	return &Handler{svc: svc}
}

// Routes registers the crypto routes.
func (h *Handler) Routes(mux *http.ServeMux) {
	mux.HandleFunc("POST /ui/api/v1/crypto/encrypt", h.encrypt)
	mux.HandleFunc("POST /ui/api/v1/crypto/decrypt", h.decrypt)
	mux.HandleFunc("POST /ui/api/v1/crypto/authenticate", h.authenticate)
	mux.HandleFunc("POST /ui/api/v1/crypto/verify", h.verify)
	mux.HandleFunc("POST /ui/api/v1/crypto/envelopes:convert", h.convertEnvelope)
	mux.HandleFunc("POST /ui/api/v1/crypto/envelopes:inspect", h.inspectEnvelope)
}

type authenticateReq struct {
	TenantID string `json:"tenant_id"`
	KeyID    string `json:"key_id"`
	Message  string `json:"message"` // base64
}

type authenticatorJSON struct {
	Version       uint8                   `json:"version"`
	SuiteID       string                  `json:"suite_id"`
	ServiceType   cryptosuite.ServiceType `json:"service_type"`
	KeyID         string                  `json:"key_id"`
	KeyVersion    uint32                  `json:"key_version"`
	PolicyVersion uint32                  `json:"policy_version"`
	Tag           string                  `json:"tag"` // base64
}

type authenticateResp struct {
	Authenticator authenticatorJSON `json:"authenticator"`
}

type verifyReq struct {
	TenantID      string            `json:"tenant_id"`
	Message       string            `json:"message"` // base64
	Authenticator authenticatorJSON `json:"authenticator"`
}

type verifyResp struct {
	Valid bool `json:"valid"`
}

func (h *Handler) authenticate(w http.ResponseWriter, r *http.Request) {
	p := middleware.PrincipalFromContext(r.Context())
	if p == nil {
		writeErr(w, 401, "AUTH_FAILED", "no principal")
		return
	}
	if !p.HasScope("crypto:authenticate") {
		writeErr(w, 403, "PERMISSION_DENIED", "missing scope crypto:authenticate")
		return
	}
	var req authenticateReq
	if err := middleware.DecodeJSONStrict(middleware.BodyFromContext(r.Context()), &req); err != nil {
		writeErr(w, 400, "BAD_REQUEST", "invalid json")
		return
	}
	if req.TenantID == "" {
		req.TenantID = p.TenantID
	}
	if p.TenantID != "" && req.TenantID != p.TenantID {
		writeErr(w, 403, "PERMISSION_DENIED", "tenant mismatch")
		return
	}
	message, err := base64.StdEncoding.DecodeString(req.Message)
	if err != nil {
		writeErr(w, 400, "BAD_REQUEST", "message not base64")
		return
	}
	res, err := h.svc.Authenticate(r.Context(), crypto.AuthenticateCommand{
		TenantID: req.TenantID, KeyID: req.KeyID, Message: message, PrincipalID: p.ID,
	})
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, 200, authenticateResp{Authenticator: authenticatorToJSON(res.Authenticator)})
}

func (h *Handler) verify(w http.ResponseWriter, r *http.Request) {
	p := middleware.PrincipalFromContext(r.Context())
	if p == nil {
		writeErr(w, 401, "AUTH_FAILED", "no principal")
		return
	}
	if !p.HasScope("crypto:verify") {
		writeErr(w, 403, "PERMISSION_DENIED", "missing scope crypto:verify")
		return
	}
	var req verifyReq
	if err := middleware.DecodeJSONStrict(middleware.BodyFromContext(r.Context()), &req); err != nil {
		writeErr(w, 400, "BAD_REQUEST", "invalid json")
		return
	}
	if req.TenantID == "" {
		req.TenantID = p.TenantID
	}
	if p.TenantID != "" && req.TenantID != p.TenantID {
		writeErr(w, 403, "PERMISSION_DENIED", "tenant mismatch")
		return
	}
	message, err := base64.StdEncoding.DecodeString(req.Message)
	if err != nil {
		writeErr(w, 400, "BAD_REQUEST", "message not base64")
		return
	}
	authenticator, err := authenticatorFromJSON(req.Authenticator)
	if err != nil {
		writeErr(w, 400, "BAD_REQUEST", "invalid authenticator")
		return
	}
	res, err := h.svc.Verify(r.Context(), crypto.VerifyCommand{
		TenantID: req.TenantID, Message: message, Authenticator: authenticator, PrincipalID: p.ID,
	})
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, 200, verifyResp{Valid: res.Valid})
}

func authenticatorToJSON(v crypto.Authenticator) authenticatorJSON {
	return authenticatorJSON{
		Version: v.Version, SuiteID: v.SuiteID, ServiceType: v.ServiceType, KeyID: v.KeyID,
		KeyVersion: v.KeyVersion, PolicyVersion: v.PolicyVersion,
		Tag: base64.StdEncoding.EncodeToString(v.Tag),
	}
}

func authenticatorFromJSON(v authenticatorJSON) (crypto.Authenticator, error) {
	tag, err := base64.StdEncoding.DecodeString(v.Tag)
	if err != nil {
		return crypto.Authenticator{}, err
	}
	return crypto.Authenticator{
		Version: v.Version, SuiteID: v.SuiteID, ServiceType: v.ServiceType, KeyID: v.KeyID,
		KeyVersion: v.KeyVersion, PolicyVersion: v.PolicyVersion, Tag: tag,
	}, nil
}

type encryptReq struct {
	TenantID       string         `json:"tenant_id"`
	KeyID          string         `json:"key_id"`
	Plaintext      string         `json:"plaintext"` // base64
	AADB64         string         `json:"aad_b64,omitempty"`
	NodeID         string         `json:"node_id,omitempty"`
	EnvelopeFormat string         `json:"envelope_format,omitempty"`
	Extensions     map[string]any `json:"extensions,omitempty"`
}

func (h *Handler) encrypt(w http.ResponseWriter, r *http.Request) {
	p := middleware.PrincipalFromContext(r.Context())
	if p == nil {
		writeErr(w, 401, "AUTH_FAILED", "no principal")
		return
	}
	if !p.HasScope("crypto:encrypt") {
		writeErr(w, 403, "PERMISSION_DENIED", "missing scope crypto:encrypt")
		return
	}
	body := middleware.BodyFromContext(r.Context())
	var req encryptReq
	if err := middleware.DecodeJSONStrict(body, &req); err != nil {
		writeErr(w, 400, "BAD_REQUEST", "invalid json")
		return
	}
	if req.TenantID == "" {
		req.TenantID = p.TenantID
	}
	if p.TenantID != "" && req.TenantID != p.TenantID {
		writeErr(w, 403, "PERMISSION_DENIED", "tenant mismatch")
		return
	}
	pt, err := base64.StdEncoding.DecodeString(req.Plaintext)
	if err != nil {
		writeErr(w, 400, "BAD_REQUEST", "plaintext not base64")
		return
	}
	aadBytes, err := decodeOptionalBase64(req.AADB64)
	if err != nil {
		writeErr(w, 400, "BAD_REQUEST", "aad_b64 not base64")
		return
	}
	nodeID := req.NodeID
	if nodeID == "" {
		nodeID = p.NodeID
	}
	if nodeID == "" {
		nodeID = "server-default"
	}
	res, err := h.svc.Encrypt(r.Context(), crypto.EncryptCommand{
		TenantID:       req.TenantID,
		KeyID:          req.KeyID,
		Plaintext:      pt,
		AAD:            aadBytes,
		NodeID:         nodeID,
		PrincipalID:    p.ID,
		EnvelopeFormat: req.EnvelopeFormat,
		Extensions:     req.Extensions,
	})
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeEnvelopeJSON(w, 200, res.Ciphertext)
}

type decryptReq struct {
	TenantID       string `json:"tenant_id"`
	AADB64         string `json:"aad_b64,omitempty"`
	EnvelopeFormat string `json:"envelope_format,omitempty"`
}

type decryptResp struct {
	KeyID      string `json:"key_id"`
	KeyVersion uint32 `json:"key_version"`
	Plaintext  string `json:"plaintext"` // base64
}

type convertEnvelopeReq struct {
	TenantID     string          `json:"tenant_id"`
	Envelope     json.RawMessage `json:"envelope"`
	SourceFormat string          `json:"source_format,omitempty"`
	TargetFormat string          `json:"target_format"`
}

type convertEnvelopeResp struct {
	Envelope       json.RawMessage `json:"envelope"`
	EnvelopeFormat string          `json:"envelope_format"`
}

type inspectEnvelopeReq struct {
	TenantID     string          `json:"tenant_id"`
	Envelope     json.RawMessage `json:"envelope"`
	SourceFormat string          `json:"source_format,omitempty"`
}

func (h *Handler) inspectEnvelope(w http.ResponseWriter, r *http.Request) {
	p := middleware.PrincipalFromContext(r.Context())
	if p == nil {
		writeErr(w, 401, "AUTH_FAILED", "no principal")
		return
	}
	if !p.HasScope("crypto:decrypt") {
		writeErr(w, 403, "PERMISSION_DENIED", "missing scope crypto:decrypt")
		return
	}
	var req inspectEnvelopeReq
	if err := middleware.DecodeJSONStrict(middleware.BodyFromContext(r.Context()), &req); err != nil {
		writeErr(w, 400, "BAD_REQUEST", "invalid json")
		return
	}
	if req.TenantID == "" {
		req.TenantID = p.TenantID
	}
	if p.TenantID != "" && req.TenantID != p.TenantID {
		writeErr(w, 403, "PERMISSION_DENIED", "tenant mismatch")
		return
	}
	if len(req.Envelope) == 0 {
		writeErr(w, 400, "BAD_REQUEST", "envelope is required")
		return
	}
	res, err := h.svc.InspectEnvelope(r.Context(), crypto.InspectEnvelopeCommand{TenantID: req.TenantID, Ciphertext: req.Envelope, SourceFormat: req.SourceFormat})
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, 200, res)
}

func (h *Handler) convertEnvelope(w http.ResponseWriter, r *http.Request) {
	p := middleware.PrincipalFromContext(r.Context())
	if p == nil {
		writeErr(w, 401, "AUTH_FAILED", "no principal")
		return
	}
	if !p.HasScope("crypto:decrypt") {
		writeErr(w, 403, "PERMISSION_DENIED", "missing scope crypto:decrypt")
		return
	}
	var req convertEnvelopeReq
	if err := middleware.DecodeJSONStrict(middleware.BodyFromContext(r.Context()), &req); err != nil {
		writeErr(w, 400, "BAD_REQUEST", "invalid json")
		return
	}
	if req.TenantID == "" {
		req.TenantID = p.TenantID
	}
	if p.TenantID != "" && req.TenantID != p.TenantID {
		writeErr(w, 403, "PERMISSION_DENIED", "tenant mismatch")
		return
	}
	if len(req.Envelope) == 0 {
		writeErr(w, 400, "BAD_REQUEST", "envelope is required")
		return
	}
	res, err := h.svc.ConvertEnvelope(r.Context(), crypto.ConvertEnvelopeCommand{TenantID: req.TenantID, Ciphertext: req.Envelope, SourceFormat: req.SourceFormat, TargetFormat: req.TargetFormat, PrincipalID: p.ID})
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, 200, convertEnvelopeResp{Envelope: res.Ciphertext, EnvelopeFormat: res.EnvelopeFormat})
}

func (h *Handler) decrypt(w http.ResponseWriter, r *http.Request) {
	p := middleware.PrincipalFromContext(r.Context())
	if p == nil {
		writeErr(w, 401, "AUTH_FAILED", "no principal")
		return
	}
	if !p.HasScope("crypto:decrypt") {
		writeErr(w, 403, "PERMISSION_DENIED", "missing scope crypto:decrypt")
		return
	}
	var req decryptReq
	body := middleware.BodyFromContext(r.Context())
	if err := json.Unmarshal(body, &req); err != nil {
		writeErr(w, 400, "BAD_REQUEST", "invalid json")
		return
	}
	if req.TenantID == "" {
		req.TenantID = p.TenantID
	}
	if p.TenantID != "" && req.TenantID != p.TenantID {
		writeErr(w, 403, "PERMISSION_DENIED", "tenant mismatch")
		return
	}
	aadBytes, err := decodeOptionalBase64(req.AADB64)
	if err != nil {
		writeErr(w, 400, "BAD_REQUEST", "aad_b64 not base64")
		return
	}
	res, err := h.svc.Decrypt(r.Context(), crypto.DecryptCommand{
		TenantID:       req.TenantID,
		Ciphertext:     body,
		AAD:            aadBytes,
		PrincipalID:    p.ID,
		EnvelopeFormat: req.EnvelopeFormat,
	})
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, 200, decryptResp{
		KeyID:      res.KeyID,
		KeyVersion: res.KeyVersion,
		Plaintext:  base64.StdEncoding.EncodeToString(res.Plaintext),
	})
}

func writeEnvelopeJSON(w http.ResponseWriter, status int, envelopeJSON []byte) {
	if !json.Valid(envelopeJSON) {
		writeErr(w, 500, "INTERNAL", "internal error")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(envelopeJSON)
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
	code := apperrors.AsCode(err)
	status := apperrors.HTTPStatus(code)
	msg := err.Error()
	if code == apperrors.CodeInternal {
		msg = "internal error"
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	b, _ := json.Marshal(map[string]any{
		"error": map[string]any{
			"code":      string(code),
			"message":   msg,
			"retryable": apperrors.AsRetryable(err),
		},
	})
	w.Write(b)
}

func decodeOptionalBase64(s string) ([]byte, error) {
	if s == "" {
		return nil, nil
	}
	return base64.StdEncoding.DecodeString(s)
}
