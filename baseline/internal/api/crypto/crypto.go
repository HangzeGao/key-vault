// Package crypto implements the Crypto API per design §12.3.
package crypto

import (
	"encoding/base64"
	"encoding/json"
	"net/http"

	"github.com/kvlt/key-vault/internal/api/middleware"
	"github.com/kvlt/key-vault/internal/application/crypto"
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
	mux.HandleFunc("POST /ui/api/v1/crypto/envelopes:convert", h.convertEnvelope)
	mux.HandleFunc("POST /ui/api/v1/crypto/envelopes:inspect", h.inspectEnvelope)
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

type encryptResp struct {
	KeyID          string `json:"key_id"`
	KeyVersion     uint32 `json:"key_version"`
	SuiteID        string `json:"suite_id"`
	Ciphertext     string `json:"ciphertext"` // base64 envelope
	EnvelopeFormat string `json:"envelope_format"`
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
	writeJSON(w, 200, encryptResp{
		KeyID:          res.KeyID,
		KeyVersion:     res.KeyVersion,
		SuiteID:        res.SuiteID,
		Ciphertext:     base64.StdEncoding.EncodeToString(res.Ciphertext),
		EnvelopeFormat: res.EnvelopeFormat,
	})
}

type decryptReq struct {
	TenantID       string `json:"tenant_id"`
	Ciphertext     string `json:"ciphertext"` // base64 envelope
	AADB64         string `json:"aad_b64,omitempty"`
	EnvelopeFormat string `json:"envelope_format,omitempty"`
}

type decryptResp struct {
	KeyID      string `json:"key_id"`
	KeyVersion uint32 `json:"key_version"`
	Plaintext  string `json:"plaintext"` // base64
}

type convertEnvelopeReq struct {
	TenantID     string `json:"tenant_id"`
	Ciphertext   string `json:"ciphertext"`
	SourceFormat string `json:"source_format,omitempty"`
	TargetFormat string `json:"target_format"`
}

type convertEnvelopeResp struct {
	Ciphertext     string `json:"ciphertext"`
	EnvelopeFormat string `json:"envelope_format"`
}

type inspectEnvelopeReq struct {
	TenantID     string `json:"tenant_id"`
	Ciphertext   string `json:"ciphertext"`
	SourceFormat string `json:"source_format,omitempty"`
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
	if p.TenantID != "" && req.TenantID != p.TenantID {
		writeErr(w, 403, "PERMISSION_DENIED", "tenant mismatch")
		return
	}
	ct, err := base64.StdEncoding.DecodeString(req.Ciphertext)
	if err != nil {
		writeErr(w, 400, "BAD_REQUEST", "ciphertext not base64")
		return
	}
	res, err := h.svc.InspectEnvelope(r.Context(), crypto.InspectEnvelopeCommand{TenantID: req.TenantID, Ciphertext: ct, SourceFormat: req.SourceFormat})
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
	if p.TenantID != "" && req.TenantID != p.TenantID {
		writeErr(w, 403, "PERMISSION_DENIED", "tenant mismatch")
		return
	}
	ct, err := base64.StdEncoding.DecodeString(req.Ciphertext)
	if err != nil {
		writeErr(w, 400, "BAD_REQUEST", "ciphertext not base64")
		return
	}
	res, err := h.svc.ConvertEnvelope(r.Context(), crypto.ConvertEnvelopeCommand{TenantID: req.TenantID, Ciphertext: ct, SourceFormat: req.SourceFormat, TargetFormat: req.TargetFormat, PrincipalID: p.ID})
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, 200, convertEnvelopeResp{Ciphertext: base64.StdEncoding.EncodeToString(res.Ciphertext), EnvelopeFormat: res.EnvelopeFormat})
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
	body := middleware.BodyFromContext(r.Context())
	var req decryptReq
	if err := middleware.DecodeJSONStrict(body, &req); err != nil {
		writeErr(w, 400, "BAD_REQUEST", "invalid json")
		return
	}
	if p.TenantID != "" && req.TenantID != p.TenantID {
		writeErr(w, 403, "PERMISSION_DENIED", "tenant mismatch")
		return
	}
	ct, err := base64.StdEncoding.DecodeString(req.Ciphertext)
	if err != nil {
		writeErr(w, 400, "BAD_REQUEST", "ciphertext not base64")
		return
	}
	aadBytes, err := decodeOptionalBase64(req.AADB64)
	if err != nil {
		writeErr(w, 400, "BAD_REQUEST", "aad_b64 not base64")
		return
	}
	res, err := h.svc.Decrypt(r.Context(), crypto.DecryptCommand{
		TenantID:       req.TenantID,
		Ciphertext:     ct,
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
