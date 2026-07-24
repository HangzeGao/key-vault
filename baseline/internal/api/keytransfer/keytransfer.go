package keytransfer

import (
	"encoding/base64"
	"encoding/json"
	"net/http"

	"github.com/kvlt/key-vault/internal/api/middleware"
	app "github.com/kvlt/key-vault/internal/application/keytransfer"
	"github.com/kvlt/key-vault/internal/errorsx"
)

type Handler struct {
	svc *app.Service
}

func New(svc *app.Service) *Handler { return &Handler{svc: svc} }

func (h *Handler) Routes(mux *http.ServeMux) {
	mux.HandleFunc("POST /ui/api/v1/key-uploads", h.createUpload)
	mux.HandleFunc("GET /ui/api/v1/key-uploads/{upload_id}", h.getUpload)
	mux.HandleFunc("POST /ui/api/v1/key-uploads/{upload_id}/confirm", h.confirmUpload)
	mux.HandleFunc("POST /ui/api/v1/key-downloads", h.importDownload)
	mux.HandleFunc("GET /ui/api/v1/key-downloads/{download_id}", h.getDownload)
}

type createUploadRequest struct {
	TargetID       string `json:"target_id"`
	Sequence       uint64 `json:"sequence"`
	KEKID          string `json:"kek_id"`
	KEKVersion     uint32 `json:"kek_version,omitempty"`
	DataKeyID      string `json:"data_key_id"`
	DataKeyVersion uint32 `json:"data_key_version,omitempty"`
}

func (h *Handler) createUpload(w http.ResponseWriter, r *http.Request) {
	p := middleware.PrincipalFromContext(r.Context())
	if p == nil || p.TenantID == "" {
		writeError(w, errorsx.New(errorsx.CodeAuthFailed, "authenticated tenant is required", false))
		return
	}
	var req createUploadRequest
	if err := middleware.DecodeJSONStrict(middleware.BodyFromContext(r.Context()), &req); err != nil {
		writeError(w, errorsx.New(errorsx.CodeInvalidArgument, "invalid json", false))
		return
	}
	dto, err := h.svc.CreateUpload(r.Context(), app.CreateUploadCommand{
		TenantID: p.TenantID, TargetID: req.TargetID, Sequence: req.Sequence,
		KEKID: req.KEKID, KEKVersion: req.KEKVersion,
		DataKeyID: req.DataKeyID, DataKeyVersion: req.DataKeyVersion,
		PrincipalID: p.ID, IdempotencyKey: r.Header.Get("Idempotency-Key"),
	})
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, dto)
}

func (h *Handler) getUpload(w http.ResponseWriter, r *http.Request) {
	p := middleware.PrincipalFromContext(r.Context())
	if p == nil || p.TenantID == "" {
		writeError(w, errorsx.New(errorsx.CodeAuthFailed, "authenticated tenant is required", false))
		return
	}
	dto, err := h.svc.GetUpload(r.Context(), p.TenantID, r.PathValue("upload_id"))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, dto)
}

func (h *Handler) confirmUpload(w http.ResponseWriter, r *http.Request) {
	p := middleware.PrincipalFromContext(r.Context())
	if p == nil || p.TenantID == "" {
		writeError(w, errorsx.New(errorsx.CodeAuthFailed, "authenticated tenant is required", false))
		return
	}
	dto, err := h.svc.ConfirmUpload(r.Context(), p.TenantID, r.PathValue("upload_id"), p.ID)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, dto)
}

type importDownloadRequest struct {
	DownloadID     string            `json:"download_id"`
	TargetID       string            `json:"target_id"`
	Sequence       uint64            `json:"sequence"`
	KEKID          string            `json:"kek_id"`
	KEKVersion     uint32            `json:"kek_version"`
	DataKeyID      string            `json:"data_key_id"`
	DataKeyVersion uint32            `json:"data_key_version"`
	DataSuiteID    string            `json:"data_suite_id"`
	Name           string            `json:"name,omitempty"`
	PolicyID       string            `json:"policy_id,omitempty"`
	Tags           map[string]string `json:"tags,omitempty"`
	Nonce          string            `json:"nonce"`
	WrappedKey     string            `json:"wrapped_key"`
	Tag            string            `json:"tag"`
	AADB64         string            `json:"aad_b64"`
}

func (h *Handler) importDownload(w http.ResponseWriter, r *http.Request) {
	p := middleware.PrincipalFromContext(r.Context())
	if p == nil || p.TenantID == "" {
		writeError(w, errorsx.New(errorsx.CodeAuthFailed, "authenticated tenant is required", false))
		return
	}
	var req importDownloadRequest
	if err := middleware.DecodeJSONStrict(middleware.BodyFromContext(r.Context()), &req); err != nil {
		writeError(w, errorsx.New(errorsx.CodeInvalidArgument, "invalid json", false))
		return
	}
	nonce, err := base64.StdEncoding.DecodeString(req.Nonce)
	if err != nil {
		writeError(w, errorsx.New(errorsx.CodeInvalidArgument, "nonce is not valid base64", false))
		return
	}
	wrappedKey, err := base64.StdEncoding.DecodeString(req.WrappedKey)
	if err != nil {
		writeError(w, errorsx.New(errorsx.CodeInvalidArgument, "wrapped_key is not valid base64", false))
		return
	}
	tag, err := base64.StdEncoding.DecodeString(req.Tag)
	if err != nil {
		writeError(w, errorsx.New(errorsx.CodeInvalidArgument, "tag is not valid base64", false))
		return
	}
	aad, err := base64.StdEncoding.DecodeString(req.AADB64)
	if err != nil {
		writeError(w, errorsx.New(errorsx.CodeInvalidArgument, "aad_b64 is not valid base64", false))
		return
	}
	dto, err := h.svc.ImportDownload(r.Context(), app.ImportDownloadCommand{
		TenantID: p.TenantID, DownloadID: req.DownloadID, TargetID: req.TargetID,
		Sequence: req.Sequence, KEKID: req.KEKID, KEKVersion: req.KEKVersion,
		DataKeyID: req.DataKeyID, DataKeyVersion: req.DataKeyVersion,
		DataSuiteID: req.DataSuiteID, Name: req.Name, PolicyID: req.PolicyID,
		Tags: req.Tags, Nonce: nonce, WrappedKey: wrappedKey, Tag: tag, AAD: aad,
		PrincipalID: p.ID,
	})
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, dto)
}

func (h *Handler) getDownload(w http.ResponseWriter, r *http.Request) {
	p := middleware.PrincipalFromContext(r.Context())
	if p == nil || p.TenantID == "" {
		writeError(w, errorsx.New(errorsx.CodeAuthFailed, "authenticated tenant is required", false))
		return
	}
	dto, err := h.svc.GetDownload(r.Context(), p.TenantID, r.PathValue("download_id"))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, dto)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, err error) {
	code := errorsx.AsCode(err)
	e, ok := err.(*errorsx.Error)
	message := "request failed"
	retryable := false
	if ok {
		message = e.Message
		retryable = e.Retryable
	}
	writeJSON(w, errorsx.HTTPStatus(code), map[string]any{"error": map[string]any{
		"code": string(code), "message": message, "retryable": retryable,
	}})
}
