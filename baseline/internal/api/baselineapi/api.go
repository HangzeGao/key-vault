// package baselineapi implements the engineering baseline API handlers.
//
// New endpoints:
//   - GET  /v1/audit/events
//   - GET  /v1/audit/chain/verify
//   - GET  /v1/audit/chain/heads
//   - POST /v1/policies:reload
//   - GET  /v1/policies/signed
//   - GET  /v1/lifecycle/jobs
//   - GET  /v1/lifecycle/outbox
//   - POST /v1/crypto/encrypt-batch
//   - POST /v1/crypto/decrypt-batch
package baselineapi

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/kvlt/key-vault/internal/api/middleware"
	"github.com/kvlt/key-vault/internal/application/crypto"
	"github.com/kvlt/key-vault/internal/auditchain"
	"github.com/kvlt/key-vault/internal/config"
	"github.com/kvlt/key-vault/internal/errorsx"
	"github.com/kvlt/key-vault/internal/lifecycle"
	"github.com/kvlt/key-vault/internal/policysig"
	"github.com/kvlt/key-vault/internal/repository"
	"github.com/kvlt/key-vault/internal/repository/models"
	"github.com/kvlt/key-vault/internal/resolver/keyresolver"
)

// Handler bundles all baseline API handlers.
type Handler struct {
	auditChain *auditchain.Service
	policyMgr  *policysig.Manager
	worker     *lifecycle.Worker
	cryptoSvc  *crypto.Service
	resolver   *keyresolver.Resolver
	store      repository.Repository
	cfg        *config.Config
	startTime  time.Time
}

// New constructs a baseline handler.
func New(ac *auditchain.Service, pm *policysig.Manager, w *lifecycle.Worker, cs *crypto.Service, resolver *keyresolver.Resolver, store repository.Repository, cfg *config.Config) *Handler {
	return &Handler{
		auditChain: ac,
		policyMgr:  pm,
		worker:     w,
		cryptoSvc:  cs,
		resolver:   resolver,
		store:      store,
		cfg:        cfg,
		startTime:  time.Now(),
	}
}

// Routes registers the baseline routes.
func (h *Handler) Routes(mux *http.ServeMux) {
	// System status
	mux.HandleFunc("GET /ui/api/v1/status", h.systemStatus)

	// Audit chain
	mux.HandleFunc("GET /ui/api/v1/audit/events", h.listAuditEvents)
	mux.HandleFunc("DELETE /ui/api/v1/audit/events", h.deleteAuditEvents)
	mux.HandleFunc("GET /ui/api/v1/audit/chain/verify", h.verifyChain)
	mux.HandleFunc("GET /ui/api/v1/audit/chain/heads", h.listChainHeads)

	// Policy
	mux.HandleFunc("POST /ui/api/v1/policies:reload", h.reloadPolicy)
	mux.HandleFunc("GET /ui/api/v1/policies/signed", h.getSignedPolicy)

	// Lifecycle
	mux.HandleFunc("GET /ui/api/v1/lifecycle/jobs", h.listJobs)
	mux.HandleFunc("GET /ui/api/v1/lifecycle/outbox", h.listOutbox)
	mux.HandleFunc("GET /ui/api/v1/lifecycle/config", h.lifecycleConfig)

	// Ops plane routes are registered by the dedicated ops handler.

	// Batch crypto
	mux.HandleFunc("POST /ui/api/v1/crypto/encrypt-batch", h.encryptBatch)
	mux.HandleFunc("POST /ui/api/v1/crypto/decrypt-batch", h.decryptBatch)
}

// --- Audit chain ---

func (h *Handler) listAuditEvents(w http.ResponseWriter, r *http.Request) {
	if !requireAnyScope(w, r, "audit:read", "audit:manage", "tenant:read", "tenant:manage") {
		return
	}
	chain := r.URL.Query().Get("chain")
	limit := clampLimit(parseIntDefault(r.URL.Query().Get("limit"), 100), 200)
	offset := max(parseIntDefault(r.URL.Query().Get("cursor"), 0), 0)
	events, err := h.auditChain.ListEvents(r.Context(), chain, 1000)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	q := r.URL.Query()
	from, _ := time.Parse(time.RFC3339, q.Get("from"))
	to, _ := time.Parse(time.RFC3339, q.Get("to"))
	filtered := events[:0]
	for _, event := range events {
		if !containsFold(event.Action, q.Get("action")) || !containsFold(event.Result, q.Get("result")) || !containsFold(event.ActorHash, q.Get("actor")) || !containsFold(event.TargetIDHash, q.Get("target")) {
			continue
		}
		if !from.IsZero() && event.Timestamp.Before(from) {
			continue
		}
		if !to.IsZero() && event.Timestamp.After(to) {
			continue
		}
		filtered = append(filtered, event)
	}
	page, next := pageSlice(filtered, offset, limit)
	writeJSON(w, 200, map[string]any{"events": page, "next_cursor": next, "total": len(filtered)})
}

func (h *Handler) deleteAuditEvents(w http.ResponseWriter, r *http.Request) {
	p := middleware.PrincipalFromContext(r.Context())
	if p == nil {
		writeErr(w, 401, "AUTH_FAILED", "no principal")
		return
	}
	if !p.HasScope("tenant:manage") && !p.HasScope("audit:manage") {
		writeErr(w, 403, "PERMISSION_DENIED", "missing scope audit:manage")
		return
	}
	chain := r.URL.Query().Get("chain")
	n, err := h.auditChain.DeleteEvents(r.Context(), chain)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"deleted": n, "chain": chain})
}

func (h *Handler) verifyChain(w http.ResponseWriter, r *http.Request) {
	if !requireAnyScope(w, r, "audit:read", "audit:manage", "tenant:read", "tenant:manage") {
		return
	}
	chain := r.URL.Query().Get("chain")
	if chain == "" {
		results, err := h.auditChain.VerifyAllChains(r.Context())
		if err != nil {
			writeServiceError(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"results": results})
		return
	}
	result, err := h.auditChain.VerifyChain(r.Context(), chain)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, 200, result)
}

func (h *Handler) listChainHeads(w http.ResponseWriter, r *http.Request) {
	if !requireAnyScope(w, r, "audit:read", "audit:manage", "tenant:read", "tenant:manage") {
		return
	}
	heads, err := h.auditChain.ListChainHeads(r.Context())
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"heads": heads})
}

// --- Policy ---

func (h *Handler) reloadPolicy(w http.ResponseWriter, r *http.Request) {
	p := middleware.PrincipalFromContext(r.Context())
	if p == nil {
		writeErr(w, 401, "AUTH_FAILED", "no principal")
		return
	}
	if !p.HasScope("policy:manage") && !p.HasScope("tenant:manage") {
		writeErr(w, 403, "PERMISSION_DENIED", "missing scope policy:manage")
		return
	}
	if err := h.policyMgr.Reload(r.Context()); err != nil {
		writeErr(w, 400, "POLICY_DENIED", err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"status": "reloaded"})
}

func (h *Handler) getSignedPolicy(w http.ResponseWriter, r *http.Request) {
	if !requireAnyScope(w, r, "policy:read", "policy:manage", "tenant:read", "tenant:manage") {
		return
	}
	sp := h.policyMgr.Current()
	if sp == nil {
		writeErr(w, 404, "NOT_FOUND", "no signed policy loaded")
		return
	}
	writeJSON(w, 200, sp)
}

// --- Lifecycle ---

func (h *Handler) listJobs(w http.ResponseWriter, r *http.Request) {
	if !requireAnyScope(w, r, "tenant:read", "tenant:manage") {
		return
	}
	status := r.URL.Query().Get("status")
	limit := clampLimit(parseIntDefault(r.URL.Query().Get("limit"), 50), 200)
	offset := max(parseIntDefault(r.URL.Query().Get("cursor"), 0), 0)
	jobs, err := h.worker.ListJobs(r.Context(), status, min(1000, offset+limit+1))
	if err != nil {
		writeServiceError(w, err)
		return
	}
	page, next := pageSlice(jobs, offset, limit)
	writeJSON(w, 200, map[string]any{"jobs": page, "next_cursor": next})
}

func (h *Handler) listOutbox(w http.ResponseWriter, r *http.Request) {
	if !requireAnyScope(w, r, "tenant:read", "tenant:manage") {
		return
	}
	status := r.URL.Query().Get("status")
	limit := clampLimit(parseIntDefault(r.URL.Query().Get("limit"), 50), 200)
	offset := max(parseIntDefault(r.URL.Query().Get("cursor"), 0), 0)
	events, err := h.worker.ListOutbox(r.Context(), status, min(1000, offset+limit+1))
	if err != nil {
		writeServiceError(w, err)
		return
	}
	page, next := pageSlice(events, offset, limit)
	writeJSON(w, 200, map[string]any{"events": page, "next_cursor": next})
}

func (h *Handler) lifecycleConfig(w http.ResponseWriter, r *http.Request) {
	if !requireAnyScope(w, r, "tenant:read", "tenant:manage") {
		return
	}
	writeJSON(w, 200, h.worker.Config())
}

// --- Batch crypto ---

type batchEntry struct {
	KeyID     string `json:"key_id"`
	Plaintext string `json:"plaintext"`
	AADB64    string `json:"aad_b64,omitempty"`
	NodeID    string `json:"node_id,omitempty"`
}

type batchEncryptReq struct {
	TenantID string       `json:"tenant_id"`
	Entries  []batchEntry `json:"entries"`
}

type batchResult struct {
	Index      int             `json:"index"`
	Success    bool            `json:"success"`
	ErrorCode  string          `json:"error_code,omitempty"`
	Message    string          `json:"message,omitempty"`
	KeyID      string          `json:"key_id,omitempty"`
	KeyVersion uint32          `json:"key_version,omitempty"`
	SuiteID    string          `json:"suite_id,omitempty"`
	Envelope   json.RawMessage `json:"envelope,omitempty"`
	Plaintext  string          `json:"plaintext,omitempty"`
}

type batchResp struct {
	Results []batchResult `json:"results"`
	Summary batchSummary  `json:"summary"`
}

type batchSummary struct {
	Total        int     `json:"total"`
	Succeeded    int     `json:"succeeded"`
	Failed       int     `json:"failed"`
	FailureRatio float64 `json:"failure_ratio"`
}

func summarizeBatch(results []batchResult) batchSummary {
	s := batchSummary{Total: len(results)}
	for _, result := range results {
		if result.Success {
			s.Succeeded++
		} else {
			s.Failed++
		}
	}
	if s.Total > 0 {
		s.FailureRatio = float64(s.Failed) / float64(s.Total)
	}
	return s
}

func (h *Handler) encryptBatch(w http.ResponseWriter, r *http.Request) {
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
	var req batchEncryptReq
	if err := middleware.DecodeJSONStrict(body, &req); err != nil {
		writeErr(w, 400, "BAD_REQUEST", "invalid json")
		return
	}
	if len(req.Entries) == 0 {
		writeErr(w, 400, "BAD_REQUEST", "no entries")
		return
	}
	if len(req.Entries) > 100 {
		writeErr(w, 400, "BAD_REQUEST", "batch exceeds 100 entries")
		return
	}
	if req.TenantID == "" {
		req.TenantID = p.TenantID
	}
	if p.TenantID != "" && req.TenantID != p.TenantID {
		writeErr(w, 403, "PERMISSION_DENIED", "tenant mismatch")
		return
	}
	results := make([]batchResult, len(req.Entries))
	for i, e := range req.Entries {
		pt, err := base64.StdEncoding.DecodeString(e.Plaintext)
		if err != nil {
			results[i] = batchResult{Index: i, Success: false, ErrorCode: "BAD_REQUEST", Message: "plaintext not base64"}
			continue
		}
		aadBytes, err := decodeOptionalBase64(e.AADB64)
		if err != nil {
			results[i] = batchResult{Index: i, Success: false, ErrorCode: "BAD_REQUEST", Message: "aad_b64 not base64"}
			continue
		}
		nodeID := e.NodeID
		if nodeID == "" {
			nodeID = p.NodeID
		}
		if nodeID == "" {
			nodeID = "server-default"
		}
		res, err := h.cryptoSvc.Encrypt(r.Context(), crypto.EncryptCommand{
			TenantID:    req.TenantID,
			KeyID:       e.KeyID,
			Plaintext:   pt,
			AAD:         aadBytes,
			NodeID:      nodeID,
			PrincipalID: p.ID,
		})
		if err != nil {
			results[i] = batchResult{Index: i, Success: false, ErrorCode: string(errorsx.AsCode(err)), Message: "encryption failed"}
			continue
		}
		results[i] = batchResult{
			Index: i, Success: true,
			KeyID: res.KeyID, KeyVersion: res.KeyVersion, SuiteID: res.SuiteID,
			Envelope: res.Ciphertext,
		}
	}
	writeJSON(w, 200, batchResp{Results: results, Summary: summarizeBatch(results)})
}

type batchDecryptEntry struct {
	Envelope json.RawMessage `json:"envelope"`
	AADB64   string          `json:"aad_b64,omitempty"`
}

type batchDecryptReq struct {
	TenantID string              `json:"tenant_id"`
	Entries  []batchDecryptEntry `json:"entries"`
}

func (h *Handler) decryptBatch(w http.ResponseWriter, r *http.Request) {
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
	var req batchDecryptReq
	if err := middleware.DecodeJSONStrict(body, &req); err != nil {
		writeErr(w, 400, "BAD_REQUEST", "invalid json")
		return
	}
	if len(req.Entries) == 0 {
		writeErr(w, 400, "BAD_REQUEST", "no entries")
		return
	}
	if len(req.Entries) > 100 {
		writeErr(w, 400, "BAD_REQUEST", "batch exceeds 100 entries")
		return
	}
	if req.TenantID == "" {
		req.TenantID = p.TenantID
	}
	if p.TenantID != "" && req.TenantID != p.TenantID {
		writeErr(w, 403, "PERMISSION_DENIED", "tenant mismatch")
		return
	}
	results := make([]batchResult, len(req.Entries))
	for i, e := range req.Entries {
		if len(e.Envelope) == 0 {
			results[i] = batchResult{Index: i, Success: false, ErrorCode: "BAD_REQUEST", Message: "envelope is required"}
			continue
		}
		aadBytes, err := decodeOptionalBase64(e.AADB64)
		if err != nil {
			results[i] = batchResult{Index: i, Success: false, ErrorCode: "BAD_REQUEST", Message: "aad_b64 not base64"}
			continue
		}
		res, err := h.cryptoSvc.Decrypt(r.Context(), crypto.DecryptCommand{
			TenantID:    req.TenantID,
			Ciphertext:  e.Envelope,
			AAD:         aadBytes,
			PrincipalID: p.ID,
		})
		if err != nil {
			results[i] = batchResult{Index: i, Success: false, ErrorCode: string(errorsx.AsCode(err)), Message: "decryption failed"}
			continue
		}
		results[i] = batchResult{
			Index: i, Success: true,
			KeyID: res.KeyID, KeyVersion: res.KeyVersion,
			Plaintext: base64.StdEncoding.EncodeToString(res.Plaintext),
		}
	}
	writeJSON(w, 200, batchResp{Results: results, Summary: summarizeBatch(results)})
}

// --- System Status ---

func (h *Handler) systemStatus(w http.ResponseWriter, r *http.Request) {
	if !requireAnyScope(w, r, "tenant:read", "tenant:manage") {
		return
	}
	ctx := r.Context()
	p := middleware.PrincipalFromContext(ctx)
	tenantID := ""
	if p != nil {
		tenantID = p.TenantID
	}
	status := map[string]any{}

	// Database / storage.
	dbPingErr := h.store.Ping(ctx)
	dbInfo := map[string]any{
		"driver":    h.cfg.Database.Driver,
		"connected": dbPingErr == nil,
	}
	if dbPingErr != nil {
		dbInfo["error"] = "DATABASE_UNREACHABLE"
	}
	status["database"] = dbInfo

	// Server info.
	status["server"] = map[string]any{
		"listen_addr":     h.cfg.Server.HTTPListenAddr,
		"tpm_provider":    h.cfg.TPM.Provider,
		"plane_isolation": h.cfg.Server.PlaneIsolationMode,
		"uptime_seconds":  int(time.Since(h.startTime).Seconds()),
	}

	// Cluster state.
	epoch, epochErr := h.store.ClusterEpoch(ctx)
	clusterInfo := map[string]any{
		"cluster_epoch": epoch,
	}
	if epochErr != nil {
		clusterInfo["error"] = "CLUSTER_STATE_UNAVAILABLE"
	}

	// CRK info.
	if crk, err := h.store.GetLatestCRKVersion(ctx); err == nil {
		clusterInfo["crk"] = map[string]any{
			"version": crk.Version,
			"epoch":   crk.Epoch,
			"status":  crk.Status,
			"created": crk.CreatedAt,
		}
	}
	status["cluster"] = clusterInfo

	// Key statistics are tenant-scoped for tenant principals. Only an explicitly
	// global principal receives global inventory.
	keyStats := map[string]any{
		"total":           0,
		"active":          0,
		"disabled":        0,
		"destroy_pending": 0,
		"destroyed":       0,
	}
	var keys []*models.Key
	var keysErr error
	if tenantID != "" {
		keys, keysErr = h.store.ListKeys(ctx, tenantID)
	} else {
		keys, keysErr = h.store.ListAllKeys(ctx)
	}
	if keysErr == nil {
		counts := map[string]int{}
		for _, k := range keys {
			counts[k.Status]++
		}
		keyStats["total"] = len(keys)
		keyStats["active"] = counts["ACTIVE"]
		keyStats["disabled"] = counts["DISABLED"]
		keyStats["destroy_pending"] = counts["DESTROY_PENDING"]
		keyStats["destroyed"] = counts["DESTROYED"]
	}
	status["keys"] = keyStats
	status["keys_scope"] = map[string]any{"scope": map[bool]string{true: "tenant", false: "global"}[tenantID != ""], "tenant_id": tenantID}

	// Audit chain heads.
	if heads, err := h.store.ListAuditChainHeads(ctx); err == nil {
		chains := make([]map[string]any, 0, len(heads))
		for _, ch := range heads {
			if tenantID != "" && ch.ChainName != "tenant:"+tenantID {
				continue
			}
			chains = append(chains, map[string]any{
				"chain":     ch.ChainName,
				"sequence":  ch.Sequence,
				"head_hash": ch.HeadHash,
				"updated":   ch.UpdatedAt,
			})
		}
		status["audit_chains"] = chains
	}

	// Lifecycle job counts.
	if jobs, err := h.store.ListLifecycleJobs(ctx, "", 1000); err == nil {
		counts := map[string]int{}
		for _, j := range jobs {
			if tenantID != "" && j.TenantID != tenantID {
				continue
			}
			counts[j.Status]++
		}
		status["lifecycle"] = map[string]any{
			"pending": counts["PENDING"],
			"running": counts["RUNNING"],
			"done":    counts["DONE"],
			"failed":  counts["FAILED"],
		}
	}

	// Nodes.
	if nodes, err := h.store.ListAllNodes(ctx); err == nil {
		nodeList := make([]map[string]any, 0, len(nodes))
		for _, n := range nodes {
			nodeList = append(nodeList, map[string]any{
				"node_id":           n.NodeID,
				"role":              n.Role,
				"status":            n.Status,
				"cluster_epoch":     n.ClusterEpoch,
				"attestation_epoch": n.AttestationEpoch,
			})
		}
		status["nodes"] = nodeList
	}

	writeJSON(w, 200, status)
}

// --- helpers ---

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
		"error": map[string]any{"code": code, "message": msg},
	})
	w.Write(b)
}

func writeServiceError(w http.ResponseWriter, err error) {
	code := errorsx.AsCode(err)
	status := errorsx.HTTPStatus(code)
	msg := errorsx.AsMessage(err)
	if msg == "" || code == errorsx.CodeInternal {
		msg = "internal error"
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

func requireAnyScope(w http.ResponseWriter, r *http.Request, scopes ...string) bool {
	p := middleware.PrincipalFromContext(r.Context())
	if p == nil {
		writeErr(w, 401, "AUTH_FAILED", "no principal")
		return false
	}
	if !p.HasAnyScope(scopes...) {
		writeErr(w, 403, "PERMISSION_DENIED", "missing required scope")
		return false
	}
	return true
}

func parseIntDefault(s string, def int) int {
	if s == "" {
		return def
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return v
}

func clampLimit(value, maximum int) int {
	if value <= 0 {
		return 1
	}
	if value > maximum {
		return maximum
	}
	return value
}
func containsFold(value, filter string) bool {
	return filter == "" || strings.Contains(strings.ToLower(value), strings.ToLower(filter))
}
func pageSlice[T any](values []T, offset, limit int) ([]T, string) {
	if offset >= len(values) {
		return []T{}, ""
	}
	end := min(offset+limit, len(values))
	next := ""
	if end < len(values) {
		next = strconv.Itoa(end)
	}
	return values[offset:end], next
}

func decodeOptionalBase64(s string) ([]byte, error) {
	if s == "" {
		return nil, nil
	}
	return base64.StdEncoding.DecodeString(s)
}

// time import guard
var _ = time.Now
