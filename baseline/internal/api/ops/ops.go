// Package ops implements the operations plane API per design §4 and §4.1.
//
// Ops Plane provides controlled operational capabilities with audit-first
// execution and redacted responses. It is an independent control plane,
// separate from management and data planes.
package ops

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/kvlt/key-vault/internal/api/middleware"
	"github.com/kvlt/key-vault/internal/auditchain"
	"github.com/kvlt/key-vault/internal/auth/principal"
	"github.com/kvlt/key-vault/internal/config"
	"github.com/kvlt/key-vault/internal/crypto/aad"
	"github.com/kvlt/key-vault/internal/errorsx"
	"github.com/kvlt/key-vault/internal/lifecycle"
	"github.com/kvlt/key-vault/internal/policysig"
	"github.com/kvlt/key-vault/internal/repository"
	"github.com/kvlt/key-vault/internal/repository/models"
	"github.com/kvlt/key-vault/internal/resolver/keyresolver"
	"github.com/kvlt/key-vault/internal/tpm/provider"
)

// Handler is the ops plane HTTP handler.
type Handler struct {
	store      repository.Repository
	resolver   *keyresolver.Resolver
	auditChain auditRecorder
	policyMgr  *policysig.Manager
	worker     *lifecycle.Worker
	cfg        *config.Config
	startTime  time.Time
}

type auditRecorder interface {
	Record(context.Context, auditchain.RecordRequest) error
}

// Deps bundles the ops handler dependencies.
type Deps struct {
	Store      repository.Repository
	Resolver   *keyresolver.Resolver
	AuditChain auditRecorder
	PolicyMgr  *policysig.Manager
	Worker     *lifecycle.Worker
	Cfg        *config.Config
}

// New constructs an ops handler.
func New(deps Deps) *Handler {
	return &Handler{
		store:      deps.Store,
		resolver:   deps.Resolver,
		auditChain: deps.AuditChain,
		policyMgr:  deps.PolicyMgr,
		worker:     deps.Worker,
		cfg:        deps.Cfg,
		startTime:  time.Now(),
	}
}

// Routes registers the ops routes.
func (h *Handler) Routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /ui/api/v1/ops/health", h.getHealth)
	mux.HandleFunc("GET /ui/api/v1/ops/db/status", h.getDBStatus)
	mux.HandleFunc("GET /ui/api/v1/ops/crk/envelope", h.getCRKEnvelope)
	mux.HandleFunc("POST /ui/api/v1/ops/crk/envelope:repair-aad-digest", h.repairCRKEnvelopeAADDigest)
	mux.HandleFunc("POST /ui/api/v1/ops/resolver:refresh", h.refreshResolver)
	mux.HandleFunc("POST /ui/api/v1/ops/lifecycle/jobs/{id}/retry", h.retryLifecycleJob)
	mux.HandleFunc("POST /ui/api/v1/ops/outbox/{id}/replay", h.replayOutboxEvent)
	// Break-glass is a separate, explicitly named flow. It exposes only the
	// same reviewed actions and never accepts SQL, shell, export, or purge.
	mux.HandleFunc("POST /ui/api/v1/ops/breakglass/crk/envelope:repair-aad-digest", h.repairCRKEnvelopeAADDigest)
	mux.HandleFunc("POST /ui/api/v1/ops/breakglass/resolver:refresh", h.refreshResolver)
	mux.HandleFunc("POST /ui/api/v1/ops/breakglass/lifecycle/jobs/{id}/retry", h.retryLifecycleJob)
	mux.HandleFunc("POST /ui/api/v1/ops/breakglass/outbox/{id}/replay", h.replayOutboxEvent)
}

type actionRequest struct {
	Reason               string `json:"reason"`
	TicketID             string `json:"ticket_id"`
	ImpactScope          string `json:"impact_scope,omitempty"`
	OperatorConfirmation bool   `json:"operator_confirmation,omitempty"`
}

type actionGuard struct {
	request     actionRequest
	principal   *principal.Principal
	idempotency string
	action      string
	targetID    string
	breakglass  bool
}

func (h *Handler) beginAction(w http.ResponseWriter, r *http.Request, action, targetID string, preflight map[string]string) (*actionGuard, bool) {
	p := middleware.PrincipalFromContext(r.Context())
	breakglass := strings.HasPrefix(r.URL.Path, "/ui/api/v1/ops/breakglass/")
	requiredScope := "ops:repair"
	if breakglass {
		requiredScope = "ops:breakglass"
	}
	if !requireAnyScope(w, r, requiredScope) {
		return nil, false
	}
	var req actionRequest
	if err := middleware.DecodeJSONStrict(middleware.BodyFromContext(r.Context()), &req); err != nil {
		writeErr(w, 400, "BAD_REQUEST", "invalid action request")
		return nil, false
	}
	req.Reason = strings.TrimSpace(req.Reason)
	req.TicketID = strings.TrimSpace(req.TicketID)
	if req.Reason == "" || len(req.Reason) > 500 {
		writeErr(w, 400, "OPS_REASON_REQUIRED", "reason is required and must not exceed 500 characters")
		return nil, false
	}
	if req.TicketID == "" || len(req.TicketID) > 128 {
		writeErr(w, 400, "OPS_TICKET_REQUIRED", "ticket_id is required and must not exceed 128 characters")
		return nil, false
	}
	idempotency := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if idempotency == "" || len(idempotency) > 128 {
		writeErr(w, 400, "IDEMPOTENCY_KEY_REQUIRED", "Idempotency-Key is required and must not exceed 128 characters")
		return nil, false
	}
	if breakglass && (strings.TrimSpace(req.ImpactScope) == "" || !req.OperatorConfirmation) {
		writeErr(w, 400, "BREAKGLASS_CONFIRMATION_REQUIRED", "impact_scope and operator_confirmation are required")
		return nil, false
	}
	requestHash := sha256.Sum256(middleware.BodyFromContext(r.Context()))
	if previous, err := h.store.GetIdempotency(r.Context(), idempotency); err == nil {
		if previous.PrincipalID != p.ID || previous.Method != r.Method || previous.Path != r.URL.Path || previous.RequestHash != hex.EncodeToString(requestHash[:]) {
			writeErr(w, 409, "IDEMPOTENCY_CONFLICT", "Idempotency-Key was used for a different request")
			return nil, false
		}
		writeJSON(w, 200, map[string]any{"status": "already_processed", "idempotency_key": idempotency})
		return nil, false
	}
	metadata := map[string]string{
		"reason": req.Reason, "ticket_id": req.TicketID,
		"idempotency_key_hash": hashTruncate(idempotency),
		"flow":                 map[bool]string{true: "breakglass", false: "repair"}[breakglass],
	}
	for key, value := range preflight {
		metadata["preflight_"+key] = value
	}
	if breakglass {
		metadata["impact_scope"] = req.ImpactScope
		metadata["operator_confirmed"] = "true"
	}
	if err := h.auditHighRisk(r, p, action, targetID, metadata); err != nil {
		writeErr(w, 503, "AUDIT_UNAVAILABLE", "audit unavailable; action was not executed")
		return nil, false
	}
	if err := h.store.RecordIdempotency(r.Context(), &models.IdempotencyKey{
		Key: idempotency, PrincipalID: p.ID, Method: r.Method, Path: r.URL.Path,
		RequestHash: hex.EncodeToString(requestHash[:]), CreatedAt: time.Now().UTC(),
	}); err != nil {
		// Complete the audit pair with an aborted final entry before returning,
		// so the audit chain always has requested → final pairing per design §4.
		_ = h.auditHighRiskResult(r, p, action, targetID, "aborted", map[string]string{
			"ticket_id": req.TicketID, "idempotency_key_hash": hashTruncate(idempotency),
			"abort_reason": "idempotency_conflict",
		})
		writeErr(w, 409, "IDEMPOTENCY_CONFLICT", "unable to reserve Idempotency-Key")
		return nil, false
	}
	return &actionGuard{request: req, principal: p, idempotency: idempotency, action: action, targetID: targetID, breakglass: breakglass}, true
}

func (h *Handler) finishAction(w http.ResponseWriter, r *http.Request, guard *actionGuard, result string, response map[string]any) bool {
	if err := h.auditHighRiskResult(r, guard.principal, guard.action, guard.targetID, result, map[string]string{
		"ticket_id": guard.request.TicketID, "idempotency_key_hash": hashTruncate(guard.idempotency),
	}); err != nil {
		writeErr(w, 503, "AUDIT_UNAVAILABLE", "final audit unavailable; action result withheld")
		return false
	}
	response["preflight"] = map[string]any{"target": guard.targetID, "flow": map[bool]string{true: "breakglass", false: "repair"}[guard.breakglass]}
	response["ticket_id"] = guard.request.TicketID
	writeJSON(w, 200, response)
	return true
}

// --- Health ---

type healthStatus struct {
	Status  string `json:"status"` // ok | warn | degraded
	Summary string `json:"summary"`
	Error   string `json:"error,omitempty"`
	Detail  any    `json:"detail,omitempty"`
}

type healthResponse struct {
	Overall string                  `json:"overall"`
	Uptime  int                     `json:"uptime_seconds"`
	Checks  map[string]healthStatus `json:"checks"`
}

func (h *Handler) getHealth(w http.ResponseWriter, r *http.Request) {
	if !requireAnyScope(w, r, "ops:read", "ops:repair", "ops:breakglass") {
		return
	}
	ctx := r.Context()
	checks := make(map[string]healthStatus)
	overall := "ok"

	// TPM provider.
	tpmStatus := "ok"
	tpmMode := "native hardware boundary"
	tpmReason := "native TSS/ESAPI provider is configured"
	if h.cfg.TPM.Provider == "tpm2-tools" || h.cfg.TPM.Provider == "tpm2" || h.cfg.TPM.Provider == "hardware" || h.cfg.TPM.Provider == "software" || h.cfg.TPM.Provider == "swtpm" {
		tpmStatus = "warn"
		tpmMode = "engineering fallback"
		tpmReason = "configured provider is an engineering fallback; production requires native, tss, or esapi"
	}
	tpmSummary := h.cfg.TPM.Provider + " · initialized"
	if tpmStatus == "warn" {
		tpmSummary += " · fallback"
	}
	checks["tpm"] = healthStatus{Status: tpmStatus, Summary: tpmSummary, Detail: map[string]any{
		"provider":          h.cfg.TPM.Provider,
		"runtime_state":     "initialized_at_boot",
		"security_boundary": tpmMode,
		"status_reason":     tpmReason,
		"pcrs":              h.cfg.TPM.PolicyPCRs,
		"transport":         map[bool]string{true: "configured", false: "provider default"}[h.cfg.TPM.TCTI != ""],
	}}
	if tpmStatus == "degraded" {
		overall = "degraded"
	} else if tpmStatus == "warn" && overall == "ok" {
		overall = "warn"
	}

	// Resolver.
	resolverStatus := "ok"
	resolverSummary := "crk cached"
	if h.resolver == nil || h.resolver.CRKVersion() == 0 {
		resolverStatus = "degraded"
		resolverSummary = "no CRK envelope loaded"
	}
	resolverVersion := uint32(0)
	if h.resolver != nil {
		resolverVersion = h.resolver.CRKVersion()
	}
	checks["resolver"] = healthStatus{Status: resolverStatus, Summary: resolverSummary, Detail: map[string]any{
		"crk_cached":  resolverVersion > 0,
		"crk_version": resolverVersion,
		"lease_scope": "short_ttl_in_memory_only",
	}}
	if resolverStatus == "degraded" {
		overall = "degraded"
	}

	// Database.
	dbStatus := "ok"
	dbSummary := h.cfg.Database.Driver
	dbDetail := map[string]any{
		"driver":     h.cfg.Database.Driver,
		"durability": map[bool]string{true: "durable", false: "volatile"}[h.cfg.Database.Driver != "memory"],
		"connection": "reachable",
	}
	if dbErr := h.store.Ping(ctx); dbErr != nil {
		dbStatus = "degraded"
		dbSummary = "ping failed"
		dbDetail["connection"] = "unreachable"
		checks["db"] = healthStatus{Status: dbStatus, Summary: dbSummary, Error: dbErr.Error(), Detail: dbDetail}
		overall = "degraded"
	} else {
		if h.cfg.Database.Driver == "memory" {
			dbStatus = "warn"
			dbSummary = "memory (non-durable)"
		}
		checks["db"] = healthStatus{Status: dbStatus, Summary: dbSummary, Detail: dbDetail}
		if dbStatus == "warn" && overall == "ok" {
			overall = "warn"
		}
	}

	// Worker.
	workerStatus := "ok"
	failedCount := 0
	if jobs, err := h.store.ListLifecycleJobs(ctx, "FAILED", 1000); err == nil {
		failedCount = len(jobs)
	}
	workerSummary := "running"
	if failedCount > 0 {
		workerStatus = "warn"
		workerSummary = formatPlural(failedCount, "failed job")
	}
	workerDetail := map[string]any{"failed_jobs": failedCount}
	if h.worker != nil {
		workerCfg := h.worker.Config()
		workerDetail["poll_interval"] = workerCfg.PollIntervalText
		workerDetail["lease_ttl"] = workerCfg.LeaseTTLText
		workerDetail["max_attempts"] = workerCfg.MaxAttempts
	}
	checks["worker"] = healthStatus{Status: workerStatus, Summary: workerSummary, Detail: workerDetail}
	if workerStatus == "warn" && overall == "ok" {
		overall = "warn"
	}

	// Audit chain.
	auditStatus := "ok"
	auditSummary := "chain ok"
	auditDetail := map[string]any{"chains": 0, "verification": "intact"}
	if heads, err := h.store.ListAuditChainHeads(ctx); err == nil {
		auditSummary = formatPlural(len(heads), "chain")
		auditDetail["chains"] = len(heads)
		broken := false
		for _, ch := range heads {
			if brokenSeq, err := h.store.VerifyAuditChain(ctx, ch.ChainName); err != nil || brokenSeq > 0 {
				broken = true
				break
			}
		}
		if broken {
			auditStatus = "degraded"
			auditSummary = "chain broken"
			auditDetail["verification"] = "broken"
			overall = "degraded"
		}
	} else {
		auditStatus = "degraded"
		auditSummary = "verify failed"
		auditDetail["verification"] = "unavailable"
		overall = "degraded"
	}
	checks["audit"] = healthStatus{Status: auditStatus, Summary: auditSummary, Detail: auditDetail}

	// Policy.
	policyStatus := "ok"
	policySummary := "signed policy loaded"
	policyDetail := map[string]any{"loaded": false}
	if h.policyMgr == nil || h.policyMgr.Current() == nil {
		policyStatus = "degraded"
		policySummary = "no policy loaded"
		overall = "degraded"
	} else if current := h.policyMgr.Current(); current != nil {
		policyDetail["loaded"] = true
		policyDetail["policy_id"] = current.PolicyID
		policyDetail["version"] = current.Version
		policyDetail["default_suite"] = current.DefaultSuite
		policyDetail["status"] = current.Status
		policyDetail["trusted_signing_keys"] = len(h.policyMgr.SigningKeys())
	}
	checks["policy"] = healthStatus{Status: policyStatus, Summary: policySummary, Detail: policyDetail}

	writeJSON(w, 200, healthResponse{
		Overall: overall,
		Uptime:  int(time.Since(h.startTime).Seconds()),
		Checks:  checks,
	})
}

// --- DB Status ---

func (h *Handler) getDBStatus(w http.ResponseWriter, r *http.Request) {
	if !requireAnyScope(w, r, "ops:read", "ops:repair", "ops:breakglass") {
		return
	}
	ctx := r.Context()
	status := map[string]any{
		"driver": h.cfg.Database.Driver,
	}

	// Connection health.
	pingErr := h.store.Ping(ctx)
	status["connected"] = pingErr == nil
	if pingErr != nil {
		status["error"] = pingErr.Error()
	}

	// Cluster epoch.
	if epoch, err := h.store.ClusterEpoch(ctx); err == nil {
		status["cluster_epoch"] = epoch
	}

	// Table sizes.
	if sizes, err := h.store.TableSizes(ctx); err == nil {
		status["table_sizes"] = sizes
	}

	// Backlog.
	backlog := map[string]any{}
	if jobs, err := h.store.ListLifecycleJobs(ctx, "FAILED", 1000); err == nil {
		backlog["lifecycle_failed"] = len(jobs)
	}
	if jobs, err := h.store.ListLifecycleJobs(ctx, "PENDING", 1000); err == nil {
		backlog["lifecycle_pending"] = len(jobs)
	}
	if events, err := h.store.ListOutboxEvents(ctx, "PENDING", 1000); err == nil {
		backlog["outbox_pending"] = len(events)
	}
	status["backlog"] = backlog

	// Ops tokens cannot use the management-plane /keys endpoint. Expose only
	// aggregate inventory here: no names, IDs, tags, payloads, or key material.
	keyInventory := map[string]any{
		"scope": "global", "total": 0,
		"by_status": map[string]int{}, "by_suite": map[string]int{}, "by_purpose": map[string]int{},
	}
	if keys, err := h.store.ListAllKeys(ctx); err == nil {
		byStatus := keyInventory["by_status"].(map[string]int)
		bySuite := keyInventory["by_suite"].(map[string]int)
		byPurpose := keyInventory["by_purpose"].(map[string]int)
		keyInventory["total"] = len(keys)
		for _, key := range keys {
			keyStatus := key.Status
			if keyStatus == "ACTIVE" && !key.ExpiresAt.IsZero() && !time.Now().UTC().Before(key.ExpiresAt) {
				keyStatus = "EXPIRED"
			}
			byStatus[keyStatus]++
			bySuite[key.SuiteID]++
			byPurpose[key.Purpose]++
		}
	}
	status["key_inventory"] = keyInventory

	// CRK envelope consistency.
	crkConsistency := map[string]any{}
	if latest, err := h.store.GetLatestCRKVersion(ctx); err == nil {
		crkConsistency["latest_version"] = latest.Version
		crkConsistency["latest_version_id"] = latest.ID
		crkConsistency["status"] = latest.Status
		// Check envelope for default node.
		if rec, env, ok := h.tryLoadCRKEnvelope(ctx, latest.ID, "node-bootstrap"); ok {
			expected := crkAADDigest(env)
			crkConsistency["digest_valid"] = env.CRKAADDigest == expected
			crkConsistency["envelope_bytes"] = len(rec.Envelope)
		} else {
			crkConsistency["digest_valid"] = false
		}
	}
	status["crk_consistency"] = crkConsistency

	writeJSON(w, 200, status)
}

// --- CRK Envelope (migrated from baselineapi) ---

type crkEnvelopeStatus struct {
	ID                string `json:"id"`
	CRKVersionID      string `json:"crk_version_id"`
	NodeID            string `json:"node_id"`
	CreatedAt         string `json:"created_at"`
	EnvelopeBytes     int    `json:"envelope_bytes"`
	WrappedCRKBytes   int    `json:"wrapped_crk_bytes"`
	CRKVersion        uint32 `json:"crk_version"`
	NRWKName          string `json:"nrwk_name"`
	ClusterID         string `json:"cluster_id"`
	PlaneRole         string `json:"plane_role"`
	CRKAADDigest      string `json:"crk_aad_digest"`
	ExpectedAADDigest string `json:"expected_aad_digest"`
	DigestValid       bool   `json:"digest_valid"`
}

func (h *Handler) getCRKEnvelope(w http.ResponseWriter, r *http.Request) {
	if !requireAnyScope(w, r, "ops:read", "ops:repair", "ops:breakglass") {
		return
	}
	rec, env, ok := h.loadCRKEnvelope(w, r)
	if !ok {
		return
	}
	writeJSON(w, 200, h.crkEnvelopeStatus(rec, env))
}

func (h *Handler) repairCRKEnvelopeAADDigest(w http.ResponseWriter, r *http.Request) {
	rec, env, ok := h.loadCRKEnvelope(w, r)
	if !ok {
		return
	}
	expected := crkAADDigest(env)
	old := env.CRKAADDigest
	guard, ok := h.beginAction(w, r, "ops.crk_envelope.repair_aad_digest", rec.ID, map[string]string{
		"target": rec.ID, "current_state": map[bool]string{true: "digest_valid", false: "digest_invalid"}[old == expected],
		"impact_scope": "single node CRK envelope metadata", "rollback": "reversible", "expected_result": "AAD digest matches envelope context",
	})
	if !ok {
		return
	}
	if old == expected {
		h.finishAction(w, r, guard, "succeeded", map[string]any{"status": "unchanged", "envelope": h.crkEnvelopeStatus(rec, env)})
		return
	}
	env.CRKAADDigest = expected
	encoded, err := json.Marshal(env)
	if err != nil {
		writeErr(w, 500, "INTERNAL", "encode crk envelope failed")
		return
	}
	rec.Envelope = encoded
	if err := h.store.UpdateCRKNodeEnvelope(r.Context(), rec); err != nil {
		_ = h.auditHighRiskResult(r, guard.principal, guard.action, guard.targetID, "failed", map[string]string{"error_code": string(errorsx.AsCode(err))})
		writeServiceError(w, err)
		return
	}
	if h.resolver != nil {
		h.resolver.SetCRKEnvelope(env)
	}
	h.finishAction(w, r, guard, "succeeded", map[string]any{"status": "repaired", "envelope": h.crkEnvelopeStatus(rec, env)})
}

// --- Resolver Refresh ---

func (h *Handler) refreshResolver(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	latest, err := h.store.GetLatestCRKVersion(ctx)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	nodeID := r.URL.Query().Get("node_id")
	if nodeID == "" {
		nodeID = "node-bootstrap"
	}
	rec, err := h.store.GetCRKNodeEnvelope(ctx, latest.ID, nodeID)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	var env provider.CRKEnvelope
	if err := json.Unmarshal(rec.Envelope, &env); err != nil {
		writeErr(w, 500, "INTERNAL", "invalid crk envelope json")
		return
	}
	guard, ok := h.beginAction(w, r, "ops.resolver.refresh", latest.ID, map[string]string{
		"target": latest.ID, "current_state": "resolver cache populated from current state", "impact_scope": "local resolver cache",
		"rollback": "self-reverting on next refresh", "expected_result": "latest CRK envelope cached", "node_id": nodeID,
	})
	if !ok {
		return
	}
	if h.resolver != nil {
		h.resolver.SetCRKEnvelope(&env)
	}
	h.finishAction(w, r, guard, "succeeded", map[string]any{
		"status":       "refreshed",
		"crk_version":  latest.Version,
		"node_id":      nodeID,
		"refreshed_at": time.Now().UTC().Format(time.RFC3339),
	})
}

// --- Lifecycle Job Retry ---

func (h *Handler) retryLifecycleJob(w http.ResponseWriter, r *http.Request) {
	jobID := r.PathValue("id")
	ctx := r.Context()
	job, err := h.store.GetLifecycleJob(ctx, jobID)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	guard, ok := h.beginAction(w, r, "ops.lifecycle_job.retry", jobID, map[string]string{
		"target": jobID, "current_state": job.Status, "impact_scope": "single lifecycle job", "rollback": "retriable",
		"expected_result": "job transitions to PENDING", "job_type": job.Type, "attempt": formatInt(job.Attempt),
	})
	if !ok {
		return
	}
	if err := h.store.RetryLifecycleJob(ctx, jobID); err != nil {
		_ = h.auditHighRiskResult(r, guard.principal, guard.action, jobID, "failed", map[string]string{"error_code": string(errorsx.AsCode(err))})
		writeServiceError(w, err)
		return
	}
	h.finishAction(w, r, guard, "succeeded", map[string]any{
		"status":     "retried",
		"job_id":     jobID,
		"new_status": "PENDING",
	})
}

// --- Outbox Replay ---

func (h *Handler) replayOutboxEvent(w http.ResponseWriter, r *http.Request) {
	eventID := r.PathValue("id")
	ctx := r.Context()
	// Find the event to capture its type for audit.
	events, _ := h.store.ListOutboxEvents(ctx, "", 1000)
	var eventType, currentStatus string
	for _, e := range events {
		if e.ID == eventID {
			eventType = e.EventType
			currentStatus = e.Status
			break
		}
	}
	guard, ok := h.beginAction(w, r, "ops.outbox.replay", eventID, map[string]string{
		"target": eventID, "current_state": currentStatus, "impact_scope": "single outbox event", "rollback": "consumer-idempotent",
		"expected_result": "event transitions to PENDING", "event_type": eventType,
	})
	if !ok {
		return
	}
	if err := h.store.ReplayOutboxEvent(ctx, eventID); err != nil {
		_ = h.auditHighRiskResult(r, guard.principal, guard.action, eventID, "failed", map[string]string{"error_code": string(errorsx.AsCode(err))})
		writeServiceError(w, err)
		return
	}
	h.finishAction(w, r, guard, "succeeded", map[string]any{
		"status":     "replayed",
		"event_id":   eventID,
		"new_status": "PENDING",
	})
}

// --- Helpers (migrated + new) ---

func (h *Handler) loadCRKEnvelope(w http.ResponseWriter, r *http.Request) (*models.CRKNodeEnvelope, *provider.CRKEnvelope, bool) {
	crkVersionID := r.URL.Query().Get("crk_version_id")
	if crkVersionID == "" {
		latest, err := h.store.GetLatestCRKVersion(r.Context())
		if err != nil {
			writeServiceError(w, err)
			return nil, nil, false
		}
		crkVersionID = latest.ID
	}
	nodeID := r.URL.Query().Get("node_id")
	if nodeID == "" {
		nodeID = "node-bootstrap"
	}
	return h.tryLoadCRKEnvelopeErr(w, r, crkVersionID, nodeID)
}

func (h *Handler) tryLoadCRKEnvelopeErr(w http.ResponseWriter, r *http.Request, crkVersionID, nodeID string) (*models.CRKNodeEnvelope, *provider.CRKEnvelope, bool) {
	rec, err := h.store.GetCRKNodeEnvelope(r.Context(), crkVersionID, nodeID)
	if err != nil {
		writeServiceError(w, err)
		return nil, nil, false
	}
	var env provider.CRKEnvelope
	if err := json.Unmarshal(rec.Envelope, &env); err != nil {
		writeErr(w, 500, "INTERNAL", "invalid crk envelope json")
		return nil, nil, false
	}
	return rec, &env, true
}

func (h *Handler) tryLoadCRKEnvelope(ctx context.Context, crkVersionID, nodeID string) (*models.CRKNodeEnvelope, *provider.CRKEnvelope, bool) {
	rec, err := h.store.GetCRKNodeEnvelope(ctx, crkVersionID, nodeID)
	if err != nil {
		return nil, nil, false
	}
	var env provider.CRKEnvelope
	if err := json.Unmarshal(rec.Envelope, &env); err != nil {
		return nil, nil, false
	}
	return rec, &env, true
}

func (h *Handler) crkEnvelopeStatus(rec *models.CRKNodeEnvelope, env *provider.CRKEnvelope) crkEnvelopeStatus {
	expected := crkAADDigest(env)
	return crkEnvelopeStatus{
		ID:                rec.ID,
		CRKVersionID:      rec.CRKVersionID,
		NodeID:            rec.NodeID,
		CreatedAt:         rec.CreatedAt.Format(time.RFC3339),
		EnvelopeBytes:     len(rec.Envelope),
		WrappedCRKBytes:   len(env.WrappedCRK),
		CRKVersion:        env.CRKVersion,
		NRWKName:          env.NRWKName,
		ClusterID:         env.ClusterID,
		PlaneRole:         env.PlaneRole,
		CRKAADDigest:      env.CRKAADDigest,
		ExpectedAADDigest: expected,
		DigestValid:       env.CRKAADDigest == expected,
	}
}

func (h *Handler) auditHighRisk(r *http.Request, p *principal.Principal, action, targetID string, metadata map[string]string) error {
	actor := ""
	if p != nil {
		actor = p.ID
	}
	return h.auditChain.Record(r.Context(), auditchain.RecordRequest{
		RequestID:    middleware.RequestIDFromContext(r.Context()),
		ActorType:    "principal",
		ActorHash:    hashTruncate(actor),
		Action:       action + ".requested",
		TargetType:   "ops_resource",
		TargetIDHash: hashTruncate(targetID),
		Result:       "requested",
		Metadata:     metadata,
	})
}

func (h *Handler) auditHighRiskResult(r *http.Request, p *principal.Principal, action, targetID, result string, metadata map[string]string) error {
	actor := ""
	if p != nil {
		actor = p.ID
	}
	return h.auditChain.Record(r.Context(), auditchain.RecordRequest{
		RequestID:    middleware.RequestIDFromContext(r.Context()),
		ActorType:    "principal",
		ActorHash:    hashTruncate(actor),
		Action:       action + "." + result,
		TargetType:   "ops_resource",
		TargetIDHash: hashTruncate(targetID),
		Result:       result,
		Metadata:     metadata,
	})
}

func crkAADDigest(env *provider.CRKEnvelope) string {
	a := aad.CRKAAD{
		ClusterID:      env.ClusterID,
		NodeID:         env.NodeID,
		PlaneRole:      env.PlaneRole,
		CRKVersion:     env.CRKVersion,
		NRWKName:       env.NRWKName,
		BaselineDigest: env.BaselineDigest,
		PolicyDigest:   env.PolicyDigest,
	}
	b, err := a.Canonical()
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func hashTruncate(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:8])
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

func formatPlural(n int, singular string) string {
	if n == 1 {
		return "1 " + singular
	}
	return formatInt(n) + " " + singular + "s"
}

func formatInt(n int) string {
	if n == 0 {
		return "0"
	}
	digits := []byte{}
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}
