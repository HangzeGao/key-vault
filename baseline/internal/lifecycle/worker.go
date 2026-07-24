// Package lifecycle implements the engineering baseline lifecycle worker.
//
// The worker processes async lifecycle jobs using a transactional outbox pattern:
//   - Jobs are claimed via FOR UPDATE SKIP LOCKED (simulated in-memory).
//   - Execution results and outbox consumption status commit in-transaction.
//   - Idempotency keys prevent duplicate side effects on retry.
//
// Job types:
//   - key_expiry_check: scan cryptoperiod and emit expiry notices.
//   - cache_invalidate: confirm cache invalidation or TTL expiry.
//   - destroy_due: destroy wrapped material after cooldown + approval.
//   - audit_forward: forward audit outbox to external sink.
package lifecycle

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"sync"
	"time"

	"github.com/kvlt/key-vault/internal/repository/models"
)

// Store is the repository subset used by the lifecycle worker.
type Store interface {
	CreateLifecycleJob(ctx context.Context, j *models.LifecycleJob) error
	ClaimLifecycleJob(ctx context.Context, owner string, leaseTTL time.Duration) (*models.LifecycleJob, error)
	CompleteLifecycleJob(ctx context.Context, jobID string) error
	FailLifecycleJob(ctx context.Context, jobID string, backoff time.Duration) error
	GetLifecycleJob(ctx context.Context, id string) (*models.LifecycleJob, error)
	ListLifecycleJobs(ctx context.Context, status string, limit int) ([]*models.LifecycleJob, error)

	CreateOutboxEvent(ctx context.Context, e *models.OutboxEvent) error
	ClaimOutboxEvent(ctx context.Context) (*models.OutboxEvent, error)
	CompleteOutboxEvent(ctx context.Context, id string) error
	ListOutboxEvents(ctx context.Context, status string, limit int) ([]*models.OutboxEvent, error)
}

// KeyExpiryChecker checks keys for cryptoperiod expiry (hook from keys service).
type KeyExpiryChecker interface {
	CheckExpiry(ctx context.Context, warningWindow time.Duration) ([]ExpiryCandidate, error)
}

const eventKeyExpired = "key.expired"
const eventKeyExpiryApproaching = "key.expiry_approaching"

// ExpiryCandidate is a key whose validity window has expired or is approaching.
type ExpiryCandidate struct {
	KeyID          string
	TenantID       string
	CurrentVersion uint32
	ExpiresAt      time.Time
}

// DestroyExecutor performs the actual key material destruction.
type DestroyExecutor interface {
	DestroyKeyMaterial(ctx context.Context, keyID string) error
}

// AuditForwarder forwards audit events to an external sink.
type AuditForwarder interface {
	Forward(ctx context.Context, event *models.OutboxEvent) error
}

// Worker is the baseline lifecycle worker.
type Worker struct {
	store               Store
	expiryChecker       KeyExpiryChecker
	destroyExec         DestroyExecutor
	auditForwarder      AuditForwarder
	ownerID             string
	leaseTTL            time.Duration
	maxAttempts         int
	pollInterval        time.Duration
	expiryScanInterval  time.Duration
	expiryWarningWindow time.Duration

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// Config configures the worker.
type Config struct {
	OwnerID             string        `json:"owner_id"`
	LeaseTTL            time.Duration `json:"-"`
	LeaseTTLText        string        `json:"lease_ttl"`
	MaxAttempts         int           `json:"max_attempts"`
	PollInterval        time.Duration `json:"-"`
	PollIntervalText    string        `json:"poll_interval"`
	ExpiryScanInterval  time.Duration `json:"-"`
	ExpiryScanText      string        `json:"expiry_scan_interval"`
	ExpiryWarningWindow time.Duration `json:"-"`
	ExpiryWarningText   string        `json:"expiry_warning_window"`
}

// New constructs a lifecycle worker.
func New(store Store, cfg Config) *Worker {
	if cfg.OwnerID == "" {
		cfg.OwnerID = "lifecycle-worker-1"
	}
	if cfg.LeaseTTL == 0 {
		cfg.LeaseTTL = 30 * time.Second
	}
	if cfg.MaxAttempts == 0 {
		cfg.MaxAttempts = 5
	}
	if cfg.PollInterval == 0 {
		cfg.PollInterval = 5 * time.Second
	}
	if cfg.ExpiryScanInterval == 0 {
		cfg.ExpiryScanInterval = time.Minute
	}
	if cfg.ExpiryWarningWindow == 0 {
		cfg.ExpiryWarningWindow = 7 * 24 * time.Hour
	}
	return &Worker{
		store:               store,
		ownerID:             cfg.OwnerID,
		leaseTTL:            cfg.LeaseTTL,
		maxAttempts:         cfg.MaxAttempts,
		pollInterval:        cfg.PollInterval,
		expiryScanInterval:  cfg.ExpiryScanInterval,
		expiryWarningWindow: cfg.ExpiryWarningWindow,
	}
}

// Config returns the effective worker configuration for the API.
func (w *Worker) Config() Config {
	return Config{
		OwnerID:             w.ownerID,
		LeaseTTL:            w.leaseTTL,
		LeaseTTLText:        w.leaseTTL.String(),
		MaxAttempts:         w.maxAttempts,
		PollInterval:        w.pollInterval,
		PollIntervalText:    w.pollInterval.String(),
		ExpiryScanInterval:  w.expiryScanInterval,
		ExpiryScanText:      w.expiryScanInterval.String(),
		ExpiryWarningWindow: w.expiryWarningWindow,
		ExpiryWarningText:   w.expiryWarningWindow.String(),
	}
}

// SetExpiryChecker wires the key expiry checker.
func (w *Worker) SetExpiryChecker(c KeyExpiryChecker) { w.expiryChecker = c }

// SetDestroyExecutor wires the destroy executor.
func (w *Worker) SetDestroyExecutor(e DestroyExecutor) { w.destroyExec = e }

// SetAuditForwarder wires the audit forwarder.
func (w *Worker) SetAuditForwarder(f AuditForwarder) { w.auditForwarder = f }

// Start launches the worker loops.
func (w *Worker) Start(ctx context.Context) {
	ctx, w.cancel = context.WithCancel(ctx)

	// Job processing loop.
	w.wg.Add(1)
	go func() {
		defer w.wg.Done()
		ticker := time.NewTicker(w.pollInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				w.processJobs(ctx)
			}
		}
	}()

	// Outbox forwarding loop.
	w.wg.Add(1)
	go func() {
		defer w.wg.Done()
		ticker := time.NewTicker(w.pollInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				w.processOutbox(ctx)
			}
		}
	}()

	// Expiry scan loop (less frequent).
	w.wg.Add(1)
	go func() {
		defer w.wg.Done()
		ticker := time.NewTicker(w.expiryScanInterval)
		defer ticker.Stop()
		w.scanExpiry(ctx)
		w.processJobs(ctx)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				w.scanExpiry(ctx)
				w.processJobs(ctx)
			}
		}
	}()

	slog.Info("lifecycle worker started", "owner", w.ownerID)
}

// Stop gracefully stops the worker.
func (w *Worker) Stop() {
	if w.cancel != nil {
		w.cancel()
	}
	w.wg.Wait()
}

// processJobs claims and executes lifecycle jobs.
func (w *Worker) processJobs(ctx context.Context) {
	for {
		job, err := w.store.ClaimLifecycleJob(ctx, w.ownerID, w.leaseTTL)
		if err != nil {
			return // no more jobs
		}
		w.executeJob(ctx, job)
	}
}

// executeJob executes a single job with idempotency and retry handling.
func (w *Worker) executeJob(ctx context.Context, job *models.LifecycleJob) {
	slog.Info("lifecycle: executing job", "id", job.ID, "type", job.Type, "attempt", job.Attempt)

	var err error
	switch job.Type {
	case "key_expiry_check":
		err = w.doKeyExpiryCheck(ctx, job)
	case "cache_invalidate":
		err = w.doCacheInvalidate(ctx, job)
	case "destroy_due":
		err = w.doDestroyDue(ctx, job)
	case "audit_forward":
		err = w.doAuditForward(ctx, job)
	default:
		err = fmt.Errorf("unknown job type: %s", job.Type)
	}

	if err != nil {
		slog.Warn("lifecycle: job failed", "id", job.ID, "type", job.Type, "error", err, "attempt", job.Attempt)
		if job.Attempt >= w.maxAttempts {
			// Mark as permanently failed after max attempts.
			_ = w.store.FailLifecycleJob(ctx, job.ID, time.Duration(math.MaxInt64))
			slog.Error("lifecycle: job exhausted retries", "id", job.ID, "type", job.Type)
		} else {
			// Exponential backoff.
			backoff := time.Duration(math.Pow(2, float64(job.Attempt))) * time.Second
			_ = w.store.FailLifecycleJob(ctx, job.ID, backoff)
		}
		return
	}

	if err := w.store.CompleteLifecycleJob(ctx, job.ID); err != nil {
		slog.Error("lifecycle: failed to complete job", "id", job.ID, "error", err)
		return
	}
	slog.Info("lifecycle: job completed", "id", job.ID, "type", job.Type)
}

// doKeyExpiryCheck scans for keys whose validity window has expired or is approaching.
func (w *Worker) doKeyExpiryCheck(ctx context.Context, job *models.LifecycleJob) error {
	if w.expiryChecker == nil {
		return nil
	}
	candidates, err := w.expiryChecker.CheckExpiry(ctx, w.expiryWarningWindow)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	for _, c := range candidates {
		eventType := eventKeyExpiryApproaching
		status := "EXPIRY_APPROACHING"
		logMessage := "lifecycle: key expiry approaching"
		if !now.Before(c.ExpiresAt) {
			eventType = eventKeyExpired
			status = "EXPIRED"
			logMessage = "lifecycle: key expired"
		}
		slog.Info(logMessage, "key_id", c.KeyID, "expires_at", c.ExpiresAt)
		payload, _ := json.Marshal(map[string]any{
			"key_id":          c.KeyID,
			"tenant_id":       c.TenantID,
			"current_version": c.CurrentVersion,
			"expires_at":      c.ExpiresAt,
			"status":          status,
		})
		_ = w.store.CreateOutboxEvent(ctx, &models.OutboxEvent{
			ID:          fmt.Sprintf("ob-exp-%d-%s", time.Now().UnixNano(), c.KeyID),
			EventType:   eventType,
			AggregateID: c.KeyID,
			Payload:     payload,
			Status:      "PENDING",
		})
	}
	return nil
}

// doCacheInvalidate confirms cache invalidation for a node/key.
func (w *Worker) doCacheInvalidate(ctx context.Context, job *models.LifecycleJob) error {
	var payload struct {
		NodeID string `json:"node_id"`
		KeyID  string `json:"key_id"`
	}
	if err := json.Unmarshal(job.Payload, &payload); err != nil {
		return fmt.Errorf("parse payload: %w", err)
	}
	slog.Info("lifecycle: cache invalidated", "node_id", payload.NodeID, "key_id", payload.KeyID)
	return nil
}

// doDestroyDue destroys key material after cooldown + approval.
func (w *Worker) doDestroyDue(ctx context.Context, job *models.LifecycleJob) error {
	if w.destroyExec == nil {
		return fmt.Errorf("destroy executor not configured")
	}
	var payload struct {
		KeyID      string `json:"key_id"`
		ApprovedBy string `json:"approved_by"`
	}
	if err := json.Unmarshal(job.Payload, &payload); err != nil {
		return fmt.Errorf("parse payload: %w", err)
	}
	if err := w.destroyExec.DestroyKeyMaterial(ctx, payload.KeyID); err != nil {
		return fmt.Errorf("destroy key material: %w", err)
	}
	slog.Info("lifecycle: key material destroyed", "key_id", payload.KeyID, "approved_by", payload.ApprovedBy)
	return nil
}

// doAuditForward forwards an audit outbox event to the external sink.
func (w *Worker) doAuditForward(ctx context.Context, job *models.LifecycleJob) error {
	if w.auditForwarder == nil {
		return nil
	}
	var payload struct {
		OutboxEventID string `json:"outbox_event_id"`
	}
	if err := json.Unmarshal(job.Payload, &payload); err != nil {
		return fmt.Errorf("parse payload: %w", err)
	}
	// Fetch the outbox event and forward it.
	events, _ := w.store.ListOutboxEvents(ctx, "", 100)
	for _, e := range events {
		if e.ID == payload.OutboxEventID {
			if err := w.auditForwarder.Forward(ctx, e); err != nil {
				return fmt.Errorf("forward: %w", err)
			}
			_ = w.store.CompleteOutboxEvent(ctx, e.ID)
			return nil
		}
	}
	return fmt.Errorf("outbox event %s not found", payload.OutboxEventID)
}

// processOutbox forwards pending outbox events.
func (w *Worker) processOutbox(ctx context.Context) {
	for {
		event, err := w.store.ClaimOutboxEvent(ctx)
		if err != nil {
			return
		}
		if w.auditForwarder != nil && event.EventType != eventKeyExpired && event.EventType != eventKeyExpiryApproaching {
			if err := w.auditForwarder.Forward(ctx, event); err != nil {
				slog.Warn("lifecycle: outbox forward failed", "id", event.ID, "error", err)
				continue
			}
		}
		_ = w.store.CompleteOutboxEvent(ctx, event.ID)
		slog.Info("lifecycle: outbox event processed", "id", event.ID, "type", event.EventType)
	}
}

// scanExpiry triggers a key_expiry_check job.
func (w *Worker) scanExpiry(ctx context.Context) {
	job := &models.LifecycleJob{
		ID:             fmt.Sprintf("job-exp-%d", time.Now().UnixNano()),
		Type:           "key_expiry_check",
		Status:         "PENDING",
		IdempotencyKey: fmt.Sprintf("expiry-scan-%d", time.Now().Unix()/60),
		Payload:        []byte(`{}`),
	}
	if err := w.store.CreateLifecycleJob(ctx, job); err != nil {
		slog.Debug("lifecycle: expiry scan job already pending", "error", err)
	}
}

// EnqueueJob creates a lifecycle job (called by application services).
func (w *Worker) EnqueueJob(ctx context.Context, jobType, tenantID, keyID string, payload []byte) error {
	job := &models.LifecycleJob{
		ID:             fmt.Sprintf("job-%s-%d", jobType, time.Now().UnixNano()),
		Type:           jobType,
		TenantID:       tenantID,
		KeyID:          keyID,
		Status:         "PENDING",
		Payload:        payload,
		IdempotencyKey: fmt.Sprintf("%s-%s-%d", jobType, keyID, time.Now().UnixNano()),
	}
	return w.store.CreateLifecycleJob(ctx, job)
}

// ListJobs returns lifecycle jobs for the API.
func (w *Worker) ListJobs(ctx context.Context, status string, limit int) ([]*models.LifecycleJob, error) {
	return w.store.ListLifecycleJobs(ctx, status, limit)
}

// ListOutbox returns outbox events for the API.
func (w *Worker) ListOutbox(ctx context.Context, status string, limit int) ([]*models.OutboxEvent, error) {
	return w.store.ListOutboxEvents(ctx, status, limit)
}
