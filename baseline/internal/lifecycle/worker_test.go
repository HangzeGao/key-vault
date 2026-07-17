package lifecycle

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/kvlt/key-vault/internal/repository/models"
)

type expiryCheckerFunc func(context.Context, time.Duration) ([]ExpiryCandidate, error)

func (f expiryCheckerFunc) CheckExpiry(ctx context.Context, warningWindow time.Duration) ([]ExpiryCandidate, error) {
	return f(ctx, warningWindow)
}

type expiryStore struct {
	events []*models.OutboxEvent
}

func (s *expiryStore) CreateLifecycleJob(context.Context, *models.LifecycleJob) error {
	return nil
}

func (s *expiryStore) ClaimLifecycleJob(context.Context, string, time.Duration) (*models.LifecycleJob, error) {
	return nil, context.Canceled
}

func (s *expiryStore) CompleteLifecycleJob(context.Context, string) error {
	return nil
}

func (s *expiryStore) FailLifecycleJob(context.Context, string, time.Duration) error {
	return nil
}

func (s *expiryStore) GetLifecycleJob(context.Context, string) (*models.LifecycleJob, error) {
	return nil, context.Canceled
}

func (s *expiryStore) ListLifecycleJobs(context.Context, string, int) ([]*models.LifecycleJob, error) {
	return nil, nil
}

func (s *expiryStore) CreateOutboxEvent(_ context.Context, e *models.OutboxEvent) error {
	s.events = append(s.events, e)
	return nil
}

func (s *expiryStore) ClaimOutboxEvent(context.Context) (*models.OutboxEvent, error) {
	return nil, context.Canceled
}

func (s *expiryStore) CompleteOutboxEvent(context.Context, string) error {
	return nil
}

func (s *expiryStore) ListOutboxEvents(context.Context, string, int) ([]*models.OutboxEvent, error) {
	return s.events, nil
}

func TestDoKeyExpiryCheckEmitsExpiredEvent(t *testing.T) {
	store := &expiryStore{}
	worker := New(store, Config{})
	expiresAt := time.Now().UTC().Add(-time.Hour)
	worker.SetExpiryChecker(expiryCheckerFunc(func(context.Context, time.Duration) ([]ExpiryCandidate, error) {
		return []ExpiryCandidate{{
			KeyID:          "key-expired",
			TenantID:       "t-default",
			CurrentVersion: 3,
			ExpiresAt:      expiresAt,
		}}, nil
	}))

	err := worker.doKeyExpiryCheck(context.Background(), &models.LifecycleJob{ID: "job-1"})
	if err != nil {
		t.Fatalf("doKeyExpiryCheck: %v", err)
	}
	if len(store.events) != 1 {
		t.Fatalf("outbox events = %d, want 1", len(store.events))
	}
	event := store.events[0]
	if event.EventType != eventKeyExpired {
		t.Fatalf("event type = %q, want %q", event.EventType, eventKeyExpired)
	}

	var payload map[string]any
	if err := json.Unmarshal(event.Payload, &payload); err != nil {
		t.Fatalf("payload json: %v", err)
	}
	if payload["status"] != "EXPIRED" {
		t.Fatalf("payload status = %v, want EXPIRED", payload["status"])
	}
}

func TestDoKeyExpiryCheckEmitsApproachingEvent(t *testing.T) {
	store := &expiryStore{}
	worker := New(store, Config{ExpiryWarningWindow: 24 * time.Hour})
	expiresAt := time.Now().UTC().Add(time.Hour)
	worker.SetExpiryChecker(expiryCheckerFunc(func(_ context.Context, warningWindow time.Duration) ([]ExpiryCandidate, error) {
		if warningWindow != 24*time.Hour {
			t.Fatalf("warningWindow = %s, want 24h", warningWindow)
		}
		return []ExpiryCandidate{{
			KeyID:          "key-soon",
			TenantID:       "t-default",
			CurrentVersion: 1,
			ExpiresAt:      expiresAt,
		}}, nil
	}))

	err := worker.doKeyExpiryCheck(context.Background(), &models.LifecycleJob{ID: "job-1"})
	if err != nil {
		t.Fatalf("doKeyExpiryCheck: %v", err)
	}
	if len(store.events) != 1 {
		t.Fatalf("outbox events = %d, want 1", len(store.events))
	}
	event := store.events[0]
	if event.EventType != eventKeyExpiryApproaching {
		t.Fatalf("event type = %q, want %q", event.EventType, eventKeyExpiryApproaching)
	}

	var payload map[string]any
	if err := json.Unmarshal(event.Payload, &payload); err != nil {
		t.Fatalf("payload json: %v", err)
	}
	if payload["status"] != "EXPIRY_APPROACHING" {
		t.Fatalf("payload status = %v, want EXPIRY_APPROACHING", payload["status"])
	}
}
