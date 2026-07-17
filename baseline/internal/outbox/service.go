// Package outbox implements the engineering baseline transactional outbox.
package outbox

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/kvlt/key-vault/internal/repository/models"
)

// Store is the repository subset for the outbox.
type Store interface {
	CreateOutboxEvent(ctx context.Context, e *models.OutboxEvent) error
	ClaimOutboxEvent(ctx context.Context) (*models.OutboxEvent, error)
	CompleteOutboxEvent(ctx context.Context, id string) error
	ListOutboxEvents(ctx context.Context, status string, limit int) ([]*models.OutboxEvent, error)
}

// Service is the outbox service.
type Service struct {
	store Store
}

// New constructs an outbox service.
func New(store Store) *Service {
	return &Service{store: store}
}

// Enqueue adds an event to the outbox.
func (s *Service) Enqueue(ctx context.Context, eventType, aggregateID string, payload []byte) error {
	e := &models.OutboxEvent{
		ID:          newID("ob"),
		EventType:   eventType,
		AggregateID: aggregateID,
		Payload:     payload,
		Status:      "PENDING",
		CreatedAt:   time.Now().UTC(),
	}
	return s.store.CreateOutboxEvent(ctx, e)
}

// List returns outbox events.
func (s *Service) List(ctx context.Context, status string, limit int) ([]*models.OutboxEvent, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	return s.store.ListOutboxEvents(ctx, status, limit)
}

func newID(prefix string) string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%s_%s", prefix, hex.EncodeToString(b))
}
