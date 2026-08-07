package ccsds

import (
	"context"
	"fmt"
	"sync"
)

// Store owns CCSDS-specific association, transmit, and replay state. It is a
// separate seam from the generic key repository.
type Store interface {
	GetAssociation(ctx context.Context, tenantID, associationID string) (*SecurityAssociation, error)
	GetAssociationBySPI(ctx context.Context, tenantID string, direction Direction, spi uint16) (*SecurityAssociation, error)
	NextTransmitCounter(ctx context.Context, associationID string) (uint32, error)
	CheckReplay(ctx context.Context, associationID string, sequence uint64, window uint8) error
	CommitReplay(ctx context.Context, associationID string, sequence uint64, window uint8) error
}

// MemoryStore is the deterministic test/development adapter. Production must
// use a durable adapter so restarts cannot reuse transmit state or forget the
// receive replay window.
type MemoryStore struct {
	mu     sync.Mutex
	byID   map[string]SecurityAssociation
	bySPI  map[string]string
	txNext map[string]uint64
	rx     map[string]ReplayState
}

// ReplayState is the durable representation of a sliding replay window.
// Exporting the value lets persistence adapters share the exact same state
// transition rules as the in-memory adapter.
type ReplayState struct {
	Highest uint64
	Bitmap  uint64
	Seen    bool
}

func NewMemoryStore(associations ...SecurityAssociation) (*MemoryStore, error) {
	s := &MemoryStore{
		byID: make(map[string]SecurityAssociation), bySPI: make(map[string]string),
		txNext: make(map[string]uint64), rx: make(map[string]ReplayState),
	}
	for _, association := range associations {
		if err := s.PutAssociation(association); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func (s *MemoryStore) PutAssociation(sa SecurityAssociation) error {
	if err := sa.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := spiKey(sa.TenantID, sa.Direction, sa.SPI)
	if existing, ok := s.bySPI[key]; ok && existing != sa.ID {
		return fmt.Errorf("ccsds: SPI already bound to association %s", existing)
	}
	if previous, ok := s.byID[sa.ID]; ok {
		delete(s.bySPI, spiKey(previous.TenantID, previous.Direction, previous.SPI))
	}
	s.byID[sa.ID] = cloneAssociation(sa)
	s.bySPI[key] = sa.ID
	return nil
}

func (s *MemoryStore) GetAssociation(_ context.Context, tenantID, associationID string) (*SecurityAssociation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sa, ok := s.byID[associationID]
	if !ok || sa.TenantID != tenantID {
		return nil, ErrAssociationNotFound
	}
	copy := cloneAssociation(sa)
	return &copy, nil
}

func (s *MemoryStore) GetAssociationBySPI(_ context.Context, tenantID string, direction Direction, spi uint16) (*SecurityAssociation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.bySPI[spiKey(tenantID, direction, spi)]
	if !ok {
		return nil, ErrAssociationNotFound
	}
	sa := cloneAssociation(s.byID[id])
	return &sa, nil
}

func (s *MemoryStore) NextTransmitCounter(_ context.Context, associationID string) (uint32, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sa, ok := s.byID[associationID]
	if !ok {
		return 0, ErrAssociationNotFound
	}
	if (sa.Direction != DirectionTCTx && sa.Direction != DirectionTCRecoveryTx) || sa.State != AssociationActive {
		return 0, ErrAssociationState
	}
	next := s.txNext[associationID]
	if next >= uint64(1)<<32 {
		return 0, ErrCounterExhausted
	}
	s.txNext[associationID] = next + 1
	return uint32(next), nil
}

func (s *MemoryStore) CheckReplay(_ context.Context, associationID string, sequence uint64, window uint8) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sa, ok := s.byID[associationID]
	if !ok {
		return ErrAssociationNotFound
	}
	if sa.Direction != DirectionAOSRx || (sa.State != AssociationActive && sa.State != AssociationGrace) {
		return ErrAssociationState
	}
	return s.rx[associationID].Check(sequence, window)
}

func (s *MemoryStore) CommitReplay(_ context.Context, associationID string, sequence uint64, window uint8) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.rx[associationID]
	if err := state.Commit(sequence, window); err != nil {
		return err
	}
	s.rx[associationID] = state
	return nil
}

// Check verifies whether sequence is acceptable without mutating state.
func (state ReplayState) Check(sequence uint64, window uint8) error {
	if window == 0 || window > 64 {
		return ErrReplay
	}
	if !state.Seen || sequence > state.Highest {
		return nil
	}
	delta := state.Highest - sequence
	if delta >= uint64(window) || state.Bitmap&(uint64(1)<<delta) != 0 {
		return ErrReplay
	}
	return nil
}

// Commit records an authenticated sequence number. Callers must serialize
// concurrent commits for the same association (for example with FOR UPDATE).
func (state *ReplayState) Commit(sequence uint64, window uint8) error {
	if err := state.Check(sequence, window); err != nil {
		return err
	}
	if !state.Seen {
		state.Highest, state.Bitmap, state.Seen = sequence, 1, true
		return nil
	}
	if sequence > state.Highest {
		shift := sequence - state.Highest
		if shift >= 64 {
			state.Bitmap = 1
		} else {
			state.Bitmap = (state.Bitmap << shift) | 1
		}
		state.Highest = sequence
		return nil
	}
	state.Bitmap |= uint64(1) << (state.Highest - sequence)
	return nil
}

func spiKey(tenantID string, direction Direction, spi uint16) string {
	return fmt.Sprintf("%s|%s|%d", tenantID, direction, spi)
}

func cloneAssociation(sa SecurityAssociation) SecurityAssociation {
	sa.Parameters.NoncePrefix = append([]byte(nil), sa.Parameters.NoncePrefix...)
	return sa
}
