package ccsds

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"
)

// Store owns CCSDS-specific association, transmit, and replay state. It is a
// separate seam from the generic key repository.
type Store interface {
	GetAssociation(ctx context.Context, tenantID, associationID string) (*SecurityAssociation, error)
	GetAssociationBySPI(ctx context.Context, tenantID string, direction Direction, spi uint16) (*SecurityAssociation, error)
	GetTransmitAssociation(ctx context.Context, tenantID string, direction Direction) (*SecurityAssociation, error)
	ReadOperationsState(ctx context.Context, tenantID string) ([]AssociationRuntimeState, error)
	ReadTCRotationState(ctx context.Context, tenantID string) (*TCRotationState, error)
	ReadMissionProfileDigest(ctx context.Context, tenantID string) ([32]byte, error)
	ReadFlightSecurityStatus(ctx context.Context, tenantID string) (*ObservedFlightSecurityStatus, error)
	ObserveFlightSecurityStatus(ctx context.Context, tenantID string, status FlightSecurityStatus) error
	MarkTCRotationPrepared(ctx context.Context, tenantID string, state TCRotationState) error
	MarkTCRotationFrameProduced(ctx context.Context, tenantID, associationID string) error
	PromoteNextTC(ctx context.Context, tenantID string) error
	NextTransmitCounter(ctx context.Context, associationID string) (uint32, error)
}

// MemoryStore is the deterministic test/development adapter. Production must
// use a durable adapter so restarts cannot reuse transmit state or forget the
// receive replay window.
type MemoryStore struct {
	mu       sync.Mutex
	byID     map[string]SecurityAssociation
	bySPI    map[string]string
	txNext   map[string]uint64
	rotation map[string]TCRotationState
	profiles map[string][32]byte
	flight   map[string]ObservedFlightSecurityStatus
}

func NewMemoryStore(associations ...SecurityAssociation) (*MemoryStore, error) {
	s := &MemoryStore{
		byID: make(map[string]SecurityAssociation), bySPI: make(map[string]string),
		txNext: make(map[string]uint64), rotation: make(map[string]TCRotationState),
		profiles: make(map[string][32]byte), flight: make(map[string]ObservedFlightSecurityStatus),
	}
	for _, association := range associations {
		if err := s.PutAssociation(association); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func (s *MemoryStore) BindMissionProfile(tenantID string, digest [32]byte) error {
	if tenantID == "" || digest == ([32]byte{}) {
		return ErrAssociationState
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.profiles[tenantID]; ok && existing != digest {
		return ErrAssociationState
	}
	s.profiles[tenantID] = digest
	return nil
}

func (s *MemoryStore) ReadMissionProfileDigest(_ context.Context, tenantID string) ([32]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	digest, ok := s.profiles[tenantID]
	if !ok {
		return [32]byte{}, ErrAssociationNotFound
	}
	return digest, nil
}

func (s *MemoryStore) ReadFlightSecurityStatus(_ context.Context, tenantID string) (*ObservedFlightSecurityStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	status, ok := s.flight[tenantID]
	if !ok {
		return nil, ErrAssociationNotFound
	}
	copy := status
	return &copy, nil
}

func (s *MemoryStore) ObserveFlightSecurityStatus(_ context.Context, tenantID string, status FlightSecurityStatus) error {
	if tenantID == "" || status.Validate() != nil {
		return ErrAssociationState
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.flight[tenantID] = ObservedFlightSecurityStatus{FlightSecurityStatus: status, ObservedAt: time.Now().UTC()}
	return nil
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

func (s *MemoryStore) GetTransmitAssociation(_ context.Context, tenantID string, direction Direction) (*SecurityAssociation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	wanted := AssociationCurrent
	if direction == DirectionTCRecoveryTx {
		wanted = AssociationActive
	} else if direction != DirectionTCTx {
		return nil, ErrAssociationState
	}
	var found *SecurityAssociation
	for _, association := range s.byID {
		if association.TenantID == tenantID && association.Direction == direction && association.State == wanted {
			if found != nil {
				return nil, ErrAssociationState
			}
			copy := cloneAssociation(association)
			found = &copy
		}
	}
	if found == nil {
		return nil, ErrAssociationNotFound
	}
	return found, nil
}

func (s *MemoryStore) ReadOperationsState(_ context.Context, tenantID string) ([]AssociationRuntimeState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	states := make([]AssociationRuntimeState, 0)
	for _, association := range s.byID {
		if association.TenantID != tenantID || association.State == AssociationDisabled {
			continue
		}
		state := AssociationRuntimeState{
			ID: association.ID, SPI: association.SPI, Direction: association.Direction, State: association.State,
			SuiteID: association.SuiteID, SecurityEpoch: association.SecurityEpoch,
			KeyVersion: association.KeyVersion, PolicyVersion: association.PolicyVersion,
			SequenceNumberLength: association.Parameters.SequenceNumberLength,
			TransmittedIVLength:  association.Parameters.TransmittedIVLength,
			TagLength:            association.Parameters.TagLength, ReplayWindow: association.Parameters.ReplayWindow,
		}
		if association.Direction == DirectionTCTx || association.Direction == DirectionTCRecoveryTx {
			counter := s.txNext[association.ID]
			state.NextIVCounter = &counter
		}
		states = append(states, state)
	}
	sort.Slice(states, func(i, j int) bool {
		if states[i].Direction != states[j].Direction {
			return states[i].Direction < states[j].Direction
		}
		return states[i].SPI < states[j].SPI
	})
	return states, nil
}

func (s *MemoryStore) ReadTCRotationState(_ context.Context, tenantID string) (*TCRotationState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state, ok := s.rotation[tenantID]
	if !ok {
		return nil, ErrAssociationNotFound
	}
	copy := state
	return &copy, nil
}

func (s *MemoryStore) MarkTCRotationPrepared(_ context.Context, tenantID string, state TCRotationState) error {
	if state.Phase != TCRotationPrepared || state.TransactionID == 0 || state.CurrentRootVersion == 0 ||
		state.NextRootVersion <= state.CurrentRootVersion || state.NextSPI != NextSPI(state.CurrentSPI) {
		return ErrAssociationState
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	currentID, currentOK := s.bySPI[spiKey(tenantID, DirectionTCTx, state.CurrentSPI)]
	nextID, nextOK := s.bySPI[spiKey(tenantID, DirectionTCTx, state.NextSPI)]
	current, next := s.byID[currentID], s.byID[nextID]
	if !currentOK || !nextOK || current.State != AssociationCurrent || next.State != AssociationNext ||
		current.KeyVersion != state.CurrentRootVersion || next.KeyVersion != state.NextRootVersion {
		return ErrAssociationState
	}
	s.rotation[tenantID] = state
	return nil
}

func (s *MemoryStore) MarkTCRotationFrameProduced(_ context.Context, tenantID, associationID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	state, ok := s.rotation[tenantID]
	if !ok || state.Phase == TCRotationActive {
		return nil
	}
	association, associationOK := s.byID[associationID]
	if !associationOK || state.Phase != TCRotationSwitching || association.State != AssociationCurrent ||
		association.SPI != state.NextSPI || association.KeyVersion != state.NextRootVersion {
		return ErrAssociationState
	}
	state.Phase = TCRotationActive
	s.rotation[tenantID] = state
	return nil
}

func (s *MemoryStore) PromoteNextTC(_ context.Context, tenantID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var currentID, nextID string
	for id, association := range s.byID {
		if association.TenantID != tenantID || association.Direction != DirectionTCTx {
			continue
		}
		switch association.State {
		case AssociationCurrent:
			if currentID != "" {
				return ErrAssociationState
			}
			currentID = id
		case AssociationNext:
			if nextID != "" {
				return ErrAssociationState
			}
			nextID = id
		}
	}
	current := s.byID[currentID]
	next := s.byID[nextID]
	rotation, rotationOK := s.rotation[tenantID]
	if currentID == "" || nextID == "" ||
		next.SecurityEpoch != current.SecurityEpoch+1 || next.SPI != NextSPI(current.SPI) ||
		!equalBytes(next.Parameters.NoncePrefix, current.Parameters.NoncePrefix) || !rotationOK ||
		rotation.Phase != TCRotationPrepared || rotation.CurrentSPI != current.SPI || rotation.NextSPI != next.SPI ||
		rotation.CurrentRootVersion != current.KeyVersion || rotation.NextRootVersion != next.KeyVersion {
		return ErrAssociationState
	}
	current.State = AssociationDisabled
	next.State = AssociationCurrent
	s.byID[currentID] = current
	s.byID[nextID] = next
	rotation.Phase = TCRotationSwitching
	s.rotation[tenantID] = rotation
	return nil
}

func (s *MemoryStore) NextTransmitCounter(_ context.Context, associationID string) (uint32, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sa, ok := s.byID[associationID]
	if !ok {
		return 0, ErrAssociationNotFound
	}
	if (sa.Direction == DirectionTCTx && sa.State != AssociationCurrent) ||
		(sa.Direction == DirectionTCRecoveryTx && sa.State != AssociationActive) ||
		(sa.Direction != DirectionTCTx && sa.Direction != DirectionTCRecoveryTx) {
		return 0, ErrAssociationState
	}
	next := s.txNext[associationID]
	if next >= uint64(1)<<32 {
		return 0, ErrCounterExhausted
	}
	s.txNext[associationID] = next + 1
	return uint32(next), nil
}

func spiKey(tenantID string, direction Direction, spi uint16) string {
	return fmt.Sprintf("%s|%s|%d", tenantID, direction, spi)
}

func cloneAssociation(sa SecurityAssociation) SecurityAssociation {
	sa.Parameters.NoncePrefix = append([]byte(nil), sa.Parameters.NoncePrefix...)
	return sa
}
