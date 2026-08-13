package securitystate

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

type DownlinkKeyState struct {
	ActiveKEKSlot      uint8
	SealedKEKSet       []byte
	CurrentGeneration  uint32
	CurrentObserved    bool
	CurrentPackage     []byte
	CurrentDigest      [32]byte
	PreviousGeneration uint32
	PreviousPackage    []byte
	PreviousDigest     [32]byte
}

func (s *Store) ReadDownlinkKeyState(ctx context.Context) (*DownlinkKeyState, error) {
	var state DownlinkKeyState
	var currentGeneration, previousGeneration sql.NullInt64
	var currentObserved int
	var currentDigest, previousDigest []byte
	err := s.db.QueryRowContext(ctx, `SELECT active_kek_slot,sealed_kek_set,current_generation,current_observed,
		current_package,current_digest,previous_generation,previous_package,previous_digest
		FROM downlink_key_state WHERE singleton=1`).Scan(&state.ActiveKEKSlot, &state.SealedKEKSet,
		&currentGeneration, &currentObserved, &state.CurrentPackage, &currentDigest,
		&previousGeneration, &state.PreviousPackage, &previousDigest)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, wrap("read downlink key state", err)
	}
	state.CurrentObserved = currentObserved == 1
	if currentGeneration.Valid {
		state.CurrentGeneration = uint32(currentGeneration.Int64)
		if len(currentDigest) != len(state.CurrentDigest) {
			return nil, errors.New("securitystate: corrupt current downlink digest")
		}
		copy(state.CurrentDigest[:], currentDigest)
	}
	if previousGeneration.Valid {
		state.PreviousGeneration = uint32(previousGeneration.Int64)
		if len(previousDigest) != len(state.PreviousDigest) {
			return nil, errors.New("securitystate: corrupt previous downlink digest")
		}
		copy(state.PreviousDigest[:], previousDigest)
	}
	return &state, nil
}

func (s *Store) ProvisionDownlinkKEKSet(ctx context.Context, sealed []byte, activeSlot uint8) error {
	if len(sealed) == 0 || activeSlot > 7 {
		return errors.New("securitystate: invalid downlink KEK set")
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO downlink_key_state(singleton,active_kek_slot,sealed_kek_set,updated_at)
		VALUES(1,?,?,?)`, activeSlot, sealed, formatTimeNow())
	return conflict("provision downlink KEK set", err)
}

func (s *Store) SetActiveDownlinkKEKSlot(ctx context.Context, slot uint8) error {
	if slot > 7 {
		return errors.New("securitystate: invalid KEK slot")
	}
	result, err := s.db.ExecContext(ctx, `UPDATE downlink_key_state SET active_kek_slot=?,updated_at=? WHERE singleton=1`,
		slot, formatTimeNow())
	if err != nil {
		return wrap("set active downlink KEK slot", err)
	}
	if count, _ := result.RowsAffected(); count != 1 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) AdvanceDownlinkBatch(ctx context.Context, expectedGeneration uint32, encoded []byte, digest [32]byte) error {
	if len(encoded) != 16417 || digest == ([32]byte{}) {
		return errors.New("securitystate: invalid downlink package")
	}
	next := expectedGeneration + 1
	if next == 0 {
		return errors.New("securitystate: downlink generation exhausted")
	}
	result, err := s.db.ExecContext(ctx, `UPDATE downlink_key_state SET
		previous_generation=current_generation,previous_package=current_package,previous_digest=current_digest,
		current_generation=?,current_package=?,current_digest=?,current_observed=0,updated_at=?
		WHERE singleton=1 AND COALESCE(current_generation,0)=? AND (current_generation IS NULL OR current_observed=1)`,
		next, encoded, digest[:], formatTimeNow(), expectedGeneration)
	if err != nil {
		return wrap("advance downlink batch", err)
	}
	if count, _ := result.RowsAffected(); count != 1 {
		return ErrConflict
	}
	return nil
}

func (s *Store) MarkCurrentDownlinkObserved(ctx context.Context, generation uint32) error {
	result, err := s.db.ExecContext(ctx, `UPDATE downlink_key_state SET current_observed=1,updated_at=?
		WHERE singleton=1 AND current_generation=?`, formatTimeNow(), generation)
	if err != nil {
		return wrap("observe current downlink batch", err)
	}
	if count, _ := result.RowsAffected(); count != 1 {
		return ErrConflict
	}
	return nil
}

func formatTimeNow() string { return formatTime(timeNow()) }

var timeNow = func() time.Time { return time.Now() }
