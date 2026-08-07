package postgres

import (
	"context"
	"encoding/binary"
	"fmt"
	"strconv"

	"github.com/jackc/pgx/v5"
	"github.com/kvlt/key-vault/internal/protocol/ccsds"
)

var _ ccsds.Store = (*Store)(nil)

const associationColumns = `id, tenant_id, spi, direction, key_id, key_version,
	policy_version, suite_id, state, sequence_number_length,
	transmitted_iv_length, tag_length, replay_window, nonce_prefix`

// CreateCCSDSAssociation provisions an immutable CCSDS key binding and its
// direction-specific state. Only protocol-scoped key material can be bound.
func (s *Store) CreateCCSDSAssociation(ctx context.Context, sa ccsds.SecurityAssociation) error {
	if err := sa.Validate(); err != nil {
		return err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	result, err := tx.Exec(ctx, `INSERT INTO ccsds_security_associations (`+associationColumns+`)
		SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14
		FROM keys k
		JOIN key_versions kv ON kv.key_id=k.id AND kv.version_no=$6
		WHERE k.id=$5 AND k.tenant_id=$2 AND k.usage_scope='PROTOCOL'
		  AND k.suite_id=$8 AND kv.suite_id=$8`,
		sa.ID, sa.TenantID, sa.SPI, sa.Direction, sa.KeyID, sa.KeyVersion,
		sa.PolicyVersion, sa.SuiteID, sa.State,
		sa.Parameters.SequenceNumberLength, sa.Parameters.TransmittedIVLength,
		sa.Parameters.TagLength, sa.Parameters.ReplayWindow, sa.Parameters.NoncePrefix)
	if err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("%w: duplicate CCSDS association, SPI, or key binding", ErrConflict)
		}
		return err
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("%w: CCSDS association requires an exact protocol-scoped key version and matching suite", ErrConflict)
	}

	if sa.Direction == ccsds.DirectionTCTx || sa.Direction == ccsds.DirectionTCRecoveryTx {
		_, err = tx.Exec(ctx, `INSERT INTO ccsds_tx_states (association_id) VALUES ($1)`, sa.ID)
	} else {
		_, err = tx.Exec(ctx, `INSERT INTO ccsds_rx_replay_states (association_id) VALUES ($1)`, sa.ID)
	}
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) GetAssociation(ctx context.Context, tenantID, associationID string) (*ccsds.SecurityAssociation, error) {
	row := s.pool.QueryRow(ctx, `SELECT `+associationColumns+`
		FROM ccsds_security_associations WHERE tenant_id=$1 AND id=$2`, tenantID, associationID)
	return scanAssociation(row)
}

func (s *Store) GetAssociationBySPI(ctx context.Context, tenantID string, direction ccsds.Direction, spi uint16) (*ccsds.SecurityAssociation, error) {
	row := s.pool.QueryRow(ctx, `SELECT `+associationColumns+`
		FROM ccsds_security_associations WHERE tenant_id=$1 AND direction=$2 AND spi=$3`, tenantID, direction, spi)
	return scanAssociation(row)
}

func (s *Store) NextTransmitCounter(ctx context.Context, associationID string) (uint32, error) {
	var value string
	err := s.pool.QueryRow(ctx, `UPDATE ccsds_tx_states tx
		SET next_iv_counter=tx.next_iv_counter+1, updated_at=NOW()
		FROM ccsds_security_associations sa
		WHERE tx.association_id=$1 AND sa.id=tx.association_id
		  AND sa.direction IN ('TC_TX','TC_RECOVERY_TX') AND sa.state='ACTIVE'
		  AND tx.next_iv_counter < 4294967296
		RETURNING (tx.next_iv_counter-1)::text`, associationID).Scan(&value)
	if isNoRows(err) {
		var direction ccsds.Direction
		var state ccsds.AssociationState
		var next *int64
		stateErr := s.pool.QueryRow(ctx, `SELECT sa.direction, sa.state, tx.next_iv_counter
			FROM ccsds_security_associations sa
			LEFT JOIN ccsds_tx_states tx ON tx.association_id=sa.id
			WHERE sa.id=$1`, associationID).Scan(&direction, &state, &next)
		if isNoRows(stateErr) {
			return 0, ccsds.ErrAssociationNotFound
		}
		if stateErr != nil {
			return 0, stateErr
		}
		if (direction != ccsds.DirectionTCTx && direction != ccsds.DirectionTCRecoveryTx) || state != ccsds.AssociationActive || next == nil {
			return 0, ccsds.ErrAssociationState
		}
		if *next >= int64(uint64(1)<<32) {
			return 0, ccsds.ErrCounterExhausted
		}
		return 0, fmt.Errorf("postgres: TC IV counter allocation returned no row")
	}
	if err != nil {
		return 0, err
	}
	counter, err := strconv.ParseUint(value, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("postgres: decode CCSDS transmit IV counter: %w", err)
	}
	return uint32(counter), nil
}

func (s *Store) CheckReplay(ctx context.Context, associationID string, sequence uint64, window uint8) error {
	state, err := s.loadReplayState(ctx, s.pool, associationID, false)
	if err != nil {
		return err
	}
	return state.Check(sequence, window)
}

func (s *Store) CommitReplay(ctx context.Context, associationID string, sequence uint64, window uint8) error {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	state, err := s.loadReplayState(ctx, tx, associationID, true)
	if err != nil {
		return err
	}
	if err := state.Commit(sequence, window); err != nil {
		return err
	}
	bitmap := make([]byte, 8)
	binary.BigEndian.PutUint64(bitmap, state.Bitmap)
	_, err = tx.Exec(ctx, `UPDATE ccsds_rx_replay_states
		SET highest_sequence=$2::numeric, bitmap=$3, seen=$4, updated_at=NOW()
		WHERE association_id=$1`, associationID, strconv.FormatUint(state.Highest, 10), bitmap, state.Seen)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

type replayQuerier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

func (s *Store) loadReplayState(ctx context.Context, q replayQuerier, associationID string, lock bool) (ccsds.ReplayState, error) {
	query := `SELECT rx.highest_sequence::text, rx.bitmap, rx.seen
		FROM ccsds_rx_replay_states rx
		JOIN ccsds_security_associations sa ON sa.id=rx.association_id
		WHERE rx.association_id=$1 AND sa.direction='AOS_RX'
		  AND sa.state IN ('ACTIVE','GRACE')`
	if lock {
		query += ` FOR UPDATE OF rx`
	}
	var highestText string
	var bitmap []byte
	var state ccsds.ReplayState
	if err := q.QueryRow(ctx, query, associationID).Scan(&highestText, &bitmap, &state.Seen); err != nil {
		if isNoRows(err) {
			return state, ccsds.ErrAssociationState
		}
		return state, err
	}
	if len(bitmap) != 8 {
		return state, fmt.Errorf("postgres: invalid CCSDS replay bitmap length %d", len(bitmap))
	}
	highest, err := strconv.ParseUint(highestText, 10, 64)
	if err != nil {
		return state, fmt.Errorf("postgres: decode CCSDS replay sequence: %w", err)
	}
	state.Highest = highest
	state.Bitmap = binary.BigEndian.Uint64(bitmap)
	return state, nil
}

func scanAssociation(row scanner) (*ccsds.SecurityAssociation, error) {
	var sa ccsds.SecurityAssociation
	err := row.Scan(
		&sa.ID, &sa.TenantID, &sa.SPI, &sa.Direction, &sa.KeyID,
		&sa.KeyVersion, &sa.PolicyVersion, &sa.SuiteID, &sa.State,
		&sa.Parameters.SequenceNumberLength, &sa.Parameters.TransmittedIVLength,
		&sa.Parameters.TagLength, &sa.Parameters.ReplayWindow, &sa.Parameters.NoncePrefix,
	)
	if isNoRows(err) {
		return nil, ccsds.ErrAssociationNotFound
	}
	if err != nil {
		return nil, err
	}
	return &sa, nil
}
