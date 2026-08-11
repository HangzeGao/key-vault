package securitystate

import (
	"context"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/kvlt/key-vault/internal/protocol/ccsds"
)

var _ ccsds.Store = (*Store)(nil)

const associationColumns = `id,tenant_id,spi,direction,key_id,key_version,security_epoch,policy_version,
	suite_id,state,sequence_number_length,transmitted_iv_length,tag_length,replay_window,nonce_prefix`

func (s *Store) CreateAssociation(ctx context.Context, association ccsds.SecurityAssociation) error {
	if err := association.Validate(); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return wrap("begin association create", err)
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `INSERT INTO security_associations (`+associationColumns+`)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, association.ID, association.TenantID, association.SPI,
		string(association.Direction), association.KeyID, association.KeyVersion, association.SecurityEpoch,
		association.PolicyVersion, association.SuiteID, string(association.State), association.Parameters.SequenceNumberLength,
		association.Parameters.TransmittedIVLength, association.Parameters.TagLength, association.Parameters.ReplayWindow,
		association.Parameters.NoncePrefix)
	if err != nil {
		return conflict("create security association", err)
	}
	now := formatTime(time.Now())
	switch association.Direction {
	case ccsds.DirectionTCTx, ccsds.DirectionTCRecoveryTx:
		_, err = tx.ExecContext(ctx, `INSERT INTO tx_states(association_id,next_iv,updated_at) VALUES(?,0,?)`, association.ID, now)
	case ccsds.DirectionAOSRx:
		_, err = tx.ExecContext(ctx, `INSERT INTO rx_states(association_id,updated_at) VALUES(?,?)`, association.ID, now)
	}
	if err != nil {
		return wrap("create association runtime state", err)
	}
	return wrap("commit association create", tx.Commit())
}

func (s *Store) GetAssociation(ctx context.Context, tenantID, associationID string) (*ccsds.SecurityAssociation, error) {
	return scanAssociation(s.db.QueryRowContext(ctx, `SELECT `+associationColumns+`
		FROM security_associations WHERE tenant_id=? AND id=?`, tenantID, associationID))
}

func (s *Store) GetAssociationBySPI(ctx context.Context, tenantID string, direction ccsds.Direction, spi uint16) (*ccsds.SecurityAssociation, error) {
	return scanAssociation(s.db.QueryRowContext(ctx, `SELECT `+associationColumns+`
		FROM security_associations WHERE tenant_id=? AND direction=? AND spi=?`, tenantID, string(direction), spi))
}

func (s *Store) GetTransmitAssociation(ctx context.Context, tenantID string, direction ccsds.Direction) (*ccsds.SecurityAssociation, error) {
	state := ccsds.AssociationCurrent
	if direction == ccsds.DirectionTCRecoveryTx {
		state = ccsds.AssociationActive
	} else if direction != ccsds.DirectionTCTx {
		return nil, ccsds.ErrAssociationState
	}
	return scanAssociation(s.db.QueryRowContext(ctx, `SELECT `+associationColumns+`
		FROM security_associations WHERE tenant_id=? AND direction=? AND state=?`, tenantID, string(direction), string(state)))
}

func scanAssociation(row rowScanner) (*ccsds.SecurityAssociation, error) {
	var association ccsds.SecurityAssociation
	var direction, state string
	if err := row.Scan(&association.ID, &association.TenantID, &association.SPI, &direction, &association.KeyID,
		&association.KeyVersion, &association.SecurityEpoch, &association.PolicyVersion, &association.SuiteID, &state,
		&association.Parameters.SequenceNumberLength, &association.Parameters.TransmittedIVLength,
		&association.Parameters.TagLength, &association.Parameters.ReplayWindow, &association.Parameters.NoncePrefix); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ccsds.ErrAssociationNotFound
		}
		return nil, wrap("scan security association", err)
	}
	association.Direction = ccsds.Direction(direction)
	association.State = ccsds.AssociationState(state)
	if err := association.Validate(); err != nil {
		return nil, fmt.Errorf("securitystate: invalid persisted association %s: %w", association.ID, err)
	}
	return &association, nil
}

func (s *Store) ReadOperationsState(ctx context.Context, tenantID string) ([]ccsds.AssociationRuntimeState, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT sa.id,sa.spi,sa.direction,sa.state,sa.suite_id,sa.security_epoch,
		sa.key_version,sa.policy_version,sa.sequence_number_length,sa.transmitted_iv_length,sa.tag_length,
		sa.replay_window,tx.next_iv,rx.highest_sequence,rx.seen
		FROM security_associations sa
		LEFT JOIN tx_states tx ON tx.association_id=sa.id
		LEFT JOIN rx_states rx ON rx.association_id=sa.id
		WHERE sa.tenant_id=? AND sa.state<>'DISABLED' ORDER BY sa.direction,sa.spi`, tenantID)
	if err != nil {
		return nil, wrap("read operations state", err)
	}
	defer rows.Close()
	var states []ccsds.AssociationRuntimeState
	for rows.Next() {
		state, err := scanOperationsState(rows)
		if err != nil {
			return nil, err
		}
		states = append(states, *state)
	}
	return states, wrap("iterate operations state", rows.Err())
}

func scanOperationsState(row rowScanner) (*ccsds.AssociationRuntimeState, error) {
	var state ccsds.AssociationRuntimeState
	var direction, associationState string
	var nextIV sql.NullInt64
	var replayHighest sql.NullString
	var replaySeen sql.NullInt64
	if err := row.Scan(&state.ID, &state.SPI, &direction, &associationState, &state.SuiteID, &state.SecurityEpoch,
		&state.KeyVersion, &state.PolicyVersion, &state.SequenceNumberLength, &state.TransmittedIVLength,
		&state.TagLength, &state.ReplayWindow, &nextIV, &replayHighest, &replaySeen); err != nil {
		return nil, wrap("scan operations state", err)
	}
	state.Direction = ccsds.Direction(direction)
	state.State = ccsds.AssociationState(associationState)
	if nextIV.Valid {
		value := uint64(nextIV.Int64)
		state.NextIVCounter = &value
	}
	state.ReplaySeen = replaySeen.Valid && replaySeen.Int64 == 1
	if state.ReplaySeen && replayHighest.Valid {
		value, err := strconv.ParseUint(replayHighest.String, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("securitystate: decode replay highest: %w", err)
		}
		state.ReplayHighest = &value
	}
	return &state, nil
}

func (s *Store) ReadTCRotationState(ctx context.Context, tenantID string) (*ccsds.TCRotationState, error) {
	var state ccsds.TCRotationState
	var phase, transactionID string
	err := s.db.QueryRowContext(ctx, `SELECT phase,transaction_id,current_spi,next_spi,current_root_version,next_root_version
		FROM tc_rotation_states WHERE tenant_id=?`, tenantID).Scan(&phase, &transactionID, &state.CurrentSPI,
		&state.NextSPI, &state.CurrentRootVersion, &state.NextRootVersion)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ccsds.ErrAssociationNotFound
	}
	if err != nil {
		return nil, wrap("read TC rotation state", err)
	}
	state.Phase = ccsds.TCRotationPhase(phase)
	state.TransactionID, err = strconv.ParseUint(transactionID, 10, 64)
	if err != nil || state.TransactionID == 0 || state.NextSPI != ccsds.NextSPI(state.CurrentSPI) ||
		state.NextRootVersion <= state.CurrentRootVersion ||
		(state.Phase != ccsds.TCRotationPrepared && state.Phase != ccsds.TCRotationSwitching && state.Phase != ccsds.TCRotationActive) {
		return nil, errors.New("securitystate: invalid persisted TC rotation state")
	}
	return &state, nil
}

func (s *Store) MarkTCRotationPrepared(ctx context.Context, tenantID string, state ccsds.TCRotationState) error {
	if state.Phase != ccsds.TCRotationPrepared || state.TransactionID == 0 ||
		state.NextSPI != ccsds.NextSPI(state.CurrentSPI) || state.NextRootVersion <= state.CurrentRootVersion {
		return ccsds.ErrAssociationState
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return wrap("begin TC rotation prepare", err)
	}
	defer tx.Rollback()
	var count int
	err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM security_associations WHERE tenant_id=? AND direction='TC_TX' AND
		((state='CURRENT' AND spi=? AND key_version=?) OR (state='NEXT' AND spi=? AND key_version=?))`,
		tenantID, state.CurrentSPI, state.CurrentRootVersion, state.NextSPI, state.NextRootVersion).Scan(&count)
	if err != nil {
		return wrap("validate TC rotation associations", err)
	}
	if count != 2 {
		return ccsds.ErrAssociationState
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO tc_rotation_states(tenant_id,phase,transaction_id,current_spi,next_spi,
		current_root_version,next_root_version,updated_at) VALUES(?,?,?,?,?,?,?,?)
		ON CONFLICT(tenant_id) DO UPDATE SET phase=excluded.phase,transaction_id=excluded.transaction_id,
		current_spi=excluded.current_spi,next_spi=excluded.next_spi,current_root_version=excluded.current_root_version,
		next_root_version=excluded.next_root_version,updated_at=excluded.updated_at`, tenantID, string(state.Phase),
		strconv.FormatUint(state.TransactionID, 10), state.CurrentSPI, state.NextSPI, state.CurrentRootVersion,
		state.NextRootVersion, formatTime(time.Now()))
	if err != nil {
		return wrap("write TC rotation prepare", err)
	}
	return wrap("commit TC rotation prepare", tx.Commit())
}

func (s *Store) MarkTCRotationFrameProduced(ctx context.Context, tenantID, associationID string) error {
	result, err := s.db.ExecContext(ctx, `UPDATE tc_rotation_states SET phase='ACTIVE',updated_at=? WHERE tenant_id=? AND phase='SWITCHING'
		AND EXISTS(SELECT 1 FROM security_associations sa WHERE sa.id=? AND sa.tenant_id=tc_rotation_states.tenant_id
		AND sa.direction='TC_TX' AND sa.state='CURRENT' AND sa.spi=tc_rotation_states.next_spi
		AND sa.key_version=tc_rotation_states.next_root_version)`, formatTime(time.Now()), tenantID, associationID)
	if err != nil {
		return wrap("complete TC rotation", err)
	}
	if count, _ := result.RowsAffected(); count == 1 {
		return nil
	}
	var phase string
	err = s.db.QueryRowContext(ctx, `SELECT phase FROM tc_rotation_states WHERE tenant_id=?`, tenantID).Scan(&phase)
	if errors.Is(err, sql.ErrNoRows) || phase == string(ccsds.TCRotationActive) {
		return nil
	}
	if err != nil {
		return wrap("read TC rotation completion", err)
	}
	return ccsds.ErrAssociationState
}

func (s *Store) PromoteNextTC(ctx context.Context, tenantID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return wrap("begin TC promotion", err)
	}
	defer tx.Rollback()
	current, err := scanAssociation(tx.QueryRowContext(ctx, `SELECT `+associationColumns+`
		FROM security_associations WHERE tenant_id=? AND direction='TC_TX' AND state='CURRENT'`, tenantID))
	if err != nil {
		return ccsds.ErrAssociationState
	}
	next, err := scanAssociation(tx.QueryRowContext(ctx, `SELECT `+associationColumns+`
		FROM security_associations WHERE tenant_id=? AND direction='TC_TX' AND state='NEXT'`, tenantID))
	if err != nil {
		return ccsds.ErrAssociationState
	}
	var rotationPhase, transactionID string
	var rotationCurrentSPI, rotationNextSPI uint16
	var rotationCurrentVersion, rotationNextVersion uint32
	err = tx.QueryRowContext(ctx, `SELECT phase,transaction_id,current_spi,next_spi,current_root_version,next_root_version
		FROM tc_rotation_states WHERE tenant_id=?`, tenantID).Scan(&rotationPhase, &transactionID,
		&rotationCurrentSPI, &rotationNextSPI, &rotationCurrentVersion, &rotationNextVersion)
	parsedTransactionID, parseErr := strconv.ParseUint(transactionID, 10, 64)
	if err != nil || parseErr != nil || parsedTransactionID == 0 || rotationPhase != string(ccsds.TCRotationPrepared) ||
		rotationCurrentSPI != current.SPI || rotationNextSPI != next.SPI ||
		rotationCurrentVersion != current.KeyVersion || rotationNextVersion != next.KeyVersion {
		return ccsds.ErrAssociationState
	}
	if next.SPI != ccsds.NextSPI(current.SPI) ||
		next.SecurityEpoch != current.SecurityEpoch+1 || string(next.Parameters.NoncePrefix) != string(current.Parameters.NoncePrefix) {
		return ccsds.ErrAssociationState
	}
	result, err := tx.ExecContext(ctx, `UPDATE security_associations SET state='DISABLED' WHERE id=? AND state='CURRENT'`, current.ID)
	if err != nil {
		return wrap("disable current TC", err)
	}
	if count, _ := result.RowsAffected(); count != 1 {
		return ccsds.ErrAssociationState
	}
	result, err = tx.ExecContext(ctx, `UPDATE security_associations SET state='CURRENT' WHERE id=? AND state='NEXT'`, next.ID)
	if err != nil {
		return wrap("promote next TC", err)
	}
	if count, _ := result.RowsAffected(); count != 1 {
		return ccsds.ErrAssociationState
	}
	result, err = tx.ExecContext(ctx, `UPDATE tc_rotation_states SET phase='SWITCHING',updated_at=?
		WHERE tenant_id=? AND phase='PREPARED'`, formatTime(time.Now()), tenantID)
	if err != nil {
		return wrap("advance TC rotation state", err)
	}
	if count, _ := result.RowsAffected(); count != 1 {
		return ccsds.ErrAssociationState
	}
	return wrap("commit TC promotion", tx.Commit())
}

func (s *Store) NextTransmitCounter(ctx context.Context, associationID string) (uint32, error) {
	var allocated int64
	err := s.db.QueryRowContext(ctx, `UPDATE tx_states SET next_iv=next_iv+1,updated_at=?
		WHERE association_id=? AND next_iv<4294967296 AND EXISTS(
			SELECT 1 FROM security_associations sa WHERE sa.id=tx_states.association_id AND
			((sa.direction='TC_TX' AND sa.state='CURRENT') OR (sa.direction='TC_RECOVERY_TX' AND sa.state='ACTIVE')))
		RETURNING next_iv-1`, formatTime(time.Now()), associationID).Scan(&allocated)
	if err == nil {
		return uint32(allocated), nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return 0, wrap("allocate transmit IV", err)
	}
	var next int64
	var direction, state string
	err = s.db.QueryRowContext(ctx, `SELECT sa.direction,sa.state,tx.next_iv FROM security_associations sa
		LEFT JOIN tx_states tx ON tx.association_id=sa.id WHERE sa.id=?`, associationID).Scan(&direction, &state, &next)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ccsds.ErrAssociationNotFound
	}
	if err != nil {
		return 0, wrap("read transmit IV state", err)
	}
	if next >= int64(uint64(1)<<32) {
		return 0, ccsds.ErrCounterExhausted
	}
	return 0, ccsds.ErrAssociationState
}

func (s *Store) CheckReplay(ctx context.Context, associationID string, sequence uint64, window uint8) error {
	state, err := s.loadReplay(ctx, s.db, associationID)
	if err != nil {
		return err
	}
	return state.Check(sequence, window)
}

func (s *Store) CommitReplay(ctx context.Context, associationID string, sequence uint64, window uint8) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return wrap("begin replay commit", err)
	}
	defer tx.Rollback()
	state, err := s.loadReplay(ctx, tx, associationID)
	if err != nil {
		return err
	}
	if err := state.Commit(sequence, window); err != nil {
		return err
	}
	bitmap := make([]byte, 8)
	binary.BigEndian.PutUint64(bitmap, state.Bitmap)
	result, err := tx.ExecContext(ctx, `UPDATE rx_states SET highest_sequence=?,bitmap=?,seen=?,updated_at=? WHERE association_id=?`,
		strconv.FormatUint(state.Highest, 10), bitmap, boolInt(state.Seen), formatTime(time.Now()), associationID)
	if err != nil {
		return wrap("update replay state", err)
	}
	if count, _ := result.RowsAffected(); count != 1 {
		return ccsds.ErrAssociationState
	}
	return wrap("commit replay state", tx.Commit())
}

type queryRower interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func (s *Store) loadReplay(ctx context.Context, query queryRower, associationID string) (ccsds.ReplayState, error) {
	var state ccsds.ReplayState
	var highest string
	var bitmap []byte
	var seen int
	err := query.QueryRowContext(ctx, `SELECT rx.highest_sequence,rx.bitmap,rx.seen FROM rx_states rx
		JOIN security_associations sa ON sa.id=rx.association_id
		WHERE rx.association_id=? AND sa.direction='AOS_RX' AND sa.state='ACTIVE'`, associationID).
		Scan(&highest, &bitmap, &seen)
	if errors.Is(err, sql.ErrNoRows) {
		return state, ccsds.ErrAssociationState
	}
	if err != nil {
		return state, wrap("load replay state", err)
	}
	if len(bitmap) != 8 {
		return state, fmt.Errorf("securitystate: invalid replay bitmap length %d", len(bitmap))
	}
	state.Highest, err = strconv.ParseUint(highest, 10, 64)
	if err != nil {
		return state, fmt.Errorf("securitystate: decode replay sequence: %w", err)
	}
	state.Bitmap = binary.BigEndian.Uint64(bitmap)
	state.Seen = seen == 1
	return state, nil
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
