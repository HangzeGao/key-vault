package securitystate

import (
	"bytes"
	"context"
	"database/sql"
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
		sa.replay_window,tx.next_iv
		FROM security_associations sa
		LEFT JOIN tx_states tx ON tx.association_id=sa.id
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
	if err := row.Scan(&state.ID, &state.SPI, &direction, &associationState, &state.SuiteID, &state.SecurityEpoch,
		&state.KeyVersion, &state.PolicyVersion, &state.SequenceNumberLength, &state.TransmittedIVLength,
		&state.TagLength, &state.ReplayWindow, &nextIV); err != nil {
		return nil, wrap("scan operations state", err)
	}
	state.Direction = ccsds.Direction(direction)
	state.State = ccsds.AssociationState(associationState)
	if nextIV.Valid {
		value := uint64(nextIV.Int64)
		state.NextIVCounter = &value
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

func (s *Store) BindMissionProfile(ctx context.Context, tenantID string, digest [32]byte) error {
	if tenantID == "" || digest == ([32]byte{}) {
		return ccsds.ErrAssociationState
	}
	var existing []byte
	err := s.db.QueryRowContext(ctx, `SELECT profile_digest FROM mission_profiles WHERE tenant_id=?`, tenantID).Scan(&existing)
	if err == nil {
		if !bytes.Equal(existing, digest[:]) {
			return ccsds.ErrAssociationState
		}
		return nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return wrap("read mission profile binding", err)
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO mission_profiles(tenant_id,profile_digest,bound_at) VALUES(?,?,?)`,
		tenantID, digest[:], formatTime(time.Now()))
	return conflict("bind mission profile", err)
}

func (s *Store) ReadMissionProfileDigest(ctx context.Context, tenantID string) ([32]byte, error) {
	var digest [32]byte
	var encoded []byte
	err := s.db.QueryRowContext(ctx, `SELECT profile_digest FROM mission_profiles WHERE tenant_id=?`, tenantID).Scan(&encoded)
	if errors.Is(err, sql.ErrNoRows) {
		return digest, ccsds.ErrAssociationNotFound
	}
	if err != nil {
		return digest, wrap("read mission profile binding", err)
	}
	if len(encoded) != len(digest) {
		return digest, errors.New("securitystate: invalid mission profile digest")
	}
	copy(digest[:], encoded)
	return digest, nil
}

func (s *Store) ObserveFlightSecurityStatus(ctx context.Context, tenantID string, status ccsds.FlightSecurityStatus) error {
	if tenantID == "" || status.Validate() != nil {
		return ccsds.ErrAssociationState
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO flight_security_status(
		tenant_id,format_version,profile_digest,self_test,crypto_backend,current_spi,next_spi,recovery_spi,
		security_epoch,root_version,pending_root_present,receive_count,last_receive_us,max_receive_us,
		cycle_limit_exceeded_count,clock_anomaly_count,observed_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(tenant_id) DO UPDATE SET
		format_version=excluded.format_version,profile_digest=excluded.profile_digest,self_test=excluded.self_test,
		crypto_backend=excluded.crypto_backend,current_spi=excluded.current_spi,next_spi=excluded.next_spi,
		recovery_spi=excluded.recovery_spi,security_epoch=excluded.security_epoch,root_version=excluded.root_version,
		pending_root_present=excluded.pending_root_present,receive_count=excluded.receive_count,
		last_receive_us=excluded.last_receive_us,max_receive_us=excluded.max_receive_us,
		cycle_limit_exceeded_count=excluded.cycle_limit_exceeded_count,clock_anomaly_count=excluded.clock_anomaly_count,
		observed_at=excluded.observed_at`, tenantID, status.FormatVersion, status.ProfileDigest[:], string(status.SelfTest),
		string(status.CryptoBackend), status.CurrentSPI, status.NextSPI, status.RecoverySPI, status.SecurityEpoch,
		status.RootVersion, status.PendingRootPresent, strconv.FormatUint(status.ReceiveCount, 10),
		strconv.FormatUint(status.LastReceiveUS, 10), strconv.FormatUint(status.MaxReceiveUS, 10),
		strconv.FormatUint(status.CycleLimitExceededCount, 10), strconv.FormatUint(status.ClockAnomalyCount, 10),
		formatTime(time.Now()))
	return wrap("observe flight security status", err)
}

func (s *Store) ReadFlightSecurityStatus(ctx context.Context, tenantID string) (*ccsds.ObservedFlightSecurityStatus, error) {
	var status ccsds.ObservedFlightSecurityStatus
	var digest []byte
	var selfTest, backend, receiveCount, lastUS, maxUS, exceeded, anomalies, observedAt string
	err := s.db.QueryRowContext(ctx, `SELECT format_version,profile_digest,self_test,crypto_backend,current_spi,
		next_spi,recovery_spi,security_epoch,root_version,pending_root_present,receive_count,last_receive_us,
		max_receive_us,cycle_limit_exceeded_count,clock_anomaly_count,observed_at
		FROM flight_security_status WHERE tenant_id=?`, tenantID).Scan(&status.FormatVersion, &digest, &selfTest,
		&backend, &status.CurrentSPI, &status.NextSPI, &status.RecoverySPI, &status.SecurityEpoch, &status.RootVersion,
		&status.PendingRootPresent, &receiveCount, &lastUS, &maxUS, &exceeded, &anomalies, &observedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ccsds.ErrAssociationNotFound
	}
	if err != nil {
		return nil, wrap("read flight security status", err)
	}
	if len(digest) != len(status.ProfileDigest) {
		return nil, errors.New("securitystate: invalid flight status digest")
	}
	copy(status.ProfileDigest[:], digest)
	status.SelfTest = ccsds.FlightSelfTestState(selfTest)
	status.CryptoBackend = ccsds.FlightCryptoBackend(backend)
	values := []*uint64{&status.ReceiveCount, &status.LastReceiveUS, &status.MaxReceiveUS,
		&status.CycleLimitExceededCount, &status.ClockAnomalyCount}
	texts := []string{receiveCount, lastUS, maxUS, exceeded, anomalies}
	for index := range values {
		value, parseErr := strconv.ParseUint(texts[index], 10, 64)
		if parseErr != nil {
			return nil, errors.New("securitystate: invalid flight status counter")
		}
		*values[index] = value
	}
	status.ObservedAt, err = parseTime(observedAt)
	if err != nil || status.Validate() != nil {
		return nil, errors.New("securitystate: invalid persisted flight security status")
	}
	return &status, nil
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
