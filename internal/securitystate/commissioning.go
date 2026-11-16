package securitystate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
)

// StageGroundCommissioning returns the commitment of the first durable
// installation. If the anchor has already been written, the staged record
// must exist and match it. Otherwise prepare either seals a new installation
// or authenticates every part of an existing, not yet anchored candidate.
func (s *Store) StageGroundCommissioning(ctx context.Context, tenant string, transaction, binding, anchor [32]byte,
	prepare func(existing []byte) ([]byte, error)) ([32]byte, error) {
	if tenant == "" || transaction == ([32]byte{}) || binding == ([32]byte{}) || prepare == nil {
		return [32]byte{}, ErrConflict
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return [32]byte{}, err
	}
	defer tx.Rollback()
	var operational bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM mission_profiles WHERE tenant_id=?)
		OR EXISTS(SELECT 1 FROM protocol_keys WHERE tenant_id=?)
		OR EXISTS(SELECT 1 FROM security_associations WHERE tenant_id=?)`, tenant, tenant, tenant).Scan(&operational); err != nil {
		return [32]byte{}, err
	}
	if operational {
		return [32]byte{}, ErrConflict
	}
	var existingTransaction, existingBinding, payload, payloadDigest []byte
	err = tx.QueryRowContext(ctx, `SELECT transaction_id, binding_digest, sealed_installation, installation_digest
		FROM ground_commissioning WHERE tenant_id=?`, tenant).Scan(&existingTransaction, &existingBinding, &payload, &payloadDigest)
	if err == nil {
		digest := sha256.Sum256(payload)
		if !bytes.Equal(existingTransaction, transaction[:]) || !bytes.Equal(existingBinding, binding[:]) || !bytes.Equal(payloadDigest, digest[:]) {
			return [32]byte{}, ErrConflict
		}
		commitment := groundInstallationCommitment(transaction, binding, digest)
		if anchor != ([32]byte{}) {
			if commitment != anchor {
				return [32]byte{}, ErrConflict
			}
		} else if verified, err := prepare(payload); err != nil || !bytes.Equal(payload, verified) {
			return [32]byte{}, ErrConflict
		}
		return commitment, tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return [32]byte{}, err
	}
	if anchor != ([32]byte{}) {
		return [32]byte{}, ErrConflict
	}
	sealed, err := prepare(nil)
	if err != nil {
		return [32]byte{}, err
	}
	if len(sealed) == 0 || len(sealed) > 64<<10 {
		return [32]byte{}, ErrConflict
	}
	digest := sha256.Sum256(sealed)
	if _, err := tx.ExecContext(ctx, `INSERT INTO ground_commissioning
		(tenant_id, transaction_id, binding_digest, sealed_installation, installation_digest) VALUES(?,?,?,?,?)`,
		tenant, transaction[:], binding[:], sealed, digest[:]); err != nil {
		return [32]byte{}, err
	}
	return groundInstallationCommitment(transaction, binding, digest), tx.Commit()
}

func groundInstallationCommitment(transaction, binding, installation [32]byte) [32]byte {
	message := append([]byte("TC-GROUND-STAGED-V1\x00"), transaction[:]...)
	message = append(message, binding[:]...)
	return sha256.Sum256(append(message, installation[:]...))
}
