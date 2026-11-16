package securitystate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
)

// StageGroundCommissioning commits an isolated installation record. It does
// not create runtime keys, associations, a mission binding or nonce state.
// A retry with the same signed binding preserves the first durable installation.
func (s *Store) StageGroundCommissioning(ctx context.Context, tenant string, transaction, binding [32]byte, sealed []byte) error {
	if tenant == "" || transaction == ([32]byte{}) || binding == ([32]byte{}) || len(sealed) == 0 || len(sealed) > 64<<10 {
		return ErrConflict
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var operational bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM mission_profiles WHERE tenant_id=?)
		OR EXISTS(SELECT 1 FROM protocol_keys WHERE tenant_id=?)
		OR EXISTS(SELECT 1 FROM security_associations WHERE tenant_id=?)`, tenant, tenant, tenant).Scan(&operational); err != nil {
		return err
	}
	if operational {
		return ErrConflict
	}
	var existingTransaction, existingBinding, payload, payloadDigest []byte
	err = tx.QueryRowContext(ctx, `SELECT transaction_id, binding_digest, sealed_installation, installation_digest
		FROM ground_commissioning WHERE tenant_id=?`, tenant).Scan(&existingTransaction, &existingBinding, &payload, &payloadDigest)
	if err == nil {
		digest := sha256.Sum256(payload)
		if !bytes.Equal(existingTransaction, transaction[:]) || !bytes.Equal(existingBinding, binding[:]) || !bytes.Equal(payloadDigest, digest[:]) {
			return ErrConflict
		}
		return tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	digest := sha256.Sum256(sealed)
	if _, err := tx.ExecContext(ctx, `INSERT INTO ground_commissioning
		(tenant_id, transaction_id, binding_digest, sealed_installation, installation_digest) VALUES(?,?,?,?,?)`,
		tenant, transaction[:], binding[:], sealed, digest[:]); err != nil {
		return err
	}
	return tx.Commit()
}
