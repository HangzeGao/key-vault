package downlink

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/kvlt/key-vault/internal/crypto/aad"
	"github.com/kvlt/key-vault/internal/tpm/provider"
)

const (
	kekSetPurpose = "downlink-kek-set"
	kekSetObject  = "singleton"
)

type KEKSealer interface {
	SealKEKSet(context.Context, []byte) ([]byte, error)
	UnsealKEKSet(context.Context, []byte) ([]byte, error)
}

type TPMSealer struct {
	provider provider.Provider
	storage  *provider.TPMObjectRef
	context  aad.SealContext
}

func NewTPMSealer(ctx context.Context, tpm provider.Provider, storageName, nodeID string,
	baselineDigest, policyDigest []byte) (*TPMSealer, error) {
	if tpm == nil || storageName == "" || nodeID == "" || len(baselineDigest) == 0 || len(policyDigest) == 0 {
		return nil, errors.New("downlink: incomplete TPM sealing context")
	}
	storage, err := tpm.EnsureStorage(ctx, storageName)
	if err != nil {
		return nil, err
	}
	return &TPMSealer{provider: tpm, storage: storage, context: aad.SealContext{
		Purpose: kekSetPurpose, ObjectID: kekSetObject, NodeID: nodeID, StorageName: storageName,
		BaselineDigest: append([]byte(nil), baselineDigest...), PolicyDigest: append([]byte(nil), policyDigest...),
	}}, nil
}

func (s *TPMSealer) SealKEKSet(ctx context.Context, kekSet []byte) ([]byte, error) {
	if len(kekSet) != KEKSetBytes {
		return nil, ErrInvalid
	}
	copyOfSet := append([]byte(nil), kekSet...)
	defer zeroize(copyOfSet)
	object, err := s.provider.Seal(ctx, s.storage, copyOfSet, s.context)
	if err != nil {
		return nil, err
	}
	return json.Marshal(object)
}

func (s *TPMSealer) UnsealKEKSet(ctx context.Context, encoded []byte) ([]byte, error) {
	var object provider.SealedObject
	if err := json.Unmarshal(encoded, &object); err != nil {
		return nil, errors.New("downlink: corrupt sealed KEK set")
	}
	plaintext, err := s.provider.Unseal(ctx, s.storage, &object, s.context)
	if err != nil {
		return nil, err
	}
	if len(plaintext) != KEKSetBytes {
		zeroize(plaintext)
		return nil, errors.New("downlink: invalid unsealed KEK set length")
	}
	return plaintext, nil
}
