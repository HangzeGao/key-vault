// Package keyresolver is the only protocol path allowed to unseal TPM-backed
// protocol roots. Every root is sealed directly; no intermediate CRK or
// software wrapping key exists.
package keyresolver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/kvlt/key-vault/internal/crypto/aad"
	"github.com/kvlt/key-vault/internal/crypto/suite"
	"github.com/kvlt/key-vault/internal/tpm/provider"
)

const protocolRootPurpose = "ccsds-protocol-root"

type Material struct {
	SealedMaterial []byte
}

type KeyLease struct {
	KeyVersionID string
	TenantID     string
	KeyID        string
	KeyVersion   uint32
	SuiteID      suite.ID
	Purpose      string
	NodeID       string
	Key          []byte
}

type Resolver struct {
	mu        sync.RWMutex
	tpm       provider.Provider
	storage   *provider.TPMObjectRef
	nodeID    string
	baseline  []byte
	policyDig []byte
	fetch     func(context.Context, string) ([]byte, error)
}

func New(tpm provider.Provider) *Resolver { return &Resolver{tpm: tpm} }

func (r *Resolver) Init(ctx context.Context, storageName, nodeID string, baseline, policyDigest []byte) error {
	if storageName == "" || nodeID == "" || len(baseline) == 0 || len(policyDigest) == 0 {
		return errors.New("keyresolver: incomplete TPM context")
	}
	storage, err := r.tpm.EnsureStorage(ctx, storageName)
	if err != nil {
		return fmt.Errorf("keyresolver: ensure storage: %w", err)
	}
	r.mu.Lock()
	r.storage = storage
	r.nodeID = nodeID
	r.baseline = append([]byte(nil), baseline...)
	r.policyDig = append([]byte(nil), policyDigest...)
	r.mu.Unlock()
	return nil
}

func (r *Resolver) Ready() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.storage != nil
}

func (r *Resolver) SealExternalKey(ctx context.Context, suiteID suite.ID, keyVersionID string, key []byte) (*Material, error) {
	if keyVersionID == "" || len(key) != suiteID.KeyBytes() {
		return nil, errors.New("keyresolver: invalid protocol key")
	}
	storage, sealContext, err := r.context(keyVersionID)
	if err != nil {
		return nil, err
	}
	copyOfKey := append([]byte(nil), key...)
	defer zeroize(copyOfKey)
	object, err := r.tpm.Seal(ctx, storage, copyOfKey, sealContext)
	if err != nil {
		return nil, fmt.Errorf("keyresolver: seal protocol root: %w", err)
	}
	encoded, err := json.Marshal(object)
	if err != nil {
		return nil, fmt.Errorf("keyresolver: encode sealed protocol root: %w", err)
	}
	return &Material{SealedMaterial: encoded}, nil
}

func (r *Resolver) UnsealKey(ctx context.Context, encoded []byte, keyVersionID string) ([]byte, error) {
	storage, sealContext, err := r.context(keyVersionID)
	if err != nil {
		return nil, err
	}
	var object provider.SealedObject
	if err := json.Unmarshal(encoded, &object); err != nil {
		return nil, errors.New("keyresolver: corrupt sealed protocol root")
	}
	key, err := r.tpm.Unseal(ctx, storage, &object, sealContext)
	if err != nil {
		return nil, fmt.Errorf("keyresolver: unseal protocol root: %w", err)
	}
	return key, nil
}

func (r *Resolver) IssueKey(ctx context.Context, keyVersionID, keyID string, keyVersion uint32,
	suiteID suite.ID, tenantID, purpose, nodeID string) (*KeyLease, error) {
	r.mu.RLock()
	fetch := r.fetch
	r.mu.RUnlock()
	if fetch == nil {
		return nil, errors.New("keyresolver: fetch hook not set")
	}
	sealed, err := fetch(ctx, keyVersionID)
	if err != nil {
		return nil, err
	}
	key, err := r.UnsealKey(ctx, sealed, keyVersionID)
	if err != nil {
		return nil, err
	}
	return &KeyLease{KeyVersionID: keyVersionID, TenantID: tenantID, KeyID: keyID,
		KeyVersion: keyVersion, SuiteID: suiteID, Purpose: purpose, NodeID: nodeID, Key: key}, nil
}

func (r *Resolver) SetFetchHook(fetch func(context.Context, string) ([]byte, error)) {
	r.mu.Lock()
	r.fetch = fetch
	r.mu.Unlock()
}

func (r *Resolver) context(objectID string) (*provider.TPMObjectRef, aad.SealContext, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.storage == nil {
		return nil, aad.SealContext{}, errors.New("keyresolver: TPM storage is not initialized")
	}
	return r.storage, aad.SealContext{Purpose: protocolRootPurpose, ObjectID: objectID,
		NodeID: r.nodeID, StorageName: r.storage.Name, BaselineDigest: append([]byte(nil), r.baseline...),
		PolicyDigest: append([]byte(nil), r.policyDig...)}, nil
}

func zeroize(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
