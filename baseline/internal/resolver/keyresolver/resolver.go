// Package keyresolver implements the Key Resolver per design §6.3, §9.3-9.5.
//
// Responsibilities:
//   - Generate and wrap DEKs under the CRK
//   - Issue short-TTL DEK leases to the data plane
//   - Manage the CRK critical section (withCRK): CRK plaintext exists only
//     inside the callback, then is zeroized.
//   - Enforce that the data plane never touches CRK or TPM.
//
// The resolver is the ONLY component that touches the TPM and CRK plaintext.
package keyresolver

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/kvlt/key-vault/internal/crypto/aad"
	"github.com/kvlt/key-vault/internal/crypto/aead"
	"github.com/kvlt/key-vault/internal/tpm/provider"
)

// DEKMaterial is the wrapped DEK + metadata, ready to persist.
type DEKMaterial struct {
	WrappedDEK   []byte // CRK-sealed DEK
	WrapMetadata []byte // JSON: crk_version, aad_digest, wrap_alg
}

// wrapMetadata is the JSON shape persisted alongside wrapped_dek.
type wrapMetadata struct {
	CRKVersionID string `json:"crk_version_id"`
	WrapAlg      string `json:"wrap_alg"`
	AADDigest    string `json:"aad_digest"`
}

// DEKLease is a short-TTL lease granting the data plane access to a DEK.
type DEKLease struct {
	LeaseID      string
	KeyVersionID string
	TenantID     string
	KeyID        string
	KeyVersion   uint32
	SuiteID      aead.SuiteID
	Purpose      string
	NodeID       string
	DEK          []byte // plaintext DEK; zeroized on expiry
	ExpiresAt    time.Time
}

// CRKContext is the context for CRK critical sections.
type CRKContext struct {
	ClusterID      string
	NodeID         string
	PlaneRole      string
	CRKVersion     uint32
	NRWKName       string
	BaselineDigest []byte
	PolicyDigest   []byte
}

// Resolver is the key resolver.
type Resolver struct {
	mu          sync.Mutex
	tpm         provider.Provider
	nrwkName    string
	nrwk        *provider.TPMObjectRef
	crkEnvelope *provider.CRKEnvelope // cached envelope for current node
	crkVersion  uint32
	clusterID   string
	nodeID      string
	planeRole   string
	baseline    []byte
	policyDig   []byte

	// DEK lease cache: (keyVersionID, nodeID, purpose) -> lease
	leaseCache map[string]*DEKLease
	leaseTTL   time.Duration
	fetchDEK   func(ctx context.Context, keyVersionID string) (wrappedDEK, metaJSON []byte, err error)

	// singleflight for CRK unseal (HA-12)
	unsealInFlight bool
}

// New constructs a resolver.
func New(tpm provider.Provider, nrwName string, leaseTTL time.Duration) *Resolver {
	return &Resolver{
		tpm:        tpm,
		nrwkName:   nrwName,
		leaseCache: make(map[string]*DEKLease),
		leaseTTL:   leaseTTL,
	}
}

// Init loads or creates the NRWK and caches the CRK envelope reference.
// The CRK envelope bytes are loaded from the store; the CRK plaintext is
// NOT held in memory.
func (r *Resolver) Init(ctx context.Context, clusterID, nodeID, planeRole string, baseline, policyDigest []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	ref, err := r.tpm.EnsureNRWK(ctx, r.nrwkName)
	if err != nil {
		return fmt.Errorf("resolver: ensure nrwk: %w", err)
	}
	r.nrwk = ref
	r.clusterID = clusterID
	r.nodeID = nodeID
	r.planeRole = planeRole
	r.baseline = baseline
	r.policyDig = policyDigest
	return nil
}

// SetCRKEnvelope caches the CRK envelope for the current node.
// Called after the management plane distributes a CRK envelope.
func (r *Resolver) SetCRKEnvelope(env *provider.CRKEnvelope) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.crkEnvelope = env
	r.crkVersion = env.CRKVersion
}

// CRKVersion returns the cached CRK version.
func (r *Resolver) CRKVersion() uint32 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.crkVersion
}

// withCRK is the CRK critical section. It unseals the CRK, calls fn with
// the plaintext, then zeroizes the CRK before returning. Per design §6.3
// and HA-03, CRK plaintext must not escape this function.
func (r *Resolver) withCRK(ctx context.Context, fn func(crk []byte) error) error {
	r.mu.Lock()
	if r.crkEnvelope == nil {
		r.mu.Unlock()
		return errors.New("resolver: no CRK envelope")
	}
	if r.nrwk == nil {
		r.mu.Unlock()
		return errors.New("resolver: NRWK not initialized")
	}
	env := r.crkEnvelope
	nrwk := r.nrwk
	r.mu.Unlock()

	a := aad.CRKAAD{
		ClusterID:      r.clusterID,
		NodeID:         r.nodeID,
		PlaneRole:      r.planeRole,
		CRKVersion:     env.CRKVersion,
		NRWKName:       env.NRWKName,
		BaselineDigest: env.BaselineDigest,
		PolicyDigest:   env.PolicyDigest,
	}
	crk, err := r.tpm.UnsealCRK(ctx, nrwk, env, a)
	if err != nil {
		return fmt.Errorf("resolver: unseal crk: %w", err)
	}
	defer zeroize(crk)
	return fn(crk)
}

// GenerateAndWrapDEK generates a new DEK and seals it under the CRK.
// Returns the wrapped DEK + metadata. The plaintext DEK is zeroized
// before return; the caller does NOT receive it.
func (r *Resolver) GenerateAndWrapDEK(ctx context.Context, suite aead.SuiteID, keyVersionID string) (*DEKMaterial, error) {
	var out *DEKMaterial
	err := r.withCRK(ctx, func(crk []byte) error {
		dek := make([]byte, suite.KeyBytes())
		if _, err := rand.Read(dek); err != nil {
			return fmt.Errorf("resolver: rand dek: %w", err)
		}
		defer zeroize(dek)
		// Seal DEK under CRK using AES-256-GCM (CRK is 32 bytes).
		a, err := aead.New(aead.SuiteAES256GCM, crk)
		if err != nil {
			return fmt.Errorf("resolver: aead new: %w", err)
		}
		nonce := make([]byte, 12)
		if _, err := rand.Read(nonce); err != nil {
			return fmt.Errorf("resolver: rand nonce: %w", err)
		}
		// DEK wrap AAD binds key_version_id (so a wrapped DEK cannot be
		// swapped to a different key version).
		dekAAD := []byte("kvlt-dek-wrap-v1|" + keyVersionID)
		ct, tag := a.Encrypt(dek, nonce, dekAAD)
		combined := append(append(append([]byte{}, nonce...), ct...), tag...)
		meta := wrapMetadata{
			CRKVersionID: fmt.Sprintf("crk-v%d", r.crkVersion),
			WrapAlg:      "AES_256_GCM",
			AADDigest:    digestHex(dekAAD),
		}
		metaJSON, err := json.Marshal(meta)
		if err != nil {
			return fmt.Errorf("resolver: marshal meta: %w", err)
		}
		out = &DEKMaterial{
			WrappedDEK:   combined,
			WrapMetadata: metaJSON,
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// WrapExternalDEK seals a caller-provided DEK plaintext under the CRK.
// Used by the controlled key import flow (EB-FR-01, design §2 "受控导入").
// Per design §2 and INV-11: the imported plaintext only enters the key-plane
// sealing flow; it is not persisted, logged, or echoed. The plaintext is
// zeroized inside the CRK critical section before return.
//
// The caller MUST validate that dekPlaintext length matches suite.KeyBytes()
// before calling; this function performs a defensive length check as well.
func (r *Resolver) WrapExternalDEK(ctx context.Context, suite aead.SuiteID, keyVersionID string, dekPlaintext []byte) (*DEKMaterial, error) {
	if len(dekPlaintext) != suite.KeyBytes() {
		return nil, fmt.Errorf("resolver: imported dek length mismatch: got %d, want %d", len(dekPlaintext), suite.KeyBytes())
	}
	var out *DEKMaterial
	err := r.withCRK(ctx, func(crk []byte) error {
		// Copy the caller's DEK into a buffer we control so we can zeroize it.
		dek := make([]byte, len(dekPlaintext))
		copy(dek, dekPlaintext)
		defer zeroize(dek)
		a, err := aead.New(aead.SuiteAES256GCM, crk)
		if err != nil {
			return fmt.Errorf("resolver: aead new: %w", err)
		}
		nonce := make([]byte, 12)
		if _, err := rand.Read(nonce); err != nil {
			return fmt.Errorf("resolver: rand nonce: %w", err)
		}
		dekAAD := []byte("kvlt-dek-wrap-v1|" + keyVersionID)
		ct, tag := a.Encrypt(dek, nonce, dekAAD)
		combined := append(append(append([]byte{}, nonce...), ct...), tag...)
		meta := wrapMetadata{
			CRKVersionID: fmt.Sprintf("crk-v%d", r.crkVersion),
			WrapAlg:      "AES_256_GCM",
			AADDigest:    digestHex(dekAAD),
		}
		metaJSON, err := json.Marshal(meta)
		if err != nil {
			return fmt.Errorf("resolver: marshal meta: %w", err)
		}
		out = &DEKMaterial{
			WrappedDEK:   combined,
			WrapMetadata: metaJSON,
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// UnwrapDEK decrypts a wrapped DEK inside the CRK critical section.
// The returned DEK plaintext is the caller's responsibility to zeroize.
func (r *Resolver) UnwrapDEK(ctx context.Context, wrappedDEK []byte, metaJSON []byte, keyVersionID string) ([]byte, error) {
	var dek []byte
	err := r.withCRK(ctx, func(crk []byte) error {
		if len(wrappedDEK) < 12+16 {
			return errors.New("resolver: wrapped dek too short")
		}
		var meta wrapMetadata
		if err := json.Unmarshal(metaJSON, &meta); err != nil {
			return fmt.Errorf("resolver: parse meta: %w", err)
		}
		a, err := aead.New(aead.SuiteAES256GCM, crk)
		if err != nil {
			return fmt.Errorf("resolver: aead new: %w", err)
		}
		nonce := wrappedDEK[:12]
		tag := wrappedDEK[len(wrappedDEK)-16:]
		ct := wrappedDEK[12 : len(wrappedDEK)-16]
		dekAAD := []byte("kvlt-dek-wrap-v1|" + keyVersionID)
		pt, err := a.Decrypt(ct, tag, nonce, dekAAD)
		if err != nil {
			return fmt.Errorf("resolver: decrypt dek: %w", err)
		}
		dek = pt
		return nil
	})
	if err != nil {
		return nil, err
	}
	return dek, nil
}

// IssueDEKLease unwraps a DEK and grants a short-TTL lease to the data plane.
// The lease is cached; subsequent calls for the same (keyVersionID, nodeID, purpose)
// return the cached lease until expiry.
func (r *Resolver) IssueDEKLease(ctx context.Context, keyVersionID, keyID string, keyVersion uint32, suite aead.SuiteID, tenantID, purpose, nodeID string) (*DEKLease, error) {
	cacheKey := keyVersionID + "|" + nodeID + "|" + purpose
	r.mu.Lock()
	if l, ok := r.leaseCache[cacheKey]; ok {
		if time.Now().Before(l.ExpiresAt) {
			lease := cloneLease(l)
			lease.LeaseID = newLeaseID()
			r.mu.Unlock()
			return lease, nil
		}
		zeroize(l.DEK)
		delete(r.leaseCache, cacheKey)
	}
	r.mu.Unlock()

	wrappedDEK, metaJSON, err := r.fetchWrappedDEK(ctx, keyVersionID)
	if err != nil {
		return nil, err
	}
	dek, err := r.UnwrapDEK(ctx, wrappedDEK, metaJSON, keyVersionID)
	if err != nil {
		return nil, err
	}
	lease := &DEKLease{
		LeaseID:      newLeaseID(),
		KeyVersionID: keyVersionID,
		TenantID:     tenantID,
		KeyID:        keyID,
		KeyVersion:   keyVersion,
		SuiteID:      suite,
		Purpose:      purpose,
		NodeID:       nodeID,
		DEK:          dek,
		ExpiresAt:    time.Now().Add(r.leaseTTL),
	}
	r.mu.Lock()
	r.leaseCache[cacheKey] = cloneLease(lease)
	r.mu.Unlock()
	return lease, nil
}

func cloneLease(l *DEKLease) *DEKLease {
	if l == nil {
		return nil
	}
	lease := *l
	if l.DEK != nil {
		lease.DEK = make([]byte, len(l.DEK))
		copy(lease.DEK, l.DEK)
	}
	return &lease
}

// fetchWrappedDEK is a hook for the application layer to supply the
// wrapped DEK + metadata from the repository. Set by the application.
func (r *Resolver) SetFetchDEKHook(fn func(ctx context.Context, keyVersionID string) (wrappedDEK, metaJSON []byte, err error)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.fetchDEK = fn
}

func (r *Resolver) fetchWrappedDEK(ctx context.Context, keyVersionID string) ([]byte, []byte, error) {
	r.mu.Lock()
	fn := r.fetchDEK
	r.mu.Unlock()
	if fn == nil {
		return nil, nil, errors.New("resolver: fetch hook not set")
	}
	return fn(ctx, keyVersionID)
}

// RevokeLease removes a lease from the cache (e.g. on node revocation).
func (r *Resolver) RevokeLease(keyVersionID, nodeID, purpose string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	cacheKey := keyVersionID + "|" + nodeID + "|" + purpose
	if l, ok := r.leaseCache[cacheKey]; ok {
		zeroize(l.DEK)
		delete(r.leaseCache, cacheKey)
	}
}

// PurgeNodeLeases removes all leases for a node (e.g. on revocation).
func (r *Resolver) PurgeNodeLeases(nodeID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for k, l := range r.leaseCache {
		if l.NodeID == nodeID {
			zeroize(l.DEK)
			delete(r.leaseCache, k)
		}
	}
}

// zeroize overwrites a byte slice with zeros.
func zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func digestHex(b []byte) string {
	h := sha256Hex(b)
	return h
}

func newLeaseID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return fmt.Sprintf("dls_%x", b)
}
