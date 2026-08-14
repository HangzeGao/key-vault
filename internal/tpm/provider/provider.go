// Package provider defines the TPMProvider interface and a software-backed
// implementation for engineering baseline testing. In environments without
// swtpm, a software provider that emulates seal/unseal with AES-256-GCM is
// acceptable for local baseline verification.
//
// The software provider persists a storage key and sealed-object envelopes so
// restart recovery can be tested. It is NOT a security boundary; deployments MUST
// use a real TPM or swtpm with proper isolation.
package provider

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/kvlt/key-vault/internal/crypto/aad"
)

// SealedObject is opaque TPM-sealed material for one named purpose.
type SealedObject struct {
	NodeID         string `json:"node_id"`
	Purpose        string `json:"purpose"`
	ObjectID       string `json:"object_id"`
	StorageName    string `json:"storage_name"`
	Blob           []byte `json:"blob"`
	Nonce          []byte `json:"nonce"`
	Tag            []byte `json:"tag"`
	BaselineDigest []byte `json:"baseline_digest"`
	PolicyDigest   []byte `json:"policy_digest"`
	ContextDigest  string `json:"context_digest"`
}

// TPMObjectRef references a provider storage object.
type TPMObjectRef struct {
	Name     string `json:"name"`
	KeyBytes []byte `json:"key_bytes"` // software provider only; real TPM never exposes
}

// Provider is the TPM abstraction.
type Provider interface {
	EnsureStorage(ctx context.Context, name string) (*TPMObjectRef, error)
	Seal(ctx context.Context, storage *TPMObjectRef, plaintext []byte, sealContext aad.SealContext) (*SealedObject, error)
	Unseal(ctx context.Context, storage *TPMObjectRef, object *SealedObject, sealContext aad.SealContext) ([]byte, error)
	// Quote is a baseline stub and returns a fixed placeholder.
	Quote(ctx context.Context, nonce []byte, pcrs []int) ([]byte, error)
	// Close releases provider resources.
	Close() error
}

// SoftwareProvider is a disk-backed software TPM emulator for baseline testing.
type SoftwareProvider struct {
	mu       sync.Mutex
	stateDir string
	storage  map[string]*TPMObjectRef
}

func validateSealedObjectContext(object *SealedObject, a aad.SealContext) error {
	if object == nil || object.ContextDigest != contextDigestHex(a) {
		return fmt.Errorf("provider: sealed-object context digest mismatch")
	}
	if object.Purpose != a.Purpose || object.ObjectID != a.ObjectID || object.NodeID != a.NodeID ||
		object.StorageName != a.StorageName || !equalBytes(object.BaselineDigest, a.BaselineDigest) ||
		!equalBytes(object.PolicyDigest, a.PolicyDigest) {
		return fmt.Errorf("provider: sealed-object context mismatch")
	}
	return nil
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

func contextDigestHex(a aad.SealContext) string {
	b, err := a.Canonical()
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// NewSoftwareProvider constructs a software provider backed by stateDir.
func NewSoftwareProvider(stateDir string) (*SoftwareProvider, error) {
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, fmt.Errorf("provider: mkdir: %w", err)
	}
	sp := &SoftwareProvider{
		stateDir: stateDir,
		storage:  make(map[string]*TPMObjectRef),
	}
	if err := sp.loadAll(); err != nil {
		return nil, err
	}
	return sp, nil
}

func (s *SoftwareProvider) loadAll() error {
	entries, err := os.ReadDir(s.stateDir)
	if err != nil {
		return fmt.Errorf("provider: readdir: %w", err)
	}
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".storage" {
			continue
		}
		path := filepath.Join(s.stateDir, e.Name())
		b, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("provider: read %s: %w", path, err)
		}
		var ref TPMObjectRef
		if err := json.Unmarshal(b, &ref); err != nil {
			return fmt.Errorf("provider: parse %s: %w", path, err)
		}
		s.storage[ref.Name] = &ref
	}
	return nil
}

// EnsureStorage creates or loads the software storage key for the given name.
func (s *SoftwareProvider) EnsureStorage(ctx context.Context, name string) (*TPMObjectRef, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ref, ok := s.storage[name]; ok {
		return ref, nil
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("provider: rand: %w", err)
	}
	ref := &TPMObjectRef{Name: name, KeyBytes: key}
	if err := s.persistStorage(ref); err != nil {
		return nil, err
	}
	s.storage[name] = ref
	return ref, nil
}

func (s *SoftwareProvider) persistStorage(ref *TPMObjectRef) error {
	path := filepath.Join(s.stateDir, ref.Name+".storage")
	b, err := json.Marshal(ref)
	if err != nil {
		return fmt.Errorf("provider: marshal: %w", err)
	}
	// Write atomically.
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return fmt.Errorf("provider: write: %w", err)
	}
	return os.Rename(tmp, path)
}

// Seal encrypts plaintext under the software storage key and binds its context.
func (s *SoftwareProvider) Seal(ctx context.Context, storage *TPMObjectRef, plaintext []byte, a aad.SealContext) (*SealedObject, error) {
	if len(storage.KeyBytes) != 32 {
		return nil, fmt.Errorf("provider: storage key length %d", len(storage.KeyBytes))
	}
	block, err := aes.NewCipher(storage.KeyBytes)
	if err != nil {
		return nil, fmt.Errorf("provider: aes new: %w", err)
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("provider: gcm new: %w", err)
	}
	aadBytes, err := a.Canonical()
	if err != nil {
		return nil, fmt.Errorf("provider: aad canonical: %w", err)
	}
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("provider: rand nonce: %w", err)
	}
	sealed := g.Seal(nil, nonce, plaintext, aadBytes)
	tagLen := g.Overhead()
	ct := sealed[:len(sealed)-tagLen]
	tag := sealed[len(sealed)-tagLen:]
	return &SealedObject{
		NodeID:         a.NodeID,
		Purpose:        a.Purpose,
		ObjectID:       a.ObjectID,
		StorageName:    storage.Name,
		Blob:           ct,
		Nonce:          nonce,
		Tag:            tag,
		BaselineDigest: a.BaselineDigest,
		PolicyDigest:   a.PolicyDigest,
		ContextDigest:  contextDigestHex(a),
	}, nil
}

// Unseal decrypts a sealed object after verifying its context.
func (s *SoftwareProvider) Unseal(ctx context.Context, storage *TPMObjectRef, object *SealedObject, a aad.SealContext) ([]byte, error) {
	if object.StorageName != storage.Name {
		return nil, fmt.Errorf("provider: storage name mismatch")
	}
	if err := validateSealedObjectContext(object, a); err != nil {
		return nil, err
	}
	if len(storage.KeyBytes) != 32 {
		return nil, fmt.Errorf("provider: storage key length %d", len(storage.KeyBytes))
	}
	block, err := aes.NewCipher(storage.KeyBytes)
	if err != nil {
		return nil, fmt.Errorf("provider: aes new: %w", err)
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("provider: gcm new: %w", err)
	}
	aadBytes, err := a.Canonical()
	if err != nil {
		return nil, fmt.Errorf("provider: aad canonical: %w", err)
	}
	combined := make([]byte, 0, len(object.Blob)+len(object.Tag))
	combined = append(combined, object.Blob...)
	combined = append(combined, object.Tag...)
	pt, err := g.Open(nil, object.Nonce, combined, aadBytes)
	if err != nil {
		return nil, fmt.Errorf("provider: unseal failed (AAD or integrity check)")
	}
	return pt, nil
}

// Quote is a baseline stub.
func (s *SoftwareProvider) Quote(ctx context.Context, nonce []byte, pcrs []int) ([]byte, error) {
	h := sha256.New()
	h.Write([]byte("swtpm-quote"))
	h.Write(nonce)
	for _, p := range pcrs {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], uint32(p))
		h.Write(b[:])
	}
	return h.Sum(nil), nil
}

// Close is a no-op for the software provider.
func (s *SoftwareProvider) Close() error { return nil }

// ErrProviderUnavailable is returned when the provider cannot service a request.
var ErrProviderUnavailable = errors.New("provider: unavailable")
