package downlink

import (
	"context"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"sync"

	"github.com/kvlt/key-vault/internal/crypto/aead"
	"github.com/kvlt/key-vault/internal/crypto/suite"
	"github.com/kvlt/key-vault/internal/securitystate"
)

type StateStore interface {
	ReadDownlinkKeyState(context.Context) (*securitystate.DownlinkKeyState, error)
	ProvisionDownlinkKEKSet(context.Context, []byte, uint8) error
	SetActiveDownlinkKEKSlot(context.Context, uint8) error
	AdvanceDownlinkBatch(context.Context, uint32, []byte, [32]byte) error
	MarkCurrentDownlinkObserved(context.Context, uint32) error
}

type Service struct {
	mu                sync.RWMutex
	store             StateStore
	sealer            KEKSealer
	current           []byte
	previous          []byte
	currentGeneration uint32
	currentObserved   bool
}

// Status is a non-secret operational projection of the singleton downlink
// key lifecycle. It never contains KEKs, DEKs, packages, nonces, or digests.
type Status struct {
	Provisioned        bool
	ActiveKEKSlot      uint8
	CurrentGeneration  uint32
	CurrentObserved    bool
	PreviousGeneration uint32
}

func NewService(store StateStore, sealer KEKSealer) *Service {
	return &Service{store: store, sealer: sealer}
}

func (s *Service) Load(ctx context.Context) error {
	state, err := s.store.ReadDownlinkKeyState(ctx)
	if errors.Is(err, securitystate.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	kekSet, err := s.sealer.UnsealKEKSet(ctx, state.SealedKEKSet)
	if err != nil {
		return err
	}
	defer zeroize(kekSet)
	current, err := decryptStoredPackage(state.CurrentPackage, state.CurrentDigest, state.CurrentGeneration, kekSet)
	if err != nil {
		return err
	}
	previous, err := decryptStoredPackage(state.PreviousPackage, state.PreviousDigest, state.PreviousGeneration, kekSet)
	if err != nil {
		zeroize(current)
		return err
	}
	s.replaceCache(current, previous, state.CurrentGeneration, state.CurrentObserved)
	return nil
}

func (s *Service) Provision(ctx context.Context, kekSet []byte, activeSlot uint8) error {
	if len(kekSet) != KEKSetBytes || activeSlot >= KEKSlots {
		return ErrInvalid
	}
	existing, err := s.store.ReadDownlinkKeyState(ctx)
	if err == nil {
		stored, unsealErr := s.sealer.UnsealKEKSet(ctx, existing.SealedKEKSet)
		if unsealErr != nil {
			return unsealErr
		}
		defer zeroize(stored)
		if existing.ActiveKEKSlot != activeSlot || subtle.ConstantTimeCompare(stored, kekSet) != 1 {
			return errors.New("downlink: provisioned KEK set does not match mission profile")
		}
		return nil
	}
	if !errors.Is(err, securitystate.ErrNotFound) {
		return err
	}
	sealed, err := s.sealer.SealKEKSet(ctx, kekSet)
	if err != nil {
		return err
	}
	return s.store.ProvisionDownlinkKEKSet(ctx, sealed, activeSlot)
}

func (s *Service) SetActiveKEKSlot(ctx context.Context, slot uint8) error {
	if slot >= KEKSlots {
		return ErrInvalid
	}
	return s.store.SetActiveDownlinkKEKSlot(ctx, slot)
}

func (s *Service) Status(ctx context.Context) (Status, error) {
	state, err := s.store.ReadDownlinkKeyState(ctx)
	if errors.Is(err, securitystate.ErrNotFound) {
		return Status{}, nil
	}
	if err != nil {
		return Status{}, err
	}
	return Status{
		Provisioned: true, ActiveKEKSlot: state.ActiveKEKSlot,
		CurrentGeneration: state.CurrentGeneration, CurrentObserved: state.CurrentObserved,
		PreviousGeneration: state.PreviousGeneration,
	}, nil
}

func (s *Service) GenerateNext(ctx context.Context) ([]byte, error) {
	state, err := s.store.ReadDownlinkKeyState(ctx)
	if errors.Is(err, securitystate.ErrNotFound) {
		return nil, ErrNotProvisioned
	}
	if err != nil {
		return nil, err
	}
	if state.CurrentGeneration != 0 && !state.CurrentObserved {
		return nil, ErrNotObserved
	}
	if state.CurrentGeneration == ^uint32(0) {
		return nil, errors.New("downlink: batch generation exhausted")
	}
	kekSet, err := s.sealer.UnsealKEKSet(ctx, state.SealedKEKSet)
	if err != nil {
		return nil, err
	}
	defer zeroize(kekSet)
	deks, err := GenerateDEKSet()
	if err != nil {
		return nil, err
	}
	defer zeroize(deks)
	pkg, err := EncryptPackage(kekSet, deks, state.ActiveKEKSlot, state.CurrentGeneration+1)
	if err != nil {
		return nil, err
	}
	encoded := pkg.MarshalBinary()
	if err := s.store.AdvanceDownlinkBatch(ctx, state.CurrentGeneration, encoded, Digest(encoded)); err != nil {
		zeroize(encoded)
		return nil, err
	}
	return encoded, nil
}

func (s *Service) ExportCurrent(ctx context.Context) ([]byte, error) {
	state, err := s.store.ReadDownlinkKeyState(ctx)
	if errors.Is(err, securitystate.ErrNotFound) {
		return nil, ErrNotProvisioned
	}
	if err != nil {
		return nil, err
	}
	if state == nil || state.CurrentGeneration == 0 {
		return nil, ErrNotProvisioned
	}
	digest := Digest(state.CurrentPackage)
	if subtle.ConstantTimeCompare(digest[:], state.CurrentDigest[:]) != 1 {
		return nil, errors.New("downlink: stored package digest mismatch")
	}
	return append([]byte(nil), state.CurrentPackage...), nil
}

func (s *Service) UnprotectRaw(ctx context.Context, encoded []byte) ([]byte, error) {
	if len(encoded) < 2+UploadNonceBytes+GCMTagBytes {
		return nil, ErrInvalid
	}
	serial := binary.BigEndian.Uint16(encoded[:2])
	nonce := encoded[2 : 2+UploadNonceBytes]
	ciphertext := encoded[2+UploadNonceBytes : len(encoded)-GCMTagBytes]
	tag := encoded[len(encoded)-GCMTagBytes:]

	s.mu.RLock()
	current := keyAt(s.current, serial)
	previous := keyAt(s.previous, serial)
	generation := s.currentGeneration
	observed := s.currentObserved
	s.mu.RUnlock()
	if current == nil {
		return nil, ErrNotProvisioned
	}
	plaintext, err := decryptRaw(current, nonce, ciphertext, tag)
	zeroize(current)
	if err == nil {
		if !observed {
			if err := s.store.MarkCurrentDownlinkObserved(ctx, generation); err != nil {
				zeroize(plaintext)
				return nil, err
			}
			s.mu.Lock()
			s.currentObserved = true
			s.mu.Unlock()
		}
		zeroize(previous)
		return plaintext, nil
	}
	if previous == nil {
		return nil, ErrAuthentication
	}
	plaintext, err = decryptRaw(previous, nonce, ciphertext, tag)
	zeroize(previous)
	if err != nil {
		return nil, ErrAuthentication
	}
	return plaintext, nil
}

func (s *Service) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	zeroize(s.current)
	zeroize(s.previous)
	s.current = nil
	s.previous = nil
	s.currentGeneration = 0
	s.currentObserved = false
}

func (s *Service) replaceCache(current, previous []byte, generation uint32, observed bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	zeroize(s.current)
	zeroize(s.previous)
	s.current = current
	s.previous = previous
	s.currentGeneration = generation
	s.currentObserved = observed
}

func decryptStoredPackage(encoded []byte, expectedDigest [32]byte, generation uint32, kekSet []byte) ([]byte, error) {
	if generation == 0 && len(encoded) == 0 {
		return nil, nil
	}
	digest := Digest(encoded)
	if subtle.ConstantTimeCompare(digest[:], expectedDigest[:]) != 1 {
		return nil, errors.New("downlink: stored package digest mismatch")
	}
	pkg, err := ParsePackage(encoded)
	if err != nil || pkg.Generation != generation {
		return nil, errors.New("downlink: corrupt stored package")
	}
	return pkg.Decrypt(kekSet)
}

func keyAt(set []byte, serial uint16) []byte {
	if int(serial) >= DEKCount || len(set) != DEKSetBytes {
		return nil
	}
	offset := int(serial) * DEKBytes
	return append([]byte(nil), set[offset:offset+DEKBytes]...)
}

func decryptRaw(key, nonce, ciphertext, tag []byte) ([]byte, error) {
	primitive, err := aead.New(suite.SM4GCM, key)
	if err != nil {
		return nil, err
	}
	plaintext, err := primitive.Decrypt(ciphertext, tag, nonce, nil)
	if err != nil {
		return nil, ErrAuthentication
	}
	return plaintext, nil
}
