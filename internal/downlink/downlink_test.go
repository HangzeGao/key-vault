//go:build downlink

package downlink

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"path/filepath"
	"testing"

	"github.com/kvlt/key-vault/internal/crypto/aead"
	"github.com/kvlt/key-vault/internal/crypto/suite"
	"github.com/kvlt/key-vault/internal/securitystate"
	"github.com/kvlt/key-vault/internal/tpm/provider"
)

func TestPackageRoundTripAndTamperRejection(t *testing.T) {
	kekSet := sequence(KEKSetBytes)
	deks := sequence(DEKSetBytes)
	pkg, err := EncryptPackage(kekSet, deks, 7, 42)
	if err != nil {
		t.Fatal(err)
	}
	encoded := pkg.MarshalBinary()
	if len(encoded) != PackageBytes || encoded[0] != 7 || binary.BigEndian.Uint32(encoded[1:5]) != 42 {
		t.Fatalf("encoded package header=%x len=%d", encoded[:5], len(encoded))
	}
	parsed, err := ParsePackage(encoded)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := parsed.Decrypt(kekSet)
	if err != nil || !bytes.Equal(opened, deks) {
		t.Fatalf("round trip err=%v", err)
	}
	for _, offset := range []int{0, 1, 5, 17, len(encoded) - 1} {
		tampered := append([]byte(nil), encoded...)
		tampered[offset] ^= 1
		candidate, parseErr := ParsePackage(tampered)
		if parseErr == nil {
			if _, err := candidate.Decrypt(kekSet); err == nil {
				t.Fatalf("tamper at %d accepted", offset)
			}
		}
	}
	if _, err := ParsePackage(encoded[:len(encoded)-1]); !errors.Is(err, ErrInvalid) {
		t.Fatalf("short package error=%v", err)
	}
}

func TestServiceGenerationGateCurrentPreviousAndRestart(t *testing.T) {
	ctx := context.Background()
	databasePath := filepath.Join(t.TempDir(), "state.db")
	store, sealer := newDependencies(t, ctx, databasePath)
	service := NewService(store, sealer)
	kekSet := sequence(KEKSetBytes)
	if err := service.Provision(ctx, kekSet, 2); err != nil {
		t.Fatal(err)
	}
	firstPackage, err := service.GenerateNext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.GenerateNext(ctx); !errors.Is(err, ErrNotObserved) {
		t.Fatalf("unobserved generation error=%v", err)
	}
	if err := service.Load(ctx); err != nil {
		t.Fatal(err)
	}
	firstDEKs := decryptPackageForTest(t, firstPackage, kekSet)
	raw := encryptRawForTest(t, firstDEKs, 1023, []byte("current-one"), 1)
	plaintext, err := service.UnprotectRaw(ctx, raw)
	if err != nil || string(plaintext) != "current-one" {
		t.Fatalf("current unprotect=%q err=%v", plaintext, err)
	}
	secondPackage, err := service.GenerateNext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(firstPackage, secondPackage) {
		t.Fatal("two generations reused package bytes")
	}
	if err := service.Load(ctx); err != nil {
		t.Fatal(err)
	}
	previousRaw := encryptRawForTest(t, firstDEKs, 1023, []byte("previous-one"), 2)
	plaintext, err = service.UnprotectRaw(ctx, previousRaw)
	if err != nil || string(plaintext) != "previous-one" {
		t.Fatalf("previous fallback=%q err=%v", plaintext, err)
	}
	service.Close()
	store.Close()

	store, sealer = newDependencies(t, ctx, databasePath)
	restarted := NewService(store, sealer)
	if err := restarted.Load(ctx); err != nil {
		t.Fatal(err)
	}
	secondDEKs := decryptPackageForTest(t, secondPackage, kekSet)
	currentRaw := encryptRawForTest(t, secondDEKs, 0, []byte("after-restart"), 3)
	plaintext, err = restarted.UnprotectRaw(ctx, currentRaw)
	if err != nil || string(plaintext) != "after-restart" {
		t.Fatalf("restart unprotect=%q err=%v", plaintext, err)
	}
	currentRaw[len(currentRaw)-1] ^= 1
	if _, err := restarted.UnprotectRaw(ctx, currentRaw); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("bad tag error=%v", err)
	}
	restarted.Close()
	store.Close()
}

func TestProvisionIdempotenceAndStrictIdentity(t *testing.T) {
	ctx := context.Background()
	store, sealer := newDependencies(t, ctx, filepath.Join(t.TempDir(), "state.db"))
	defer store.Close()
	service := NewService(store, sealer)
	kekSet := sequence(KEKSetBytes)
	if err := service.Provision(ctx, kekSet, 0); err != nil {
		t.Fatal(err)
	}
	if err := service.Provision(ctx, kekSet, 0); err != nil {
		t.Fatalf("identical provisioning is not idempotent: %v", err)
	}
	changed := append([]byte(nil), kekSet...)
	changed[0] ^= 1
	if err := service.Provision(ctx, changed, 0); err == nil {
		t.Fatal("different KEK set accepted")
	}
	if err := service.Provision(ctx, kekSet, 1); err == nil {
		t.Fatal("different active slot accepted")
	}
}

func TestLoadRejectsStoredPackageDigestMismatch(t *testing.T) {
	ctx := context.Background()
	store, sealer := newDependencies(t, ctx, filepath.Join(t.TempDir(), "state.db"))
	defer store.Close()
	service := NewService(store, sealer)
	kekSet := sequence(KEKSetBytes)
	if err := service.Provision(ctx, kekSet, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := service.GenerateNext(ctx); err != nil {
		t.Fatal(err)
	}
	state, err := store.ReadDownlinkKeyState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	state.CurrentDigest[0] ^= 1
	corrupt := &stateStoreOverride{Store: store, state: state}
	if err := NewService(corrupt, sealer).Load(ctx); err == nil {
		t.Fatal("stored package digest mismatch accepted")
	}
}

type stateStoreOverride struct {
	*securitystate.Store
	state *securitystate.DownlinkKeyState
}

func (s *stateStoreOverride) ReadDownlinkKeyState(context.Context) (*securitystate.DownlinkKeyState, error) {
	return s.state, nil
}

func newDependencies(t *testing.T, ctx context.Context, path string) (*securitystate.Store, *TPMSealer) {
	t.Helper()
	store, err := securitystate.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	tpm, err := provider.NewSoftwareProvider(filepath.Join(filepath.Dir(path), "tpm"))
	if err != nil {
		t.Fatal(err)
	}
	sealer, err := NewTPMSealer(ctx, tpm, "test-storage", "node-1", []byte("baseline"), []byte("policy"))
	if err != nil {
		t.Fatal(err)
	}
	return store, sealer
}

func decryptPackageForTest(t *testing.T, encoded, kekSet []byte) []byte {
	t.Helper()
	pkg, err := ParsePackage(encoded)
	if err != nil {
		t.Fatal(err)
	}
	deks, err := pkg.Decrypt(kekSet)
	if err != nil {
		t.Fatal(err)
	}
	return deks
}

func encryptRawForTest(t *testing.T, deks []byte, serial uint16, plaintext []byte, nonceByte byte) []byte {
	t.Helper()
	key := deks[int(serial)*DEKBytes : int(serial+1)*DEKBytes]
	primitive, err := aead.New(suite.SM4GCM, key)
	if err != nil {
		t.Fatal(err)
	}
	nonce := bytes.Repeat([]byte{nonceByte}, UploadNonceBytes)
	ciphertext, tag := primitive.Encrypt(plaintext, nonce, nil)
	result := make([]byte, 2)
	binary.BigEndian.PutUint16(result, serial)
	return append(result, append(nonce, append(ciphertext, tag...)...)...)
}

func sequence(length int) []byte {
	result := make([]byte, length)
	for index := range result {
		result[index] = byte(index)
	}
	return result
}
