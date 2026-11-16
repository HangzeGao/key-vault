package commissioning

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"testing"
	"time"
)

func TestAuthorizedGroundInstall(t *testing.T) {
	receiver, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	authority, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b := Binding{Purpose: GroundRoots, Transaction: [32]byte{1}, ProfileDigest: [32]byte{2},
		DeviceID: [32]byte{3}, RecipientKeyID: sha256.Sum256(receiver.PublicKey().Bytes())}
	roots := bytes.Repeat([]byte{17}, 48)
	envelope, err := Seal(b, receiver.PublicKey(), issuer, roots)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1024, 0)
	auth := GroundAuthorization{ClosureDigest: [32]byte{4}, ExpiresUnix: 1025}
	info, _ := b.info()
	packageBytes := bytes.Join([][]byte{envelope.Enc, envelope.Ciphertext, envelope.Signature}, nil)
	digest := sha256.Sum256(packageBytes)
	message := bytes.Join([][]byte{[]byte("TC-GROUND-INSTALL-V1\x00"), info, digest[:], auth.ClosureDigest[:]}, nil)
	wantRecord := sha256.Sum256(message)
	auth.Signature = ed25519.Sign(private, binary.BigEndian.AppendUint64(message, uint64(auth.ExpiresUnix)))
	verified, err := AuthorizeGroundInstall(b, envelope, auth, authority, now)
	if err != nil || verified.RecordDigest() != wantRecord {
		t.Fatalf("authorize: %v", err)
	}
	wrong := b
	wrong.Transaction[0] ^= 1
	if _, err := AuthorizeGroundInstall(wrong, envelope, auth, authority, now); !errors.Is(err, ErrLifecycle) {
		t.Fatal("approval worked for a different transaction")
	}
	wrong.Purpose = FlightRoots
	if _, err := AuthorizeGroundInstall(wrong, envelope, auth, authority, now); !errors.Is(err, ErrLifecycle) {
		t.Fatal("ground approval worked for a flight envelope")
	}
	if _, err := AuthorizeGroundInstall(b, envelope, auth, authority, time.Unix(auth.ExpiresUnix, 0)); !errors.Is(err, ErrLifecycle) {
		t.Fatal("expired approval accepted")
	}
	envelope.Ciphertext[0] ^= 1
	if _, err := AuthorizeGroundInstall(b, envelope, auth, authority, now); !errors.Is(err, ErrLifecycle) {
		t.Fatal("changed package accepted")
	}
	var retained []byte
	if err := verified.Import(receiver, &issuer.PublicKey, func(plain []byte) error {
		if !bytes.Equal(plain, roots) {
			t.Fatal("import returned different roots")
		}
		retained = plain
		return nil
	}); err != nil || !bytes.Equal(retained, make([]byte, 48)) {
		t.Fatalf("import did not clear roots: %v", err)
	}
}
