package commissioning

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"time"
)

// GroundAuthorization binds approval to a verified cold-restart closure receipt
// and one exact package. The deployment authority signs only after verifying
// the receipt and authenticating the operator's installation request.
type GroundAuthorization struct {
	ClosureDigest [32]byte
	AnchorName    [2 + sha256.Size]byte
	ExpiresUnix   int64
	Signature     []byte
}

type AuthorizedGroundInstall struct {
	binding      Binding
	envelope     Envelope
	recordDigest [32]byte
	anchorName   [2 + sha256.Size]byte
}

// AuthorizeGroundInstall verifies the approval before the import key can be
// used. It owns a copy of the authenticated envelope for subsequent opening.
func AuthorizeGroundInstall(binding Binding, envelope Envelope, auth GroundAuthorization,
	authority ed25519.PublicKey, now time.Time) (*AuthorizedGroundInstall, error) {
	info, size := binding.info()
	if binding.Purpose != GroundRoots || size == 0 || auth.ClosureDigest == ([32]byte{}) || auth.ExpiresUnix <= now.Unix() ||
		binary.BigEndian.Uint16(auth.AnchorName[:]) != 0x000b ||
		len(authority) != ed25519.PublicKeySize || len(envelope.Enc) != encSize || len(envelope.Ciphertext) != size+16 ||
		len(envelope.Signature) == 0 || len(envelope.Signature) > maxSignature {
		return nil, ErrLifecycle
	}
	packageDigest := groundPackageDigest(envelope)
	message := append([]byte("TC-GROUND-INSTALL-V2\x00"), info...)
	message = append(message, packageDigest[:]...)
	message = append(message, auth.ClosureDigest[:]...)
	message = append(message, auth.AnchorName[:]...)
	recordDigest := sha256.Sum256(message)
	message = binary.BigEndian.AppendUint64(message, uint64(auth.ExpiresUnix))
	if !ed25519.Verify(authority, message, auth.Signature) {
		return nil, ErrLifecycle
	}
	return &AuthorizedGroundInstall{binding: binding, recordDigest: recordDigest, anchorName: auth.AnchorName, envelope: Envelope{
		Enc: append([]byte(nil), envelope.Enc...), Ciphertext: append([]byte(nil), envelope.Ciphertext...),
		Signature: append([]byte(nil), envelope.Signature...),
	}}, nil
}

func groundPackageDigest(envelope Envelope) [32]byte {
	packageBytes := append([]byte(nil), envelope.Enc...)
	packageBytes = append(packageBytes, envelope.Ciphertext...)
	return sha256.Sum256(append(packageBytes, envelope.Signature...))
}

func (a *AuthorizedGroundInstall) RecordDigest() [32]byte { return a.recordDigest }
func (a *AuthorizedGroundInstall) Binding() Binding       { return a.binding }
func (a *AuthorizedGroundInstall) AnchorName() [34]byte   { return a.anchorName }

// Import verifies the trusted issuer's envelope signature before ECDH.
func (a *AuthorizedGroundInstall) Import(key ecdh.KeyExchanger, issuer *ecdsa.PublicKey, install func([]byte) error) error {
	return open(a.binding, a.envelope, key, issuer, install)
}
