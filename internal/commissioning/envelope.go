// Package commissioning implements controls shared by the offline test and
// commissioning tools. Device identity, trusted storage and authorization are
// supplied by the platform integration.
package commissioning

import (
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hpke"
	"crypto/rand"
	"crypto/sha256"
	"errors"
)

type Purpose byte

const (
	TestRoots    Purpose = 1
	GroundRoots  Purpose = 2
	FlightRoots  Purpose = 3
	rootSize             = 16
	encSize              = 65
	maxSignature         = 72
)

var ErrEnvelope = errors.New("commissioning: rejected key envelope")

// Binding is reconstructed by the receiver from independently verified
// authorization and local device identity. Authorization is never taken from
// the envelope. All binary identifiers have exactly 32 bytes.
type Binding struct {
	Purpose        Purpose
	ProfileDigest  [32]byte
	DeviceID       [32]byte
	RecipientKeyID [32]byte
	Transaction    [32]byte
}

type Envelope struct {
	Enc        []byte
	Ciphertext []byte
	Signature  []byte // ECDSA P-256, ASN.1 DER
}

// GenerateRoots uses the ground host TPM through the supplied random source.
// Roots are available to the trusted consumer for the duration of the call.
func GenerateRoots(ctx context.Context, purpose Purpose, random func(context.Context, []byte) error, consume func([]byte) error) error {
	size := purpose.size()
	if size == 0 || random == nil || consume == nil {
		return ErrEnvelope
	}
	roots := make([]byte, size)
	defer clear(roots)
	if random(ctx, roots) != nil || consume(roots) != nil {
		return errors.New("commissioning: protected root preparation failed")
	}
	return nil
}

func (p Purpose) size() int {
	switch p {
	case TestRoots, FlightRoots:
		return 2 * rootSize
	case GroundRoots:
		return 3 * rootSize
	default:
		return 0
	}
}

func (b Binding) info() ([]byte, int) {
	if b.ProfileDigest == ([32]byte{}) || b.DeviceID == ([32]byte{}) ||
		b.RecipientKeyID == ([32]byte{}) || b.Transaction == ([32]byte{}) {
		return nil, 0
	}
	size := b.Purpose.size()
	if size == 0 {
		return nil, 0
	}
	info := append([]byte("TC-ROOT-ENVELOPE-V1\x00"), byte(b.Purpose))
	info = append(info, b.ProfileDigest[:]...)
	info = append(info, b.DeviceID[:]...)
	info = append(info, b.RecipientKeyID[:]...)
	return append(info, b.Transaction[:]...), size
}

func signatureDigest(info []byte, e Envelope) [32]byte {
	data := append([]byte("TC-ROOT-ENVELOPE-SIGN-V1\x00"), info...)
	data = append(data, e.Enc...)
	return sha256.Sum256(append(data, e.Ciphertext...))
}

func p256Signer(key crypto.PublicKey) (*ecdsa.PublicKey, bool) {
	pub, ok := key.(*ecdsa.PublicKey)
	return pub, ok && pub != nil && pub.Curve == elliptic.P256() && pub.X != nil && pub.Y != nil && pub.Curve.IsOnCurve(pub.X, pub.Y)
}

// Seal accepts roots in Current, Recovery, then Next order. Only a ground
// production envelope includes Next. The caller owns the plaintext input.
func Seal(binding Binding, recipient *ecdh.PublicKey, signer crypto.Signer, roots []byte) (Envelope, error) {
	info, size := binding.info()
	if size == 0 || len(roots) != size || recipient == nil || signer == nil ||
		recipient.Curve() != ecdh.P256() || sha256.Sum256(recipient.Bytes()) != binding.RecipientKeyID {
		return Envelope{}, ErrEnvelope
	}
	pub, ok := p256Signer(signer.Public())
	if !ok {
		return Envelope{}, ErrEnvelope
	}
	key, err := hpke.NewDHKEMPublicKey(recipient)
	if err != nil {
		return Envelope{}, ErrEnvelope
	}
	enc, sender, err := hpke.NewSender(key, hpke.HKDFSHA256(), hpke.AES128GCM(), info)
	if err != nil {
		return Envelope{}, ErrEnvelope
	}
	ciphertext, err := sender.Seal(info, roots)
	if err != nil {
		return Envelope{}, ErrEnvelope
	}
	e := Envelope{Enc: enc, Ciphertext: ciphertext}
	digest := signatureDigest(info, e)
	e.Signature, err = signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil || !ecdsa.VerifyASN1(pub, digest[:], e.Signature) {
		return Envelope{}, ErrEnvelope
	}
	return e, nil
}

// open verifies the independently pinned issuer before using the device key.
// Roots are only available to install, which must synchronously seal or store
// them without retaining the slice. Open clears the transient plaintext.
func open(binding Binding, e Envelope, recipient ecdh.KeyExchanger, issuer *ecdsa.PublicKey, install func([]byte) error) error {
	info, size := binding.info()
	if size == 0 || len(e.Enc) != encSize || len(e.Ciphertext) != size+16 ||
		len(e.Signature) == 0 || len(e.Signature) > maxSignature || recipient == nil || install == nil {
		return ErrEnvelope
	}
	if _, ok := p256Signer(issuer); !ok {
		return ErrEnvelope
	}
	digest := signatureDigest(info, e)
	if !ecdsa.VerifyASN1(issuer, digest[:], e.Signature) {
		return ErrEnvelope
	}
	pub := recipient.PublicKey()
	if pub == nil || recipient.Curve() != ecdh.P256() || pub.Curve() != ecdh.P256() ||
		sha256.Sum256(pub.Bytes()) != binding.RecipientKeyID {
		return ErrEnvelope
	}
	key, err := hpke.NewDHKEMPrivateKey(recipient)
	if err != nil {
		return ErrEnvelope
	}
	receiver, err := hpke.NewRecipient(e.Enc, key, hpke.HKDFSHA256(), hpke.AES128GCM(), info)
	if err != nil {
		return ErrEnvelope
	}
	roots, err := receiver.Open(info, e.Ciphertext)
	if err != nil {
		return ErrEnvelope
	}
	defer clear(roots)
	if install(roots) != nil {
		return errors.New("commissioning: protected root installation failed")
	}
	return nil
}
