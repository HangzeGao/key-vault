package provider

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/sha256"
	"errors"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
)

// RegisteredImportKey comes from the trusted local enrollment record. Names
// are TPM SHA-256 object Names, including the two-byte hash algorithm ID.
type RegisteredImportKey struct {
	Handle      uint32
	ObjectName  [2 + sha256.Size]byte
	StorageName [2 + sha256.Size]byte
}

var errImportKey = errors.New("provider: TPM import key unavailable or unauthorized")

type nativeImportKey struct {
	provider     *NativeProvider
	ctx          context.Context
	registration RegisteredImportKey
	public       *ecdh.PublicKey
	shared       []byte // guarded by provider.mu and cleared when the import ends
}

// WithImportKey makes a registered TPM key available for a scoped HPKE import.
// The caller verifies transaction authorization and the envelope signature
// before invoking ECDH. One successful exchange is allowed per scope. Its
// result is cleared and the exchanger expires when consume returns.
func (p *NativeProvider) WithImportKey(ctx context.Context, registration RegisteredImportKey, consume func(ecdh.KeyExchanger) error) error {
	if consume == nil || registration.Handle>>24 != uint32(tpm2.TPMHTPersistent) ||
		registration.Handle == uint32(nativeSRKPersistentHandle) || len(p.pcrs) == 0 {
		return errImportKey
	}
	public, err := p.importPublicKey(ctx, registration)
	if err != nil {
		return err
	}
	scope, cancel := context.WithCancel(ctx)
	key := &nativeImportKey{provider: p, ctx: scope, registration: registration, public: public}
	defer func() {
		cancel()
		p.mu.Lock()
		clear(key.shared)
		p.mu.Unlock()
	}()
	return consume(key)
}

func (p *NativeProvider) importPublicKey(ctx context.Context, registration RegisteredImportKey) (*ecdh.PublicKey, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if ctx.Err() != nil || p.rw == nil {
		return nil, errImportKey
	}
	t := transport.FromReadWriter(p.rw)
	public, err := readRegisteredPublic(t, tpm2.TPMHandle(registration.Handle), registration.ObjectName)
	if err != nil {
		return nil, err
	}
	attrs := public.ObjectAttributes
	if public.Type != tpm2.TPMAlgECC || len(public.AuthPolicy.Buffer) != sha256.Size ||
		!attrs.FixedTPM || !attrs.FixedParent || !attrs.SensitiveDataOrigin || !attrs.Decrypt ||
		attrs.UserWithAuth || attrs.Restricted || attrs.SignEncrypt {
		return nil, errImportKey
	}
	params, err := public.Parameters.ECCDetail()
	if err != nil || params.CurveID != tpm2.TPMECCNistP256 || params.Scheme.Scheme != tpm2.TPMAlgECDH {
		return nil, errImportKey
	}
	point, err := public.Unique.ECC()
	if err != nil {
		return nil, errImportKey
	}
	key, err := tpm2.ECDHPub(params, point)
	if err != nil {
		return nil, errImportKey
	}
	return key, nil
}

func readRegisteredPublic(t transport.TPM, handle tpm2.TPMHandle, expected [2 + sha256.Size]byte) (*tpm2.TPMTPublic, error) {
	response, err := (tpm2.ReadPublic{ObjectHandle: handle}).Execute(t)
	if err != nil || !bytes.Equal(response.Name.Buffer, expected[:]) {
		return nil, errImportKey
	}
	public, err := response.OutPublic.Contents()
	if err != nil || public.NameAlg != tpm2.TPMAlgSHA256 {
		return nil, errImportKey
	}
	name, err := tpm2.ObjectName(public)
	if err != nil || !bytes.Equal(name.Buffer, expected[:]) {
		return nil, errImportKey
	}
	return public, nil
}

func (k *nativeImportKey) PublicKey() *ecdh.PublicKey { return k.public }
func (k *nativeImportKey) Curve() ecdh.Curve          { return ecdh.P256() }

func (k *nativeImportKey) ECDH(peer *ecdh.PublicKey) ([]byte, error) {
	if peer == nil || peer.Curve() != k.Curve() {
		return nil, errImportKey
	}
	p := k.provider
	p.mu.Lock()
	defer p.mu.Unlock()
	if k.ctx.Err() != nil || p.rw == nil || k.shared != nil {
		return nil, errImportKey
	}
	t := transport.FromReadWriter(p.rw)
	saltHandle := tpm2.TPMHandle(nativeSRKPersistentHandle)
	salt, err := readRegisteredPublic(t, saltHandle, k.registration.StorageName)
	if err != nil {
		return nil, err
	}
	session, closeSession, err := tpm2.PolicySession(t, tpm2.TPMAlgSHA256, 16,
		tpm2.Salted(saltHandle, *salt), tpm2.AESEncryption(128, tpm2.EncryptOut))
	if err != nil {
		return nil, errImportKey
	}
	defer closeSession()
	if err := p.applyPCRPolicy(tpmutil.Handle(session.Handle())); err != nil {
		return nil, errImportKey
	}
	if _, err := (tpm2.PolicyCommandCode{PolicySession: session.Handle(), Code: tpm2.TPMCCECDHZGen}).Execute(t); err != nil {
		return nil, errImportKey
	}
	point := peer.Bytes()
	response, err := (tpm2.ECDHZGen{
		KeyHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMHandle(k.registration.Handle),
			Name:   tpm2.TPM2BName{Buffer: k.registration.ObjectName[:]},
			Auth:   session,
		},
		InPoint: tpm2.New2B(tpm2.TPMSECCPoint{
			X: tpm2.TPM2BECCParameter{Buffer: point[1:33]},
			Y: tpm2.TPM2BECCParameter{Buffer: point[33:]},
		}),
	}).Execute(t)
	if err != nil {
		return nil, errImportKey
	}
	defer clear(response.OutPoint.Bytes())
	shared, err := response.OutPoint.Contents()
	if err != nil {
		return nil, errImportKey
	}
	defer clear(shared.X.Buffer)
	defer clear(shared.Y.Buffer)
	if len(shared.X.Buffer) == 0 || len(shared.X.Buffer) > sha256.Size || k.ctx.Err() != nil {
		return nil, errImportKey
	}
	k.shared = make([]byte, sha256.Size)
	copy(k.shared[len(k.shared)-len(shared.X.Buffer):], shared.X.Buffer)
	return k.shared, nil
}
