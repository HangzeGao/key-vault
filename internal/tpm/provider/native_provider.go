package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"

	legacy "github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
	"github.com/kvlt/key-vault/internal/crypto/aad"
)

// NativeOptions configures the in-process TPM 2.0 provider. On POSIX, TCTI is
// the absolute raw character-device path; no external command is executed.
type NativeOptions struct {
	TCTI string
	PCRs []int
}

// NativeProvider talks directly to TPM 2.0 using go-tpm. Sensitive parameters
// on the TPM transport are protected by salted sessions.
type NativeProvider struct {
	mu   sync.Mutex
	rw   io.ReadWriteCloser
	pcrs []int
}

type nativeSealedBundle struct {
	FormatVersion uint32 `json:"format_version"`
	Public        []byte `json:"public"`
	Private       []byte `json:"private"`
	PCRs          []int  `json:"pcrs"`
}

const (
	nativeSRKPersistentHandle tpmutil.Handle = 0x81000001
	nativeBundleFormatVersion uint32         = 2
)

func newNativeSRKTemplate() legacy.Public {
	return legacy.Public{
		Type: legacy.AlgRSA, NameAlg: legacy.AlgSHA256,
		Attributes: legacy.FlagFixedTPM | legacy.FlagFixedParent | legacy.FlagSensitiveDataOrigin |
			legacy.FlagUserWithAuth | legacy.FlagRestricted | legacy.FlagDecrypt | legacy.FlagNoDA,
		RSAParameters: &legacy.RSAParams{
			Symmetric: &legacy.SymScheme{Alg: legacy.AlgAES, KeyBits: 128, Mode: legacy.AlgCFB},
			KeyBits:   2048, ModulusRaw: make([]byte, 256),
		},
	}
}

func (p *NativeProvider) saltKey() (tpm2.NamedHandle, *tpm2.TPMTPublic, error) {
	template := newNativeSRKTemplate()
	public, name, _, err := legacy.ReadPublic(p.rw, nativeSRKPersistentHandle)
	if err != nil {
		var handleErr legacy.HandleError
		if !errors.As(err, &handleErr) || handleErr.Code != legacy.RCHandle {
			return tpm2.NamedHandle{}, nil, fmt.Errorf("provider: inspect persistent SRK: %w", err)
		}
		transient, _, err := legacy.CreatePrimary(p.rw, legacy.HandleOwner, legacy.PCRSelection{}, "", "", template)
		if err != nil {
			return tpm2.NamedHandle{}, nil, fmt.Errorf("provider: create native storage primary: %w", err)
		}
		defer legacy.FlushContext(p.rw, transient)
		if err := legacy.EvictControl(p.rw, "", legacy.HandleOwner, transient, nativeSRKPersistentHandle); err != nil {
			return tpm2.NamedHandle{}, nil, fmt.Errorf("provider: persist native storage primary: %w", err)
		}
		public, name, _, err = legacy.ReadPublic(p.rw, nativeSRKPersistentHandle)
		if err != nil {
			return tpm2.NamedHandle{}, nil, fmt.Errorf("provider: read native storage primary: %w", err)
		}
	}
	if !public.MatchesTemplate(template) {
		return tpm2.NamedHandle{}, nil, errors.New("provider: persistent SRK handle contains an incompatible object")
	}
	encoded, err := public.Encode()
	if err != nil {
		return tpm2.NamedHandle{}, nil, fmt.Errorf("provider: encode TPM storage public key: %w", err)
	}
	key, err := tpm2.Unmarshal[tpm2.TPMTPublic](encoded)
	if err != nil {
		return tpm2.NamedHandle{}, nil, fmt.Errorf("provider: decode TPM storage public key: %w", err)
	}
	return tpm2.NamedHandle{Handle: tpm2.TPMHandle(nativeSRKPersistentHandle), Name: tpm2.TPM2BName{Buffer: name}}, key, nil
}

func NewNativeProvider(opts NativeOptions) (*NativeProvider, error) {
	for _, pcr := range opts.PCRs {
		if pcr < 0 || pcr > 23 {
			return nil, fmt.Errorf("provider: PCR index %d out of range", pcr)
		}
	}
	rw, err := openNativeTPM(opts.TCTI)
	if err != nil {
		return nil, fmt.Errorf("provider: open native TPM transport: %w", err)
	}
	return newNativeProviderWithTransport(rw, opts.PCRs)
}

func newNativeProviderWithTransport(rw io.ReadWriteCloser, pcrs []int) (*NativeProvider, error) {
	if rw == nil {
		return nil, errors.New("provider: nil native TPM transport")
	}
	for _, pcr := range pcrs {
		if pcr < 0 || pcr > 23 {
			return nil, fmt.Errorf("provider: PCR index %d out of range", pcr)
		}
	}
	return &NativeProvider{rw: rw, pcrs: append([]int(nil), pcrs...)}, nil
}

func (p *NativeProvider) EnsureStorage(ctx context.Context, name string) (*TPMObjectRef, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if name == "" {
		return nil, errors.New("provider: empty storage name")
	}
	// The deterministic storage primary is recreated on demand. Its sensitive
	// material never leaves the TPM; the reference intentionally has no bytes.
	return &TPMObjectRef{Name: name}, nil
}

// FillRandom fills the caller-owned buffer from the physical TPM. Callers
// must restrict access to the TPM transport and clear the resulting material.
func (p *NativeProvider) FillRandom(ctx context.Context, output []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := ctx.Err(); err != nil {
		clear(output)
		return err
	}
	if len(output) == 0 {
		return nil
	}
	t := transport.FromReadWriter(p.rw)
	parent, public, err := p.saltKey()
	if err != nil {
		clear(output)
		return err
	}
	remaining := output
	for len(remaining) != 0 {
		if err := ctx.Err(); err != nil {
			clear(output)
			return err
		}
		requested := min(len(remaining), 32)
		session := tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.Salted(parent.Handle, *public), tpm2.AESEncryption(128, tpm2.EncryptOut))
		response, err := (tpm2.GetRandom{BytesRequested: uint16(requested)}).Execute(t, session)
		if err != nil {
			clear(output)
			return errors.New("provider: TPM random generation failed")
		}
		part := response.RandomBytes.Buffer
		if len(part) == 0 || len(part) > requested {
			clear(part)
			clear(output)
			return errors.New("provider: TPM random generation failed")
		}
		remaining = remaining[copy(remaining, part):]
		clear(part)
	}
	return nil
}

func (p *NativeProvider) Seal(ctx context.Context, storage *TPMObjectRef, plaintext []byte, sealContext aad.SealContext) (*SealedObject, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := validateNativeInputs(ctx, storage, sealContext); err != nil {
		return nil, err
	}
	t := transport.FromReadWriter(p.rw)
	parent, public, err := p.saltKey()
	if err != nil {
		return nil, err
	}
	// The policy session calculates the explicit PCR policy digest. Host access
	// is enforced by the dedicated non-root service account and TPM device ACL;
	// a deterministic context-derived password would not add a secret factor.
	session, policy, err := p.policySession()
	if err != nil {
		return nil, err
	}
	_ = legacy.FlushContext(p.rw, session)
	created, err := (tpm2.Create{
		ParentHandle: tpm2.AuthHandle{Handle: parent.Handle, Name: parent.Name,
			Auth: tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.Salted(parent.Handle, *public), tpm2.AESEncryption(128, tpm2.EncryptIn))},
		InSensitive: tpm2.TPM2BSensitiveCreate{Sensitive: &tpm2.TPMSSensitiveCreate{
			Data: tpm2.NewTPMUSensitiveCreate(&tpm2.TPM2BSensitiveData{Buffer: plaintext}),
		}},
		InPublic: tpm2.New2B(tpm2.TPMTPublic{
			Type: tpm2.TPMAlgKeyedHash, NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{FixedTPM: true, FixedParent: true},
			AuthPolicy:       tpm2.TPM2BDigest{Buffer: policy},
		}),
	}).Execute(t)
	if err != nil {
		return nil, fmt.Errorf("provider: seal secret in native TPM: %w", err)
	}
	bundle, err := json.Marshal(nativeSealedBundle{FormatVersion: nativeBundleFormatVersion, Public: created.OutPublic.Bytes(), Private: created.OutPrivate.Buffer, PCRs: p.pcrs})
	if err != nil {
		return nil, fmt.Errorf("provider: encode native sealed object: %w", err)
	}
	return &SealedObject{
		NodeID: sealContext.NodeID, Purpose: sealContext.Purpose, ObjectID: sealContext.ObjectID,
		StorageName: storage.Name, Blob: bundle,
		BaselineDigest: append([]byte(nil), sealContext.BaselineDigest...), PolicyDigest: append([]byte(nil), sealContext.PolicyDigest...),
		ContextDigest: contextDigestHex(sealContext),
	}, nil
}

func (p *NativeProvider) Unseal(ctx context.Context, storage *TPMObjectRef, object *SealedObject, sealContext aad.SealContext) ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := validateNativeInputs(ctx, storage, sealContext); err != nil {
		return nil, err
	}
	if object == nil || object.StorageName != storage.Name {
		return nil, errors.New("provider: storage name mismatch")
	}
	if err := validateSealedObjectContext(object, sealContext); err != nil {
		return nil, err
	}
	var bundle nativeSealedBundle
	if err := json.Unmarshal(object.Blob, &bundle); err != nil ||
		bundle.FormatVersion != nativeBundleFormatVersion || len(bundle.Public) == 0 || len(bundle.Private) == 0 {
		return nil, errors.New("provider: corrupt native sealed object")
	}
	if !equalInts(bundle.PCRs, p.pcrs) {
		return nil, errors.New("provider: TPM policy PCR set mismatch")
	}
	t := transport.FromReadWriter(p.rw)
	parent, public, err := p.saltKey()
	if err != nil {
		return nil, err
	}
	loaded, err := (tpm2.Load{ParentHandle: parent,
		InPublic: tpm2.BytesAs2B[tpm2.TPMTPublic](bundle.Public), InPrivate: tpm2.TPM2BPrivate{Buffer: bundle.Private},
	}).Execute(t)
	if err != nil {
		return nil, fmt.Errorf("provider: load native sealed object: %w", err)
	}
	defer (tpm2.FlushContext{FlushHandle: loaded.ObjectHandle}).Execute(t)
	session, closeSession, err := tpm2.PolicySession(t, tpm2.TPMAlgSHA256, 16,
		tpm2.Salted(parent.Handle, *public), tpm2.AESEncryption(128, tpm2.EncryptOut))
	if err != nil {
		return nil, fmt.Errorf("provider: start encrypted TPM policy session: %w", err)
	}
	defer closeSession()
	if err := p.applyPCRPolicy(tpmutil.Handle(session.Handle())); err != nil {
		return nil, err
	}
	response, err := (tpm2.Unseal{ItemHandle: tpm2.AuthHandle{Handle: loaded.ObjectHandle, Name: loaded.Name, Auth: session}}).Execute(t)
	if err != nil {
		return nil, errors.New("provider: TPM policy refused secret unseal")
	}
	return response.OutData.Buffer, nil
}

func (p *NativeProvider) policySession() (tpmutil.Handle, []byte, error) {
	session, _, err := legacy.StartAuthSession(p.rw, legacy.HandleNull, legacy.HandleNull, make([]byte, 16), nil, legacy.SessionPolicy, legacy.AlgNull, legacy.AlgSHA256)
	if err != nil {
		return legacy.HandleNull, nil, fmt.Errorf("provider: start TPM policy session: %w", err)
	}
	if err := p.applyPCRPolicy(session); err != nil {
		_ = legacy.FlushContext(p.rw, session)
		return legacy.HandleNull, nil, err
	}
	digest, err := legacy.PolicyGetDigest(p.rw, session)
	if err != nil {
		_ = legacy.FlushContext(p.rw, session)
		return legacy.HandleNull, nil, fmt.Errorf("provider: read policy digest: %w", err)
	}
	return session, digest, nil
}

func (p *NativeProvider) applyPCRPolicy(session tpmutil.Handle) error {
	if len(p.pcrs) > 0 {
		selection := legacy.PCRSelection{Hash: legacy.AlgSHA256, PCRs: p.pcrs}
		if err := legacy.PolicyPCR(p.rw, session, nil, selection); err != nil {
			return fmt.Errorf("provider: apply PolicyPCR: %w", err)
		}
	}
	return nil
}

func validateNativeInputs(ctx context.Context, storage *TPMObjectRef, a aad.SealContext) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if storage == nil || storage.Name == "" {
		return errors.New("provider: missing storage reference")
	}
	if a.Purpose == "" || a.ObjectID == "" || a.NodeID == "" || a.StorageName == "" || len(a.BaselineDigest) == 0 || len(a.PolicyDigest) == 0 {
		return errors.New("provider: incomplete TPM policy context")
	}
	return nil
}

func equalInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
func (p *NativeProvider) Quote(context.Context, []byte, []int) ([]byte, error) {
	return nil, errors.New("provider: quote requires a provisioned attestation key")
}
func (p *NativeProvider) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.rw == nil {
		return nil
	}
	err := p.rw.Close()
	p.rw = nil
	return err
}
