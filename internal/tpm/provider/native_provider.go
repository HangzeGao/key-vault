package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"

	legacy "github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"github.com/kvlt/key-vault/internal/crypto/aad"
)

// NativeOptions configures the in-process TPM 2.0 provider. On POSIX, TCTI is
// the absolute raw character-device path; no external command is executed.
type NativeOptions struct {
	TCTI string
	PCRs []int
}

// NativeProvider talks directly to TPM 2.0 using go-tpm. Secret plaintext is
// passed only in the TPM command buffer and is never written to disk.
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

func (p *NativeProvider) ensureStorageRootKey() (tpmutil.Handle, error) {
	template := newNativeSRKTemplate()
	public, _, _, err := legacy.ReadPublic(p.rw, nativeSRKPersistentHandle)
	if err == nil {
		if !public.MatchesTemplate(template) {
			return 0, errors.New("provider: persistent SRK handle contains an incompatible object")
		}
		return nativeSRKPersistentHandle, nil
	}
	var handleErr legacy.HandleError
	if !errors.As(err, &handleErr) || handleErr.Code != legacy.RCHandle {
		return 0, fmt.Errorf("provider: inspect persistent SRK: %w", err)
	}
	transient, _, err := legacy.CreatePrimary(p.rw, legacy.HandleOwner, legacy.PCRSelection{}, "", "", template)
	if err != nil {
		return 0, fmt.Errorf("provider: create native storage primary: %w", err)
	}
	defer legacy.FlushContext(p.rw, transient)
	if err := legacy.EvictControl(p.rw, "", legacy.HandleOwner, transient, nativeSRKPersistentHandle); err != nil {
		return 0, fmt.Errorf("provider: persist native storage primary: %w", err)
	}
	return nativeSRKPersistentHandle, nil
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

func (p *NativeProvider) Seal(ctx context.Context, storage *TPMObjectRef, plaintext []byte, sealContext aad.SealContext) (*SealedObject, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := validateNativeInputs(ctx, storage, sealContext); err != nil {
		return nil, err
	}
	primary, err := p.ensureStorageRootKey()
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
	private, public, err := legacy.Seal(p.rw, primary, "", "", policy, plaintext)
	if err != nil {
		return nil, fmt.Errorf("provider: seal secret in native TPM: %w", err)
	}
	bundle, err := json.Marshal(nativeSealedBundle{FormatVersion: nativeBundleFormatVersion, Public: public, Private: private, PCRs: p.pcrs})
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
	if object.StorageName != storage.Name {
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
	primary, err := p.ensureStorageRootKey()
	if err != nil {
		return nil, err
	}
	objectHandle, _, err := legacy.Load(p.rw, primary, "", bundle.Public, bundle.Private)
	if err != nil {
		return nil, fmt.Errorf("provider: load native sealed object: %w", err)
	}
	defer legacy.FlushContext(p.rw, objectHandle)
	session, _, err := p.policySession()
	if err != nil {
		return nil, err
	}
	defer legacy.FlushContext(p.rw, session)
	plaintext, err := legacy.UnsealWithSession(p.rw, session, objectHandle, "")
	if err != nil {
		return nil, errors.New("provider: TPM policy refused secret unseal")
	}
	return plaintext, nil
}

func (p *NativeProvider) policySession() (tpmutil.Handle, []byte, error) {
	session, _, err := legacy.StartAuthSession(p.rw, legacy.HandleNull, legacy.HandleNull, make([]byte, 16), nil, legacy.SessionPolicy, legacy.AlgNull, legacy.AlgSHA256)
	if err != nil {
		return legacy.HandleNull, nil, fmt.Errorf("provider: start TPM policy session: %w", err)
	}
	selection := legacy.PCRSelection{Hash: legacy.AlgSHA256, PCRs: p.pcrs}
	if len(p.pcrs) > 0 {
		if err := legacy.PolicyPCR(p.rw, session, nil, selection); err != nil {
			_ = legacy.FlushContext(p.rw, session)
			return legacy.HandleNull, nil, fmt.Errorf("provider: apply PolicyPCR: %w", err)
		}
	}
	digest, err := legacy.PolicyGetDigest(p.rw, session)
	if err != nil {
		_ = legacy.FlushContext(p.rw, session)
		return legacy.HandleNull, nil, fmt.Errorf("provider: read policy digest: %w", err)
	}
	return session, digest, nil
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
