package provider

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"

	legacy "github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"github.com/kvlt/key-vault/internal/crypto/aad"
)

// NativeOptions configures the in-process TPM 2.0 provider. TCTI is a device
// path or supported platform transport name; no external command is executed.
type NativeOptions struct {
	TCTI string
	PCRs []int
}

// NativeProvider talks directly to TPM 2.0 using go-tpm. CRK plaintext is
// passed only in the TPM command buffer and is never written to disk.
type NativeProvider struct {
	mu   sync.Mutex
	rw   io.ReadWriteCloser
	pcrs []int
}

type nativeSealedBundle struct {
	Public  []byte `json:"public"`
	Private []byte `json:"private"`
	PCRs    []int  `json:"pcrs"`
}

var nativeSRKTemplate = legacy.Public{
	Type: legacy.AlgRSA, NameAlg: legacy.AlgSHA256,
	Attributes: legacy.FlagFixedTPM | legacy.FlagFixedParent | legacy.FlagSensitiveDataOrigin |
		legacy.FlagUserWithAuth | legacy.FlagRestricted | legacy.FlagDecrypt | legacy.FlagNoDA,
	RSAParameters: &legacy.RSAParams{
		Symmetric: &legacy.SymScheme{Alg: legacy.AlgAES, KeyBits: 128, Mode: legacy.AlgCFB},
		KeyBits:   2048, ModulusRaw: make([]byte, 256),
	},
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

func (p *NativeProvider) EnsureNRWK(ctx context.Context, name string) (*TPMObjectRef, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if name == "" {
		return nil, errors.New("provider: empty NRWK name")
	}
	// The deterministic storage primary is recreated on demand. Its sensitive
	// material never leaves the TPM; the reference intentionally has no bytes.
	return &TPMObjectRef{Name: name}, nil
}

func (p *NativeProvider) SealCRK(ctx context.Context, nrwk *TPMObjectRef, crk []byte, contextAAD aad.CRKAAD) (*CRKEnvelope, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := validateNativeInputs(ctx, nrwk, contextAAD); err != nil {
		return nil, err
	}
	primary, _, err := legacy.CreatePrimary(p.rw, legacy.HandleOwner, legacy.PCRSelection{}, "", "", nativeSRKTemplate)
	if err != nil {
		return nil, fmt.Errorf("provider: create native storage primary: %w", err)
	}
	defer legacy.FlushContext(p.rw, primary)
	password, err := nativeContextPassword(contextAAD)
	if err != nil {
		return nil, err
	}
	// The policy session is used here to calculate the object policy digest;
	// unseal recreates the same PolicyPCR + PolicyPassword session.
	session, policy, err := p.policySession(password)
	if err != nil {
		return nil, err
	}
	_ = legacy.FlushContext(p.rw, session)
	private, public, err := legacy.Seal(p.rw, primary, "", password, policy, crk)
	if err != nil {
		return nil, fmt.Errorf("provider: seal CRK in native TPM: %w", err)
	}
	bundle, err := json.Marshal(nativeSealedBundle{Public: public, Private: private, PCRs: p.pcrs})
	if err != nil {
		return nil, fmt.Errorf("provider: encode native sealed object: %w", err)
	}
	return &CRKEnvelope{
		NodeID: contextAAD.NodeID, ClusterID: contextAAD.ClusterID, PlaneRole: contextAAD.PlaneRole,
		CRKVersion: contextAAD.CRKVersion, NRWKName: nrwk.Name, WrappedCRK: bundle,
		BaselineDigest: append([]byte(nil), contextAAD.BaselineDigest...), PolicyDigest: append([]byte(nil), contextAAD.PolicyDigest...),
		CRKAADDigest: aadDigestHex(contextAAD),
	}, nil
}

func (p *NativeProvider) UnsealCRK(ctx context.Context, nrwk *TPMObjectRef, env *CRKEnvelope, contextAAD aad.CRKAAD) ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := validateNativeInputs(ctx, nrwk, contextAAD); err != nil {
		return nil, err
	}
	if env.NRWKName != nrwk.Name {
		return nil, errors.New("provider: NRWK name mismatch")
	}
	if err := validateCRKEnvelopeAAD(env, contextAAD); err != nil {
		return nil, err
	}
	var bundle nativeSealedBundle
	if err := json.Unmarshal(env.WrappedCRK, &bundle); err != nil || len(bundle.Public) == 0 || len(bundle.Private) == 0 {
		return nil, errors.New("provider: corrupt native CRK envelope")
	}
	if !equalInts(bundle.PCRs, p.pcrs) {
		return nil, errors.New("provider: TPM policy PCR set mismatch")
	}
	primary, _, err := legacy.CreatePrimary(p.rw, legacy.HandleOwner, legacy.PCRSelection{}, "", "", nativeSRKTemplate)
	if err != nil {
		return nil, fmt.Errorf("provider: create native storage primary: %w", err)
	}
	defer legacy.FlushContext(p.rw, primary)
	object, _, err := legacy.Load(p.rw, primary, "", bundle.Public, bundle.Private)
	if err != nil {
		return nil, fmt.Errorf("provider: load native sealed object: %w", err)
	}
	defer legacy.FlushContext(p.rw, object)
	password, err := nativeContextPassword(contextAAD)
	if err != nil {
		return nil, err
	}
	session, _, err := p.policySession(password)
	if err != nil {
		return nil, err
	}
	defer legacy.FlushContext(p.rw, session)
	plaintext, err := legacy.UnsealWithSession(p.rw, session, object, password)
	if err != nil {
		return nil, errors.New("provider: TPM policy refused CRK unseal")
	}
	return plaintext, nil
}

func (p *NativeProvider) policySession(password string) (tpmutil.Handle, []byte, error) {
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
	if err := legacy.PolicyPassword(p.rw, session); err != nil {
		_ = legacy.FlushContext(p.rw, session)
		return legacy.HandleNull, nil, fmt.Errorf("provider: apply PolicyPassword: %w", err)
	}
	digest, err := legacy.PolicyGetDigest(p.rw, session)
	if err != nil {
		_ = legacy.FlushContext(p.rw, session)
		return legacy.HandleNull, nil, fmt.Errorf("provider: read policy digest: %w", err)
	}
	return session, digest, nil
}

func nativeContextPassword(a aad.CRKAAD) (string, error) {
	b, err := a.Canonical()
	if err != nil {
		return "", fmt.Errorf("provider: canonical context: %w", err)
	}
	sum := sha256.Sum256(append([]byte("kvlt-tpm-policy-context-v1\x00"), b...))
	return hex.EncodeToString(sum[:]), nil
}

func validateNativeInputs(ctx context.Context, nrwk *TPMObjectRef, a aad.CRKAAD) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if nrwk == nil || nrwk.Name == "" {
		return errors.New("provider: missing NRWK reference")
	}
	if a.ClusterID == "" || a.NodeID == "" || a.PlaneRole == "" || len(a.BaselineDigest) == 0 || len(a.PolicyDigest) == 0 {
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
