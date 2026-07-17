// Package provider defines the TPMProvider interface and a software-backed
// implementation for engineering baseline testing. In environments without
// swtpm, a software provider that emulates seal/unseal with AES-256-GCM is
// acceptable for local baseline verification.
//
// The software provider persists NRWK and CRK envelopes to disk so that
// restart recovery works (design §19.1: "swtpm 创建 NRWK、封装/解封 CRK、
// 重启后恢复"). It is NOT a security boundary; production deployments MUST
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
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/kvlt/key-vault/internal/crypto/aad"
)

// CRKEnvelope is the sealed CRK material for a node.
type CRKEnvelope struct {
	NodeID         string `json:"node_id"`
	ClusterID      string `json:"cluster_id"`
	PlaneRole      string `json:"plane_role"`
	CRKVersion     uint32 `json:"crk_version"`
	NRWKName       string `json:"nrwk_name"`
	WrappedCRK     []byte `json:"wrapped_crk"` // AES-GCM sealed
	Nonce          []byte `json:"nonce"`
	Tag            []byte `json:"tag"`
	BaselineDigest []byte `json:"baseline_digest"`
	PolicyDigest   []byte `json:"policy_digest"`
	CRKAADDigest   string `json:"crk_aad_digest"`
}

// TPMObjectRef references an NRWK in the provider.
type TPMObjectRef struct {
	Name     string `json:"name"`
	KeyBytes []byte `json:"key_bytes"` // software provider only; real TPM never exposes
}

// Provider is the TPM abstraction.
type Provider interface {
	// EnsureNRWK creates or loads the NRWK for the given name.
	EnsureNRWK(ctx context.Context, name string) (*TPMObjectRef, error)
	// SealCRK encrypts the CRK plaintext under the NRWK, bound to the AAD.
	SealCRK(ctx context.Context, nrwk *TPMObjectRef, crk []byte, aad aad.CRKAAD) (*CRKEnvelope, error)
	// UnsealCRK decrypts the CRK envelope, verifying the AAD.
	UnsealCRK(ctx context.Context, nrwk *TPMObjectRef, env *CRKEnvelope, aad aad.CRKAAD) ([]byte, error)
	// Quote is a baseline stub and returns a fixed placeholder.
	Quote(ctx context.Context, nonce []byte, pcrs []int) ([]byte, error)
	// Close releases provider resources.
	Close() error
}

// SoftwareProvider is a disk-backed software TPM emulator for baseline testing.
type SoftwareProvider struct {
	mu       sync.Mutex
	stateDir string
	nrwk     map[string]*TPMObjectRef
}

// HardwareOptions controls the restricted tpm2-tools based provider.
type HardwareOptions struct {
	StateDir   string
	ToolDir    string
	TCTI       string
	ExtraEnv   []string
	AllowShell bool
}

// NewHardwareProvider constructs a TPM2-backed provider using tpm2-tools.
func NewHardwareProvider(stateDir string) (*HardwareProvider, error) {
	return NewHardwareProviderWithOptions(HardwareOptions{StateDir: stateDir})
}

// NewHardwareProviderWithOptions constructs a TPM2-backed provider using a
// restricted tpm2-tools runner. This provider is a hardened engineering
// baseline; production deployments should use a native TSS/ESAPI provider.
func NewHardwareProviderWithOptions(opts HardwareOptions) (*HardwareProvider, error) {
	if opts.AllowShell {
		return nil, fmt.Errorf("provider: shell execution is not allowed")
	}
	stateDir := opts.StateDir
	if stateDir == "" {
		stateDir = filepath.Join(os.TempDir(), "kvlt-tpm")
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, fmt.Errorf("provider: mkdir: %w", err)
	}
	if err := restrictDirMode(stateDir); err != nil {
		return nil, err
	}
	h := &HardwareProvider{
		stateDir: stateDir,
		tools:    make(map[string]string),
		tcti:     opts.TCTI,
		extraEnv: append([]string(nil), opts.ExtraEnv...),
	}
	for _, name := range []string{"tpm2_getrandom", "tpm2_createprimary", "tpm2_create", "tpm2_load", "tpm2_unseal"} {
		path, err := resolveTool(opts.ToolDir, name)
		if err != nil {
			return nil, err
		}
		h.tools[name] = path
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := h.run(ctx, "", "tpm2_getrandom", "8"); err != nil {
		return nil, fmt.Errorf("provider: hardware TPM unavailable: %w", err)
	}
	return h, nil
}

// HardwareProvider uses the host TPM 2.0 through tpm2-tools. It never exposes
// a wrapping key in process memory; sealed CRK objects are stored as TPM public
// and private blobs inside CRKEnvelope.WrappedCRK.
type HardwareProvider struct {
	mu       sync.Mutex
	stateDir string
	tools    map[string]string
	tcti     string
	extraEnv []string
}

type sealedObjectBundle struct {
	Public  []byte `json:"public"`
	Private []byte `json:"private"`
}

func (h *HardwareProvider) EnsureNRWK(ctx context.Context, name string) (*TPMObjectRef, error) {
	if name == "" {
		return nil, fmt.Errorf("provider: empty NRWK name")
	}
	return &TPMObjectRef{Name: name}, nil
}

func (h *HardwareProvider) SealCRK(ctx context.Context, nrwk *TPMObjectRef, crk []byte, a aad.CRKAAD) (*CRKEnvelope, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	workDir, err := os.MkdirTemp(h.stateDir, "seal-*")
	if err != nil {
		return nil, fmt.Errorf("provider: tempdir: %w", err)
	}
	defer os.RemoveAll(workDir)

	primary := filepath.Join(workDir, "primary.ctx")
	input := filepath.Join(workDir, "crk.bin")
	pub := filepath.Join(workDir, "sealed.pub")
	priv := filepath.Join(workDir, "sealed.priv")
	if err := os.WriteFile(input, crk, 0o600); err != nil {
		return nil, fmt.Errorf("provider: write crk input: %w", err)
	}
	defer secureRemove(input)
	if err := h.run(ctx, workDir, "tpm2_createprimary", "-C", "o", "-c", primary); err != nil {
		return nil, fmt.Errorf("provider: create primary: %w", err)
	}
	if err := h.run(ctx, workDir, "tpm2_create", "-C", primary, "-i", input, "-u", pub, "-r", priv); err != nil {
		return nil, fmt.Errorf("provider: create sealed object: %w", err)
	}
	pubBytes, err := os.ReadFile(pub)
	if err != nil {
		return nil, fmt.Errorf("provider: read sealed public: %w", err)
	}
	privBytes, err := os.ReadFile(priv)
	if err != nil {
		return nil, fmt.Errorf("provider: read sealed private: %w", err)
	}
	bundle, err := json.Marshal(sealedObjectBundle{Public: pubBytes, Private: privBytes})
	if err != nil {
		return nil, fmt.Errorf("provider: marshal sealed bundle: %w", err)
	}
	return &CRKEnvelope{
		NodeID:         a.NodeID,
		ClusterID:      a.ClusterID,
		PlaneRole:      a.PlaneRole,
		CRKVersion:     a.CRKVersion,
		NRWKName:       nrwk.Name,
		WrappedCRK:     bundle,
		BaselineDigest: a.BaselineDigest,
		PolicyDigest:   a.PolicyDigest,
		CRKAADDigest:   aadDigestHex(a),
	}, nil
}

func (h *HardwareProvider) UnsealCRK(ctx context.Context, nrwk *TPMObjectRef, env *CRKEnvelope, a aad.CRKAAD) ([]byte, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if env.NRWKName != nrwk.Name {
		return nil, fmt.Errorf("provider: NRWK name mismatch")
	}
	if err := validateCRKEnvelopeAAD(env, a); err != nil {
		return nil, err
	}
	var bundle sealedObjectBundle
	if err := json.Unmarshal(env.WrappedCRK, &bundle); err != nil {
		return nil, fmt.Errorf("provider: parse sealed bundle: %w", err)
	}

	workDir, err := os.MkdirTemp(h.stateDir, "unseal-*")
	if err != nil {
		return nil, fmt.Errorf("provider: tempdir: %w", err)
	}
	defer os.RemoveAll(workDir)

	primary := filepath.Join(workDir, "primary.ctx")
	pub := filepath.Join(workDir, "sealed.pub")
	priv := filepath.Join(workDir, "sealed.priv")
	sealed := filepath.Join(workDir, "sealed.ctx")
	out := filepath.Join(workDir, "crk.out")
	if err := os.WriteFile(pub, bundle.Public, 0o600); err != nil {
		return nil, fmt.Errorf("provider: write sealed public: %w", err)
	}
	if err := os.WriteFile(priv, bundle.Private, 0o600); err != nil {
		return nil, fmt.Errorf("provider: write sealed private: %w", err)
	}
	if err := h.run(ctx, workDir, "tpm2_createprimary", "-C", "o", "-c", primary); err != nil {
		return nil, fmt.Errorf("provider: create primary: %w", err)
	}
	if err := h.run(ctx, workDir, "tpm2_load", "-C", primary, "-u", pub, "-r", priv, "-c", sealed); err != nil {
		return nil, fmt.Errorf("provider: load sealed object: %w", err)
	}
	if err := h.run(ctx, workDir, "tpm2_unseal", "-c", sealed, "-o", out); err != nil {
		return nil, fmt.Errorf("provider: unseal: %w", err)
	}
	defer secureRemove(out)
	pt, err := os.ReadFile(out)
	if err != nil {
		return nil, fmt.Errorf("provider: read unsealed CRK: %w", err)
	}
	return pt, nil
}

func (h *HardwareProvider) Quote(ctx context.Context, nonce []byte, pcrs []int) ([]byte, error) {
	return nil, errors.New("provider: quote not implemented")
}

func (h *HardwareProvider) Close() error { return nil }

func (h *HardwareProvider) run(ctx context.Context, dir, name string, args ...string) error {
	runCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	path, ok := h.tools[name]
	if !ok {
		return fmt.Errorf("provider: tpm tool %s not registered", name)
	}
	cmd := exec.CommandContext(runCtx, path, args...)
	if dir != "" {
		cmd.Dir = dir
	}
	cmd.Env = h.commandEnv()
	out, err := cmd.CombinedOutput()
	if runCtx.Err() != nil {
		return runCtx.Err()
	}
	if err != nil {
		return fmt.Errorf("%s %v failed: %w: %s", name, args, err, sanitizeCommandOutput(out))
	}
	return nil
}

func (h *HardwareProvider) commandEnv() []string {
	env := []string{
		"LC_ALL=C",
		"LANG=C",
		"TMPDIR=" + h.stateDir,
	}
	if h.tcti != "" {
		env = append(env, "TPM2TOOLS_TCTI="+h.tcti)
	} else if v := os.Getenv("TPM2TOOLS_TCTI"); v != "" {
		env = append(env, "TPM2TOOLS_TCTI="+v)
	}
	for _, kv := range h.extraEnv {
		if strings.HasPrefix(kv, "TPM2TOOLS_TCTI=") || strings.HasPrefix(kv, "TSS2_LOG=") {
			env = append(env, kv)
		}
	}
	return env
}

func resolveTool(toolDir, name string) (string, error) {
	if toolDir != "" {
		path := filepath.Join(toolDir, name)
		if _, err := os.Stat(path); err != nil {
			return "", fmt.Errorf("provider: tpm tool %s not found in %s: %w", name, toolDir, err)
		}
		abs, err := filepath.Abs(path)
		if err != nil {
			return "", fmt.Errorf("provider: resolve tpm tool %s: %w", name, err)
		}
		return abs, nil
	}
	path, err := exec.LookPath(name)
	if err != nil {
		return "", fmt.Errorf("provider: tpm tool %s not found: %w", name, err)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("provider: resolve tpm tool %s: %w", name, err)
	}
	return abs, nil
}

func restrictDirMode(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("provider: stat state dir: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("provider: state dir is not a directory")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("provider: state dir %s must not be group/world accessible", path)
	}
	return nil
}

func secureRemove(path string) {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err == nil {
		if info, statErr := f.Stat(); statErr == nil && info.Size() > 0 {
			_, _ = f.Seek(0, io.SeekStart)
			zeros := make([]byte, int(minInt64(info.Size(), 32*1024)))
			remaining := info.Size()
			for remaining > 0 {
				n := minInt64(remaining, int64(len(zeros)))
				_, _ = f.Write(zeros[:int(n)])
				remaining -= n
			}
			_ = f.Sync()
		}
		_ = f.Close()
	}
	_ = os.Remove(path)
}

func sanitizeCommandOutput(out []byte) string {
	const max = 512
	s := strings.TrimSpace(string(out))
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > max {
		s = s[:max] + "...<truncated>"
	}
	return s
}

func validateCRKEnvelopeAAD(env *CRKEnvelope, a aad.CRKAAD) error {
	if env.CRKAADDigest != aadDigestHex(a) {
		return fmt.Errorf("provider: CRK envelope AAD digest mismatch")
	}
	if env.ClusterID != a.ClusterID ||
		env.NodeID != a.NodeID ||
		env.PlaneRole != a.PlaneRole ||
		env.CRKVersion != a.CRKVersion ||
		env.NRWKName != a.NRWKName ||
		!equalBytes(env.BaselineDigest, a.BaselineDigest) ||
		!equalBytes(env.PolicyDigest, a.PolicyDigest) {
		return fmt.Errorf("provider: CRK envelope AAD mismatch")
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

func aadDigestHex(a aad.CRKAAD) string {
	b, err := a.Canonical()
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func minInt64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

// NewSoftwareProvider constructs a software provider backed by stateDir.
func NewSoftwareProvider(stateDir string) (*SoftwareProvider, error) {
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, fmt.Errorf("provider: mkdir: %w", err)
	}
	sp := &SoftwareProvider{
		stateDir: stateDir,
		nrwk:     make(map[string]*TPMObjectRef),
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
		if e.IsDir() || filepath.Ext(e.Name()) != ".nrwk" {
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
		s.nrwk[ref.Name] = &ref
	}
	return nil
}

// EnsureNRWK creates or loads the NRWK for the given name.
func (s *SoftwareProvider) EnsureNRWK(ctx context.Context, name string) (*TPMObjectRef, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ref, ok := s.nrwk[name]; ok {
		return ref, nil
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("provider: rand: %w", err)
	}
	ref := &TPMObjectRef{Name: name, KeyBytes: key}
	if err := s.persistNRWK(ref); err != nil {
		return nil, err
	}
	s.nrwk[name] = ref
	return ref, nil
}

func (s *SoftwareProvider) persistNRWK(ref *TPMObjectRef) error {
	path := filepath.Join(s.stateDir, ref.Name+".nrwk")
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

// SealCRK encrypts the CRK under the NRWK with AES-256-GCM, binding the AAD.
func (s *SoftwareProvider) SealCRK(ctx context.Context, nrwk *TPMObjectRef, crk []byte, a aad.CRKAAD) (*CRKEnvelope, error) {
	if len(nrwk.KeyBytes) != 32 {
		return nil, fmt.Errorf("provider: NRWK key length %d", len(nrwk.KeyBytes))
	}
	block, err := aes.NewCipher(nrwk.KeyBytes)
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
	sealed := g.Seal(nil, nonce, crk, aadBytes)
	tagLen := g.Overhead()
	ct := sealed[:len(sealed)-tagLen]
	tag := sealed[len(sealed)-tagLen:]
	return &CRKEnvelope{
		NodeID:         a.NodeID,
		ClusterID:      a.ClusterID,
		PlaneRole:      a.PlaneRole,
		CRKVersion:     a.CRKVersion,
		NRWKName:       nrwk.Name,
		WrappedCRK:     ct,
		Nonce:          nonce,
		Tag:            tag,
		BaselineDigest: a.BaselineDigest,
		PolicyDigest:   a.PolicyDigest,
		CRKAADDigest:   aadDigestHex(a),
	}, nil
}

// UnsealCRK decrypts the CRK envelope, verifying the AAD.
func (s *SoftwareProvider) UnsealCRK(ctx context.Context, nrwk *TPMObjectRef, env *CRKEnvelope, a aad.CRKAAD) ([]byte, error) {
	if env.NRWKName != nrwk.Name {
		return nil, fmt.Errorf("provider: NRWK name mismatch")
	}
	if err := validateCRKEnvelopeAAD(env, a); err != nil {
		return nil, err
	}
	if len(nrwk.KeyBytes) != 32 {
		return nil, fmt.Errorf("provider: NRWK key length %d", len(nrwk.KeyBytes))
	}
	block, err := aes.NewCipher(nrwk.KeyBytes)
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
	combined := make([]byte, 0, len(env.WrappedCRK)+len(env.Tag))
	combined = append(combined, env.WrappedCRK...)
	combined = append(combined, env.Tag...)
	pt, err := g.Open(nil, env.Nonce, combined, aadBytes)
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
