// Package provider defines the TPMProvider interface and a software-backed
// implementation for engineering baseline testing. In environments without
// swtpm, a software provider that emulates seal/unseal with AES-256-GCM is
// acceptable for local baseline verification.
//
// The software provider persists a storage key and sealed-object envelopes so
// restart recovery can be tested. It is NOT a security boundary; deployments MUST
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

// SealedObject is opaque TPM-sealed material for one named purpose.
type SealedObject struct {
	NodeID         string `json:"node_id"`
	Purpose        string `json:"purpose"`
	ObjectID       string `json:"object_id"`
	StorageName    string `json:"storage_name"`
	Blob           []byte `json:"blob"`
	Nonce          []byte `json:"nonce"`
	Tag            []byte `json:"tag"`
	BaselineDigest []byte `json:"baseline_digest"`
	PolicyDigest   []byte `json:"policy_digest"`
	ContextDigest  string `json:"context_digest"`
}

// TPMObjectRef references a provider storage object.
type TPMObjectRef struct {
	Name     string `json:"name"`
	KeyBytes []byte `json:"key_bytes"` // software provider only; real TPM never exposes
}

// Provider is the TPM abstraction.
type Provider interface {
	EnsureStorage(ctx context.Context, name string) (*TPMObjectRef, error)
	Seal(ctx context.Context, storage *TPMObjectRef, plaintext []byte, sealContext aad.SealContext) (*SealedObject, error)
	Unseal(ctx context.Context, storage *TPMObjectRef, object *SealedObject, sealContext aad.SealContext) ([]byte, error)
	// Quote is a baseline stub and returns a fixed placeholder.
	Quote(ctx context.Context, nonce []byte, pcrs []int) ([]byte, error)
	// Close releases provider resources.
	Close() error
}

// SoftwareProvider is a disk-backed software TPM emulator for baseline testing.
type SoftwareProvider struct {
	mu       sync.Mutex
	stateDir string
	storage  map[string]*TPMObjectRef
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
// a wrapping key in process memory; sealed objects are stored as TPM public
// and private blobs inside SealedObject.Blob.
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

func (h *HardwareProvider) EnsureStorage(ctx context.Context, name string) (*TPMObjectRef, error) {
	if name == "" {
		return nil, fmt.Errorf("provider: empty storage name")
	}
	return &TPMObjectRef{Name: name}, nil
}

func (h *HardwareProvider) Seal(ctx context.Context, storage *TPMObjectRef, plaintext []byte, a aad.SealContext) (*SealedObject, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	workDir, err := os.MkdirTemp(h.stateDir, "seal-*")
	if err != nil {
		return nil, fmt.Errorf("provider: tempdir: %w", err)
	}
	defer os.RemoveAll(workDir)

	primary := filepath.Join(workDir, "primary.ctx")
	input := filepath.Join(workDir, "secret.bin")
	pub := filepath.Join(workDir, "sealed.pub")
	priv := filepath.Join(workDir, "sealed.priv")
	if err := os.WriteFile(input, plaintext, 0o600); err != nil {
		return nil, fmt.Errorf("provider: write secret input: %w", err)
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
	return &SealedObject{
		NodeID:         a.NodeID,
		Purpose:        a.Purpose,
		ObjectID:       a.ObjectID,
		StorageName:    storage.Name,
		Blob:           bundle,
		BaselineDigest: a.BaselineDigest,
		PolicyDigest:   a.PolicyDigest,
		ContextDigest:  contextDigestHex(a),
	}, nil
}

func (h *HardwareProvider) Unseal(ctx context.Context, storage *TPMObjectRef, object *SealedObject, a aad.SealContext) ([]byte, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if object.StorageName != storage.Name {
		return nil, fmt.Errorf("provider: storage name mismatch")
	}
	if err := validateSealedObjectContext(object, a); err != nil {
		return nil, err
	}
	var bundle sealedObjectBundle
	if err := json.Unmarshal(object.Blob, &bundle); err != nil {
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
	out := filepath.Join(workDir, "secret.out")
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
		return nil, fmt.Errorf("provider: read unsealed secret: %w", err)
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

func validateSealedObjectContext(object *SealedObject, a aad.SealContext) error {
	if object == nil || object.ContextDigest != contextDigestHex(a) {
		return fmt.Errorf("provider: sealed-object context digest mismatch")
	}
	if object.Purpose != a.Purpose || object.ObjectID != a.ObjectID || object.NodeID != a.NodeID ||
		object.StorageName != a.StorageName || !equalBytes(object.BaselineDigest, a.BaselineDigest) ||
		!equalBytes(object.PolicyDigest, a.PolicyDigest) {
		return fmt.Errorf("provider: sealed-object context mismatch")
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

func contextDigestHex(a aad.SealContext) string {
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
		storage:  make(map[string]*TPMObjectRef),
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
		if e.IsDir() || filepath.Ext(e.Name()) != ".storage" {
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
		s.storage[ref.Name] = &ref
	}
	return nil
}

// EnsureStorage creates or loads the software storage key for the given name.
func (s *SoftwareProvider) EnsureStorage(ctx context.Context, name string) (*TPMObjectRef, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ref, ok := s.storage[name]; ok {
		return ref, nil
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("provider: rand: %w", err)
	}
	ref := &TPMObjectRef{Name: name, KeyBytes: key}
	if err := s.persistStorage(ref); err != nil {
		return nil, err
	}
	s.storage[name] = ref
	return ref, nil
}

func (s *SoftwareProvider) persistStorage(ref *TPMObjectRef) error {
	path := filepath.Join(s.stateDir, ref.Name+".storage")
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

// Seal encrypts plaintext under the software storage key and binds its context.
func (s *SoftwareProvider) Seal(ctx context.Context, storage *TPMObjectRef, plaintext []byte, a aad.SealContext) (*SealedObject, error) {
	if len(storage.KeyBytes) != 32 {
		return nil, fmt.Errorf("provider: storage key length %d", len(storage.KeyBytes))
	}
	block, err := aes.NewCipher(storage.KeyBytes)
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
	sealed := g.Seal(nil, nonce, plaintext, aadBytes)
	tagLen := g.Overhead()
	ct := sealed[:len(sealed)-tagLen]
	tag := sealed[len(sealed)-tagLen:]
	return &SealedObject{
		NodeID:         a.NodeID,
		Purpose:        a.Purpose,
		ObjectID:       a.ObjectID,
		StorageName:    storage.Name,
		Blob:           ct,
		Nonce:          nonce,
		Tag:            tag,
		BaselineDigest: a.BaselineDigest,
		PolicyDigest:   a.PolicyDigest,
		ContextDigest:  contextDigestHex(a),
	}, nil
}

// Unseal decrypts a sealed object after verifying its context.
func (s *SoftwareProvider) Unseal(ctx context.Context, storage *TPMObjectRef, object *SealedObject, a aad.SealContext) ([]byte, error) {
	if object.StorageName != storage.Name {
		return nil, fmt.Errorf("provider: storage name mismatch")
	}
	if err := validateSealedObjectContext(object, a); err != nil {
		return nil, err
	}
	if len(storage.KeyBytes) != 32 {
		return nil, fmt.Errorf("provider: storage key length %d", len(storage.KeyBytes))
	}
	block, err := aes.NewCipher(storage.KeyBytes)
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
	combined := make([]byte, 0, len(object.Blob)+len(object.Tag))
	combined = append(combined, object.Blob...)
	combined = append(combined, object.Tag...)
	pt, err := g.Open(nil, object.Nonce, combined, aadBytes)
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
