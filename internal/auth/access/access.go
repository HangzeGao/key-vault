// Package access owns the fixed machine-access contract for the Data and Ops
// planes. The server retains only SHA-256 verifiers for random 256-bit bearer
// tokens; plane and scope assignments are compiled into this module.
package access

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"

	"github.com/kvlt/key-vault/internal/auth/principal"
)

const (
	TokenBytes       = 32
	encodedTokenSize = 43
	DataTokenFile    = "data.token"
	OpsTokenFile     = "ops.token"
	VerifierFile     = "access-token-verifiers.json"
)

var (
	dataScopes = []string{"ccsds:tc:protect", "ccsds:flight-status:observe"}
	opsScopes  = []string{"audit:read", "ops:read"}
)

// Verifier authenticates the two fixed machine identities without retaining
// their bearer tokens.
type Verifier struct {
	tenantID string
	dataHash [sha256.Size]byte
	opsHash  [sha256.Size]byte
}

type verifierDocument struct {
	TenantID        string `json:"tenant_id"`
	DataTokenSHA256 string `json:"data_token_sha256"`
	OpsTokenSHA256  string `json:"ops_token_sha256"`
}

// ParseVerifier parses the only accepted server-side credential format.
func ParseVerifier(raw []byte) (*Verifier, error) {
	var document verifierDocument
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("access: parse verifier document: %w", err)
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return nil, errors.New("access: trailing or invalid verifier data")
	}
	if !validTenantID(document.TenantID) {
		return nil, errors.New("access: tenant_id must be 1..64 safe ASCII characters")
	}
	dataHash, err := parseDigest(document.DataTokenSHA256)
	if err != nil {
		return nil, fmt.Errorf("access: invalid data token verifier: %w", err)
	}
	opsHash, err := parseDigest(document.OpsTokenSHA256)
	if err != nil {
		return nil, fmt.Errorf("access: invalid ops token verifier: %w", err)
	}
	if subtle.ConstantTimeCompare(dataHash[:], opsHash[:]) == 1 {
		return nil, errors.New("access: Data and Ops token verifiers must differ")
	}
	return &Verifier{tenantID: document.TenantID, dataHash: dataHash, opsHash: opsHash}, nil
}

// LoadVerifier reads a controlled verifier document from disk.
func LoadVerifier(path string) (*Verifier, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("access: read verifier file: %w", err)
	}
	return ParseVerifier(raw)
}

// NewVerifier hashes two raw tokens immediately. It is useful for controlled
// generation and tests; production bootstrap loads a verifier document.
func NewVerifier(tenantID, dataToken, opsToken string) (*Verifier, error) {
	if !validTenantID(tenantID) {
		return nil, errors.New("access: tenant_id must be 1..64 safe ASCII characters")
	}
	if !validToken(dataToken) || !validToken(opsToken) || dataToken == opsToken {
		return nil, errors.New("access: distinct 256-bit base64url Data and Ops tokens are required")
	}
	return &Verifier{tenantID: tenantID, dataHash: sha256.Sum256([]byte(dataToken)), opsHash: sha256.Sum256([]byte(opsToken))}, nil
}

// TenantID returns the single tenant bound to both machine identities.
func (v *Verifier) TenantID() string {
	if v == nil {
		return ""
	}
	return v.tenantID
}

// Authenticate returns a fresh fixed principal for a matching token.
func (v *Verifier) Authenticate(token string) *principal.Principal {
	if v == nil || !validToken(token) {
		return nil
	}
	digest := sha256.Sum256([]byte(token))
	dataMatch := subtle.ConstantTimeCompare(digest[:], v.dataHash[:])
	opsMatch := subtle.ConstantTimeCompare(digest[:], v.opsHash[:])
	switch {
	case dataMatch == 1 && opsMatch == 0:
		return &principal.Principal{ID: "static:data", TenantID: v.tenantID, Scopes: append([]string(nil), dataScopes...), Plane: principal.PlaneData, AuthMethod: "bearer_sha256"}
	case opsMatch == 1 && dataMatch == 0:
		return &principal.Principal{ID: "static:ops", TenantID: v.tenantID, Scopes: append([]string(nil), opsScopes...), Plane: principal.PlaneOps, AuthMethod: "bearer_sha256"}
	default:
		return nil
	}
}

// Bundle is generated offline and written without printing either token.
type Bundle struct {
	tenantID  string
	dataToken string
	opsToken  string
}

// GenerateBundle creates two independent 256-bit tokens from crypto/rand.
func GenerateBundle(tenantID string) (*Bundle, error) {
	return generateBundle(tenantID, rand.Reader)
}

func generateBundle(tenantID string, source io.Reader) (*Bundle, error) {
	if !validTenantID(tenantID) {
		return nil, errors.New("access: tenant_id must be 1..64 safe ASCII characters")
	}
	dataToken, err := randomToken(source)
	if err != nil {
		return nil, err
	}
	opsToken, err := randomToken(source)
	if err != nil {
		return nil, err
	}
	if dataToken == opsToken {
		return nil, errors.New("access: random source returned duplicate tokens")
	}
	return &Bundle{tenantID: tenantID, dataToken: dataToken, opsToken: opsToken}, nil
}

// Write writes the two client secrets and server-only verifier document. It
// refuses symlink output directories and never overwrites existing files.
func (b *Bundle) Write(directory string) (err error) {
	if b == nil || !validTenantID(b.tenantID) || !validToken(b.dataToken) || !validToken(b.opsToken) {
		return errors.New("access: invalid generated bundle")
	}
	if strings.TrimSpace(directory) == "" {
		return errors.New("access: output directory is required")
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("access: create output directory: %w", err)
	}
	info, err := os.Lstat(directory)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("access: output path must be a non-symlink directory")
	}
	dataHash := sha256.Sum256([]byte(b.dataToken))
	opsHash := sha256.Sum256([]byte(b.opsToken))
	document, err := json.MarshalIndent(verifierDocument{TenantID: b.tenantID,
		DataTokenSHA256: hex.EncodeToString(dataHash[:]), OpsTokenSHA256: hex.EncodeToString(opsHash[:])}, "", "  ")
	if err != nil {
		return fmt.Errorf("access: encode verifier document: %w", err)
	}
	document = append(document, '\n')
	created := make([]string, 0, 3)
	defer func() {
		if err != nil {
			for _, path := range created {
				_ = os.Remove(path)
			}
		}
	}()
	values := []struct {
		name    string
		content []byte
	}{
		{DataTokenFile, []byte(b.dataToken + "\n")},
		{OpsTokenFile, []byte(b.opsToken + "\n")},
		{VerifierFile, document},
	}
	for _, value := range values {
		path := filepath.Join(directory, value.name)
		if err = writeExclusive(path, value.content); err != nil {
			return err
		}
		created = append(created, path)
	}
	return nil
}

func writeExclusive(path string, content []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("access: create %s: %w", filepath.Base(path), err)
	}
	if _, err = file.Write(content); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return fmt.Errorf("access: write %s: %w", filepath.Base(path), err)
	}
	if closeErr != nil {
		return fmt.Errorf("access: close %s: %w", filepath.Base(path), closeErr)
	}
	return nil
}

func randomToken(source io.Reader) (string, error) {
	raw := make([]byte, TokenBytes)
	if _, err := io.ReadFull(source, raw); err != nil {
		return "", fmt.Errorf("access: generate token: %w", err)
	}
	defer clear(raw)
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func validToken(token string) bool {
	if len(token) != encodedTokenSize {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) != TokenBytes {
		clear(raw)
		return false
	}
	canonical := base64.RawURLEncoding.EncodeToString(raw) == token
	clear(raw)
	return canonical
}

// ValidateToken verifies the fixed 256-bit unpadded base64url client format.
func ValidateToken(token string) error {
	if !validToken(token) {
		return errors.New("access: token must be one canonical 256-bit base64url value")
	}
	return nil
}

func parseDigest(value string) ([sha256.Size]byte, error) {
	var digest [sha256.Size]byte
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size || hex.EncodeToString(decoded) != value {
		return digest, errors.New("expected 64 lowercase hexadecimal characters")
	}
	copy(digest[:], decoded)
	clear(decoded)
	if digest == ([sha256.Size]byte{}) {
		return digest, errors.New("zero verifier is forbidden")
	}
	return digest, nil
}

func validTenantID(value string) bool {
	if len(value) == 0 || len(value) > 64 {
		return false
	}
	for _, char := range value {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') || char == '.' || char == '_' || char == '-' {
			continue
		}
		return false
	}
	return true
}

// Counters contains bounded, non-secret access rejection telemetry.
type Counters struct {
	sourceIPRejected atomic.Uint64
	tokenRejected    atomic.Uint64
	planeRejected    atomic.Uint64
	rateLimited      atomic.Uint64
}

type CounterSnapshot struct {
	SourceIPRejected uint64 `json:"source_ip_rejected"`
	TokenRejected    uint64 `json:"token_rejected"`
	PlaneRejected    uint64 `json:"plane_rejected"`
	RateLimited      uint64 `json:"rate_limited"`
}

func (c *Counters) RejectSourceIP() {
	if c != nil {
		c.sourceIPRejected.Add(1)
	}
}
func (c *Counters) RejectToken() {
	if c != nil {
		c.tokenRejected.Add(1)
	}
}
func (c *Counters) RejectPlane() {
	if c != nil {
		c.planeRejected.Add(1)
	}
}
func (c *Counters) RejectRate() {
	if c != nil {
		c.rateLimited.Add(1)
	}
}

func (c *Counters) Snapshot() CounterSnapshot {
	if c == nil {
		return CounterSnapshot{}
	}
	return CounterSnapshot{SourceIPRejected: c.sourceIPRejected.Load(), TokenRejected: c.tokenRejected.Load(),
		PlaneRejected: c.planeRejected.Load(), RateLimited: c.rateLimited.Load()}
}
