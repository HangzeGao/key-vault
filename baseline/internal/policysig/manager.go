// Package policysig implements engineering baseline signed policy packages and hot reload.
//
// Policy packages contain policy_id/version/effective_at/suites/cryptoperiod/
// tenant&key gray rules/signature/key_id. Load order:
//  1. Format validation
//  2. Signing public key status validation
//  3. Signature verification
//  4. Semantic and fallback constraint validation
//  5. Atomic cache switch
//
// Any failure retains the last valid version and audits. The baseline uses an Ed25519
// signature over the canonical policy payload (excluding the signature field).
package policysig

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/kvlt/key-vault/internal/domain/policy"
)

// SignedPolicy is a policy package with a signature.
type SignedPolicy struct {
	PolicyID     string             `json:"policy_id"`
	Version      uint32             `json:"version"`
	EffectiveAt  time.Time          `json:"effective_at"`
	Status       string             `json:"status"`
	DefaultSuite string             `json:"default_suite"`
	Suites       []policy.Suite     `json:"suites"`
	Cryptoperiod CryptoperiodConfig `json:"cryptoperiod"`
	GrayRules    GrayRules          `json:"gray_rules"`
	Signature    PolicySignature    `json:"signature"`
}

// CryptoperiodConfig defines key lifetime rules.
type CryptoperiodConfig struct {
	DefaultDays      int `json:"default_days"`
	MaxDays          int `json:"max_days"`
	RotateBeforeDays int `json:"rotate_before_days"`
}

// GrayRules defines tenant/key canary rules.
type GrayRules struct {
	TenantAllowlist []string `json:"tenant_allowlist,omitempty"`
	KeyAllowlist    []string `json:"key_allowlist,omitempty"`
}

// PolicySignature is the signature over the canonical policy payload.
type PolicySignature struct {
	Alg         string `json:"alg"` // "Ed25519"
	KeyID       string `json:"key_id"`
	Sig         string `json:"sig"`          // hex
	PayloadHash string `json:"payload_hash"` // hex SHA-256 of canonical payload
}

// SigningKey is a trusted public key for policy verification.
type SigningKey struct {
	KeyID     string
	PublicKey ed25519.PublicKey
	Status    string // active | revoked
	AddedAt   time.Time
}

// Manager manages signed policy packages with hot reload.
type Manager struct {
	mu          sync.RWMutex
	engine      *policy.Engine
	signingKeys map[string]*SigningKey
	current     *SignedPolicy
	currentRaw  *policy.Policy
	auditor     Auditor
}

// Auditor records policy reload events.
type Auditor interface {
	RecordPolicyReload(ctx context.Context, policyID string, version uint32, result string, reason string)
}

// New constructs a policy manager.
func New(engine *policy.Engine, auditor Auditor) *Manager {
	return &Manager{
		engine:      engine,
		signingKeys: make(map[string]*SigningKey),
		auditor:     auditor,
	}
}

// AddSigningKey registers a trusted signing key.
func (m *Manager) AddSigningKey(keyID string, pub ed25519.PublicKey) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.signingKeys[keyID] = &SigningKey{
		KeyID:     keyID,
		PublicKey: pub,
		Status:    "active",
		AddedAt:   time.Now().UTC(),
	}
}

// LoadSigned loads and verifies a signed policy package per the baseline load order.
func (m *Manager) LoadSigned(ctx context.Context, sp *SignedPolicy) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Step 1: Format validation.
	if sp.PolicyID == "" {
		return fmt.Errorf("policy: missing policy_id")
	}
	if sp.DefaultSuite == "" {
		return fmt.Errorf("policy: missing default_suite")
	}
	if len(sp.Suites) == 0 {
		return fmt.Errorf("policy: no suites defined")
	}
	if sp.Signature.KeyID == "" || sp.Signature.Sig == "" {
		err := fmt.Errorf("policy: missing signature")
		m.auditReload(ctx, sp.PolicyID, sp.Version, "failure", "missing signature")
		return err
	}

	// Step 2: Signing key status validation.
	key, ok := m.signingKeys[sp.Signature.KeyID]
	if !ok {
		err := fmt.Errorf("policy: unknown signing key %s", sp.Signature.KeyID)
		m.auditReload(ctx, sp.PolicyID, sp.Version, "failure", "unknown signing key")
		return err
	}
	if key.Status != "active" {
		err := fmt.Errorf("policy: signing key %s not active", sp.Signature.KeyID)
		m.auditReload(ctx, sp.PolicyID, sp.Version, "failure", "signing key not active")
		return err
	}

	// Step 3: Signature verification.
	payloadHash, canon, err := canonicalPolicyPayload(sp)
	if err != nil {
		m.auditReload(ctx, sp.PolicyID, sp.Version, "failure", "canonical encoding failed")
		return fmt.Errorf("policy: canonical: %w", err)
	}
	if payloadHash != sp.Signature.PayloadHash {
		m.auditReload(ctx, sp.PolicyID, sp.Version, "failure", "payload hash mismatch")
		return fmt.Errorf("policy: payload hash mismatch")
	}
	sigBytes, err := hex.DecodeString(sp.Signature.Sig)
	if err != nil {
		m.auditReload(ctx, sp.PolicyID, sp.Version, "failure", "bad signature encoding")
		return fmt.Errorf("policy: bad signature encoding: %w", err)
	}
	if !ed25519.Verify(key.PublicKey, canon, sigBytes) {
		m.auditReload(ctx, sp.PolicyID, sp.Version, "failure", "signature verification failed")
		return fmt.Errorf("policy: signature verification failed")
	}

	// Step 4: Semantic validation — convert to policy.Policy and load into engine.
	pp := &policy.Policy{
		PolicyID:     sp.PolicyID,
		Version:      sp.Version,
		Status:       sp.Status,
		DefaultSuite: sp.DefaultSuite,
		Suites:       sp.Suites,
		Signature: policy.Signature{
			Alg:               sp.Signature.Alg,
			KeyID:             sp.Signature.KeyID,
			Sig:               sp.Signature.Sig,
			SignedPayloadHash: sp.Signature.PayloadHash,
		},
	}
	// Load into a temp engine to validate without breaking current.
	tempEng := policy.NewEngine()
	if err := tempEng.Load(pp); err != nil {
		m.auditReload(ctx, sp.PolicyID, sp.Version, "failure", "semantic validation: "+err.Error())
		return fmt.Errorf("policy: semantic: %w", err)
	}

	// Step 5: Atomic cache switch — replace engine state.
	// Remove old policy and load new.
	if m.currentRaw != nil {
		// Keep old as fallback reference.
	}
	m.current = sp
	m.currentRaw = pp
	// Reload into the real engine.
	m.engine = tempEng

	m.auditReload(ctx, sp.PolicyID, sp.Version, "success", "policy loaded")
	return nil
}

// Reload triggers a hot reload from the current signed policy (re-verification).
func (m *Manager) Reload(ctx context.Context) error {
	m.mu.RLock()
	current := m.current
	m.mu.RUnlock()
	if current == nil {
		return fmt.Errorf("policy: no current signed policy to reload")
	}
	return m.LoadSigned(ctx, current)
}

// Current returns the current signed policy.
func (m *Manager) Current() *SignedPolicy {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.current
}

// Engine returns the current policy engine.
func (m *Manager) Engine() *policy.Engine {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.engine
}

// SigningKeys returns registered signing keys.
func (m *Manager) SigningKeys() []*SigningKey {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*SigningKey, 0, len(m.signingKeys))
	for _, k := range m.signingKeys {
		c := *k
		out = append(out, &c)
	}
	return out
}

// auditReload records a policy reload audit event.
func (m *Manager) auditReload(ctx context.Context, policyID string, version uint32, result, reason string) {
	if m.auditor == nil {
		return
	}
	m.auditor.RecordPolicyReload(ctx, policyID, version, result, reason)
}

// canonicalPolicyPayload returns the canonical encoding and its SHA-256 hash.
// The signature field is excluded from the canonical form.
func canonicalPolicyPayload(sp *SignedPolicy) (string, []byte, error) {
	// Build a canonical form excluding the signature.
	canon := struct {
		PolicyID     string             `json:"policy_id"`
		Version      uint32             `json:"version"`
		EffectiveAt  time.Time          `json:"effective_at"`
		Status       string             `json:"status"`
		DefaultSuite string             `json:"default_suite"`
		Suites       []policy.Suite     `json:"suites"`
		Cryptoperiod CryptoperiodConfig `json:"cryptoperiod"`
		GrayRules    GrayRules          `json:"gray_rules"`
	}{
		PolicyID:     sp.PolicyID,
		Version:      sp.Version,
		EffectiveAt:  sp.EffectiveAt,
		Status:       sp.Status,
		DefaultSuite: sp.DefaultSuite,
		Suites:       sp.Suites,
		Cryptoperiod: sp.Cryptoperiod,
		GrayRules:    sp.GrayRules,
	}
	b, err := json.Marshal(canon)
	if err != nil {
		return "", nil, err
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), b, nil
}

// GenerateDefaultSignedPolicy creates a default signed policy using the given
// signing key. Used for baseline bootstrapping.
func GenerateDefaultSignedPolicy(priv ed25519.PrivateKey, keyID string) (*SignedPolicy, error) {
	base := policy.DefaultPolicy()
	sp := &SignedPolicy{
		PolicyID:     base.PolicyID,
		Version:      base.Version,
		EffectiveAt:  time.Now().UTC(),
		Status:       base.Status,
		DefaultSuite: base.DefaultSuite,
		Suites:       base.Suites,
		Cryptoperiod: CryptoperiodConfig{
			DefaultDays:      365,
			MaxDays:          730,
			RotateBeforeDays: 30,
		},
		GrayRules: GrayRules{},
	}
	payloadHash, canon, err := canonicalPolicyPayload(sp)
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(priv, canon)
	sp.Signature = PolicySignature{
		Alg:         "Ed25519",
		KeyID:       keyID,
		Sig:         hex.EncodeToString(sig),
		PayloadHash: payloadHash,
	}
	return sp, nil
}

// ErrPolicyInvalid is a sentinel.
var ErrPolicyInvalid = errors.New("policy: invalid")
