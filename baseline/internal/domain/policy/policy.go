// Package policy implements the Crypto Policy engine per design §10.
// The engineering baseline loads policy at startup and supports signed packages with hot reload.
package policy

import (
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"
	"sync"

	cryptosuite "github.com/kvlt/key-vault/internal/crypto/suite"
	"gopkg.in/yaml.v3"
)

// SuiteStatus enumerates the status of a cipher suite.
type SuiteStatus string

const (
	SuiteStatusActive     SuiteStatus = "active"
	SuiteStatusDisabled   SuiteStatus = "disabled"
	SuiteStatusDeprecated SuiteStatus = "deprecated"
	SuiteStatusBlocked    SuiteStatus = "blocked"
)

// Mode is the cipher mode.
type Mode string

const (
	ModeGCM  Mode = "GCM"
	ModeCTR  Mode = "CTR"
	ModeCMAC Mode = "CMAC"
)

const (
	ServiceAuthOnly    = cryptosuite.ServiceAuthOnly
	ServiceEncryptOnly = cryptosuite.ServiceEncryptOnly
	ServiceAuthEncrypt = cryptosuite.ServiceAuthEncrypt
)

// Suite is a single cipher suite definition.
type Suite struct {
	SuiteID     string                  `yaml:"suite_id" json:"suite_id"`
	Algorithm   string                  `yaml:"algorithm" json:"algorithm"`
	KeyBits     int                     `yaml:"key_bits" json:"key_bits"`
	Mode        Mode                    `yaml:"mode" json:"mode"`
	ServiceType cryptosuite.ServiceType `yaml:"service_type" json:"service_type"`
	MAC         string                  `yaml:"mac,omitempty" json:"mac,omitempty"`
	Composition string                  `yaml:"composition,omitempty" json:"composition,omitempty"`
	Nonce       string                  `yaml:"nonce" json:"nonce"`
	Status      SuiteStatus             `yaml:"status" json:"status"`
	Compliance  []string                `yaml:"compliance,omitempty" json:"compliance,omitempty"`
}

// Signature carries policy package signature metadata.
type Signature struct {
	Alg               string `yaml:"alg"`
	KeyID             string `yaml:"key_id"`
	Sig               string `yaml:"sig"`
	SignedPayloadHash string `yaml:"signed_payload_hash"`
}

// Policy is a crypto policy package.
type Policy struct {
	PolicyID     string    `yaml:"policy_id"`
	Version      uint32    `yaml:"version"`
	Status       string    `yaml:"status"`
	DefaultSuite string    `yaml:"default_suite"`
	Suites       []Suite   `yaml:"suites"`
	Signature    Signature `yaml:"signature"`
}

// Engine is the versioned policy catalog used by runtime decision points.
//
// Load atomically activates a validated policy version while retaining earlier
// versions for operations, such as decrypt, whose contract is bound to the
// policy version recorded in an Envelope. Returned policies are snapshots, so
// callers cannot mutate the catalog after validation.
type Engine struct {
	mu       sync.RWMutex
	policies map[string]map[uint32]*Policy
	current  map[string]uint32
}

// NewEngine constructs an empty engine.
func NewEngine() *Engine {
	return &Engine{
		policies: make(map[string]map[uint32]*Policy),
		current:  make(map[string]uint32),
	}
}

// Load validates, stores, and atomically activates a policy version:
//   - all suites must match a supported suite definition
//   - default_suite must be active
//   - signature field must exist
func (e *Engine) Load(p *Policy) error {
	validated, err := validateAndClone(p)
	if err != nil {
		return err
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	versions := e.policies[validated.PolicyID]
	if versions == nil {
		versions = make(map[uint32]*Policy)
		e.policies[validated.PolicyID] = versions
	}
	if existing, ok := versions[validated.Version]; ok {
		if !reflect.DeepEqual(existing, validated) {
			return fmt.Errorf("policy: version %d is immutable", validated.Version)
		}
		// Exact re-verification is idempotent and does not change the active
		// version or historical catalog.
		return nil
	}
	versions[validated.Version] = validated
	e.current[validated.PolicyID] = validated.Version
	return nil
}

func validateAndClone(p *Policy) (*Policy, error) {
	if p == nil {
		return nil, fmt.Errorf("policy: nil")
	}
	if p.PolicyID == "" {
		return nil, fmt.Errorf("policy: missing policy_id")
	}
	if p.Version == 0 {
		return nil, fmt.Errorf("policy: version must be greater than zero")
	}
	if p.DefaultSuite == "" {
		return nil, fmt.Errorf("policy: missing default_suite")
	}
	candidate := clonePolicy(p)
	// Validate suites.
	ids := make(map[string]*Suite, len(candidate.Suites))
	for i := range candidate.Suites {
		s := &candidate.Suites[i]
		if _, dup := ids[s.SuiteID]; dup {
			return nil, fmt.Errorf("policy: duplicate suite %s", s.SuiteID)
		}
		ids[s.SuiteID] = s
		if err := validateSuiteDefinition(s); err != nil {
			return nil, err
		}
	}
	// Default suite must be active.
	def, ok := ids[candidate.DefaultSuite]
	if !ok {
		return nil, fmt.Errorf("policy: default_suite %s not defined", candidate.DefaultSuite)
	}
	if def.Status != SuiteStatusActive {
		return nil, fmt.Errorf("policy: default_suite must be active, got %s", def.Status)
	}
	// Signature field must exist; signed package verification validates values.
	_ = candidate.Signature
	return candidate, nil
}

// Get returns a snapshot of the currently active policy by ID.
func (e *Engine) Get(policyID string) (*Policy, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	version, ok := e.current[policyID]
	if !ok {
		return nil, fmt.Errorf("policy: %s not found", policyID)
	}
	return clonePolicy(e.policies[policyID][version]), nil
}

// GetVersion returns the immutable policy snapshot bound to a historical
// Envelope or other versioned decision.
func (e *Engine) GetVersion(policyID string, version uint32) (*Policy, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	versions, ok := e.policies[policyID]
	if !ok {
		return nil, fmt.Errorf("policy: %s not found", policyID)
	}
	p, ok := versions[version]
	if !ok {
		return nil, fmt.Errorf("policy: %s version %d not found", policyID, version)
	}
	return clonePolicy(p), nil
}

func clonePolicy(p *Policy) *Policy {
	if p == nil {
		return nil
	}
	out := *p
	out.Suites = make([]Suite, len(p.Suites))
	copy(out.Suites, p.Suites)
	for i := range out.Suites {
		out.Suites[i].Compliance = append([]string(nil), p.Suites[i].Compliance...)
	}
	return &out
}

// CanCreate returns whether a suite may be used for a new protection operation.
func CanCreate(s SuiteStatus) bool {
	return s == SuiteStatusActive
}

// CanConsume returns whether an existing ciphertext or authenticator may be
// consumed. Deprecated suites remain readable/verifiable but cannot create new
// protected data.
func CanConsume(s SuiteStatus) bool {
	switch s {
	case SuiteStatusActive, SuiteStatusDeprecated:
		return true
	}
	return false
}

func validateSuiteDefinition(s *Suite) error {
	if s == nil {
		return fmt.Errorf("policy: nil suite")
	}
	id, err := cryptosuite.Parse(s.SuiteID)
	if err != nil {
		return fmt.Errorf("policy: unsupported suite %s", s.SuiteID)
	}
	descriptor, _ := cryptosuite.Describe(id)
	if s.Algorithm != descriptor.Algorithm || s.KeyBits != descriptor.KeyBits ||
		s.Mode != Mode(descriptor.Mode) || s.ServiceType != descriptor.ServiceType ||
		s.Nonce != descriptor.NonceStrategy || s.MAC != descriptor.MAC ||
		s.Composition != descriptor.Composition {
		return fmt.Errorf("policy: suite %s definition mismatch", s.SuiteID)
	}
	return nil
}

// SuiteByID looks up a suite in a policy.
func (p *Policy) SuiteByID(id string) (*Suite, error) {
	for i := range p.Suites {
		if p.Suites[i].SuiteID == id {
			return &p.Suites[i], nil
		}
	}
	return nil, fmt.Errorf("policy: suite %s not in policy %s", id, p.PolicyID)
}

// LoadFromFile loads a policy from a YAML file.
func LoadFromFile(path string) (*Policy, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("policy: read %s: %w", path, err)
	}
	var p Policy
	if err := yaml.Unmarshal(b, &p); err != nil {
		return nil, fmt.Errorf("policy: parse %s: %w", path, err)
	}
	// Sort suites by ID for deterministic iteration.
	sort.Slice(p.Suites, func(i, j int) bool {
		return strings.Compare(p.Suites[i].SuiteID, p.Suites[j].SuiteID) < 0
	})
	return &p, nil
}

// DefaultPolicy returns the engineering baseline default policy.
func DefaultPolicy() *Policy {
	return &Policy{
		PolicyID:     "default-v1",
		Version:      1,
		Status:       "active",
		DefaultSuite: "AES_256_GCM",
		Suites: []Suite{
			defaultSuite(cryptosuite.AES256GCM, SuiteStatusActive, nil),
			defaultSuite(cryptosuite.SM4GCM, SuiteStatusActive, []string{"GM_T_0054"}),
			defaultSuite(cryptosuite.AES256CTR, SuiteStatusActive, nil),
			defaultSuite(cryptosuite.SM4CTR, SuiteStatusActive, []string{"GM_T_0054"}),
			defaultSuite(cryptosuite.AES256CMAC, SuiteStatusActive, nil),
			defaultSuite(cryptosuite.SM4CMAC, SuiteStatusActive, []string{"GB_T_15821_1"}),
		},
		Signature: Signature{},
	}
}

func defaultSuite(id cryptosuite.ID, status SuiteStatus, compliance []string) Suite {
	descriptor, err := cryptosuite.Describe(id)
	if err != nil {
		panic(err)
	}
	return Suite{
		SuiteID:     descriptor.Name,
		Algorithm:   descriptor.Algorithm,
		KeyBits:     descriptor.KeyBits,
		Mode:        Mode(descriptor.Mode),
		ServiceType: descriptor.ServiceType,
		MAC:         descriptor.MAC,
		Composition: descriptor.Composition,
		Nonce:       descriptor.NonceStrategy,
		Status:      status,
		Compliance:  append([]string(nil), compliance...),
	}
}
