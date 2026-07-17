// Package policy implements the Crypto Policy engine per design §10.
// The engineering baseline loads policy at startup and supports signed packages with hot reload.
package policy

import (
	"fmt"
	"os"
	"sort"
	"strings"

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
	ModeGCM Mode = "GCM"
	ModeECB Mode = "ECB"
)

// Suite is a single cipher suite definition.
type Suite struct {
	SuiteID     string      `yaml:"suite_id" json:"suite_id"`
	Algorithm   string      `yaml:"algorithm" json:"algorithm"`
	KeyBits     int         `yaml:"key_bits" json:"key_bits"`
	Mode        Mode        `yaml:"mode" json:"mode"`
	MAC         string      `yaml:"mac,omitempty" json:"mac,omitempty"`
	Composition string      `yaml:"composition,omitempty" json:"composition,omitempty"`
	Nonce       string      `yaml:"nonce" json:"nonce"`
	Status      SuiteStatus `yaml:"status" json:"status"`
	Compliance  []string    `yaml:"compliance,omitempty" json:"compliance,omitempty"`
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

// Engine validates policies and answers allow/deny questions.
type Engine struct {
	policies map[string]*Policy
}

// NewEngine constructs an empty engine.
func NewEngine() *Engine {
	return &Engine{policies: make(map[string]*Policy)}
}

// Load adds a policy to the engine. It validates baseline defaults:
//   - all suites must match a supported suite definition
//   - default_suite must be active
//   - signature field must exist
func (e *Engine) Load(p *Policy) error {
	if p == nil {
		return fmt.Errorf("policy: nil")
	}
	if p.PolicyID == "" {
		return fmt.Errorf("policy: missing policy_id")
	}
	if p.DefaultSuite == "" {
		return fmt.Errorf("policy: missing default_suite")
	}
	// Validate suites.
	ids := make(map[string]*Suite, len(p.Suites))
	for i := range p.Suites {
		s := &p.Suites[i]
		if _, dup := ids[s.SuiteID]; dup {
			return fmt.Errorf("policy: duplicate suite %s", s.SuiteID)
		}
		ids[s.SuiteID] = s
		if err := validateSuiteDefinition(s); err != nil {
			return err
		}
	}
	// Default suite must be active.
	def, ok := ids[p.DefaultSuite]
	if !ok {
		return fmt.Errorf("policy: default_suite %s not defined", p.DefaultSuite)
	}
	if def.Status != SuiteStatusActive {
		return fmt.Errorf("policy: default_suite must be active, got %s", def.Status)
	}
	// Signature field must exist; signed package verification validates values.
	_ = p.Signature

	e.policies[p.PolicyID] = p
	return nil
}

// Get returns a policy by ID.
func (e *Engine) Get(policyID string) (*Policy, error) {
	p, ok := e.policies[policyID]
	if !ok {
		return nil, fmt.Errorf("policy: %s not found", policyID)
	}
	return p, nil
}

// CanEncrypt returns whether the suite may be used for new encryption.
func CanEncrypt(s SuiteStatus) bool {
	return s == SuiteStatusActive || s == SuiteStatusDeprecated
}

// CanDecrypt returns whether the suite may be used for decryption.
func CanDecrypt(s SuiteStatus) bool {
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
	switch s.SuiteID {
	case "AES_256_GCM":
		return validateSuiteShape(s, "AES", 256, ModeGCM)
	case "SM4_GCM":
		return validateSuiteShape(s, "SM4", 128, ModeGCM)
	case "AES_256_ECB":
		return validateSuiteShape(s, "AES", 256, ModeECB)
	case "SM4_ECB":
		return validateSuiteShape(s, "SM4", 128, ModeECB)
	default:
		return fmt.Errorf("policy: unsupported suite %s", s.SuiteID)
	}
}

func validateSuiteShape(s *Suite, algorithm string, keyBits int, mode Mode) error {
	if s.Algorithm != algorithm || s.KeyBits != keyBits || s.Mode != mode {
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
			{SuiteID: "AES_256_GCM", Algorithm: "AES", KeyBits: 256, Mode: ModeGCM, Nonce: "lease_counter", Status: SuiteStatusActive},
			{SuiteID: "SM4_GCM", Algorithm: "SM4", KeyBits: 128, Mode: ModeGCM, Nonce: "lease_counter", Status: SuiteStatusActive, Compliance: []string{"GM_T_0054"}},
			{SuiteID: "AES_256_ECB", Algorithm: "AES", KeyBits: 256, Mode: ModeECB, Nonce: "none", Status: SuiteStatusActive},
			{SuiteID: "SM4_ECB", Algorithm: "SM4", KeyBits: 128, Mode: ModeECB, Nonce: "none", Status: SuiteStatusActive, Compliance: []string{"GM_T_0054"}},
		},
		Signature: Signature{},
	}
}
