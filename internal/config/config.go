package config

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the runtime configuration for the key-vault service.
type Config struct {
	Environment  string             `yaml:"environment"`
	Server       ServerConfig       `yaml:"server"`
	Database     DatabaseConfig     `yaml:"database"`
	TPM          TPMConfig          `yaml:"tpm"`
	Auth         AuthConfig         `yaml:"auth"`
	Policy       PolicyConfig       `yaml:"policy"`
	Audit        AuditConfig        `yaml:"audit"`
	TrafficGuard TrafficGuardConfig `yaml:"traffic_guard"`
	Recovery     RecoveryConfig     `yaml:"recovery"`
	Baseline     BaselineConfig     `yaml:"baseline"`
	CCSDS        CCSDSConfig        `yaml:"ccsds"`
	LogLevel     string             `yaml:"log_level"`
}

type ServerConfig struct {
	DataListenAddr    string        `yaml:"data_listen_addr"`
	OpsListenAddr     string        `yaml:"ops_listen_addr"`
	TLSCertFile       string        `yaml:"tls_cert_file"`
	TLSKeyFile        string        `yaml:"tls_key_file"`
	ReadTimeout       time.Duration `yaml:"read_timeout"`
	ReadHeaderTimeout time.Duration `yaml:"read_header_timeout"`
	WriteTimeout      time.Duration `yaml:"write_timeout"`
	IdleTimeout       time.Duration `yaml:"idle_timeout"`
	MaxHeaderBytes    int           `yaml:"max_header_bytes"`
	MaxRequestBody    int           `yaml:"max_request_body"`
	NodeID            string        `yaml:"node_id"`
}

type DatabaseConfig struct {
	Path string `yaml:"path"`
}

type TPMConfig struct {
	Provider   string `yaml:"provider"`
	StateDir   string `yaml:"state_dir"`
	ToolDir    string `yaml:"tool_dir"`
	TCTI       string `yaml:"tcti"`
	PolicyPCRs []int  `yaml:"policy_pcrs"`
}

type AuthConfig struct {
	AccessTokensFile string `yaml:"access_tokens_file"`
}

type PolicyConfig struct {
	TrustedKeysPath  string `yaml:"trusted_keys_path"`
	SignedPolicyPath string `yaml:"signed_policy_path"`
}

type AuditConfig struct {
	RedactionPepperFile string `yaml:"redaction_pepper_file"`
}

type TrafficGuardConfig struct {
	RateWindow         time.Duration `yaml:"rate_window"`
	RateSigmaThreshold float64       `yaml:"rate_sigma_threshold"`
}

// RecoveryConfig records externally enforced recovery controls. Restoring an
// old runtime counter snapshot is forbidden; the drill must recover by moving
// to a new operational root/SPI through Recovery GCM.
type RecoveryConfig struct {
	RestoreDrillEvidenceFile string `yaml:"restore_drill_evidence_file"`
}

type BaselineConfig struct {
	Version        string `yaml:"version"`
	SELinuxStatus  string `yaml:"selinux_status"`
	KernelVersion  string `yaml:"kernel_version"`
	VirtPlatform   string `yaml:"virt_platform"`
	TPM2TSSVersion string `yaml:"tpm2_tss_version"`
	SwtpmIsolated  bool   `yaml:"swtpm_isolated"`
}

// CCSDSConfig defines mission-fixed frame boundaries. Per-association wire
// parameters remain in the CCSDS Security Association store.
type CCSDSConfig struct {
	MaxFrameLength int    `yaml:"max_frame_length"`
	TCSpacecraftID uint16 `yaml:"tc_spacecraft_id"`
}

// Diagnostic is a non-secret, user-facing configuration assessment emitted at
// startup. It explains the active deployment posture without weakening the
// fail-closed validation performed by Validate.
type Diagnostic struct {
	Level   string
	Code    string
	Message string
}

// Diagnostics returns a concise deployment posture report for operators.
func (c *Config) Diagnostics() []Diagnostic {
	findings := make([]Diagnostic, 0, 4)
	if c.Environment == "production" {
		findings = append(findings, Diagnostic{"info", "production_hardening", "production hardening is active"})
	} else {
		findings = append(findings, Diagnostic{"warn", "non_production", "development/test safeguards are active; this profile must not hold production data"})
	}
	if c.TPM.Provider == "software" || c.TPM.Provider == "swtpm" || c.TPM.Provider == "tpm2-tools" || c.TPM.Provider == "hardware" {
		findings = append(findings, Diagnostic{"warn", "tpm_fallback", "a non-native TPM provider is active; use native TSS/ESAPI for production"})
	}
	return findings
}

// Default returns a config with safe engineering baseline defaults.
func Default() *Config {
	tmpDir := os.TempDir()
	return &Config{
		Environment: "development",
		Server: ServerConfig{
			OpsListenAddr:     "127.0.0.1:8080",
			DataListenAddr:    ":8081",
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       15 * time.Second,
			WriteTimeout:      15 * time.Second,
			IdleTimeout:       60 * time.Second,
			MaxHeaderBytes:    16 * 1024,
			MaxRequestBody:    64 * 1024,
			NodeID:            "node-development",
		},
		Database: DatabaseConfig{Path: filepath.Join(tmpDir, "key-vault", "security-state.db")},
		TPM:      TPMConfig{Provider: "swtpm", StateDir: filepath.Join(tmpDir, "kvlt-tpm"), PolicyPCRs: []int{7}},
		Auth:     AuthConfig{},
		TrafficGuard: TrafficGuardConfig{
			RateWindow:         time.Minute,
			RateSigmaThreshold: 3.0,
		},
		Baseline: BaselineConfig{
			Version:        "engineering-baseline-v1",
			SELinuxStatus:  "not_applicable",
			KernelVersion:  "local",
			VirtPlatform:   "local",
			TPM2TSSVersion: "local",
			SwtpmIsolated:  false,
		},
		CCSDS: CCSDSConfig{
			MaxFrameLength: 65536,
			TCSpacecraftID: 0,
		},
		LogLevel: "INFO",
	}
}

// Load reads a YAML config file and applies env overrides.
func Load(path string) (*Config, error) {
	c := Default()
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read config: %w", err)
		}
		decoder := yaml.NewDecoder(strings.NewReader(string(b)))
		decoder.KnownFields(true)
		if err := decoder.Decode(c); err != nil {
			return nil, fmt.Errorf("parse config: %w", err)
		}
	}
	applyEnv(c)
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

func applyEnv(c *Config) {
	if v := os.Getenv("KVLT_ENVIRONMENT"); v != "" {
		c.Environment = strings.ToLower(v)
	}
	if v := os.Getenv("KVLT_DATA_ADDR"); v != "" {
		c.Server.DataListenAddr = v
	}
	if v := os.Getenv("KVLT_OPS_ADDR"); v != "" {
		c.Server.OpsListenAddr = v
	}
	if v := os.Getenv("KVLT_TLS_CERT_FILE"); v != "" {
		c.Server.TLSCertFile = v
	}
	if v := os.Getenv("KVLT_TLS_KEY_FILE"); v != "" {
		c.Server.TLSKeyFile = v
	}
	if v := os.Getenv("KVLT_NODE_ID"); v != "" {
		c.Server.NodeID = strings.TrimSpace(v)
	}
	if v := os.Getenv("KVLT_STATE_DB"); v != "" {
		c.Database.Path = v
	}
	if v := os.Getenv("KVLT_TPM_PROVIDER"); v != "" {
		c.TPM.Provider = v
	}
	if v := os.Getenv("KVLT_TPM_STATE_DIR"); v != "" {
		c.TPM.StateDir = v
	}
	if v := os.Getenv("KVLT_TPM_TOOL_DIR"); v != "" {
		c.TPM.ToolDir = v
	}
	if v := os.Getenv("KVLT_TPM_TCTI"); v != "" {
		c.TPM.TCTI = v
	}
	if v := os.Getenv("KVLT_ACCESS_TOKENS_FILE"); v != "" {
		c.Auth.AccessTokensFile = v
	}
	if v := os.Getenv("KVLT_POLICY_TRUSTED_KEYS_FILE"); v != "" {
		c.Policy.TrustedKeysPath = v
	}
	if v := os.Getenv("KVLT_SIGNED_POLICY_FILE"); v != "" {
		c.Policy.SignedPolicyPath = v
	}
	if v := os.Getenv("KVLT_REDACTION_PEPPER_FILE"); v != "" {
		c.Audit.RedactionPepperFile = v
	}
	if v := os.Getenv("KVLT_RESTORE_DRILL_EVIDENCE_FILE"); v != "" {
		c.Recovery.RestoreDrillEvidenceFile = v
	}
	if v := os.Getenv("KVLT_LOG_LEVEL"); v != "" {
		c.LogLevel = strings.ToUpper(v)
	}
}

// Validate enforces safe engineering baseline defaults.
func (c *Config) Validate() error {
	if c.Environment == "" {
		c.Environment = "development"
	}
	if c.Environment != "development" && c.Environment != "test" && c.Environment != "production" {
		return fmt.Errorf("config: environment must be development, test, or production")
	}
	if c.Server.ReadHeaderTimeout <= 0 {
		c.Server.ReadHeaderTimeout = 5 * time.Second
	}
	if c.Server.ReadTimeout <= 0 {
		c.Server.ReadTimeout = 15 * time.Second
	}
	if c.Server.WriteTimeout <= 0 {
		c.Server.WriteTimeout = 15 * time.Second
	}
	if c.Server.IdleTimeout <= 0 {
		c.Server.IdleTimeout = 60 * time.Second
	}
	if c.Server.MaxHeaderBytes <= 0 || c.Server.MaxHeaderBytes > 64*1024 {
		c.Server.MaxHeaderBytes = 16 * 1024
	}
	if c.Server.MaxRequestBody <= 0 || c.Server.MaxRequestBody > 64*1024 {
		c.Server.MaxRequestBody = 64 * 1024
	}
	if strings.TrimSpace(c.Server.DataListenAddr) == "" || strings.TrimSpace(c.Server.OpsListenAddr) == "" {
		return fmt.Errorf("config: data_listen_addr and ops_listen_addr are required")
	}
	if c.Server.DataListenAddr == c.Server.OpsListenAddr {
		return fmt.Errorf("config: data and ops listeners must use different addresses")
	}
	host, _, err := net.SplitHostPort(c.Server.OpsListenAddr)
	if err != nil || (host != "localhost" && (net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback())) {
		return fmt.Errorf("config: ops_listen_addr must bind an explicit loopback address")
	}
	if c.Server.NodeID == "" {
		c.Server.NodeID = "node-development"
	}
	if !validNodeID(c.Server.NodeID) {
		return fmt.Errorf("config: node_id must be 1-64 ASCII letters, digits, dots, underscores, or hyphens")
	}
	if strings.TrimSpace(c.Database.Path) == "" {
		return fmt.Errorf("config: database.path is required")
	}
	// A native TPM configuration is a production fingerprint. Refuse to run it
	// under development/test safeguards by accident.
	if c.Environment != "production" {
		nativeTPM := c.TPM.Provider == "native" || c.TPM.Provider == "tss" || c.TPM.Provider == "esapi"
		if nativeTPM {
			return fmt.Errorf("config: native TPM configuration requires environment: production")
		}
	}
	if c.Environment == "production" {
		if !filepath.IsAbs(c.Database.Path) {
			return fmt.Errorf("config: production database.path must be absolute")
		}
		switch c.TPM.Provider {
		case "software", "swtpm", "tpm2", "hardware", "tpm2-tools":
			return fmt.Errorf("config: production requires native tss/esapi TPM provider")
		}
		if c.TPM.Provider != "native" && c.TPM.Provider != "tss" && c.TPM.Provider != "esapi" {
			return fmt.Errorf("config: production requires native tss/esapi TPM provider")
		}
		if strings.TrimSpace(c.TPM.TCTI) == "" {
			return fmt.Errorf("config: production requires an explicit TPM TCTI")
		}
		if c.Server.NodeID == "" || c.Server.NodeID == "node-development" {
			return fmt.Errorf("config: production requires a unique node_id")
		}
		requiredFiles := []struct {
			name       string
			path       string
			restricted bool
		}{
			{"tls_cert_file", c.Server.TLSCertFile, false},
			{"tls_key_file", c.Server.TLSKeyFile, true},
			{"auth.access_tokens_file", c.Auth.AccessTokensFile, true},
			{"policy.trusted_keys_path", c.Policy.TrustedKeysPath, false},
			{"policy.signed_policy_path", c.Policy.SignedPolicyPath, false},
			{"audit.redaction_pepper_file", c.Audit.RedactionPepperFile, true},
			{"recovery.restore_drill_evidence_file", c.Recovery.RestoreDrillEvidenceFile, true},
		}
		for _, required := range requiredFiles {
			if strings.TrimSpace(required.path) == "" {
				return fmt.Errorf("config: production requires %s", required.name)
			}
			if err := validateReadableRegularFile(required.path); err != nil {
				return fmt.Errorf("config: production %s must reference a readable regular file: %w", required.name, err)
			}
			if required.restricted {
				if err := validateRestrictedFile(required.path); err != nil {
					return fmt.Errorf("config: production %s must be an owner-only, non-symlink file: %w", required.name, err)
				}
			}
		}
	}
	if c.TrafficGuard.RateWindow <= 0 {
		c.TrafficGuard.RateWindow = time.Minute
	}
	if c.TrafficGuard.RateSigmaThreshold <= 0 {
		c.TrafficGuard.RateSigmaThreshold = 3.0
	}
	if c.CCSDS.MaxFrameLength <= 0 || c.CCSDS.MaxFrameLength > 16*1024*1024 {
		return fmt.Errorf("config: ccsds.max_frame_length must be 1..16777216")
	}
	if c.CCSDS.TCSpacecraftID > 0x03ff {
		return fmt.Errorf("config: ccsds.tc_spacecraft_id must fit the 10-bit TC spacecraft ID")
	}
	return nil
}

func validNodeID(value string) bool {
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

func validateReadableRegularFile(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("not a regular file")
	}
	return nil
}

func validateRestrictedFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("symbolic links are forbidden")
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("not a regular file")
	}
	return validateRestrictedFilePlatform(info)
}
