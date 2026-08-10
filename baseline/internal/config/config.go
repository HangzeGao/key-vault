package config

import (
	"fmt"
	"net/url"
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
	HTTPListenAddr     string        `yaml:"http_listen_addr"`
	HTTPSListenAddr    string        `yaml:"https_listen_addr"`
	TLSCertFile        string        `yaml:"tls_cert_file"`
	TLSKeyFile         string        `yaml:"tls_key_file"`
	TLSClientCAFile    string        `yaml:"tls_client_ca_file"`
	ReadTimeout        time.Duration `yaml:"read_timeout"`
	ReadHeaderTimeout  time.Duration `yaml:"read_header_timeout"`
	WriteTimeout       time.Duration `yaml:"write_timeout"`
	IdleTimeout        time.Duration `yaml:"idle_timeout"`
	MaxHeaderBytes     int           `yaml:"max_header_bytes"`
	MaxRequestBody     int           `yaml:"max_request_body"`
	PlaneIsolationMode string        `yaml:"plane_isolation_mode"`
	ActivePlane        string        `yaml:"active_plane"`
	NodeID             string        `yaml:"node_id"`
	AllowedOrigins     []string      `yaml:"allowed_origins"`
	IPAllowlist        []string      `yaml:"ip_allowlist"`
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
	JWTIssuer        string        `yaml:"jwt_issuer"`
	JWTAudience      string        `yaml:"jwt_audience"`
	JWTAlgWhite      []string      `yaml:"jwt_alg_whitelist"`
	JWKSetURL        string        `yaml:"jwk_set_url"`
	JWKCacheTTL      time.Duration `yaml:"jwk_cache_ttl"`
	DefaultTokenTTL  time.Duration `yaml:"default_token_ttl"`
	HMACEnabled      bool          `yaml:"hmac_enabled"`
	HMACSecretB64    string        `yaml:"hmac_secret_b64"`
	HMACMaxSkew      time.Duration `yaml:"hmac_max_skew"`
	StaticTokensFile string        `yaml:"static_tokens_file"`
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
	AOSPrimaryHeaderLength int    `yaml:"aos_primary_header_length"`
	MaxFrameLength         int    `yaml:"max_frame_length"`
	TCSpacecraftID         uint16 `yaml:"tc_spacecraft_id"`
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
	if c.Server.PlaneIsolationMode != "physical" {
		findings = append(findings, Diagnostic{"warn", "logical_planes", "plane isolation is logical; use physical isolation for production"})
	}
	return findings
}

// Default returns a config with safe engineering baseline defaults.
func Default() *Config {
	tmpDir := os.TempDir()
	return &Config{
		Environment: "development",
		Server: ServerConfig{
			HTTPListenAddr:     ":8080",
			ReadHeaderTimeout:  5 * time.Second,
			ReadTimeout:        15 * time.Second,
			WriteTimeout:       15 * time.Second,
			IdleTimeout:        60 * time.Second,
			MaxHeaderBytes:     16 * 1024,
			MaxRequestBody:     64 * 1024,
			PlaneIsolationMode: "logical",
			ActivePlane:        "all",
			NodeID:             "node-development",
		},
		Database: DatabaseConfig{Path: filepath.Join(tmpDir, "key-vault", "security-state.db")},
		TPM:      TPMConfig{Provider: "swtpm", StateDir: filepath.Join(tmpDir, "kvlt-tpm"), PolicyPCRs: []int{7}},
		Auth: AuthConfig{
			JWTAlgWhite:     []string{"RS256", "ES256"},
			JWKCacheTTL:     5 * time.Minute,
			DefaultTokenTTL: 15 * time.Minute,
			HMACEnabled:     true,
			HMACMaxSkew:     5 * time.Minute,
		},
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
			AOSPrimaryHeaderLength: 6,
			MaxFrameLength:         65536,
			TCSpacecraftID:         0,
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
	if v := os.Getenv("KVLT_HTTP_ADDR"); v != "" {
		c.Server.HTTPListenAddr = v
	}
	if v := os.Getenv("KVLT_HTTPS_ADDR"); v != "" {
		c.Server.HTTPSListenAddr = v
	}
	if v := os.Getenv("KVLT_TLS_CERT_FILE"); v != "" {
		c.Server.TLSCertFile = v
	}
	if v := os.Getenv("KVLT_TLS_KEY_FILE"); v != "" {
		c.Server.TLSKeyFile = v
	}
	if v := os.Getenv("KVLT_TLS_CLIENT_CA_FILE"); v != "" {
		c.Server.TLSClientCAFile = v
	}
	if v := os.Getenv("KVLT_ACTIVE_PLANE"); v != "" {
		c.Server.ActivePlane = strings.ToLower(strings.TrimSpace(v))
	}
	if v := os.Getenv("KVLT_NODE_ID"); v != "" {
		c.Server.NodeID = strings.TrimSpace(v)
	}
	if v := os.Getenv("KVLT_ALLOWED_ORIGINS"); v != "" {
		c.Server.AllowedOrigins = splitCSV(v)
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
	if v := os.Getenv("KVLT_JWT_ISSUER"); v != "" {
		c.Auth.JWTIssuer = v
	}
	if v := os.Getenv("KVLT_JWT_AUDIENCE"); v != "" {
		c.Auth.JWTAudience = v
	}
	if v := os.Getenv("KVLT_JWKS_URL"); v != "" {
		c.Auth.JWKSetURL = v
	}
	if v := os.Getenv("KVLT_JWKS_CACHE_TTL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			c.Auth.JWKCacheTTL = d
		}
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

func splitCSV(raw string) []string {
	var out []string
	for _, value := range strings.Split(raw, ",") {
		if value = strings.TrimSpace(value); value != "" {
			out = append(out, value)
		}
	}
	return out
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
	if c.Server.ActivePlane == "" {
		c.Server.ActivePlane = "all"
	}
	if c.Server.NodeID == "" {
		c.Server.NodeID = "node-development"
	}
	if !validNodeID(c.Server.NodeID) {
		return fmt.Errorf("config: node_id must be 1-64 ASCII letters, digits, dots, underscores, or hyphens")
	}
	if !activePlane(c.Server.ActivePlane) {
		return fmt.Errorf("config: active_plane must be all, management, data, or ops")
	}
	if c.Auth.JWKCacheTTL <= 0 {
		c.Auth.JWKCacheTTL = 5 * time.Minute
	}
	if strings.TrimSpace(c.Database.Path) == "" {
		return fmt.Errorf("config: database.path is required")
	}
	// Production-fingerprint guard: if the config looks like a production
	// deployment (native TPM + physical isolation) but environment
	// is not explicitly set to production, refuse to start. This prevents
	// accidentally running with insecure development defaults in production.
	if c.Environment != "production" {
		nativeTPM := c.TPM.Provider == "native" || c.TPM.Provider == "tss" || c.TPM.Provider == "esapi"
		physical := c.Server.PlaneIsolationMode == "physical"
		if nativeTPM && physical {
			return fmt.Errorf("config: production-like configuration detected (native TPM + physical isolation) but environment is %q; set environment: production explicitly to enable production hardening", c.Environment)
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
		if c.Server.PlaneIsolationMode != "physical" {
			return fmt.Errorf("config: production requires physical plane isolation")
		}
		if !productionPlane(c.Server.ActivePlane) {
			return fmt.Errorf("config: production active_plane must be management, data, or ops")
		}
		if c.Server.NodeID == "" || c.Server.NodeID == "node-development" {
			return fmt.Errorf("config: production requires a unique node_id")
		}
		if strings.TrimSpace(c.Server.HTTPSListenAddr) == "" {
			return fmt.Errorf("config: production requires https_listen_addr")
		}
		requiredFiles := []struct {
			name string
			path string
		}{
			{"tls_cert_file", c.Server.TLSCertFile},
			{"tls_key_file", c.Server.TLSKeyFile},
			{"tls_client_ca_file", c.Server.TLSClientCAFile},
			{"policy.trusted_keys_path", c.Policy.TrustedKeysPath},
			{"policy.signed_policy_path", c.Policy.SignedPolicyPath},
			{"audit.redaction_pepper_file", c.Audit.RedactionPepperFile},
			{"recovery.restore_drill_evidence_file", c.Recovery.RestoreDrillEvidenceFile},
		}
		for _, required := range requiredFiles {
			if strings.TrimSpace(required.path) == "" {
				return fmt.Errorf("config: production requires %s", required.name)
			}
			if err := validateReadableRegularFile(required.path); err != nil {
				return fmt.Errorf("config: production %s must reference a readable regular file: %w", required.name, err)
			}
		}
		if err := validateProductionJWT(c.Auth); err != nil {
			return err
		}
		if c.Auth.HMACEnabled || c.Auth.HMACSecretB64 != "" ||
			c.Auth.StaticTokensFile != "" || os.Getenv("KVLT_STATIC_TOKENS") != "" {
			return fmt.Errorf("config: production forbids HMAC and static token authentication")
		}
		for _, origin := range c.Server.AllowedOrigins {
			if err := validateProductionOrigin(origin); err != nil {
				return err
			}
		}
	}
	if c.Server.PlaneIsolationMode != "logical" && c.Server.PlaneIsolationMode != "physical" {
		c.Server.PlaneIsolationMode = "logical"
	}
	if c.TrafficGuard.RateWindow <= 0 {
		c.TrafficGuard.RateWindow = time.Minute
	}
	if c.TrafficGuard.RateSigmaThreshold <= 0 {
		c.TrafficGuard.RateSigmaThreshold = 3.0
	}
	if c.CCSDS.AOSPrimaryHeaderLength <= 0 || c.CCSDS.AOSPrimaryHeaderLength > 64 {
		return fmt.Errorf("config: ccsds.aos_primary_header_length must be 1..64")
	}
	if c.CCSDS.MaxFrameLength <= 0 || c.CCSDS.MaxFrameLength > 16*1024*1024 {
		return fmt.Errorf("config: ccsds.max_frame_length must be 1..16777216")
	}
	if c.CCSDS.MaxFrameLength <= c.CCSDS.AOSPrimaryHeaderLength {
		return fmt.Errorf("config: ccsds.max_frame_length must exceed the AOS primary header length")
	}
	if c.CCSDS.TCSpacecraftID > 0x03ff {
		return fmt.Errorf("config: ccsds.tc_spacecraft_id must fit the 10-bit TC spacecraft ID")
	}
	return nil
}

func productionPlane(plane string) bool {
	switch plane {
	case "management", "data", "ops":
		return true
	default:
		return false
	}
}

func activePlane(plane string) bool {
	return plane == "all" || productionPlane(plane)
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

func validateProductionJWT(auth AuthConfig) error {
	if auth.JWTIssuer == "" || auth.JWTAudience == "" || auth.JWKSetURL == "" {
		return fmt.Errorf("config: production requires jwt_issuer, jwt_audience, and jwk_set_url")
	}
	issuer, err := url.Parse(auth.JWTIssuer)
	if err != nil || issuer.Scheme != "https" || issuer.Host == "" || issuer.User != nil {
		return fmt.Errorf("config: production jwt_issuer must be an HTTPS URL without userinfo")
	}
	jwks, err := url.Parse(auth.JWKSetURL)
	if err != nil || jwks.Scheme != "https" || jwks.Host == "" || jwks.User != nil || jwks.Fragment != "" {
		return fmt.Errorf("config: production jwk_set_url must be an HTTPS URL without userinfo or fragment")
	}
	if !strings.EqualFold(issuer.Host, jwks.Host) {
		return fmt.Errorf("config: production jwk_set_url must use the JWT issuer host")
	}
	if len(auth.JWTAlgWhite) == 0 {
		return fmt.Errorf("config: production requires an asymmetric JWT algorithm allowlist")
	}
	for _, alg := range auth.JWTAlgWhite {
		if alg != "RS256" && alg != "ES256" {
			return fmt.Errorf("config: production JWT algorithms are limited to RS256 and ES256")
		}
	}
	if auth.DefaultTokenTTL <= 0 || auth.DefaultTokenTTL > 15*time.Minute {
		return fmt.Errorf("config: production default_token_ttl must be between 1ns and 15m")
	}
	if auth.JWKCacheTTL <= 0 || auth.JWKCacheTTL > time.Hour {
		return fmt.Errorf("config: production jwk_cache_ttl must be between 1ns and 1h")
	}
	return nil
}

func validateProductionOrigin(raw string) error {
	if raw == "*" {
		return fmt.Errorf("config: wildcard CORS is forbidden in production")
	}
	origin, err := url.Parse(raw)
	if err != nil || origin.Scheme != "https" || origin.Host == "" || origin.User != nil ||
		origin.Path != "" || origin.RawQuery != "" || origin.Fragment != "" {
		return fmt.Errorf("config: production allowed origin %q must be an HTTPS origin", raw)
	}
	return nil
}
