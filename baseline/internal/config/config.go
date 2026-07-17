package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the runtime configuration for the key-vault service.
type Config struct {
	Environment string          `yaml:"environment"`
	Server      ServerConfig    `yaml:"server"`
	Database    DatabaseConfig  `yaml:"database"`
	TPM         TPMConfig       `yaml:"tpm"`
	Auth        AuthConfig      `yaml:"auth"`
	Policy      PolicyConfig    `yaml:"policy"`
	Audit       AuditConfig     `yaml:"audit"`
	Nonce       NonceConfig     `yaml:"nonce"`
	Lifecycle   LifecycleConfig `yaml:"lifecycle"`
	Baseline    BaselineConfig  `yaml:"baseline"`
	LogLevel    string          `yaml:"log_level"`
}

type ServerConfig struct {
	HTTPListenAddr     string        `yaml:"http_listen_addr"`
	HTTPSListenAddr    string        `yaml:"https_listen_addr"`
	TLSCertFile        string        `yaml:"tls_cert_file"`
	TLSKeyFile         string        `yaml:"tls_key_file"`
	ReadTimeout        time.Duration `yaml:"read_timeout"`
	WriteTimeout       time.Duration `yaml:"write_timeout"`
	MaxRequestBody     int           `yaml:"max_request_body"`
	PlaneIsolationMode string        `yaml:"plane_isolation_mode"`
	IPAllowlist        []string      `yaml:"ip_allowlist"`
}

type DatabaseConfig struct {
	Driver string `yaml:"driver"`
	DSN    string `yaml:"dsn"`
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
	DefaultTokenTTL  time.Duration `yaml:"default_token_ttl"`
	HMACEnabled      bool          `yaml:"hmac_enabled"`
	HMACSecretB64    string        `yaml:"hmac_secret_b64"`
	HMACMaxSkew      time.Duration `yaml:"hmac_max_skew"`
	StaticTokensFile string        `yaml:"static_tokens_file"`
}

type PolicyConfig struct {
	ConfigPath string `yaml:"config_path"`
}

type AuditConfig struct {
	WALDir          string `yaml:"wal_dir"`
	WALMaxSizeBytes int64  `yaml:"wal_max_size_bytes"`
	WALEnabled      bool   `yaml:"wal_enabled"`
	BufferSize      int    `yaml:"buffer_size"`
}

type NonceConfig struct {
	LeaseSize          uint64        `yaml:"lease_size"`
	PrefetchWatermark  float64       `yaml:"prefetch_watermark"`
	ThrottleWatermark  float64       `yaml:"throttle_watermark"`
	LeaseTTL           time.Duration `yaml:"lease_ttl"`
	RateWindow         time.Duration `yaml:"rate_window"`
	RateSigmaThreshold float64       `yaml:"rate_sigma_threshold"`
	UnusedRatioAlert   float64       `yaml:"unused_ratio_alert"`
}

type LifecycleConfig struct {
	OwnerID             string        `yaml:"owner_id"`
	LeaseTTL            time.Duration `yaml:"lease_ttl"`
	MaxAttempts         int           `yaml:"max_attempts"`
	PollInterval        time.Duration `yaml:"poll_interval"`
	ExpiryScanInterval  time.Duration `yaml:"expiry_scan_interval"`
	ExpiryWarningWindow time.Duration `yaml:"expiry_warning_window"`
}

type BaselineConfig struct {
	Version        string `yaml:"version"`
	SELinuxStatus  string `yaml:"selinux_status"`
	KernelVersion  string `yaml:"kernel_version"`
	VirtPlatform   string `yaml:"virt_platform"`
	TPM2TSSVersion string `yaml:"tpm2_tss_version"`
	SwtpmIsolated  bool   `yaml:"swtpm_isolated"`
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
	if c.Database.Driver == "memory" {
		findings = append(findings, Diagnostic{"warn", "volatile_storage", "memory storage is volatile; use PostgreSQL for durable keys and audit evidence"})
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
			ReadTimeout:        15 * time.Second,
			WriteTimeout:       15 * time.Second,
			MaxRequestBody:     64 * 1024,
			PlaneIsolationMode: "logical",
		},
		Database: DatabaseConfig{Driver: "memory"},
		TPM:      TPMConfig{Provider: "swtpm", StateDir: filepath.Join(tmpDir, "kvlt-tpm"), PolicyPCRs: []int{7}},
		Auth: AuthConfig{
			JWTAlgWhite:     []string{"RS256", "ES256"},
			DefaultTokenTTL: 15 * time.Minute,
			HMACEnabled:     true,
			HMACMaxSkew:     5 * time.Minute,
		},
		Nonce: NonceConfig{
			LeaseSize:          1024,
			PrefetchWatermark:  0.70,
			ThrottleWatermark:  0.90,
			LeaseTTL:           10 * time.Minute,
			RateWindow:         time.Minute,
			RateSigmaThreshold: 3.0,
			UnusedRatioAlert:   0.50,
		},
		Audit: AuditConfig{
			WALDir:          filepath.Join(tmpDir, "kvlt-wal"),
			WALMaxSizeBytes: 64 * 1024 * 1024,
			WALEnabled:      true,
			BufferSize:      1024,
		},
		Lifecycle: LifecycleConfig{
			OwnerID:             "lifecycle-worker-1",
			LeaseTTL:            30 * time.Second,
			MaxAttempts:         5,
			PollInterval:        5 * time.Second,
			ExpiryScanInterval:  time.Minute,
			ExpiryWarningWindow: 7 * 24 * time.Hour,
		},
		Baseline: BaselineConfig{
			Version:        "engineering-baseline-v1",
			SELinuxStatus:  "not_applicable",
			KernelVersion:  "local",
			VirtPlatform:   "local",
			TPM2TSSVersion: "local",
			SwtpmIsolated:  false,
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
		if err := yaml.Unmarshal(b, c); err != nil {
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
	if v := os.Getenv("KVLT_DB_DRIVER"); v != "" {
		c.Database.Driver = v
	}
	if v := os.Getenv("KVLT_DB_DSN"); v != "" {
		c.Database.DSN = v
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
	if v := os.Getenv("KVLT_LOG_LEVEL"); v != "" {
		c.LogLevel = strings.ToUpper(v)
	}
	if v := os.Getenv("KVLT_WAL_DIR"); v != "" {
		c.Audit.WALDir = v
	}
	if v := os.Getenv("KVLT_LIFECYCLE_OWNER_ID"); v != "" {
		c.Lifecycle.OwnerID = v
	}
	if v := os.Getenv("KVLT_LIFECYCLE_LEASE_TTL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			c.Lifecycle.LeaseTTL = d
		}
	}
	if v := os.Getenv("KVLT_LIFECYCLE_POLL_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			c.Lifecycle.PollInterval = d
		}
	}
	if v := os.Getenv("KVLT_LIFECYCLE_EXPIRY_SCAN_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			c.Lifecycle.ExpiryScanInterval = d
		}
	}
	if v := os.Getenv("KVLT_LIFECYCLE_EXPIRY_WARNING_WINDOW"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			c.Lifecycle.ExpiryWarningWindow = d
		}
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
	// Production-fingerprint guard: if the config looks like a production
	// deployment (postgres + native TPM + physical isolation) but environment
	// is not explicitly set to production, refuse to start. This prevents
	// accidentally running with insecure development defaults in production.
	if c.Environment != "production" {
		postgres := c.Database.Driver == "postgres"
		nativeTPM := c.TPM.Provider == "native" || c.TPM.Provider == "tss" || c.TPM.Provider == "esapi"
		physical := c.Server.PlaneIsolationMode == "physical"
		if postgres && nativeTPM && physical {
			return fmt.Errorf("config: production-like configuration detected (postgres + native TPM + physical isolation) but environment is %q; set environment: production explicitly to enable production hardening", c.Environment)
		}
	}
	if c.Environment == "production" {
		if c.Database.Driver == "memory" {
			return fmt.Errorf("config: memory repository is forbidden in production")
		}
		switch c.TPM.Provider {
		case "software", "swtpm", "tpm2", "hardware", "tpm2-tools":
			return fmt.Errorf("config: production requires native tss/esapi TPM provider")
		}
		if c.Server.PlaneIsolationMode != "physical" {
			return fmt.Errorf("config: production requires physical plane isolation")
		}
	}
	if c.Server.MaxRequestBody <= 0 || c.Server.MaxRequestBody > 64*1024 {
		c.Server.MaxRequestBody = 64 * 1024
	}
	if c.Nonce.PrefetchWatermark <= 0 || c.Nonce.PrefetchWatermark >= 1 {
		c.Nonce.PrefetchWatermark = 0.70
	}
	if c.Nonce.ThrottleWatermark <= c.Nonce.PrefetchWatermark || c.Nonce.ThrottleWatermark > 1 {
		c.Nonce.ThrottleWatermark = 0.90
	}
	if c.Server.PlaneIsolationMode != "logical" && c.Server.PlaneIsolationMode != "physical" {
		c.Server.PlaneIsolationMode = "logical"
	}
	if c.Lifecycle.OwnerID == "" {
		c.Lifecycle.OwnerID = "lifecycle-worker-1"
	}
	if c.Lifecycle.LeaseTTL <= 0 {
		c.Lifecycle.LeaseTTL = 30 * time.Second
	}
	if c.Lifecycle.MaxAttempts <= 0 {
		c.Lifecycle.MaxAttempts = 5
	}
	if c.Lifecycle.PollInterval <= 0 {
		c.Lifecycle.PollInterval = 5 * time.Second
	}
	if c.Lifecycle.ExpiryScanInterval <= 0 {
		c.Lifecycle.ExpiryScanInterval = time.Minute
	}
	if c.Lifecycle.ExpiryWarningWindow <= 0 {
		c.Lifecycle.ExpiryWarningWindow = 7 * 24 * time.Hour
	}
	return nil
}
