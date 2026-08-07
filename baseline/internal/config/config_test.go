package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLifecycleExpiryWarningWindowDefault(t *testing.T) {
	cfg := Default()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if cfg.Lifecycle.ExpiryWarningWindow != 7*24*time.Hour {
		t.Fatalf("ExpiryWarningWindow = %s, want 168h", cfg.Lifecycle.ExpiryWarningWindow)
	}
}

func TestCCSDSFrameBoundariesAreExplicitAndValidated(t *testing.T) {
	cfg := Default()
	if cfg.CCSDS.AOSPrimaryHeaderLength != 6 {
		t.Fatalf("unexpected CCSDS defaults: %+v", cfg.CCSDS)
	}
	cfg.CCSDS.MaxFrameLength = cfg.CCSDS.AOSPrimaryHeaderLength
	if err := cfg.Validate(); err == nil {
		t.Fatal("CCSDS max frame length not exceeding the header was accepted")
	}
}

func TestLifecycleExpiryWarningWindowEnvOverride(t *testing.T) {
	t.Setenv("KVLT_LIFECYCLE_EXPIRY_WARNING_WINDOW", "2h")

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Lifecycle.ExpiryWarningWindow != 2*time.Hour {
		t.Fatalf("ExpiryWarningWindow = %s, want 2h", cfg.Lifecycle.ExpiryWarningWindow)
	}
}

func TestProductionRejectsNonDurableOrFallbackSecurityBoundaries(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{"memory repository", func(c *Config) {
			c.Database.Driver = "memory"
		}},
		{"software TPM", func(c *Config) {
			c.TPM.Provider = "software"
		}},
		{"logical isolation", func(c *Config) {
			c.Server.PlaneIsolationMode = "logical"
		}},
		{"all planes in one process", func(c *Config) {
			c.Server.ActivePlane = "all"
		}},
		{"HMAC enabled", func(c *Config) {
			c.Auth.HMACEnabled = true
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := productionConfig(t)
			tt.mutate(cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatal("unsafe production config accepted")
			}
		})
	}
	cfg := productionConfig(t)
	if err := cfg.Validate(); err != nil {
		t.Fatalf("safe production config rejected: %v", err)
	}
}

func productionConfig(t *testing.T) *Config {
	t.Helper()
	dir := t.TempDir()
	file := filepath.Join(dir, "required")
	if err := os.WriteFile(file, []byte("0123456789abcdef0123456789abcdef"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := Default()
	cfg.Environment = "production"
	cfg.Database = DatabaseConfig{Driver: "postgres", DSN: "postgres://kvlt@db/kvlt"}
	cfg.TPM = TPMConfig{Provider: "native", TCTI: "device:/dev/tpmrm0"}
	cfg.Server.PlaneIsolationMode = "physical"
	cfg.Server.ActivePlane = "management"
	cfg.Server.NodeID = "node-01"
	cfg.Server.HTTPSListenAddr = ":8443"
	cfg.Server.TLSCertFile = file
	cfg.Server.TLSKeyFile = file
	cfg.Server.TLSClientCAFile = file
	cfg.Auth.JWTIssuer = "https://id.example.test"
	cfg.Auth.JWTAudience = "key-vault"
	cfg.Auth.JWKSetURL = "https://id.example.test/.well-known/jwks.json"
	cfg.Auth.JWTAlgWhite = []string{"RS256", "ES256"}
	cfg.Auth.HMACEnabled = false
	cfg.Policy.TrustedKeysPath = file
	cfg.Policy.SignedPolicyPath = file
	cfg.Audit.RedactionPepperFile = file
	cfg.Recovery.PITREnabled = true
	cfg.Recovery.RestoreDrillEvidenceFile = file
	return cfg
}

func TestProductionFingerprintGuardRejectsAmbiguousConfig(t *testing.T) {
	// A config that looks production-ready (postgres + native TPM + physical
	// isolation) but is missing environment: production must fail-closed,
	// preventing accidental deployment with development-mode safeguards off.
	cfg := Default()
	cfg.Environment = "development"
	cfg.Database.Driver = "postgres"
	cfg.TPM.Provider = "native"
	cfg.Server.PlaneIsolationMode = "physical"
	if err := cfg.Validate(); err == nil {
		t.Fatal("production-like config with development environment was accepted")
	}
	// Partial production fingerprints should still be allowed (e.g. postgres
	// with swtpm is a valid integration-test setup).
	cfg2 := Default()
	cfg2.Environment = "test"
	cfg2.Database.Driver = "postgres"
	cfg2.TPM.Provider = "swtpm"
	cfg2.Server.PlaneIsolationMode = "logical"
	if err := cfg2.Validate(); err != nil {
		t.Fatalf("partial production fingerprint wrongly rejected: %v", err)
	}
}

func TestDiagnosticsDescribeDeploymentPosture(t *testing.T) {
	dev := Default().Diagnostics()
	if len(dev) < 3 {
		t.Fatalf("development diagnostics = %v, want posture and fallback warnings", dev)
	}
	prod := Default()
	prod.Environment = "production"
	prod.Database.Driver = "postgres"
	prod.TPM.Provider = "native"
	prod.Server.PlaneIsolationMode = "physical"
	findings := prod.Diagnostics()
	if len(findings) != 1 || findings[0].Code != "production_hardening" {
		t.Fatalf("production diagnostics = %v, want hardened posture only", findings)
	}
}
