package config

import (
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
			c.TPM.Provider = "native"
			c.Server.PlaneIsolationMode = "physical"
		}},
		{"software TPM", func(c *Config) {
			c.Database.Driver = "postgres"
			c.TPM.Provider = "software"
			c.Server.PlaneIsolationMode = "physical"
		}},
		{"logical isolation", func(c *Config) {
			c.Database.Driver = "postgres"
			c.TPM.Provider = "native"
			c.Server.PlaneIsolationMode = "logical"
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Default()
			cfg.Environment = "production"
			tt.mutate(cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatal("unsafe production config accepted")
			}
		})
	}
	cfg := Default()
	cfg.Environment = "production"
	cfg.Database.Driver = "postgres"
	cfg.TPM.Provider = "native"
	cfg.Server.PlaneIsolationMode = "physical"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("safe production config rejected: %v", err)
	}
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
