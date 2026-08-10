package config

import (
	"os"
	"path/filepath"
	"testing"
)

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

func TestTCMissionSpacecraftIDMustFitWireField(t *testing.T) {
	cfg := Default()
	cfg.CCSDS.TCSpacecraftID = 1024
	if err := cfg.Validate(); err == nil {
		t.Fatal("11-bit TC spacecraft ID was accepted")
	}
}

func TestLegacyStorageAndLifecycleFieldsAreRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.yaml")
	if err := os.WriteFile(path, []byte("database:\n  driver: postgres\nlifecycle:\n  owner_id: old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("legacy database and lifecycle contract was accepted")
	}
}

func TestProductionRejectsNonDurableOrFallbackSecurityBoundaries(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{"relative state path", func(c *Config) {
			c.Database.Path = "relative/security.db"
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
	cfg.Database = DatabaseConfig{Path: filepath.Join(dir, "security-state.db")}
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
	cfg.Recovery.RestoreDrillEvidenceFile = file
	return cfg
}

func TestProductionFingerprintGuardRejectsAmbiguousConfig(t *testing.T) {
	// A config that looks production-ready (native TPM + physical
	// isolation) but is missing environment: production must fail-closed,
	// preventing accidental deployment with development-mode safeguards off.
	cfg := Default()
	cfg.Environment = "development"
	cfg.TPM.Provider = "native"
	cfg.Server.PlaneIsolationMode = "physical"
	if err := cfg.Validate(); err == nil {
		t.Fatal("production-like config with development environment was accepted")
	}
	// A software TPM with logical isolation remains a valid test setup.
	cfg2 := Default()
	cfg2.Environment = "test"
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
	prod.TPM.Provider = "native"
	prod.Server.PlaneIsolationMode = "physical"
	findings := prod.Diagnostics()
	if len(findings) != 1 || findings[0].Code != "production_hardening" {
		t.Fatalf("production diagnostics = %v, want hardened posture only", findings)
	}
}
