package config

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestCCSDSFrameBoundariesAreExplicitAndValidated(t *testing.T) {
	cfg := Default()
	cfg.CCSDS.MaxFrameLength = 0
	if err := cfg.Validate(); err == nil {
		t.Fatal("zero CCSDS max frame length was accepted")
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

func TestLegacyPlaneAndMTLSFieldsAreRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.yaml")
	legacy := "server:\n  active_plane: management\n  plane_isolation_mode: physical\n  tls_client_ca_file: client-ca.pem\n"
	if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("legacy plane or mTLS configuration was accepted")
	}
}

func TestLegacyAccessAndTrafficFieldsAreRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.yaml")
	legacy := "auth:\n  access_tokens_file: tokens.json\ntraffic_guard:\n  rate_sigma_threshold: 3\n"
	if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("legacy raw-token or sigma configuration was accepted")
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
		{"test TPM", func(c *Config) {
			c.TPM.Provider = "swtpm"
		}},
		{"shared listener", func(c *Config) {
			c.Server.DataListenAddr = c.Server.OpsListenAddr
		}},
		{"wildcard data listener", func(c *Config) {
			c.Server.DataListenAddr = ":8443"
		}},
		{"missing data source", func(c *Config) {
			c.Auth.DataSourceIP = ""
		}},
		{"CIDR data source", func(c *Config) {
			c.Auth.DataSourceIP = "192.0.2.0/24"
		}},
		{"TPM transport URI", func(c *Config) {
			c.TPM.TCTI = "device:/dev/tpmrm0"
		}},
		{"missing TPM PCR policy", func(c *Config) {
			c.TPM.PolicyPCRs = nil
		}},
		{"duplicate TPM PCR", func(c *Config) {
			c.TPM.PolicyPCRs = []int{7, 7}
		}},
		{"invalid TPM PCR", func(c *Config) {
			c.TPM.PolicyPCRs = []int{24}
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
	if runtime.GOOS == "windows" {
		t.Skip("production owner-only file validation requires POSIX ownership semantics")
	}
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
	cfg.Server.OpsListenAddr = "127.0.0.1:8443"
	cfg.Database = DatabaseConfig{Path: filepath.Join(dir, "security-state.db")}
	cfg.TPM = TPMConfig{Provider: "native", TCTI: "/dev/tpmrm0", PolicyPCRs: []int{7}}
	cfg.Server.NodeID = "node-01"
	cfg.Server.DataListenAddr = "192.0.2.10:8443"
	cfg.Server.OpsListenAddr = "127.0.0.1:8444"
	cfg.Server.TLSCertFile = file
	cfg.Server.TLSKeyFile = file
	cfg.Auth.TokenVerifiersFile = file
	cfg.Auth.DataSourceIP = "192.0.2.20"
	cfg.Policy.TrustedKeysPath = file
	cfg.Policy.SignedPolicyPath = file
	cfg.Audit.RedactionPepperFile = file
	cfg.Recovery.RestoreDrillEvidenceFile = file
	return cfg
}

func TestProductionFingerprintGuardRejectsAmbiguousConfig(t *testing.T) {
	// A config that looks production-ready (native TPM) but is missing
	// environment: production must fail-closed,
	// preventing accidental deployment with development-mode safeguards off.
	cfg := Default()
	cfg.Environment = "development"
	cfg.TPM.Provider = "native"
	if err := cfg.Validate(); err == nil {
		t.Fatal("production-like config with development environment was accepted")
	}
	// A software TPM remains a valid test setup.
	cfg2 := Default()
	cfg2.Environment = "test"
	cfg2.TPM.Provider = "swtpm"
	if err := cfg2.Validate(); err != nil {
		t.Fatalf("partial production fingerprint wrongly rejected: %v", err)
	}
}

func TestDiagnosticsDescribeDeploymentPosture(t *testing.T) {
	dev := Default().Diagnostics()
	if len(dev) != 2 {
		t.Fatalf("development diagnostics = %v, want posture and fallback warnings", dev)
	}
	prod := Default()
	prod.Environment = "production"
	prod.TPM.Provider = "native"
	findings := prod.Diagnostics()
	if len(findings) != 1 || findings[0].Code != "production_hardening" {
		t.Fatalf("production diagnostics = %v, want hardened posture only", findings)
	}
}
