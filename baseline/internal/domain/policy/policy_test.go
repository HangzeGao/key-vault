package policy

import "testing"

func TestDefaultPolicyIncludesIsolatedGCMEBCSuites(t *testing.T) {
	p := DefaultPolicy()
	wantModes := map[string]Mode{
		"AES_256_GCM": ModeGCM,
		"SM4_GCM":     ModeGCM,
		"AES_256_ECB": ModeECB,
		"SM4_ECB":     ModeECB,
	}
	for suiteID, wantMode := range wantModes {
		suite, err := p.SuiteByID(suiteID)
		if err != nil {
			t.Fatalf("SuiteByID(%q) error = %v", suiteID, err)
		}
		if suite.Mode != wantMode {
			t.Fatalf("%s mode = %s, want %s", suiteID, suite.Mode, wantMode)
		}
	}
	if err := NewEngine().Load(p); err != nil {
		t.Fatalf("Load(DefaultPolicy()) error = %v", err)
	}
}

func TestPolicyRejectsSuiteModeMismatch(t *testing.T) {
	p := DefaultPolicy()
	for i := range p.Suites {
		if p.Suites[i].SuiteID == "AES_256_GCM" {
			p.Suites[i].Mode = ModeECB
			break
		}
	}
	if err := NewEngine().Load(p); err == nil {
		t.Fatal("Load accepted AES_256_GCM with ECB mode")
	}
}
