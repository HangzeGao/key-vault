package policy

import "testing"

func TestDefaultPolicyIncludesAllProtectionServices(t *testing.T) {
	p := DefaultPolicy()
	want := map[string]struct {
		mode    Mode
		service string
	}{
		"AES_256_GCM":  {ModeGCM, "AUTH_ENCRYPT"},
		"SM4_GCM":      {ModeGCM, "AUTH_ENCRYPT"},
		"AES_256_CTR":  {ModeCTR, "ENCRYPT_ONLY"},
		"SM4_CTR":      {ModeCTR, "ENCRYPT_ONLY"},
		"AES_256_CMAC": {ModeCMAC, "AUTH_ONLY"},
		"SM4_CMAC":     {ModeCMAC, "AUTH_ONLY"},
	}
	for suiteID, expected := range want {
		suite, err := p.SuiteByID(suiteID)
		if err != nil {
			t.Fatalf("SuiteByID(%q) error = %v", suiteID, err)
		}
		if suite.Mode != expected.mode || string(suite.ServiceType) != expected.service {
			t.Fatalf("%s = mode %s service %s, want mode %s service %s", suiteID, suite.Mode, suite.ServiceType, expected.mode, expected.service)
		}
	}
	if err := NewEngine().Load(p); err != nil {
		t.Fatalf("Load(DefaultPolicy()) error = %v", err)
	}
}

func TestPolicyRejectsECB(t *testing.T) {
	p := DefaultPolicy()
	p.Suites = append(p.Suites, Suite{
		SuiteID: "AES_256_ECB", Algorithm: "AES", KeyBits: 256,
		Mode: Mode("ECB"), ServiceType: ServiceEncryptOnly, Nonce: "none", Status: SuiteStatusActive,
	})
	if err := NewEngine().Load(p); err == nil {
		t.Fatal("Load accepted unauthenticated ECB suite")
	}
}

func TestPolicyRejectsSuiteModeMismatch(t *testing.T) {
	p := DefaultPolicy()
	for i := range p.Suites {
		if p.Suites[i].SuiteID == "AES_256_GCM" {
			p.Suites[i].Mode = ModeCTR
			break
		}
	}
	if err := NewEngine().Load(p); err == nil {
		t.Fatal("Load accepted AES_256_GCM with ECB mode")
	}
}

func TestPolicyRejectsSuiteServiceTypeMismatch(t *testing.T) {
	p := DefaultPolicy()
	for i := range p.Suites {
		if p.Suites[i].SuiteID == "AES_256_GCM" {
			p.Suites[i].ServiceType = ServiceEncryptOnly
			break
		}
	}
	if err := NewEngine().Load(p); err == nil {
		t.Fatal("Load accepted AES_256_GCM as ENCRYPT_ONLY")
	}
}

func TestPolicyRejectsZeroVersion(t *testing.T) {
	p := DefaultPolicy()
	p.Version = 0
	if err := NewEngine().Load(p); err == nil {
		t.Fatal("Load accepted policy version zero")
	}
}

func TestEngineActivatesNewVersionAndRetainsHistoricalSnapshot(t *testing.T) {
	engine := NewEngine()
	v1 := DefaultPolicy()
	if err := engine.Load(v1); err != nil {
		t.Fatalf("Load(v1): %v", err)
	}

	// Mutating the caller-owned value after Load must not change the catalog.
	v1.Suites[0].Status = SuiteStatusBlocked

	v2 := DefaultPolicy()
	v2.Version = 2
	for i := range v2.Suites {
		if v2.Suites[i].SuiteID == "SM4_GCM" {
			v2.Suites[i].Status = SuiteStatusDisabled
		}
	}
	if err := engine.Load(v2); err != nil {
		t.Fatalf("Load(v2): %v", err)
	}

	current, err := engine.Get(v2.PolicyID)
	if err != nil {
		t.Fatalf("Get current: %v", err)
	}
	if current.Version != 2 {
		t.Fatalf("current version = %d, want 2", current.Version)
	}

	historical, err := engine.GetVersion(v1.PolicyID, 1)
	if err != nil {
		t.Fatalf("GetVersion(v1): %v", err)
	}
	suite, err := historical.SuiteByID("AES_256_GCM")
	if err != nil {
		t.Fatalf("SuiteByID: %v", err)
	}
	if suite.Status != SuiteStatusActive {
		t.Fatalf("historical suite status = %s, want active", suite.Status)
	}

	// Returned values are snapshots too.
	historical.Suites[0].Status = SuiteStatusBlocked
	again, err := engine.GetVersion(v1.PolicyID, 1)
	if err != nil {
		t.Fatalf("GetVersion(v1) again: %v", err)
	}
	againSuite, _ := again.SuiteByID("AES_256_GCM")
	if againSuite.Status != SuiteStatusActive {
		t.Fatalf("catalog mutated through returned snapshot: %s", againSuite.Status)
	}
}

func TestEngineRejectsDifferentContentForExistingVersion(t *testing.T) {
	engine := NewEngine()
	original := DefaultPolicy()
	if err := engine.Load(original); err != nil {
		t.Fatal(err)
	}
	replacement := DefaultPolicy()
	replacement.Suites[1].Status = SuiteStatusDisabled
	if err := engine.Load(replacement); err == nil {
		t.Fatal("existing policy version was overwritten with different content")
	}
}

func TestEngineRejectsCandidateWithoutChangingCurrentPolicy(t *testing.T) {
	engine := NewEngine()
	v1 := DefaultPolicy()
	if err := engine.Load(v1); err != nil {
		t.Fatalf("Load(v1): %v", err)
	}

	invalid := DefaultPolicy()
	invalid.Version = 2
	for i := range invalid.Suites {
		if invalid.Suites[i].SuiteID == invalid.DefaultSuite {
			invalid.Suites[i].Status = SuiteStatusBlocked
		}
	}
	if err := engine.Load(invalid); err == nil {
		t.Fatal("Load accepted a blocked default suite")
	}

	current, err := engine.Get(v1.PolicyID)
	if err != nil {
		t.Fatalf("Get current: %v", err)
	}
	if current.Version != 1 {
		t.Fatalf("current version = %d, want 1", current.Version)
	}
	if _, err := engine.GetVersion(v1.PolicyID, 2); err == nil {
		t.Fatal("rejected policy version was retained")
	}
}
