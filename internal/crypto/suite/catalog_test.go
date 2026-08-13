package suite

import "testing"

func TestCatalogEnforcesServiceAlgorithmMapping(t *testing.T) {
	tests := []struct {
		id         ID
		service    ServiceType
		canEncrypt bool
		canAuth    bool
	}{
		{AES256CMAC, ServiceAuthOnly, false, true},
		{SM4CMAC, ServiceAuthOnly, false, true},
		{AES256CTR, ServiceEncryptOnly, true, false},
		{SM4CTR, ServiceEncryptOnly, true, false},
		{SM4HCTR, ServiceEncryptOnly, true, false},
		{AES256GCM, ServiceAuthEncrypt, true, false},
		{SM4GCM, ServiceAuthEncrypt, true, false},
	}

	for _, test := range tests {
		if got := test.id.ServiceType(); got != test.service {
			t.Fatalf("%s service = %s, want %s", test.id, got, test.service)
		}
		if got := test.id.Supports(OperationEncrypt); got != test.canEncrypt {
			t.Fatalf("%s encrypt support = %t, want %t", test.id, got, test.canEncrypt)
		}
		if got := test.id.Supports(OperationAuthenticate); got != test.canAuth {
			t.Fatalf("%s authenticate support = %t, want %t", test.id, got, test.canAuth)
		}
	}
}

func TestHCTRSeparatesStoredRootAndWorkingKeyLengths(t *testing.T) {
	if SM4HCTR.KeyBytes() != 16 || SM4HCTR.WorkingKeyBytes() != 32 {
		t.Fatalf("SM4_HCTR lengths = root %d, working %d", SM4HCTR.KeyBytes(), SM4HCTR.WorkingKeyBytes())
	}
}

func TestParseAndDescribeRoundTrip(t *testing.T) {
	for _, descriptor := range All() {
		id, err := Parse(descriptor.Name)
		if err != nil {
			t.Fatalf("Parse(%q): %v", descriptor.Name, err)
		}
		if id != descriptor.ID || id.String() != descriptor.Name {
			t.Fatalf("round-trip mismatch for %q", descriptor.Name)
		}
	}
}

func TestDescriptorAccessorsAndUnknownValues(t *testing.T) {
	for _, descriptor := range All() {
		id := descriptor.ID
		if id.KeyPurpose() != descriptor.KeyPurpose ||
			id.NonceLen() != descriptor.NonceBytes ||
			id.TagLen() != descriptor.TagBytes ||
			id.AuthenticatesAAD() != (descriptor.ServiceType == ServiceAuthEncrypt) ||
			id.CiphertextLen(37) != 37 {
			t.Fatalf("accessor mismatch for %s", id)
		}
		if descriptor.ServiceType == ServiceAuthOnly {
			if !id.Supports(OperationVerify) || id.Supports(OperationDecrypt) {
				t.Fatalf("authentication operation mismatch for %s", id)
			}
		} else if !id.Supports(OperationDecrypt) || id.Supports(OperationVerify) {
			t.Fatalf("encryption operation mismatch for %s", id)
		}
	}
	if _, err := Parse("UNKNOWN"); err == nil {
		t.Fatal("unknown name parsed")
	}
	unknown := ID(0xffff)
	if _, err := Describe(unknown); err == nil {
		t.Fatal("unknown ID described")
	}
	if unknown.String() != "SUITE_0xFFFF" || unknown.KeyPurpose() != "" ||
		unknown.Supports(OperationEncrypt) || unknown.AuthenticatesAAD() {
		t.Fatalf("unknown ID accessors were not fail closed: %s", unknown)
	}
}
