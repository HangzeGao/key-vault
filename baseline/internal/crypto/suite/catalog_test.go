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
