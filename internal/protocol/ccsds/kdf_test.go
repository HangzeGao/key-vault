package ccsds

import (
	"encoding/hex"
	"testing"

	"github.com/kvlt/key-vault/internal/crypto/suite"
)

func TestCMACCounterKDFCanonicalVectors(t *testing.T) {
	tests := []struct {
		name   string
		derive func() ([]byte, error)
		want   string
	}{
		{"sm4 hctr ordinary", func() ([]byte, error) {
			return DeriveOrdinaryTrafficKey(kdfHex("0123456789abcdeffedcba9876543210"), 0x1234, suite.SM4HCTR, 0x2001, 7, 9)
		}, "d077e6052e64fa4b35b2465d3250dcb7055fa70d4d1de6807b5a2497d5c703e6"},
		{"sm4 recovery", func() ([]byte, error) {
			return DeriveRecoveryGCMKey(kdfHex("0123456789abcdeffedcba9876543210"), 0x1234, suite.SM4GCM, 0x7002, 3)
		}, "173537c63f1e50ad3629cfdc49118d2b"},
	}
	for _, test := range tests {
		got, err := test.derive()
		if err != nil {
			t.Fatalf("%s: %v", test.name, err)
		}
		if hex.EncodeToString(got) != test.want {
			t.Fatalf("%s = %x, want %s", test.name, got, test.want)
		}
	}
}

func kdfHex(value string) []byte {
	decoded, _ := hex.DecodeString(value)
	return decoded
}
