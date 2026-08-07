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
		{"aes ordinary", func() ([]byte, error) {
			return DeriveOrdinaryTrafficKey(kdfHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"), 0x1234, suite.AES256CTR, 0x2001, 7, 9)
		}, "6d02d7a848796331e9b466bae9121c92a8c6757767e18c6a1c633a23bc0e5ceb"},
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
