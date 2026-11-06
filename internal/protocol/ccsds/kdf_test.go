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
		{"sm4 gcm32 ordinary", func() ([]byte, error) {
			return DeriveOrdinaryTrafficKey(kdfHex("0123456789abcdeffedcba9876543210"), 0x1234, suite.SM4GCM32, 0x2001, 7, 9)
		}, "e65e51da8d91ab0265ae2edc06df6345"},
		{"sm4 recovery", func() ([]byte, error) {
			return DeriveRecoveryGCMKey(kdfHex("0123456789abcdeffedcba9876543210"), 0x1234, suite.SM4GCM, 0x7002, 3)
		}, "fd9de82c509cc2b9b7afd907a63baa7e"},
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
