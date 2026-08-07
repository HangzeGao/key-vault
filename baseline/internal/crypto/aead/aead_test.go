package aead

import (
	"bytes"
	"testing"

	"github.com/kvlt/key-vault/internal/crypto/suite"
)

func TestCTRSuitesRoundTrip(t *testing.T) {
	tests := []struct {
		name  string
		suite suite.ID
		key   []byte
	}{
		{name: "aes-256-ctr", suite: suite.AES256CTR, key: bytes.Repeat([]byte{0x11}, 32)},
		{name: "sm4-ctr", suite: suite.SM4CTR, key: bytes.Repeat([]byte{0x22}, 16)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := New(tt.suite, tt.key)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			plaintext := []byte("CTR supports unaligned payloads")
			iv := bytes.Repeat([]byte{0x33}, c.NonceSize())
			ciphertext, tag := c.Encrypt(plaintext, iv, nil)
			if len(tag) != 0 {
				t.Fatalf("tag length = %d, want 0", len(tag))
			}
			if bytes.Equal(ciphertext, plaintext) {
				t.Fatal("ciphertext equals plaintext")
			}
			got, err := c.Decrypt(ciphertext, tag, iv, nil)
			if err != nil {
				t.Fatalf("Decrypt() error = %v", err)
			}
			if !bytes.Equal(got, plaintext) {
				t.Fatalf("plaintext mismatch: got %q want %q", got, plaintext)
			}
		})
	}
}

func TestCMACSuiteCannotConstructCipher(t *testing.T) {
	if _, err := New(suite.AES256CMAC, make([]byte, 32)); err == nil {
		t.Fatal("New accepted authentication-only suite")
	}
}
