package aead

import (
	"bytes"
	"testing"
)

func TestECBSuitesRoundTrip(t *testing.T) {
	tests := []struct {
		name      string
		suite     SuiteID
		key       []byte
		plaintext []byte
	}{
		{name: "aes-256-ecb", suite: SuiteAES256ECB, key: bytes.Repeat([]byte{0x11}, 32), plaintext: []byte("not aligned plaintext")},
		{name: "sm4-ecb", suite: SuiteSM4ECB, key: bytes.Repeat([]byte{0x22}, 16), plaintext: []byte("sixteen bytes...")},
		{name: "empty", suite: SuiteAES256ECB, key: bytes.Repeat([]byte{0x33}, 32), plaintext: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := New(tt.suite, tt.key)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			ciphertext, tag := c.Encrypt(tt.plaintext, nil, []byte("ignored aad"))
			if len(tag) != 0 {
				t.Fatalf("tag length = %d, want 0", len(tag))
			}
			if got, want := len(ciphertext), tt.suite.CiphertextLen(len(tt.plaintext)); got != want {
				t.Fatalf("ciphertext length = %d, want %d", got, want)
			}
			plaintext, err := c.Decrypt(ciphertext, tag, nil, []byte("different ignored aad"))
			if err != nil {
				t.Fatalf("Decrypt() error = %v", err)
			}
			if !bytes.Equal(plaintext, tt.plaintext) {
				t.Fatalf("plaintext mismatch: got %q want %q", plaintext, tt.plaintext)
			}
		})
	}
}

func TestECBRejectsInvalidPadding(t *testing.T) {
	c, err := New(SuiteAES256ECB, bytes.Repeat([]byte{0x44}, 32))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	ciphertext, tag := c.Encrypt([]byte("payload"), nil, nil)
	ciphertext[len(ciphertext)-1] ^= 0xff
	if _, err := c.Decrypt(ciphertext, tag, nil, nil); err == nil {
		t.Fatal("Decrypt() accepted invalid padding")
	}
}
