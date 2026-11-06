package aead

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/kvlt/key-vault/internal/crypto/suite"
)

func expectPanic(t *testing.T, fn func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic")
		}
	}()
	fn()
}

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
			if c.TagSize() != 0 {
				t.Fatalf("tag size = %d, want 0", c.TagSize())
			}
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

func TestSM4GCM32TamperAndBounds(t *testing.T) {
	c, _ := New(suite.SM4GCM32, make([]byte, 16))
	if c.TagSize() != 4 || c.NonceSize() != 12 {
		t.Fatal("ordinary GCM sizes violate the fixed profile")
	}
	nonce := make([]byte, 12)
	aad := make([]byte, 7)
	for _, n := range []int{0, 1, 15, 16, 17, 31, 32, 1017} {
		plain := bytes.Repeat([]byte{0x32}, n)
		encrypted, tag := c.Encrypt(plain, nonce, aad)
		got, err := c.Decrypt(encrypted, tag, nonce, aad)
		if err != nil || !bytes.Equal(got, plain) {
			t.Fatal(n, err)
		}
		for _, input := range [][]byte{encrypted, tag, nonce, aad} {
			for i := range input {
				for bit := uint(0); bit < 8; bit++ {
					input[i] ^= 1 << bit
					got, err = c.Decrypt(encrypted, tag, nonce, aad)
					if err == nil || got != nil {
						t.Fatalf("tamper accepted n=%d", n)
					}
					input[i] ^= 1 << bit
				}
			}
		}
	}
	expectPanic(t, func() { c.Encrypt(make([]byte, 1018), nonce, aad) })
	expectPanic(t, func() { c.Encrypt(nil, nonce[:11], nil) })
	for _, packet := range []struct{ data, tag, nonce, aad []byte }{{nil, nil, nonce, nil}, {nil, make([]byte, 16), nonce, nil}, {nil, make([]byte, 4), nonce[:11], nil}, {make([]byte, 1018), make([]byte, 4), nonce, aad}} {
		if p, err := c.Decrypt(packet.data, packet.tag, packet.nonce, packet.aad); err == nil || p != nil {
			t.Fatal("invalid profile accepted")
		}
	}
}

func decodeHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func TestCMACSuiteCannotConstructCipher(t *testing.T) {
	if _, err := New(suite.AES256CMAC, make([]byte, 32)); err == nil {
		t.Fatal("New accepted authentication-only suite")
	}
}

func TestGCMSuitesRoundTripAndRejectInvalidTags(t *testing.T) {
	for _, tt := range []struct {
		id  suite.ID
		key []byte
	}{
		{suite.AES256GCM, bytes.Repeat([]byte{0x41}, 32)},
		{suite.SM4GCM, bytes.Repeat([]byte{0x42}, 16)},
	} {
		primitive, err := New(tt.id, tt.key)
		if err != nil {
			t.Fatal(err)
		}
		if primitive.NonceSize() != 12 || primitive.TagSize() != 16 {
			t.Fatalf("%s sizes = %d/%d", tt.id, primitive.NonceSize(), primitive.TagSize())
		}
		nonce := bytes.Repeat([]byte{0x21}, primitive.NonceSize())
		aad := []byte("security-header")
		plaintext := []byte("authenticated payload")
		ciphertext, tag := primitive.Encrypt(plaintext, nonce, aad)
		got, err := primitive.Decrypt(ciphertext, tag, nonce, aad)
		if err != nil || !bytes.Equal(got, plaintext) {
			t.Fatalf("%s decrypt = %q/%v", tt.id, got, err)
		}
		if _, err := primitive.Decrypt(ciphertext, tag[:len(tag)-1], nonce, aad); err == nil {
			t.Fatalf("%s accepted short tag", tt.id)
		}
		corrupt := append([]byte(nil), tag...)
		corrupt[0] ^= 1
		if _, err := primitive.Decrypt(ciphertext, corrupt, nonce, aad); err == nil {
			t.Fatalf("%s accepted corrupt tag", tt.id)
		}
	}
}

func TestCipherConstructionAndInputRejections(t *testing.T) {
	for _, id := range []suite.ID{
		suite.AES256GCM, suite.SM4GCM, suite.AES256CTR,
		suite.SM4CTR, suite.SM4GCM32, suite.AES256CMAC, suite.SM4CMAC,
	} {
		if _, err := New(id, make([]byte, id.KeyBytes()-1)); err == nil {
			t.Fatalf("%s accepted invalid key length", id)
		}
	}
	if _, err := New((suite.ID)(0xffff), nil); err == nil {
		t.Fatal("unknown suite was accepted")
	}

	ctr, err := New(suite.SM4CTR, make([]byte, suite.SM4CTR.KeyBytes()))
	if err != nil {
		t.Fatal(err)
	}
	expectPanic(t, func() { ctr.Encrypt([]byte("x"), make([]byte, 16), []byte("aad")) })
	expectPanic(t, func() { ctr.Encrypt([]byte("x"), make([]byte, 15), nil) })
	if _, err := ctr.Decrypt(nil, nil, make([]byte, 16), []byte("aad")); err == nil {
		t.Fatal("CTR accepted AAD")
	}
	if _, err := ctr.Decrypt(nil, []byte{1}, make([]byte, 16), nil); err == nil {
		t.Fatal("CTR accepted tag")
	}
	if _, err := ctr.Decrypt(nil, nil, make([]byte, 15), nil); err == nil {
		t.Fatal("CTR accepted short counter")
	}

}

func TestCipherConstructorsCoverEverySupportedEncryptionSuite(t *testing.T) {
	for _, id := range []suite.ID{suite.AES256GCM, suite.SM4GCM, suite.AES256CTR, suite.SM4CTR, suite.SM4GCM32} {
		primitive, err := New(id, make([]byte, id.KeyBytes()))
		if err != nil || primitive.NonceSize() == 0 {
			t.Fatalf("suite=%s primitive=%v err=%v", id, primitive, err)
		}
	}
	if _, err := New(suite.SM4CMAC, make([]byte, suite.SM4CMAC.KeyBytes())); err == nil {
		t.Fatal("SM4 CMAC constructed as cipher")
	}
}
