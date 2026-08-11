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

func TestSM4HCTRCanonicalVectors(t *testing.T) {
	tests := []struct {
		plaintext  string
		ciphertext string
	}{
		{
			plaintext:  "6bc1bee22e409f96e93d7e117393172a",
			ciphertext: "b7b1dd75f608012dc69621d4ea720a60",
		},
		{
			plaintext:  "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417b",
			ciphertext: "f7505aff357ac13107cdb2848c6bb2dcdda473f7a6ea939d44f52c986c11ca9341042f2b0091a1ca5c8f708cae8ca6a5c59e2228b3616c4455627722",
		},
	}
	workingKey := decodeHex(t, "2B7E151628AED2A6ABF7158809CF4F3C000102030405060708090A0B0C0D0E0F")
	tweak := decodeHex(t, "F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF")
	primitive, err := New(suite.SM4HCTR, workingKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range tests {
		plaintext := decodeHex(t, test.plaintext)
		want := decodeHex(t, test.ciphertext)
		ciphertext, tag := primitive.Encrypt(plaintext, tweak, nil)
		if len(tag) != 0 || !bytes.Equal(ciphertext, want) {
			t.Fatalf("Encrypt() = %x/%x, want %x/empty", ciphertext, tag, want)
		}
		got, err := primitive.Decrypt(ciphertext, nil, tweak, nil)
		if err != nil || !bytes.Equal(got, plaintext) {
			t.Fatalf("Decrypt() = %x/%v, want %x", got, err, plaintext)
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
		suite.SM4CTR, suite.SM4HCTR, suite.AES256CMAC, suite.SM4CMAC,
	} {
		if _, err := New(id, make([]byte, id.WorkingKeyBytes()-1)); err == nil {
			t.Fatalf("%s accepted invalid key length", id)
		}
	}
	if _, err := New((suite.ID)(0xffff), nil); err == nil {
		t.Fatal("unknown suite was accepted")
	}

	ctr, err := New(suite.SM4CTR, make([]byte, suite.SM4CTR.WorkingKeyBytes()))
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

	hctr, err := New(suite.SM4HCTR, make([]byte, suite.SM4HCTR.WorkingKeyBytes()))
	if err != nil {
		t.Fatal(err)
	}
	if hctr.NonceSize() != 16 || hctr.TagSize() != 0 {
		t.Fatalf("HCTR sizes = %d/%d", hctr.NonceSize(), hctr.TagSize())
	}
	expectPanic(t, func() { hctr.Encrypt(make([]byte, 16), make([]byte, 16), []byte("aad")) })
	expectPanic(t, func() { hctr.Encrypt(make([]byte, 15), make([]byte, 16), nil) })
	expectPanic(t, func() { hctr.Encrypt(make([]byte, 16), make([]byte, 15), nil) })
	if _, err := hctr.Decrypt(make([]byte, 16), nil, make([]byte, 16), []byte("aad")); err == nil {
		t.Fatal("HCTR accepted AAD")
	}
	if _, err := hctr.Decrypt(make([]byte, 16), []byte{1}, make([]byte, 16), nil); err == nil {
		t.Fatal("HCTR accepted tag")
	}
	if _, err := hctr.Decrypt(make([]byte, 15), nil, make([]byte, 16), nil); err == nil {
		t.Fatal("HCTR accepted short input")
	}
	if _, err := hctr.Decrypt(make([]byte, 16), nil, make([]byte, 15), nil); err == nil {
		t.Fatal("HCTR accepted short tweak")
	}
}
