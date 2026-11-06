// Package aead implements the confidentiality capabilities of supported
// symmetric suites. GCM provides authenticated encryption while CTR
// provide confidentiality only. Authentication-only CMAC lives in crypto/mac so a
// caller cannot accidentally treat a MAC as encryption.
package aead

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"fmt"

	"github.com/emmansun/gmsm/sm4"
	"github.com/kvlt/key-vault/internal/crypto/suite"
)

// Cipher is the encryption interface used by the envelope. Suite metadata tells
// callers whether the returned tag is mandatory (GCM) or empty (CTR).
type Cipher interface {
	Encrypt(plaintext, nonce, aad []byte) (ciphertext, tag []byte)
	Decrypt(ciphertext, tag, nonce, aad []byte) ([]byte, error)
	NonceSize() int
	TagSize() int
}

// New constructs an encryption primitive for the given suite and key.
func New(suiteID suite.ID, key []byte) (Cipher, error) {
	if len(key) != suiteID.KeyBytes() {
		return nil, fmt.Errorf("aead: key length %d does not match suite %s (%d)",
			len(key), suiteID, suiteID.KeyBytes())
	}
	switch suiteID {
	case suite.AES256GCM:
		b, _ := aes.NewCipher(key) // AES-256 length was checked above.
		g, _ := cipher.NewGCMWithNonceSize(b, 12)
		return &gcmAEAD{g: g}, nil
	case suite.SM4GCM:
		b, _ := sm4.NewCipher(key) // SM4 length was checked above.
		g, _ := cipher.NewGCMWithNonceSize(b, 12)
		return &gcmAEAD{g: g}, nil
	case suite.AES256CTR:
		b, _ := aes.NewCipher(key)
		return &ctrCipher{block: b}, nil
	case suite.SM4CTR:
		b, _ := sm4.NewCipher(key)
		return &ctrCipher{block: b}, nil
	case suite.SM4GCM32:
		b, _ := sm4.NewCipher(key)
		g, _ := cipher.NewGCM(b)
		return &shortGCM{block: b, g: g}, nil
	case suite.AES256CMAC, suite.SM4CMAC:
		return nil, fmt.Errorf("aead: suite %s is authentication-only", suiteID)
	default:
		return nil, fmt.Errorf("aead: suite %s does not support encryption", suiteID)
	}
}

type gcmAEAD struct {
	g cipher.AEAD
}

func (a *gcmAEAD) Encrypt(plaintext, nonce, aad []byte) (ciphertext, tag []byte) {
	out := a.g.Seal(nil, nonce, plaintext, aad)
	tagLen := a.g.Overhead()
	return out[:len(out)-tagLen], out[len(out)-tagLen:]
}

func (a *gcmAEAD) Decrypt(ciphertext, tag, nonce, aad []byte) ([]byte, error) {
	if len(tag) != a.g.Overhead() {
		return nil, fmt.Errorf("aead: tag length mismatch")
	}
	combined := make([]byte, 0, len(ciphertext)+len(tag))
	combined = append(combined, ciphertext...)
	combined = append(combined, tag...)
	return a.g.Open(nil, nonce, combined, aad)
}

func (a *gcmAEAD) NonceSize() int { return a.g.NonceSize() }
func (a *gcmAEAD) TagSize() int   { return a.g.Overhead() }

type ctrCipher struct {
	block cipher.Block
}

func (c *ctrCipher) Encrypt(plaintext, nonce, aad []byte) (ciphertext, tag []byte) {
	if len(aad) != 0 {
		panic("aead: CTR does not accept AAD")
	}
	if len(nonce) != c.block.BlockSize() {
		panic("aead: CTR initial counter length mismatch")
	}
	out := make([]byte, len(plaintext))
	cipher.NewCTR(c.block, nonce).XORKeyStream(out, plaintext)
	return out, nil
}

func (c *ctrCipher) Decrypt(ciphertext, tag, nonce, aad []byte) ([]byte, error) {
	if len(aad) != 0 {
		return nil, fmt.Errorf("aead: CTR does not accept AAD")
	}
	if len(tag) != 0 {
		return nil, fmt.Errorf("aead: CTR tag must be empty")
	}
	if len(nonce) != c.block.BlockSize() {
		return nil, fmt.Errorf("aead: CTR initial counter length mismatch")
	}
	out := make([]byte, len(ciphertext))
	cipher.NewCTR(c.block, nonce).XORKeyStream(out, ciphertext)
	return out, nil
}

func (c *ctrCipher) NonceSize() int { return c.block.BlockSize() }
func (c *ctrCipher) TagSize() int   { return 0 }

// shortGCM is the fixed 32-bit-tag TC profile. Callers cannot change tag length.
// The protocol enforces the persistent per-key verification budget.
type shortGCM struct {
	block cipher.Block
	g     cipher.AEAD
}

func (c *shortGCM) NonceSize() int { return 12 }
func (c *shortGCM) TagSize() int   { return 4 }
func (c *shortGCM) Encrypt(plaintext, nonce, aad []byte) ([]byte, []byte) {
	if len(nonce) != 12 || len(plaintext)+len(aad) > 1024 {
		panic("aead: GCM32 packet exceeds fixed profile")
	}
	out := c.g.Seal(nil, nonce, plaintext, aad)
	tag := append([]byte(nil), out[len(plaintext):len(plaintext)+4]...)
	ciphertext := append([]byte(nil), out[:len(plaintext)]...)
	clear(out)
	return ciphertext, tag
}
func (c *shortGCM) Decrypt(ciphertext, tag, nonce, aad []byte) ([]byte, error) {
	if len(nonce) != 12 || len(tag) != 4 || len(ciphertext)+len(aad) > 1024 {
		return nil, fmt.Errorf("aead: invalid GCM32 packet")
	}
	// Standard Go GCM accepts at least 12-byte tags. Recover into private scratch,
	// recompute the full tag using its GCM implementation, and expose no bytes
	// until the constant-time comparison succeeds. The bounded packet cannot
	// overflow GCM's 32-bit block counter.
	var counter [16]byte
	copy(counter[:12], nonce)
	counter[15] = 2
	scratch := make([]byte, len(ciphertext))
	cipher.NewCTR(c.block, counter[:]).XORKeyStream(scratch, ciphertext)
	check := c.g.Seal(nil, nonce, scratch, aad)
	valid := subtle.ConstantTimeCompare(tag, check[len(ciphertext):len(ciphertext)+4])
	clear(check)
	clear(counter[:])
	if valid != 1 {
		clear(scratch)
		return nil, fmt.Errorf("aead: GCM32 authentication failed")
	}
	return scratch, nil
}
