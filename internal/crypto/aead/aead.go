// Package aead implements the confidentiality capabilities of supported
// symmetric suites. GCM provides authenticated encryption while CTR and HCTR
// provide confidentiality only. Authentication-only CMAC lives in crypto/mac so a
// caller cannot accidentally treat a MAC as encryption.
package aead

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"

	smcipher "github.com/emmansun/gmsm/cipher"
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
	if len(key) != suiteID.WorkingKeyBytes() {
		return nil, fmt.Errorf("aead: key length %d does not match suite %s (%d)",
			len(key), suiteID, suiteID.WorkingKeyBytes())
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
	case suite.SM4HCTR:
		b, _ := sm4.NewCipher(key[:suite.SM4HCTR.KeyBytes()])
		return &hctrCipher{block: b, hashKey: append([]byte(nil), key[suite.SM4HCTR.KeyBytes():]...)}, nil
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

type hctrCipher struct {
	block   cipher.Block
	hashKey []byte
}

func (c *hctrCipher) mode(tweak []byte) (smcipher.LengthPreservingMode, error) {
	if len(tweak) != c.block.BlockSize() {
		return nil, fmt.Errorf("aead: HCTR tweak length mismatch")
	}
	return smcipher.NewHCTR(c.block, tweak, c.hashKey)
}

func (c *hctrCipher) Encrypt(plaintext, tweak, aad []byte) (ciphertext, tag []byte) {
	if len(aad) != 0 {
		panic("aead: HCTR does not accept AAD")
	}
	if len(plaintext) < c.block.BlockSize() {
		panic("aead: HCTR input is shorter than one block")
	}
	mode, err := c.mode(tweak)
	if err != nil {
		panic(err)
	}
	out := make([]byte, len(plaintext))
	mode.EncryptBytes(out, plaintext)
	return out, nil
}

func (c *hctrCipher) Decrypt(ciphertext, tag, tweak, aad []byte) ([]byte, error) {
	if len(aad) != 0 {
		return nil, fmt.Errorf("aead: HCTR does not accept AAD")
	}
	if len(tag) != 0 {
		return nil, fmt.Errorf("aead: HCTR tag must be empty")
	}
	if len(ciphertext) < c.block.BlockSize() {
		return nil, fmt.Errorf("aead: HCTR input is shorter than one block")
	}
	mode, err := c.mode(tweak)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(ciphertext))
	mode.DecryptBytes(out, ciphertext)
	return out, nil
}

func (c *hctrCipher) NonceSize() int { return c.block.BlockSize() }
func (c *hctrCipher) TagSize() int   { return 0 }
