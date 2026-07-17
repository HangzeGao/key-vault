// Package aead wraps supported block-cipher suites behind a uniform interface.
// Per design §8.4, basic algorithms must come from mature libraries;
// AES uses Go standard library; SM4 uses github.com/emmansun/gmsm.
package aead

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"

	"github.com/emmansun/gmsm/sm4"
)

// SuiteID identifies an algorithm suite. Values are stable and part of
// the Envelope v1 wire format (design §8.3, §8.1).
type SuiteID uint16

const (
	SuiteAES256GCM SuiteID = 0x0001
	SuiteSM4GCM    SuiteID = 0x0002
	SuiteAES256ECB SuiteID = 0x0003
	SuiteSM4ECB    SuiteID = 0x0004
)

func (s SuiteID) String() string {
	switch s {
	case SuiteAES256GCM:
		return "AES_256_GCM"
	case SuiteSM4GCM:
		return "SM4_GCM"
	case SuiteAES256ECB:
		return "AES_256_ECB"
	case SuiteSM4ECB:
		return "SM4_ECB"
	default:
		return fmt.Sprintf("SUITE_0x%04X", uint16(s))
	}
}

// KeyBits returns the key length in bits for the suite.
func (s SuiteID) KeyBits() int {
	switch s {
	case SuiteAES256GCM, SuiteAES256ECB:
		return 256
	case SuiteSM4GCM, SuiteSM4ECB:
		return 128
	default:
		return 0
	}
}

// KeyBytes returns the key length in bytes.
func (s SuiteID) KeyBytes() int { return s.KeyBits() / 8 }

// NonceLen returns the GCM nonce length (12 bytes for both AES-GCM and SM4-GCM).
func (s SuiteID) NonceLen() int {
	switch s {
	case SuiteAES256GCM, SuiteSM4GCM:
		return 12
	case SuiteAES256ECB, SuiteSM4ECB:
		return 0
	}
	return 0
}

// TagLen returns the AEAD tag length.
func (s SuiteID) TagLen() int {
	switch s {
	case SuiteAES256GCM, SuiteSM4GCM:
		return 16
	case SuiteAES256ECB, SuiteSM4ECB:
		return 0
	}
	return 0
}

// AuthenticatesAAD reports whether caller AAD is cryptographically bound by
// the suite. ECB suites have no AAD semantics.
func (s SuiteID) AuthenticatesAAD() bool {
	switch s {
	case SuiteAES256GCM, SuiteSM4GCM:
		return true
	default:
		return false
	}
}

// CiphertextLen returns the exact encrypted payload size for a plaintext length.
func (s SuiteID) CiphertextLen(plaintextLen int) int {
	switch s {
	case SuiteAES256ECB, SuiteSM4ECB:
		blockSize := aes.BlockSize
		if s == SuiteSM4ECB {
			blockSize = sm4.BlockSize
		}
		return plaintextLen + blockSize - plaintextLen%blockSize
	default:
		return plaintextLen
	}
}

// AEAD is the legacy uniform interface used by the envelope. GCM suites provide
// authenticated encryption; ECB suites ignore nonce/AAD and return an empty tag.
type AEAD interface {
	Encrypt(plaintext, nonce, aad []byte) (ciphertext, tag []byte)
	Decrypt(ciphertext, tag, nonce, aad []byte) ([]byte, error)
	NonceSize() int
	TagSize() int
}

// New constructs an AEAD for the given suite and key.
func New(suite SuiteID, key []byte) (AEAD, error) {
	if len(key) != suite.KeyBytes() {
		return nil, fmt.Errorf("aead: key length %d does not match suite %s (%d)",
			len(key), suite, suite.KeyBytes())
	}
	switch suite {
	case SuiteAES256GCM:
		b, err := aes.NewCipher(key)
		if err != nil {
			return nil, fmt.Errorf("aead: aes new: %w", err)
		}
		g, err := cipher.NewGCMWithNonceSize(b, 12)
		if err != nil {
			return nil, fmt.Errorf("aead: gcm new: %w", err)
		}
		return &gcmAEAD{g: g}, nil
	case SuiteSM4GCM:
		b, err := sm4.NewCipher(key)
		if err != nil {
			return nil, fmt.Errorf("aead: sm4 new: %w", err)
		}
		g, err := cipher.NewGCMWithNonceSize(b, 12)
		if err != nil {
			return nil, fmt.Errorf("aead: sm4 gcm new: %w", err)
		}
		return &gcmAEAD{g: g}, nil
	case SuiteAES256ECB:
		b, err := aes.NewCipher(key)
		if err != nil {
			return nil, fmt.Errorf("aead: aes new: %w", err)
		}
		return &ecbCipher{block: b}, nil
	case SuiteSM4ECB:
		b, err := sm4.NewCipher(key)
		if err != nil {
			return nil, fmt.Errorf("aead: sm4 new: %w", err)
		}
		return &ecbCipher{block: b}, nil
	default:
		return nil, fmt.Errorf("aead: suite %s not supported for new encryption in the engineering baseline", suite)
	}
}

type gcmAEAD struct {
	g cipher.AEAD
}

func (a *gcmAEAD) Encrypt(plaintext, nonce, aad []byte) (ciphertext, tag []byte) {
	// Use Seal with dst=nil to get ciphertext||tag, then split.
	out := a.g.Seal(nil, nonce, plaintext, aad)
	tagLen := a.g.Overhead()
	if len(out) < tagLen {
		// Should never happen.
		panic("aead: seal output shorter than tag")
	}
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

type ecbCipher struct {
	block cipher.Block
}

func (e *ecbCipher) Encrypt(plaintext, nonce, aad []byte) (ciphertext, tag []byte) {
	_ = aad
	if len(nonce) != 0 {
		panic("aead: ECB nonce must be empty")
	}
	blockSize := e.block.BlockSize()
	padded := pkcs7Pad(plaintext, blockSize)
	out := make([]byte, len(padded))
	for off := 0; off < len(padded); off += blockSize {
		e.block.Encrypt(out[off:off+blockSize], padded[off:off+blockSize])
	}
	return out, nil
}

func (e *ecbCipher) Decrypt(ciphertext, tag, nonce, aad []byte) ([]byte, error) {
	_ = aad
	if len(nonce) != 0 {
		return nil, fmt.Errorf("aead: ECB nonce must be empty")
	}
	if len(tag) != 0 {
		return nil, fmt.Errorf("aead: ECB tag must be empty")
	}
	blockSize := e.block.BlockSize()
	if len(ciphertext) == 0 || len(ciphertext)%blockSize != 0 {
		return nil, fmt.Errorf("aead: invalid ECB ciphertext")
	}
	padded := make([]byte, len(ciphertext))
	for off := 0; off < len(ciphertext); off += blockSize {
		e.block.Decrypt(padded[off:off+blockSize], ciphertext[off:off+blockSize])
	}
	return pkcs7Unpad(padded, blockSize)
}

func (e *ecbCipher) NonceSize() int { return 0 }
func (e *ecbCipher) TagSize() int   { return 0 }

func pkcs7Pad(plaintext []byte, blockSize int) []byte {
	padLen := blockSize - len(plaintext)%blockSize
	out := make([]byte, len(plaintext)+padLen)
	copy(out, plaintext)
	for i := len(plaintext); i < len(out); i++ {
		out[i] = byte(padLen)
	}
	return out
}

func pkcs7Unpad(padded []byte, blockSize int) ([]byte, error) {
	if len(padded) == 0 || len(padded)%blockSize != 0 {
		return nil, fmt.Errorf("aead: invalid PKCS7 padding")
	}
	padLen := int(padded[len(padded)-1])
	if padLen == 0 || padLen > blockSize || padLen > len(padded) {
		return nil, fmt.Errorf("aead: invalid PKCS7 padding")
	}
	for _, b := range padded[len(padded)-padLen:] {
		if int(b) != padLen {
			return nil, fmt.Errorf("aead: invalid PKCS7 padding")
		}
	}
	out := make([]byte, len(padded)-padLen)
	copy(out, padded[:len(padded)-padLen])
	return out, nil
}
