// Package downlink implements the fixed software data-downlink contract.
// It accepts only the 880-byte encrypted data field, independent of AOS layout.
package downlink

import (
	"crypto/aes"
	"errors"
)

const (
	KeyLength  = 32
	DataLength = 880
)

var (
	ErrKeyLength  = errors.New("downlink: AES-256 key must be 32 bytes")
	ErrDataLength = errors.New("downlink: data field must be 880 bytes")
)

// DecryptData decrypts exactly 55 AES-256-ECB blocks without padding. It returns
// a new buffer and does not retain or modify the caller's key or ciphertext.
// Successful decryption provides no authentication or replay assurance.
func DecryptData(key, ciphertext []byte) ([]byte, error) {
	if len(key) != KeyLength {
		return nil, ErrKeyLength
	}
	if len(ciphertext) != DataLength {
		return nil, ErrDataLength
	}
	block, _ := aes.NewCipher(key) // The strict AES-256 key length is checked above.
	plaintext := make([]byte, DataLength)
	for offset := 0; offset < DataLength; offset += aes.BlockSize {
		block.Decrypt(plaintext[offset:offset+aes.BlockSize], ciphertext[offset:offset+aes.BlockSize])
	}
	return plaintext, nil
}
