// Package mac implements authentication-only cryptographic operations.
package mac

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"fmt"

	"github.com/emmansun/gmsm/cbcmac"
	"github.com/emmansun/gmsm/sm4"
	"github.com/kvlt/key-vault/internal/crypto/suite"
)

const (
	// TagVersion is the current detached authenticator format.
	TagVersion uint8 = 1
	tagSize          = 16
)

var domain = [4]byte{'K', 'M', 'A', 'C'}

// Metadata is cryptographically bound to a detached CMAC tag. It prevents a
// valid tag from being transplanted to another key, version, policy, or suite.
type Metadata struct {
	Version       uint8
	SuiteID       suite.ID
	TenantID      string
	KeyID         string
	KeyVersion    uint32
	PolicyVersion uint32
}

// Compute returns a full-length CMAC over metadata and message.
func Compute(suiteID suite.ID, key []byte, metadata Metadata, message []byte) ([]byte, error) {
	if !suiteID.Supports(suite.OperationAuthenticate) || metadata.SuiteID != suiteID {
		return nil, fmt.Errorf("mac: suite %s does not support standalone authentication", suiteID)
	}
	if metadata.Version != TagVersion {
		return nil, fmt.Errorf("mac: unsupported tag version %d", metadata.Version)
	}
	if metadata.TenantID == "" || len(metadata.TenantID) > 1<<16-1 ||
		metadata.KeyID == "" || len(metadata.KeyID) > 1<<16-1 ||
		metadata.KeyVersion == 0 || metadata.PolicyVersion == 0 {
		return nil, fmt.Errorf("mac: invalid metadata")
	}
	if len(key) != suiteID.KeyBytes() {
		return nil, fmt.Errorf("mac: key length %d does not match suite %s (%d)", len(key), suiteID, suiteID.KeyBytes())
	}

	input := make([]byte, 0, len(message)+64)
	input = append(input, canonicalPrefix(metadata, len(message))...)
	input = append(input, metadata.TenantID...)
	input = append(input, metadata.KeyID...)
	input = append(input, message...)
	return ComputeRaw(suiteID, key, input)
}

// Verify compares a supplied tag in constant time.
func Verify(suiteID suite.ID, key []byte, metadata Metadata, message, tag []byte) (bool, error) {
	if len(tag) != tagSize {
		return false, nil
	}
	expected, err := Compute(suiteID, key, metadata, message)
	if err != nil {
		return false, err
	}
	return subtle.ConstantTimeCompare(expected, tag) == 1, nil
}

// ComputeRaw returns a full-length CMAC over an already canonicalized protocol
// input. Protocol modules own their wire-level authentication layout; this
// primitive deliberately adds no Key Vault or Envelope metadata.
func ComputeRaw(suiteID suite.ID, key, input []byte) ([]byte, error) {
	if !suiteID.Supports(suite.OperationAuthenticate) {
		return nil, fmt.Errorf("mac: suite %s does not support standalone authentication", suiteID)
	}
	if len(key) != suiteID.KeyBytes() {
		return nil, fmt.Errorf("mac: key length %d does not match suite %s (%d)", len(key), suiteID, suiteID.KeyBytes())
	}
	var blockCipher cipher.Block
	var err error
	switch suiteID {
	case suite.AES256CMAC:
		blockCipher, err = aes.NewCipher(key)
	case suite.SM4CMAC:
		blockCipher, err = sm4.NewCipher(key)
	default:
		return nil, fmt.Errorf("mac: unsupported CMAC suite %s", suiteID)
	}
	if err != nil {
		return nil, fmt.Errorf("mac: create block cipher: %w", err)
	}
	h := cbcmac.NewCMAC(blockCipher, tagSize)
	_, _ = h.Write(input)
	return h.Sum(nil), nil
}

// VerifyRaw validates a raw protocol CMAC in constant time.
func VerifyRaw(suiteID suite.ID, key, input, tag []byte) (bool, error) {
	if len(tag) != tagSize {
		return false, nil
	}
	expected, err := ComputeRaw(suiteID, key, input)
	if err != nil {
		return false, err
	}
	return subtle.ConstantTimeCompare(expected, tag) == 1, nil
}

func canonicalPrefix(metadata Metadata, messageLen int) []byte {
	// domain || format version || suite || tenant-id length || key-id length ||
	// key version || policy version || message length
	out := make([]byte, 0, 4+1+2+2+2+4+4+8)
	out = append(out, domain[:]...)
	out = append(out, metadata.Version)
	var u16 [2]byte
	binary.BigEndian.PutUint16(u16[:], uint16(metadata.SuiteID))
	out = append(out, u16[:]...)
	binary.BigEndian.PutUint16(u16[:], uint16(len(metadata.TenantID)))
	out = append(out, u16[:]...)
	binary.BigEndian.PutUint16(u16[:], uint16(len(metadata.KeyID)))
	out = append(out, u16[:]...)
	var u32 [4]byte
	binary.BigEndian.PutUint32(u32[:], metadata.KeyVersion)
	out = append(out, u32[:]...)
	binary.BigEndian.PutUint32(u32[:], metadata.PolicyVersion)
	out = append(out, u32[:]...)
	var u64 [8]byte
	binary.BigEndian.PutUint64(u64[:], uint64(messageLen))
	return append(out, u64[:]...)
}
