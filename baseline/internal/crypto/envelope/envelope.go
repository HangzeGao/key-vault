// Package envelope implements the Envelope v1 binary format per design §8.3.
//
// Wire layout (big-endian):
//
//	+----------------------+---------+
//	| magic                | 4 bytes | "KVLT"
//	| version              | 1 byte  | 0x01
//	| flags                | 2 bytes | reserved bits must be 0 in baseline
//	| suite_id             | 2 bytes |
//	| key_id_len           | 2 bytes |
//	| key_version          | 4 bytes |
//	| policy_version       | 4 bytes |
//	| nonce_len            | 1 byte  |
//	| tag_len              | 1 byte  |
//	| ciphertext_len       | 8 bytes |
//	| aad_hash             | 32 bytes| SHA-256(caller_aad), present only for AAD-authenticating suites
//	| key_id               | var     |
//	| nonce                | var     |
//	| ciphertext           | var     |
//	| tag                  | var     |
//	+----------------------+---------+
//
// Parsing rules (design §8.3 "Envelope 解析安全"):
//   - Validate fixed header minimum length first.
//   - Magic must match exactly; otherwise reject without further parsing.
//   - All length fields validated against suite-fixed values AND global upper bounds.
//   - Overflow-safe addition when checking total length.
//   - Reject trailing bytes.
//   - All parse failures return ErrEnvelopeInvalid; no panic, no side-channel.
package envelope

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/kvlt/key-vault/internal/crypto/aead"
)

// Magic is the 4-byte envelope magic.
var Magic = [4]byte{'K', 'V', 'L', 'T'}

// Version1 is the current envelope version.
const Version1 uint8 = 1

// Flag bits.
const (
	FlagReserved1  uint16 = 1 << 0
	FlagReserved2  uint16 = 1 << 1
	FlagReserved3  uint16 = 1 << 2
	FlagReserved4  uint16 = 1 << 3
	FlagReserved5  uint16 = 1 << 4
	FlagReserved6  uint16 = 1 << 5
	FlagReserved7  uint16 = 1 << 6
	FlagReserved8  uint16 = 1 << 7
	FlagPQCKem     uint16 = 1 << 8 // must be 0 in the current baseline
	FlagReserved9  uint16 = 1 << 9
	FlagReserved10 uint16 = 1 << 10
	FlagReserved11 uint16 = 1 << 11
	FlagReserved12 uint16 = 1 << 12
	FlagReserved13 uint16 = 1 << 13
	FlagReserved14 uint16 = 1 << 14
	FlagReserved15 uint16 = 1 << 15
)

// Allowed baseline flags: none. Any non-zero flag is rejected.
const allowedV1Flags uint16 = 0

// Length bounds.
const (
	MaxKeyIDLen      = 256
	MaxNonceLen      = 16
	MaxCiphertextLen = 1 << 24 // 16 MiB; well above the 64 KiB sync API limit
	MaxTagLen        = 32
	MaxPolicyVersion = (1 << 32) - 1
	MaxKeyVersion    = (1 << 32) - 1
)

// BaseHeaderSize is the size of the fixed portion of the envelope header that
// is present for every suite.
// magic(4) + version(1) + flags(2) + suite_id(2) + key_id_len(2) +
// key_version(4) + policy_version(4) + nonce_len(1) + tag_len(1) +
// ciphertext_len(8) = 29
const BaseHeaderSize = 4 + 1 + 2 + 2 + 2 + 4 + 4 + 1 + 1 + 8

const AADHashSize = 32

// FixedHeaderSize is the GCM header size retained for tests and GCM vectors.
const FixedHeaderSize = BaseHeaderSize + AADHashSize

// Envelope is the in-memory representation of an Envelope v1.
type Envelope struct {
	Version       uint8
	Flags         uint16
	SuiteID       aead.SuiteID
	KeyID         []byte
	KeyVersion    uint32
	PolicyVersion uint32
	Nonce         []byte
	Ciphertext    []byte
	Tag           []byte
	AADHash       [32]byte
}

// ProtectedHeader represents the header fields that are authenticated as AAD.
type ProtectedHeader struct {
	Magic         [4]byte
	Version       uint8
	Flags         uint16
	SuiteID       uint16
	KeyIDLen      uint16
	KeyVersion    uint32
	PolicyVersion uint32
	NonceLen      uint8
	TagLen        uint8
	CiphertextLen uint64
}

// ErrInvalid is the single error returned for any parse failure (no side-channel).
var ErrInvalid = errors.New("envelope: invalid")

// Build constructs the AEAD AAD per design §8.3:
//
//	aad = "kvlt-envelope-v1" || canonical(protected_header) || canonical(caller_aad)
//
// The protected_header canonical encoding is a fixed-layout byte sequence
// (deterministic, not TLV) so that cross-language implementations agree.
func BuildAEADAAD(hdr ProtectedHeader, callerAAD []byte) []byte {
	prefix := []byte("kvlt-envelope-v1")
	hdrBytes := encodeProtectedHeader(hdr)
	out := make([]byte, 0, len(prefix)+len(hdrBytes)+len(callerAAD))
	out = append(out, prefix...)
	out = append(out, hdrBytes...)
	out = append(out, callerAAD...)
	return out
}

// encodeProtectedHeader serializes the protected header in a fixed layout.
// Order matches the wire format (excluding aad_hash).
func encodeProtectedHeader(h ProtectedHeader) []byte {
	buf := make([]byte, 0, BaseHeaderSize)
	buf = append(buf, h.Magic[:]...)
	buf = append(buf, h.Version)
	var u16 [2]byte
	var u32 [4]byte
	var u64 [8]byte
	binary.BigEndian.PutUint16(u16[:], h.Flags)
	buf = append(buf, u16[:]...)
	binary.BigEndian.PutUint16(u16[:], h.SuiteID)
	buf = append(buf, u16[:]...)
	binary.BigEndian.PutUint16(u16[:], h.KeyIDLen)
	buf = append(buf, u16[:]...)
	binary.BigEndian.PutUint32(u32[:], h.KeyVersion)
	buf = append(buf, u32[:]...)
	binary.BigEndian.PutUint32(u32[:], h.PolicyVersion)
	buf = append(buf, u32[:]...)
	buf = append(buf, h.NonceLen)
	buf = append(buf, h.TagLen)
	binary.BigEndian.PutUint64(u64[:], h.CiphertextLen)
	buf = append(buf, u64[:]...)
	return buf
}

// Seal builds a complete Envelope v1 byte slice from plaintext + caller AAD.
// It generates the AAD hash, encrypts, and assembles the wire format.
// The caller MUST supply a unique nonce (from the nonce lease).
func Seal(suite aead.SuiteID, key []byte, keyID string, keyVersion uint32,
	policyVersion uint32, nonce, plaintext []byte, callerAAD []byte) ([]byte, error) {

	a, err := aead.New(suite, key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != suite.NonceLen() {
		return nil, fmt.Errorf("envelope: nonce length %d does not match suite %s",
			len(nonce), suite)
	}
	if len(keyID) > MaxKeyIDLen {
		return nil, fmt.Errorf("envelope: key_id too long")
	}
	if len(plaintext) > MaxCiphertextLen {
		return nil, fmt.Errorf("envelope: plaintext too long")
	}
	ciphertextLen := suite.CiphertextLen(len(plaintext))
	if ciphertextLen > MaxCiphertextLen {
		return nil, fmt.Errorf("envelope: plaintext too long")
	}

	hdr := ProtectedHeader{
		Magic:         Magic,
		Version:       Version1,
		Flags:         0,
		SuiteID:       uint16(suite),
		KeyIDLen:      uint16(len(keyID)),
		KeyVersion:    keyVersion,
		PolicyVersion: policyVersion,
		NonceLen:      uint8(len(nonce)),
		TagLen:        uint8(suite.TagLen()),
		CiphertextLen: uint64(ciphertextLen),
	}

	cipherAAD := callerAADForSuite(suite, callerAAD)
	aadHash := aadHashForSuite(suite, cipherAAD)
	aeadAAD := BuildAEADAAD(hdr, cipherAAD)
	ciphertext, tag := a.Encrypt(plaintext, nonce, aeadAAD)

	return assemble(hdr, aadHash, []byte(keyID), nonce, ciphertext, tag)
}

// assemble concatenates the wire format. Validates lengths.
func assemble(hdr ProtectedHeader, aadHash [32]byte, keyID, nonce, ciphertext, tag []byte) ([]byte, error) {
	if int(hdr.KeyIDLen) != len(keyID) {
		return nil, fmt.Errorf("envelope: key_id_len mismatch")
	}
	if int(hdr.NonceLen) != len(nonce) {
		return nil, fmt.Errorf("envelope: nonce_len mismatch")
	}
	if int(hdr.TagLen) != len(tag) {
		return nil, fmt.Errorf("envelope: tag_len mismatch")
	}
	if hdr.CiphertextLen != uint64(len(ciphertext)) {
		return nil, fmt.Errorf("envelope: ciphertext_len mismatch")
	}
	out := make([]byte, 0, headerSizeForSuite(aead.SuiteID(hdr.SuiteID))+len(keyID)+len(nonce)+len(ciphertext)+len(tag))
	out = append(out, encodeProtectedHeader(hdr)...)
	if aead.SuiteID(hdr.SuiteID).AuthenticatesAAD() {
		out = append(out, aadHash[:]...)
	}
	out = append(out, keyID...)
	out = append(out, nonce...)
	out = append(out, ciphertext...)
	out = append(out, tag...)
	return out, nil
}

// Open parses an Envelope v1 byte slice, reconstructs the AAD, and decrypts.
// callerAAD must be the canonical TLV-encoded caller AAD (NOT the raw struct).
// Per design §8.3, decryption MUST rebuild the full AAD and rely on AEAD
// verification; aad_hash is only a fast consistency check.
func Open(b []byte, key []byte, callerAAD []byte) (*Envelope, []byte, error) {
	env, err := Parse(b)
	if err != nil {
		return nil, nil, err
	}
	a, err := aead.New(env.SuiteID, key)
	if err != nil {
		return nil, nil, err
	}
	hdr := env.protectedHeader()
	aeadAAD := BuildAEADAAD(hdr, callerAADForSuite(env.SuiteID, callerAAD))
	pt, err := a.Decrypt(env.Ciphertext, env.Tag, env.Nonce, aeadAAD)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: decrypt failed", ErrInvalid)
	}
	return env, pt, nil
}

// Parse strictly parses an Envelope v1 byte slice without decrypting.
// All failures return ErrInvalid; no panic.
func Parse(b []byte) (*Envelope, error) {
	if len(b) < BaseHeaderSize {
		return nil, fmt.Errorf("%w: header too short", ErrInvalid)
	}
	// Magic
	var magic [4]byte
	copy(magic[:], b[0:4])
	if magic != Magic {
		return nil, fmt.Errorf("%w: magic mismatch", ErrInvalid)
	}
	// Version
	version := b[4]
	if version != Version1 {
		return nil, fmt.Errorf("%w: unsupported version %d", ErrInvalid, version)
	}
	// Flags
	flags := binary.BigEndian.Uint16(b[5:7])
	if flags&^allowedV1Flags != 0 {
		return nil, fmt.Errorf("%w: unknown flags 0x%04x", ErrInvalid, flags)
	}
	suiteID := aead.SuiteID(binary.BigEndian.Uint16(b[7:9]))
	keyIDLen := binary.BigEndian.Uint16(b[9:11])
	keyVersion := binary.BigEndian.Uint32(b[11:15])
	policyVersion := binary.BigEndian.Uint32(b[15:19])
	nonceLen := b[19]
	tagLen := b[20]
	ciphertextLen := binary.BigEndian.Uint64(b[21:29])
	var aadHash [32]byte

	// Validate lengths against suite-fixed values and global bounds.
	if err := validateLengths(suiteID, keyIDLen, uint16(nonceLen), uint16(tagLen), ciphertextLen); err != nil {
		return nil, err
	}
	headerSize := headerSizeForSuite(suiteID)
	if len(b) < headerSize {
		return nil, fmt.Errorf("%w: header too short", ErrInvalid)
	}
	if suiteID.AuthenticatesAAD() {
		copy(aadHash[:], b[BaseHeaderSize:headerSize])
	}

	// Overflow-safe total length check.
	remaining := len(b) - headerSize
	needed := int(keyIDLen) + int(nonceLen) + int(tagLen) + int(ciphertextLen)
	if needed > remaining {
		return nil, fmt.Errorf("%w: declared length exceeds buffer", ErrInvalid)
	}
	if needed < remaining {
		return nil, fmt.Errorf("%w: trailing bytes", ErrInvalid)
	}

	off := headerSize
	keyID := slice(b, off, int(keyIDLen))
	off += int(keyIDLen)
	nonce := slice(b, off, int(nonceLen))
	off += int(nonceLen)
	ciphertext := slice(b, off, int(ciphertextLen))
	off += int(ciphertextLen)
	tag := slice(b, off, int(tagLen))

	// Copy out so callers cannot mutate the input buffer accidentally.
	keyIDCopy := append([]byte(nil), keyID...)
	nonceCopy := append([]byte(nil), nonce...)
	ctCopy := append([]byte(nil), ciphertext...)
	tagCopy := append([]byte(nil), tag...)

	return &Envelope{
		Version:       version,
		Flags:         flags,
		SuiteID:       suiteID,
		KeyID:         keyIDCopy,
		KeyVersion:    keyVersion,
		PolicyVersion: policyVersion,
		Nonce:         nonceCopy,
		Ciphertext:    ctCopy,
		Tag:           tagCopy,
		AADHash:       aadHash,
	}, nil
}

func slice(b []byte, off, n int) []byte {
	return b[off : off+n]
}

func validateLengths(suite aead.SuiteID, keyIDLen, nonceLen, tagLen uint16, ciphertextLen uint64) error {
	if int(keyIDLen) > MaxKeyIDLen {
		return fmt.Errorf("%w: key_id_len too large", ErrInvalid)
	}
	if int(nonceLen) > MaxNonceLen {
		return fmt.Errorf("%w: nonce_len too large", ErrInvalid)
	}
	if int(tagLen) > MaxTagLen {
		return fmt.Errorf("%w: tag_len too large", ErrInvalid)
	}
	if ciphertextLen > MaxCiphertextLen {
		return fmt.Errorf("%w: ciphertext_len too large", ErrInvalid)
	}
	// Suite-fixed tag and nonce lengths.
	if int(tagLen) != suite.TagLen() {
		return fmt.Errorf("%w: tag_len does not match suite", ErrInvalid)
	}
	if int(nonceLen) != suite.NonceLen() {
		return fmt.Errorf("%w: nonce_len does not match suite", ErrInvalid)
	}
	// Validate suite is known.
	switch suite {
	case aead.SuiteAES256GCM, aead.SuiteSM4GCM, aead.SuiteAES256ECB, aead.SuiteSM4ECB:
		// known
	default:
		return fmt.Errorf("%w: unknown suite_id 0x%04x", ErrInvalid, uint16(suite))
	}
	return nil
}
func (e *Envelope) protectedHeader() ProtectedHeader {
	return ProtectedHeader{
		Magic:         Magic,
		Version:       e.Version,
		Flags:         e.Flags,
		SuiteID:       uint16(e.SuiteID),
		KeyIDLen:      uint16(len(e.KeyID)),
		KeyVersion:    e.KeyVersion,
		PolicyVersion: e.PolicyVersion,
		NonceLen:      uint8(len(e.Nonce)),
		TagLen:        uint8(len(e.Tag)),
		CiphertextLen: uint64(len(e.Ciphertext)),
	}
}

// VerifyAADHash returns true if the envelope's aad_hash matches SHA-256(callerAAD).
// ECB suites have no AAD semantics, so their AAD hash is intentionally ignored.
// For GCM this is ONLY a fast consistency check; AEAD verification is authoritative.
func (e *Envelope) VerifyAADHash(callerAAD []byte) bool {
	if !e.SuiteID.AuthenticatesAAD() {
		return true
	}
	got := sha256.Sum256(callerAAD)
	return got == e.AADHash
}

func callerAADForSuite(suite aead.SuiteID, callerAAD []byte) []byte {
	if suite.AuthenticatesAAD() {
		return callerAAD
	}
	return nil
}

func aadHashForSuite(suite aead.SuiteID, callerAAD []byte) [32]byte {
	if suite.AuthenticatesAAD() {
		return sha256.Sum256(callerAAD)
	}
	return [32]byte{}
}

func headerSizeForSuite(suite aead.SuiteID) int {
	if suite.AuthenticatesAAD() {
		return FixedHeaderSize
	}
	return BaseHeaderSize
}

// Encode serializes a parsed Envelope back to bytes (round-trip).
func (e *Envelope) Encode() ([]byte, error) {
	hdr := e.protectedHeader()
	return assemble(hdr, e.AADHash, e.KeyID, e.Nonce, e.Ciphertext, e.Tag)
}
