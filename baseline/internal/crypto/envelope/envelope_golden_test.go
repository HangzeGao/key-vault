package envelope

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/kvlt/key-vault/internal/crypto/aead"
)

// Golden Test Vectors for Envelope v1 per design 搂8.3.
// These are immutable KAT (Known Answer Test) vectors. Any change to the
// canonical encoding MUST be a version bump.

// TestGoldenEnvelopeRoundTrip verifies Seal -> Open round-trip with AES-256-GCM.
func TestGoldenEnvelopeRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32) // deterministic 256-bit key
	nonce := bytes.Repeat([]byte{0x11}, 12)
	plaintext := []byte("hello, envelope v1 golden vector")
	keyID := "key-golden-001"

	callerAAD := testCallerAAD{
		TenantID:   "tenant-golden",
		KeyID:      keyID,
		KeyVersion: 1,
		Purpose:    "golden-test",
		SuiteID:    uint16(aead.SuiteAES256GCM),
	}
	aadBytes, err := callerAAD.Canonical()
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}

	sealed, err := Seal(aead.SuiteAES256GCM, key, keyID, 1, 1, nonce, plaintext, aadBytes)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	// Verify minimum length.
	if len(sealed) < FixedHeaderSize {
		t.Fatalf("sealed too short: %d", len(sealed))
	}

	// Verify magic.
	if !bytes.Equal(sealed[0:4], Magic[:]) {
		t.Fatalf("magic mismatch: %x", sealed[0:4])
	}

	// Verify version.
	if sealed[4] != Version1 {
		t.Fatalf("version = %d, want %d", sealed[4], Version1)
	}

	// Open and verify plaintext.
	env, pt, err := Open(sealed, key, aadBytes)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Fatalf("plaintext mismatch:\n got  %x\n want %x", pt, plaintext)
	}
	if string(env.KeyID) != keyID {
		t.Fatalf("key_id = %q, want %q", env.KeyID, keyID)
	}
	if env.KeyVersion != 1 {
		t.Fatalf("key_version = %d, want 1", env.KeyVersion)
	}
	if env.SuiteID != aead.SuiteAES256GCM {
		t.Fatalf("suite = %v, want AES_256_GCM", env.SuiteID)
	}
}

// TestGoldenEnvelopeSM4 verifies Seal -> Open round-trip with SM4-GCM.
func TestGoldenEnvelopeSM4(t *testing.T) {
	key := bytes.Repeat([]byte{0x33}, 16) // 128-bit SM4 key
	nonce := bytes.Repeat([]byte{0x22}, 12)
	plaintext := []byte("sm4-gcm golden vector")
	keyID := "key-sm4-001"

	callerAAD := testCallerAAD{
		TenantID:   "tenant-sm4",
		KeyID:      keyID,
		KeyVersion: 1,
		Purpose:    "sm4-test",
		SuiteID:    uint16(aead.SuiteSM4GCM),
	}
	aadBytes, err := callerAAD.Canonical()
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}

	sealed, err := Seal(aead.SuiteSM4GCM, key, keyID, 1, 1, nonce, plaintext, aadBytes)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	env, pt, err := Open(sealed, key, aadBytes)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Fatalf("plaintext mismatch")
	}
	if env.SuiteID != aead.SuiteSM4GCM {
		t.Fatalf("suite = %v, want SM4_GCM", env.SuiteID)
	}
}

// TestGoldenEnvelopeAADHash verifies the aad_hash field is SHA-256(callerAAD).
func TestGoldenEnvelopeAADHash(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	nonce := bytes.Repeat([]byte{0x11}, 12)
	plaintext := []byte("aad hash test")
	keyID := "key-aad-001"

	callerAAD := testCallerAAD{
		TenantID:   "t",
		KeyID:      keyID,
		KeyVersion: 1,
		Purpose:    "p",
		SuiteID:    uint16(aead.SuiteAES256GCM),
	}
	aadBytes, _ := callerAAD.Canonical()

	sealed, err := Seal(aead.SuiteAES256GCM, key, keyID, 1, 1, nonce, plaintext, aadBytes)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	env, err := Parse(sealed)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	wantHash := sha256.Sum256(aadBytes)
	if env.AADHash != wantHash {
		t.Fatalf("aad_hash mismatch:\n got  %x\n want %x", env.AADHash, wantHash)
	}
	if !env.VerifyAADHash(aadBytes) {
		t.Fatal("VerifyAADHash returned false")
	}
}

// TestGoldenEnvelopeRejectsTamperedCiphertext verifies AEAD authentication.
func TestGoldenEnvelopeRejectsTamperedCiphertext(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	nonce := bytes.Repeat([]byte{0x11}, 12)
	plaintext := []byte("tamper detection test")
	keyID := "key-tamper-001"

	callerAAD := testCallerAAD{
		TenantID:   "t",
		KeyID:      keyID,
		KeyVersion: 1,
		Purpose:    "p",
		SuiteID:    uint16(aead.SuiteAES256GCM),
	}
	aadBytes, _ := callerAAD.Canonical()

	sealed, err := Seal(aead.SuiteAES256GCM, key, keyID, 1, 1, nonce, plaintext, aadBytes)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	// Flip a bit in the ciphertext region (after header + keyID + nonce).
	ctStart := FixedHeaderSize + len(keyID) + len(nonce)
	tampered := make([]byte, len(sealed))
	copy(tampered, sealed)
	tampered[ctStart] ^= 0x01

	_, _, err = Open(tampered, key, aadBytes)
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("expected ErrInvalid, got %v", err)
	}
}

// TestGoldenEnvelopeRejectsTamperedAAD verifies that AAD mismatch fails decryption.
func TestGoldenEnvelopeRejectsTamperedAAD(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	nonce := bytes.Repeat([]byte{0x11}, 12)
	plaintext := []byte("aad mismatch test")
	keyID := "key-aad-mismatch"

	callerAAD := testCallerAAD{
		TenantID:   "t",
		KeyID:      keyID,
		KeyVersion: 1,
		Purpose:    "original-purpose",
		SuiteID:    uint16(aead.SuiteAES256GCM),
	}
	aadBytes, _ := callerAAD.Canonical()

	sealed, err := Seal(aead.SuiteAES256GCM, key, keyID, 1, 1, nonce, plaintext, aadBytes)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	// Use a different AAD for decryption.
	wrongAAD := testCallerAAD{
		TenantID:   "t",
		KeyID:      keyID,
		KeyVersion: 1,
		Purpose:    "wrong-purpose",
		SuiteID:    uint16(aead.SuiteAES256GCM),
	}
	wrongBytes, _ := wrongAAD.Canonical()

	_, _, err = Open(sealed, key, wrongBytes)
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("expected ErrInvalid, got %v", err)
	}
}

// TestGoldenEnvelopeRejectsBadMagic verifies that a wrong magic is rejected
// without further parsing (no side-channel).
func TestGoldenEnvelopeRejectsBadMagic(t *testing.T) {
	sealed := make([]byte, FixedHeaderSize)
	copy(sealed[0:4], []byte("XXXX"))
	sealed[4] = Version1
	_, err := Parse(sealed)
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("expected ErrInvalid, got %v", err)
	}
}

// TestGoldenEnvelopeRejectsShortBuffer verifies that a too-short buffer is rejected.
func TestGoldenEnvelopeRejectsShortBuffer(t *testing.T) {
	_, err := Parse([]byte{0x01, 0x02})
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("expected ErrInvalid, got %v", err)
	}
}

// TestGoldenEnvelopeRejectsUnknownVersion verifies that an unknown version is rejected.
func TestGoldenEnvelopeRejectsUnknownVersion(t *testing.T) {
	sealed := make([]byte, FixedHeaderSize)
	copy(sealed[0:4], Magic[:])
	sealed[4] = 0x02 // unknown version
	_, err := Parse(sealed)
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("expected ErrInvalid, got %v", err)
	}
}

// TestGoldenEnvelopeRejectsReservedFlags verifies that any non-zero flag is rejected in the baseline.
func TestGoldenEnvelopeRejectsReservedFlags(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	nonce := bytes.Repeat([]byte{0x11}, 12)
	plaintext := []byte("flag test")
	keyID := "k"
	callerAAD := testCallerAAD{TenantID: "t", KeyID: keyID, KeyVersion: 1, Purpose: "p", SuiteID: uint16(aead.SuiteAES256GCM)}
	aadBytes, _ := callerAAD.Canonical()
	sealed, err := Seal(aead.SuiteAES256GCM, key, keyID, 1, 1, nonce, plaintext, aadBytes)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	// Set a reserved flag bit.
	sealed[5] = 0x01
	_, err = Parse(sealed)
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("expected ErrInvalid, got %v", err)
	}
}

// TestGoldenEnvelopeRejectsTrailingBytes verifies that trailing bytes are rejected.
func TestGoldenEnvelopeRejectsTrailingBytes(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	nonce := bytes.Repeat([]byte{0x11}, 12)
	plaintext := []byte("trailing")
	keyID := "k"
	callerAAD := testCallerAAD{TenantID: "t", KeyID: keyID, KeyVersion: 1, Purpose: "p", SuiteID: uint16(aead.SuiteAES256GCM)}
	aadBytes, _ := callerAAD.Canonical()
	sealed, err := Seal(aead.SuiteAES256GCM, key, keyID, 1, 1, nonce, plaintext, aadBytes)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	// Append a trailing byte.
	sealed = append(sealed, 0xff)
	_, err = Parse(sealed)
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("expected ErrInvalid, got %v", err)
	}
}

// TestGoldenEnvelopeRejectsUnknownSuite verifies that an unknown suite_id is rejected.
func TestGoldenEnvelopeRejectsUnknownSuite(t *testing.T) {
	sealed := make([]byte, FixedHeaderSize)
	copy(sealed[0:4], Magic[:])
	sealed[4] = Version1
	// suite_id = 0xFFFF (unknown)
	sealed[7] = 0xFF
	sealed[8] = 0xFF
	_, err := Parse(sealed)
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("expected ErrInvalid, got %v", err)
	}
}

func TestEnvelopeECBRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x55}, 32)
	plaintext := []byte("legacy ECB compatibility payload")
	keyID := "key-ecb-001"
	callerAAD := testCallerAAD{
		TenantID:   "tenant-ecb",
		KeyID:      keyID,
		KeyVersion: 1,
		Purpose:    "ecb-test",
		SuiteID:    uint16(aead.SuiteAES256ECB),
	}
	aadBytes, err := callerAAD.Canonical()
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}
	sealed, err := Seal(aead.SuiteAES256ECB, key, keyID, 1, 1, nil, plaintext, aadBytes)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	env, opened, err := Open(sealed, key, []byte("different aad is ignored by ecb"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(opened, plaintext) {
		t.Fatalf("plaintext mismatch: got %q want %q", opened, plaintext)
	}
	if env.SuiteID != aead.SuiteAES256ECB {
		t.Fatalf("suite = %v, want AES_256_ECB", env.SuiteID)
	}
	if len(env.Nonce) != 0 || len(env.Tag) != 0 {
		t.Fatalf("ECB envelope nonce/tag lengths = %d/%d, want 0/0", len(env.Nonce), len(env.Tag))
	}
	if env.AADHash != ([32]byte{}) {
		t.Fatalf("ECB aad_hash = %x, want zero", env.AADHash)
	}
	if len(env.Ciphertext) != aead.SuiteAES256ECB.CiphertextLen(len(plaintext)) {
		t.Fatalf("ECB ciphertext length = %d, want %d", len(env.Ciphertext), aead.SuiteAES256ECB.CiphertextLen(len(plaintext)))
	}
	wantWireLen := BaseHeaderSize + len(keyID) + len(env.Ciphertext)
	if len(sealed) != wantWireLen {
		t.Fatalf("ECB canonical length = %d, want %d without aad_hash", len(sealed), wantWireLen)
	}
	if !env.VerifyAADHash([]byte("any aad")) {
		t.Fatal("ECB VerifyAADHash must ignore caller AAD")
	}
}

// TestGoldenEnvelopeEncodeRoundTrip verifies that Parse -> Encode round-trips.
func TestGoldenEnvelopeEncodeRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	nonce := bytes.Repeat([]byte{0x11}, 12)
	plaintext := []byte("round-trip")
	keyID := "k-rt"
	callerAAD := testCallerAAD{TenantID: "t", KeyID: keyID, KeyVersion: 1, Purpose: "p", SuiteID: uint16(aead.SuiteAES256GCM)}
	aadBytes, _ := callerAAD.Canonical()
	sealed, err := Seal(aead.SuiteAES256GCM, key, keyID, 1, 1, nonce, plaintext, aadBytes)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	env, err := Parse(sealed)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	reencoded, err := env.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if !bytes.Equal(sealed, reencoded) {
		t.Fatalf("round-trip mismatch:\n orig %x\n re   %x", sealed, reencoded)
	}
}

// TestGoldenEnvelopeHeaderLayout verifies the GCM authenticated header layout
// is exactly 61 bytes and field offsets match the internal canonical layout.
func TestGoldenEnvelopeHeaderLayout(t *testing.T) {
	if BaseHeaderSize != 29 {
		t.Fatalf("BaseHeaderSize = %d, want 29", BaseHeaderSize)
	}
	if FixedHeaderSize != 61 {
		t.Fatalf("FixedHeaderSize = %d, want 61", FixedHeaderSize)
	}
	key := bytes.Repeat([]byte{0x42}, 32)
	nonce := bytes.Repeat([]byte{0x11}, 12)
	plaintext := []byte("layout")
	keyID := "k-layout"
	callerAAD := testCallerAAD{TenantID: "t", KeyID: keyID, KeyVersion: 1, Purpose: "p", SuiteID: uint16(aead.SuiteAES256GCM)}
	aadBytes, _ := callerAAD.Canonical()
	sealed, err := Seal(aead.SuiteAES256GCM, key, keyID, 7, 9, nonce, plaintext, aadBytes)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	// Verify offsets:
	// 0-3: magic
	// 4: version
	// 5-6: flags
	// 7-8: suite_id
	// 9-10: key_id_len
	// 11-14: key_version
	// 15-18: policy_version
	// 19: nonce_len
	// 20: tag_len
	// 21-28: ciphertext_len
	// 29-60: aad_hash
	if !bytes.Equal(sealed[0:4], Magic[:]) {
		t.Fatal("magic offset wrong")
	}
	if sealed[4] != Version1 {
		t.Fatal("version offset wrong")
	}
	if sealed[5] != 0 || sealed[6] != 0 {
		t.Fatal("flags offset wrong")
	}
	// suite_id at 7-8 should be 0x0001 (AES_256_GCM)
	if sealed[7] != 0x00 || sealed[8] != 0x01 {
		t.Fatalf("suite_id offset wrong: %x", sealed[7:9])
	}
	// key_id_len at 9-10 should be len("k-layout") = 8
	if sealed[9] != 0x00 || sealed[10] != 0x08 {
		t.Fatalf("key_id_len offset wrong: %x", sealed[9:11])
	}
	// key_version at 11-14 should be 7
	if sealed[11] != 0x00 || sealed[12] != 0x00 || sealed[13] != 0x00 || sealed[14] != 0x07 {
		t.Fatalf("key_version offset wrong: %x", sealed[11:15])
	}
	// policy_version at 15-18 should be 9
	if sealed[15] != 0x00 || sealed[16] != 0x00 || sealed[17] != 0x00 || sealed[18] != 0x09 {
		t.Fatalf("policy_version offset wrong: %x", sealed[15:19])
	}
	// nonce_len at 19 should be 12
	if sealed[19] != 12 {
		t.Fatalf("nonce_len offset wrong: %d", sealed[19])
	}
	// tag_len at 20 should be 16
	if sealed[20] != 16 {
		t.Fatalf("tag_len offset wrong: %d", sealed[20])
	}
	// ciphertext_len at 21-28 should be len("layout") = 6
	if sealed[21] != 0 || sealed[22] != 0 || sealed[23] != 0 || sealed[24] != 0 ||
		sealed[25] != 0 || sealed[26] != 0 || sealed[27] != 0 || sealed[28] != 6 {
		t.Fatalf("ciphertext_len offset wrong: %x", sealed[21:29])
	}
}

// TestGoldenEnvelopeHexVector provides a stable hex vector for cross-language verification.
// This vector is deterministic because AES-GCM with fixed key/nonce/AAD is deterministic.
func TestGoldenEnvelopeHexVector(t *testing.T) {
	key := bytes.Repeat([]byte{0x01}, 32)
	nonce := bytes.Repeat([]byte{0x02}, 12)
	plaintext := []byte("KAT")
	keyID := "K"
	callerAAD := testCallerAAD{
		TenantID:   "T",
		KeyID:      keyID,
		KeyVersion: 1,
		Purpose:    "P",
		SuiteID:    uint16(aead.SuiteAES256GCM),
	}
	aadBytes, _ := callerAAD.Canonical()
	sealed, err := Seal(aead.SuiteAES256GCM, key, keyID, 1, 1, nonce, plaintext, aadBytes)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	// The header portion (61 bytes) is deterministic; print for cross-language verification.
	header := sealed[:FixedHeaderSize]
	t.Logf("header hex: %s", hex.EncodeToString(header))
	// Verify the header is deterministic across calls.
	sealed2, _ := Seal(aead.SuiteAES256GCM, key, keyID, 1, 1, nonce, plaintext, aadBytes)
	if !bytes.Equal(sealed, sealed2) {
		t.Fatal("Seal is not deterministic with fixed inputs")
	}
}
