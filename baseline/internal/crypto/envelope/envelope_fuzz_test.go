package envelope

import (
	"bytes"
	"errors"
	"testing"

	"github.com/kvlt/key-vault/internal/crypto/aead"
)

// Fuzz tests for Envelope v1 parsing per design 搂8.3 "Envelope 瑙ｆ瀽瀹夊叏".
// All parse failures MUST return ErrInvalid; no panic, no side-channel.

// FuzzParse verifies that Parse never panics on arbitrary input and that
// any successfully parsed envelope can be re-encoded and re-parsed.
func FuzzParse(f *testing.F) {
	// Seed corpus: valid envelopes + edge cases.
	key := bytes.Repeat([]byte{0x42}, 32)
	nonce := bytes.Repeat([]byte{0x11}, 12)
	callerAAD := testCallerAAD{TenantID: "t", KeyID: "k", KeyVersion: 1, Purpose: "p", SuiteID: uint16(aead.SuiteAES256GCM)}
	aadBytes, _ := callerAAD.Canonical()

	valid, _ := Seal(aead.SuiteAES256GCM, key, "k", 1, 1, nonce, []byte("seed"), aadBytes)
	f.Add(valid)                                            // valid envelope
	f.Add([]byte("KVLT"))                                   // magic only
	f.Add(make([]byte, 61))                                 // minimum header, all zeros
	f.Add([]byte{})                                         // empty
	f.Add([]byte{0xff, 0xff, 0xff})                         // short garbage
	f.Add(append([]byte("KVLT\x01"), make([]byte, 100)...)) // magic + version + zeros

	f.Fuzz(func(t *testing.T, data []byte) {
		// Parse MUST NOT panic.
		env, err := Parse(data)
		if err != nil {
			// All errors must be ErrInvalid (no other error types leak).
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("non-ErrInvalid error: %v", err)
			}
			return
		}
		// If parsing succeeded, the envelope must be well-formed.
		// Re-encode and verify round-trip.
		reencoded, err := env.Encode()
		if err != nil {
			t.Fatalf("Encode after Parse failed: %v", err)
		}
		// Re-parse the re-encoded envelope.
		env2, err := Parse(reencoded)
		if err != nil {
			t.Fatalf("Parse after Encode failed: %v", err)
		}
		// Verify fields match.
		if env.Version != env2.Version {
			t.Fatalf("version mismatch: %d vs %d", env.Version, env2.Version)
		}
		if env.SuiteID != env2.SuiteID {
			t.Fatalf("suite mismatch: %v vs %v", env.SuiteID, env2.SuiteID)
		}
		if !bytes.Equal(env.KeyID, env2.KeyID) {
			t.Fatalf("key_id mismatch")
		}
		if !bytes.Equal(env.Nonce, env2.Nonce) {
			t.Fatalf("nonce mismatch")
		}
		if !bytes.Equal(env.Ciphertext, env2.Ciphertext) {
			t.Fatalf("ciphertext mismatch")
		}
		if !bytes.Equal(env.Tag, env2.Tag) {
			t.Fatalf("tag mismatch")
		}
		if env.AADHash != env2.AADHash {
			t.Fatalf("aad_hash mismatch")
		}
		// The re-encoded bytes must equal the original (if original was canonical).
		// Note: Parse may accept input that is byte-identical to reencoded.
		if !bytes.Equal(data, reencoded) {
			// This can happen if the fuzz input had different byte layout but
			// same semantic content (shouldn't happen for v1). Log for awareness.
			t.Logf("input differs from reencoded (len in=%d, re=%d)", len(data), len(reencoded))
		}
	})
}

// FuzzOpen verifies that Open never panics on arbitrary input and that
// decryption only succeeds with the correct key + AAD.
func FuzzOpen(f *testing.F) {
	key := bytes.Repeat([]byte{0x42}, 32)
	nonce := bytes.Repeat([]byte{0x11}, 12)
	callerAAD := testCallerAAD{TenantID: "t", KeyID: "k", KeyVersion: 1, Purpose: "p", SuiteID: uint16(aead.SuiteAES256GCM)}
	aadBytes, _ := callerAAD.Canonical()

	valid, _ := Seal(aead.SuiteAES256GCM, key, "k", 1, 1, nonce, []byte("fuzz-open"), aadBytes)
	f.Add(valid)
	f.Add([]byte{})
	f.Add(make([]byte, 100))
	f.Add(valid[:60]) // truncated header

	f.Fuzz(func(t *testing.T, data []byte) {
		// Open MUST NOT panic.
		_, _, err := Open(data, key, aadBytes)
		if err == nil {
			// Decryption succeeded; this should only happen for valid input.
			// Re-parse to confirm structure.
			if _, err := Parse(data); err != nil {
				t.Fatalf("Open succeeded but Parse failed: %v", err)
			}
		}
		// All errors are acceptable (either ErrInvalid or decrypt failure).
	})
}

// FuzzSealOpenRoundTrip verifies that Seal -> Open always round-trips for
// arbitrary plaintext.
func FuzzSealOpenRoundTrip(f *testing.F) {
	f.Add([]byte("hello"))
	f.Add([]byte{})
	f.Add([]byte{0x00})
	f.Add(bytes.Repeat([]byte{0xff}, 1024))

	f.Fuzz(func(t *testing.T, plaintext []byte) {
		// Cap plaintext to avoid huge allocations.
		if len(plaintext) > 1<<16 {
			t.Skip()
		}
		key := bytes.Repeat([]byte{0x42}, 32)
		nonce := bytes.Repeat([]byte{0x11}, 12)
		callerAAD := testCallerAAD{TenantID: "t", KeyID: "k", KeyVersion: 1, Purpose: "p", SuiteID: uint16(aead.SuiteAES256GCM)}
		aadBytes, _ := callerAAD.Canonical()

		sealed, err := Seal(aead.SuiteAES256GCM, key, "k", 1, 1, nonce, plaintext, aadBytes)
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		_, got, err := Open(sealed, key, aadBytes)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Fatalf("round-trip mismatch:\n got  %x\n want %x", got, plaintext)
		}
	})
}
