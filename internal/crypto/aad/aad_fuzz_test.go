package aad

import (
	"bytes"
	"errors"
	"testing"
)

// Fuzz tests for AAD Canonical TLV encoding per design §8.3.

// FuzzEncodeDecode verifies that Encode -> Decode round-trips for valid inputs
// and never panics for arbitrary inputs.
func FuzzEncodeDecode(f *testing.F) {
	// Seed corpus.
	f.Add([]byte{0x01, 0x00, 0x01, 0x41}) // tag 1, len 1, value "A"
	f.Add([]byte{})                       // empty
	f.Add([]byte{0x01, 0x00, 0x00})       // tag 1, len 0
	f.Add([]byte{0xff, 0xff, 0xff, 0xff}) // garbage

	f.Fuzz(func(t *testing.T, data []byte) {
		// Decode MUST NOT panic.
		fields, err := Decode(data)
		if err != nil {
			// All errors must be ErrInvalid.
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("non-ErrInvalid error: %v", err)
			}
			return
		}
		// If decoding succeeded, re-encode and verify round-trip.
		reencoded, err := Encode(fields)
		if err != nil {
			t.Fatalf("Encode after Decode failed: %v", err)
		}
		if !bytes.Equal(data, reencoded) {
			t.Fatalf("round-trip mismatch:\n got  %x\n want %x", reencoded, data)
		}
	})
}
