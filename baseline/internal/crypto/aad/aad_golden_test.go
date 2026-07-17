package aad

import (
	"bytes"
	"testing"
)

func TestGoldenCanonicalCRKAAD(t *testing.T) {
	baseline := []byte{0xaa, 0xbb, 0xcc, 0xdd}
	policy := []byte{0x11, 0x22, 0x33, 0x44}
	c := CRKAAD{
		ClusterID:      "cluster-prod",
		NodeID:         "node-1",
		PlaneRole:      "key-plane",
		CRKVersion:     1,
		NRWKName:       "nrwk-primary",
		BaselineDigest: baseline,
		PolicyDigest:   policy,
	}
	got, err := c.Canonical()
	if err != nil {
		t.Fatalf("Canonical: %v", err)
	}
	fields, err := Decode(got)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(fields) != 7 {
		t.Fatalf("expected 7 fields, got %d", len(fields))
	}
	expectedTags := []uint8{0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D}
	for i, f := range fields {
		if f.ID != expectedTags[i] {
			t.Fatalf("field %d: tag 0x%02x, want 0x%02x", i, f.ID, expectedTags[i])
		}
	}
}

func TestGoldenCanonicalRoundTrip(t *testing.T) {
	fields := []Field{
		{ID: 0x01, Value: []byte("alpha")},
		{ID: 0x02, Value: []byte("beta")},
		{ID: 0x03, Value: []byte("gamma")},
	}
	enc, err := Encode(fields)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	dec, err := Decode(enc)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(dec) != len(fields) {
		t.Fatalf("len = %d, want %d", len(dec), len(fields))
	}
	for i, f := range fields {
		if dec[i].ID != f.ID {
			t.Fatalf("field %d: ID mismatch", i)
		}
		if !bytes.Equal(dec[i].Value, f.Value) {
			t.Fatalf("field %d: value mismatch", i)
		}
	}
}

func TestGoldenCanonicalRejectsOutOfOrder(t *testing.T) {
	fields := []Field{
		{ID: 0x02, Value: []byte("b")},
		{ID: 0x01, Value: []byte("a")},
	}
	if _, err := Encode(fields); err == nil {
		t.Fatal("expected error for out-of-order fields")
	}
}

func TestGoldenCanonicalRejectsRepeated(t *testing.T) {
	fields := []Field{
		{ID: 0x01, Value: []byte("a")},
		{ID: 0x01, Value: []byte("b")},
	}
	if _, err := Encode(fields); err == nil {
		t.Fatal("expected error for repeated fields")
	}
}

func TestGoldenCanonicalRejectsTrailingBytes(t *testing.T) {
	enc, err := Encode([]Field{{ID: 0x01, Value: []byte("a")}})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	enc = append(enc, 0xff)
	if _, err := Decode(enc); err == nil {
		t.Fatal("expected error for trailing bytes")
	}
}

func TestGoldenCanonicalEmptyValue(t *testing.T) {
	fields := []Field{
		{ID: 0x01, Value: []byte{}},
		{ID: 0x02, Value: nil},
	}
	enc, err := Encode(fields)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if len(enc) != 6 {
		t.Fatalf("len = %d, want 6", len(enc))
	}
	dec, err := Decode(enc)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(dec) != 2 {
		t.Fatalf("decoded len = %d, want 2", len(dec))
	}
	if len(dec[0].Value) != 0 || len(dec[1].Value) != 0 {
		t.Fatal("expected empty values")
	}
}
