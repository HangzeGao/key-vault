// Package aad implements deterministic TLV canonical encoding for
// system-internal TPM sealed-object context. Data-plane caller AAD is opaque
// bytes supplied by the caller and is not canonicalized by this package.
package aad

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Field IDs (uint8). Order in this list defines the canonical order.
// Encode rejects out-of-order or repeated fields.
const (
	FieldPurpose     uint8 = 0x07
	FieldObjectID    uint8 = 0x08
	FieldNodeID      uint8 = 0x09
	FieldStorageName uint8 = 0x0A
	FieldBaselineDig uint8 = 0x0B
	FieldPolicyDig   uint8 = 0x0C
)

const (
	maxFieldLen    = 1 << 16 // 64 KiB per field
	maxFieldCount  = 32
	fieldHeaderLen = 3 // 1 byte tag + 2 bytes length
)

// Field is a single TLV field.
type Field struct {
	ID    uint8
	Value []byte
}

// ErrInvalid is returned for any canonical-encoding violation.
var ErrInvalid = errors.New("aad: invalid canonical encoding")

// Encode serializes fields as deterministic TLV.
// Format per field: [tag:1][len:2 BE][value:len].
// Fields MUST be in ascending tag order with no repeats.
// Empty values are allowed (encoded with len=0).
func Encode(fields []Field) ([]byte, error) {
	if len(fields) > maxFieldCount {
		return nil, fmt.Errorf("%w: too many fields", ErrInvalid)
	}
	var last uint8
	seen := make(map[uint8]struct{}, len(fields))
	total := 0
	for _, f := range fields {
		if _, ok := seen[f.ID]; ok {
			return nil, fmt.Errorf("%w: repeated field 0x%02x", ErrInvalid, f.ID)
		}
		if len(fields) > 0 && f.ID != 0 && f.ID <= last && last != 0 {
			return nil, fmt.Errorf("%w: out-of-order field 0x%02x (last 0x%02x)", ErrInvalid, f.ID, last)
		}
		if len(f.Value) > maxFieldLen {
			return nil, fmt.Errorf("%w: field 0x%02x too long", ErrInvalid, f.ID)
		}
		seen[f.ID] = struct{}{}
		last = f.ID
		total += fieldHeaderLen + len(f.Value)
	}
	out := make([]byte, 0, total)
	for _, f := range fields {
		out = append(out, f.ID)
		var l [2]byte
		binary.BigEndian.PutUint16(l[:], uint16(len(f.Value)))
		out = append(out, l[:]...)
		out = append(out, f.Value...)
	}
	return out, nil
}

// Decode parses a TLV byte slice and returns fields. It enforces:
//   - ascending tag order, no repeats
//   - length fields within bounds
//   - no trailing bytes
//   - max field count
func Decode(b []byte) ([]Field, error) {
	var fields []Field
	var last uint8
	seen := make(map[uint8]struct{})
	i := 0
	for i < len(b) {
		if len(b)-i < fieldHeaderLen {
			return nil, fmt.Errorf("%w: truncated header at offset %d", ErrInvalid, i)
		}
		tag := b[i]
		ln := binary.BigEndian.Uint16(b[i+1:])
		i += fieldHeaderLen
		if int(ln) > len(b)-i {
			return nil, fmt.Errorf("%w: field 0x%02x length exceeds buffer", ErrInvalid, tag)
		}
		if int(ln) > maxFieldLen {
			return nil, fmt.Errorf("%w: field 0x%02x too long", ErrInvalid, tag)
		}
		if _, ok := seen[tag]; ok {
			return nil, fmt.Errorf("%w: repeated field 0x%02x", ErrInvalid, tag)
		}
		if len(fields) > 0 && tag <= last {
			return nil, fmt.Errorf("%w: out-of-order field 0x%02x (last 0x%02x)", ErrInvalid, tag, last)
		}
		seen[tag] = struct{}{}
		last = tag
		val := make([]byte, ln)
		copy(val, b[i:i+int(ln)])
		fields = append(fields, Field{ID: tag, Value: val})
		i += int(ln)
		if len(fields) > maxFieldCount {
			return nil, fmt.Errorf("%w: too many fields", ErrInvalid)
		}
	}
	return fields, nil
}

// SealContext binds a TPM-sealed object to its one intended role and identity.
type SealContext struct {
	Purpose        string
	ObjectID       string
	NodeID         string
	StorageName    string
	BaselineDigest []byte
	PolicyDigest   []byte
}

// Canonical returns the canonical TLV encoding of the sealed-object context.
func (c SealContext) Canonical() ([]byte, error) {
	fields := []Field{
		{ID: FieldPurpose, Value: []byte(c.Purpose)},
		{ID: FieldObjectID, Value: []byte(c.ObjectID)},
		{ID: FieldNodeID, Value: []byte(c.NodeID)},
		{ID: FieldStorageName, Value: []byte(c.StorageName)},
		{ID: FieldBaselineDig, Value: c.BaselineDigest},
		{ID: FieldPolicyDig, Value: c.PolicyDigest},
	}
	return Encode(fields)
}
