package keyresolver

import (
	"crypto/sha256"
	"encoding/hex"
)

// sha256Hex returns hex-encoded SHA-256 of the input.
func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
