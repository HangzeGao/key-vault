package hmacsign

import "crypto/rand"

// readRandom is a small indirection so tests can replace the RNG.
var readRandom = func(b []byte) (int, error) {
	return rand.Read(b)
}
