// Package confirmation authenticates a single maintenance exchange using the
// committed Current and Recovery roots. The caller owns the fresh local
// challenge and consumes the exchange before acting on its result.
package confirmation

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"

	"github.com/kvlt/key-vault/internal/crypto/kdf"
	"github.com/kvlt/key-vault/internal/crypto/mac"
	"github.com/kvlt/key-vault/internal/crypto/suite"
)

const TranscriptSize = 192

type Transcript struct {
	Transaction, Profile, Ground, Flight, GroundChallenge, FlightChallenge [32]byte
}

type Proof [32]byte // Current tag followed by Recovery tag

var ErrConfirmation = errors.New("commissioning: key confirmation rejected")

// NewChallenge creates a challenge for the local maintenance exchange.
func NewChallenge() [32]byte {
	var challenge [32]byte
	_, _ = rand.Read(challenge[:])
	return challenge
}

func (t Transcript) MarshalBinary() ([]byte, error) {
	if t.Ground == t.Flight || t.GroundChallenge == t.FlightChallenge {
		return nil, ErrConfirmation
	}
	encoded := make([]byte, 0, TranscriptSize)
	for _, field := range [...][32]byte{t.Transaction, t.Profile, t.Ground, t.Flight, t.GroundChallenge, t.FlightChallenge} {
		if field == ([32]byte{}) {
			return nil, ErrConfirmation
		}
		encoded = append(encoded, field[:]...)
	}
	return encoded, nil
}

const groundDirection byte = 1
const flightDirection byte = 2

func makeProof(encoded []byte, direction byte, current, recovery []byte) (Proof, error) {
	var proof Proof
	if len(current) != 16 || len(recovery) != 16 || subtle.ConstantTimeCompare(current, recovery) == 1 {
		return proof, ErrConfirmation
	}
	context := append([]byte{0}, encoded...)
	message := append([]byte("TC-CONFIRM-MAC-V1\x00"), direction)
	message = append(message, context...)
	for index, root := range [...][]byte{current, recovery} {
		purpose := byte(index + 1)
		context[0] = purpose
		message[len("TC-CONFIRM-MAC-V1\x00")+1] = purpose
		key, err := kdf.CMACCounter(root, suite.SM4CMAC, []byte("TC-CONFIRM-KDF-V1"), context)
		if err != nil {
			return Proof{}, ErrConfirmation
		}
		tag, err := mac.ComputeRaw(suite.SM4CMAC, key, message)
		clear(key)
		if err != nil {
			return Proof{}, ErrConfirmation
		}
		copy(proof[16*index:], tag)
		clear(tag)
	}
	return proof, nil
}

func respond(encoded []byte, flight Proof, current, recovery []byte) (Proof, error) {
	expected, err := makeProof(encoded, flightDirection, current, recovery)
	if err != nil || subtle.ConstantTimeCompare(expected[:], flight[:]) != 1 {
		return Proof{}, ErrConfirmation
	}
	return makeProof(encoded, groundDirection, current, recovery)
}
