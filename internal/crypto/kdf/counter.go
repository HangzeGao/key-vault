package kdf

import (
	"encoding/binary"
	"errors"

	cryptomac "github.com/kvlt/key-vault/internal/crypto/mac"
	"github.com/kvlt/key-vault/internal/crypto/suite"
)

// CMACCounter implements the fixed-width counter-mode KDF used by the TC
// schedule. The caller owns domain separation through label and context.
func CMACCounter(root []byte, targetSuite suite.ID, label, context []byte) ([]byte, error) {
	if len(root) != targetSuite.KeyBytes() || len(label) == 0 || len(context) == 0 {
		return nil, errors.New("kdf: root, label, or context is invalid")
	}
	cmacSuite := suite.AES256CMAC
	descriptor, err := suite.Describe(targetSuite)
	if err != nil {
		return nil, err
	}
	if descriptor.Algorithm == "SM4" {
		cmacSuite = suite.SM4CMAC
	}
	outputLength := targetSuite.WorkingKeyBytes()
	output := make([]byte, 0, outputLength)
	for counter := uint32(1); len(output) < outputLength; counter++ {
		input := make([]byte, 0, 4+len(label)+1+len(context)+4)
		var value [4]byte
		binary.BigEndian.PutUint32(value[:], counter)
		input = append(input, value[:]...)
		input = append(input, label...)
		input = append(input, 0)
		input = append(input, context...)
		binary.BigEndian.PutUint32(value[:], uint32(outputLength*8))
		input = append(input, value[:]...)
		block, err := cryptomac.ComputeRaw(cmacSuite, root, input)
		zeroize(input)
		if err != nil {
			zeroize(output)
			return nil, err
		}
		output = append(output, block...)
		zeroize(block)
	}
	return output[:outputLength], nil
}

func zeroize(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
