package ccsds

import (
	"encoding/binary"
	"fmt"

	cryptomac "github.com/kvlt/key-vault/internal/crypto/mac"
	"github.com/kvlt/key-vault/internal/crypto/suite"
)

const tcDirectionCode byte = 1

var (
	ordinaryKDFLabel = []byte("TC-TRAFFIC")
	recoveryKDFLabel = []byte("TC-RECOVERY-GCM")
)

func DeriveOrdinaryTrafficKey(root []byte, spacecraftID uint16, ordinarySuite suite.ID,
	spi uint16, securityEpoch, keyVersion uint32) ([]byte, error) {
	if ordinarySuite != suite.AES256CTR && ordinarySuite != suite.SM4CTR {
		return nil, fmt.Errorf("%w: ordinary KDF requires a CTR suite", ErrFrameInvalid)
	}
	context := make([]byte, 15)
	binary.BigEndian.PutUint16(context[0:2], spacecraftID)
	context[2] = tcDirectionCode
	binary.BigEndian.PutUint16(context[3:5], uint16(ordinarySuite))
	binary.BigEndian.PutUint16(context[5:7], spi)
	binary.BigEndian.PutUint32(context[7:11], securityEpoch)
	binary.BigEndian.PutUint32(context[11:15], keyVersion)
	return deriveCMACCounter(root, ordinarySuite, ordinaryKDFLabel, context)
}

func DeriveRecoveryGCMKey(root []byte, spacecraftID uint16, recoverySuite suite.ID,
	spi uint16, recoveryKeyVersion uint32) ([]byte, error) {
	if recoverySuite != suite.AES256GCM && recoverySuite != suite.SM4GCM {
		return nil, fmt.Errorf("%w: recovery KDF requires a GCM suite", ErrFrameInvalid)
	}
	context := make([]byte, 10)
	binary.BigEndian.PutUint16(context[0:2], spacecraftID)
	binary.BigEndian.PutUint16(context[2:4], uint16(recoverySuite))
	binary.BigEndian.PutUint16(context[4:6], spi)
	binary.BigEndian.PutUint32(context[6:10], recoveryKeyVersion)
	return deriveCMACCounter(root, recoverySuite, recoveryKDFLabel, context)
}

func deriveCMACCounter(root []byte, targetSuite suite.ID, label, context []byte) ([]byte, error) {
	if len(root) != targetSuite.KeyBytes() {
		return nil, fmt.Errorf("%w: root length does not match target suite", ErrFrameInvalid)
	}
	cmacSuite := suite.AES256CMAC
	if targetSuite == suite.SM4CTR || targetSuite == suite.SM4GCM {
		cmacSuite = suite.SM4CMAC
	}
	outputLength := targetSuite.KeyBytes()
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
		if err != nil {
			return nil, err
		}
		output = append(output, block...)
	}
	return output[:outputLength], nil
}
