package ccsds

import (
	"encoding/binary"
	"fmt"

	"github.com/kvlt/key-vault/internal/crypto/kdf"
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
	context := ordinaryKDFContext(spacecraftID, ordinarySuite, spi, securityEpoch, keyVersion)
	return kdf.CMACCounter(root, ordinarySuite, ordinaryKDFLabel, context)
}

func ordinaryKDFContext(spacecraftID uint16, ordinarySuite suite.ID, spi uint16,
	securityEpoch, keyVersion uint32) []byte {
	context := make([]byte, 15)
	binary.BigEndian.PutUint16(context[0:2], spacecraftID)
	context[2] = tcDirectionCode
	binary.BigEndian.PutUint16(context[3:5], uint16(ordinarySuite))
	binary.BigEndian.PutUint16(context[5:7], spi)
	binary.BigEndian.PutUint32(context[7:11], securityEpoch)
	binary.BigEndian.PutUint32(context[11:15], keyVersion)
	return context
}

func DeriveRecoveryGCMKey(root []byte, spacecraftID uint16, recoverySuite suite.ID,
	spi uint16, recoveryKeyVersion uint32) ([]byte, error) {
	if recoverySuite != suite.AES256GCM && recoverySuite != suite.SM4GCM {
		return nil, fmt.Errorf("%w: recovery KDF requires a GCM suite", ErrFrameInvalid)
	}
	context := recoveryKDFContext(spacecraftID, recoverySuite, spi, recoveryKeyVersion)
	return kdf.CMACCounter(root, recoverySuite, recoveryKDFLabel, context)
}

func recoveryKDFContext(spacecraftID uint16, recoverySuite suite.ID, spi uint16,
	recoveryKeyVersion uint32) []byte {
	context := make([]byte, 10)
	binary.BigEndian.PutUint16(context[0:2], spacecraftID)
	binary.BigEndian.PutUint16(context[2:4], uint16(recoverySuite))
	binary.BigEndian.PutUint16(context[4:6], spi)
	binary.BigEndian.PutUint32(context[6:10], recoveryKeyVersion)
	return context
}
