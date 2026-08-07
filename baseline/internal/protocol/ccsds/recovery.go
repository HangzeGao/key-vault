package ccsds

import (
	"encoding/binary"
	"fmt"

	"github.com/kvlt/key-vault/internal/crypto/suite"
)

const (
	RootRecoveryFormatVersion = 1
	rootRecoveryFixedLength   = 23
)

// RootRecoveryCommand is the only plaintext accepted by a recovery SPI. It is
// deliberately an exact transaction rather than a generic command envelope.
type RootRecoveryCommand struct {
	TransactionID              uint64
	ExpectedCurrentRootVersion uint32
	NewRootVersion             uint32
	ActivationEpoch            uint32
	OrdinarySuiteID            suite.ID
	NewOperationalRoot         []byte
}

func (command RootRecoveryCommand) Validate() error {
	if command.TransactionID == 0 || command.ExpectedCurrentRootVersion == 0 ||
		command.NewRootVersion <= command.ExpectedCurrentRootVersion || command.ActivationEpoch == 0 {
		return fmt.Errorf("%w: invalid recovery transaction versions or identifier", ErrFrameInvalid)
	}
	if command.OrdinarySuiteID != suite.AES256CTR && command.OrdinarySuiteID != suite.SM4CTR {
		return fmt.Errorf("%w: recovery transaction requires an ordinary CTR suite", ErrFrameInvalid)
	}
	if len(command.NewOperationalRoot) != command.OrdinarySuiteID.KeyBytes() {
		return fmt.Errorf("%w: operational root length does not match ordinary suite", ErrFrameInvalid)
	}
	return nil
}

func (command RootRecoveryCommand) MarshalBinary() ([]byte, error) {
	if err := command.Validate(); err != nil {
		return nil, err
	}
	out := make([]byte, rootRecoveryFixedLength+len(command.NewOperationalRoot))
	out[0] = RootRecoveryFormatVersion
	binary.BigEndian.PutUint64(out[1:9], command.TransactionID)
	binary.BigEndian.PutUint32(out[9:13], command.ExpectedCurrentRootVersion)
	binary.BigEndian.PutUint32(out[13:17], command.NewRootVersion)
	binary.BigEndian.PutUint32(out[17:21], command.ActivationEpoch)
	binary.BigEndian.PutUint16(out[21:23], uint16(command.OrdinarySuiteID))
	copy(out[23:], command.NewOperationalRoot)
	return out, nil
}

func ParseRootRecoveryCommand(raw []byte) (RootRecoveryCommand, error) {
	var command RootRecoveryCommand
	if len(raw) != rootRecoveryFixedLength+suite.AES256CTR.KeyBytes() &&
		len(raw) != rootRecoveryFixedLength+suite.SM4CTR.KeyBytes() {
		return command, fmt.Errorf("%w: recovery transaction length must be 39 or 55 bytes", ErrFrameInvalid)
	}
	if raw[0] != RootRecoveryFormatVersion {
		return command, fmt.Errorf("%w: unsupported recovery transaction version", ErrFrameInvalid)
	}
	command.TransactionID = binary.BigEndian.Uint64(raw[1:9])
	command.ExpectedCurrentRootVersion = binary.BigEndian.Uint32(raw[9:13])
	command.NewRootVersion = binary.BigEndian.Uint32(raw[13:17])
	command.ActivationEpoch = binary.BigEndian.Uint32(raw[17:21])
	command.OrdinarySuiteID = suite.ID(binary.BigEndian.Uint16(raw[21:23]))
	command.NewOperationalRoot = append([]byte(nil), raw[23:]...)
	if err := command.Validate(); err != nil {
		return RootRecoveryCommand{}, err
	}
	return command, nil
}

func tcRecoveryNonce(prefix []byte, spi uint16, counter uint32) []byte {
	nonce := make([]byte, 12)
	copy(nonce[:TCNoncePrefixLength], prefix)
	binary.BigEndian.PutUint16(nonce[6:8], spi)
	binary.BigEndian.PutUint32(nonce[8:12], counter)
	return nonce
}
