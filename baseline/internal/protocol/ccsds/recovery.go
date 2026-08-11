package ccsds

import (
	"encoding/binary"
	"fmt"

	"github.com/kvlt/key-vault/internal/crypto/suite"
)

const (
	RootPrepareFormatVersion = 1
	rootPrepareFixedLength   = 25
)

// RootPrepareCommand is the only plaintext accepted by a recovery SPI. It
// installs the exact root and epoch used by the next ordinary SPI; activation
// occurs automatically on the first accepted frame under that SPI.
type RootPrepareCommand struct {
	TransactionID              uint64
	ExpectedCurrentRootVersion uint32
	NewRootVersion             uint32
	NextSecurityEpoch          uint32
	NextSPI                    uint16
	OrdinarySuiteID            suite.ID
	NewOperationalRoot         []byte
}

func (command RootPrepareCommand) Validate() error {
	if command.TransactionID == 0 || command.ExpectedCurrentRootVersion == 0 ||
		command.NewRootVersion <= command.ExpectedCurrentRootVersion || command.NextSecurityEpoch == 0 {
		return fmt.Errorf("%w: invalid recovery transaction versions or identifier", ErrFrameInvalid)
	}
	if command.OrdinarySuiteID != suite.SM4HCTR {
		return fmt.Errorf("%w: recovery transaction requires SM4_HCTR", ErrFrameInvalid)
	}
	if len(command.NewOperationalRoot) != command.OrdinarySuiteID.KeyBytes() {
		return fmt.Errorf("%w: operational root length does not match ordinary suite", ErrFrameInvalid)
	}
	return nil
}

func (command RootPrepareCommand) MarshalBinary() ([]byte, error) {
	if err := command.Validate(); err != nil {
		return nil, err
	}
	out := make([]byte, rootPrepareFixedLength+len(command.NewOperationalRoot))
	out[0] = RootPrepareFormatVersion
	binary.BigEndian.PutUint64(out[1:9], command.TransactionID)
	binary.BigEndian.PutUint32(out[9:13], command.ExpectedCurrentRootVersion)
	binary.BigEndian.PutUint32(out[13:17], command.NewRootVersion)
	binary.BigEndian.PutUint32(out[17:21], command.NextSecurityEpoch)
	binary.BigEndian.PutUint16(out[21:23], command.NextSPI)
	binary.BigEndian.PutUint16(out[23:25], uint16(command.OrdinarySuiteID))
	copy(out[25:], command.NewOperationalRoot)
	return out, nil
}

func ParseRootPrepareCommand(raw []byte) (RootPrepareCommand, error) {
	var command RootPrepareCommand
	if len(raw) != rootPrepareFixedLength+suite.SM4HCTR.KeyBytes() {
		return command, fmt.Errorf("%w: root prepare transaction length must be 41 bytes", ErrFrameInvalid)
	}
	if raw[0] != RootPrepareFormatVersion {
		return command, fmt.Errorf("%w: unsupported recovery transaction version", ErrFrameInvalid)
	}
	command.TransactionID = binary.BigEndian.Uint64(raw[1:9])
	command.ExpectedCurrentRootVersion = binary.BigEndian.Uint32(raw[9:13])
	command.NewRootVersion = binary.BigEndian.Uint32(raw[13:17])
	command.NextSecurityEpoch = binary.BigEndian.Uint32(raw[17:21])
	command.NextSPI = binary.BigEndian.Uint16(raw[21:23])
	command.OrdinarySuiteID = suite.ID(binary.BigEndian.Uint16(raw[23:25]))
	command.NewOperationalRoot = append([]byte(nil), raw[25:]...)
	if err := command.Validate(); err != nil {
		return RootPrepareCommand{}, err
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
