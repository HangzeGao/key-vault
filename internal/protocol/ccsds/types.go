// Package ccsds implements the CCSDS link-security protocol module above the
// protocol-neutral protection core. The generic key and crypto packages do not
// import this package.
package ccsds

import (
	"errors"
	"fmt"

	"github.com/kvlt/key-vault/internal/crypto/suite"
)

type Direction string

const (
	DirectionTCTx         Direction = "TC_TX"
	DirectionTCRecoveryTx Direction = "TC_RECOVERY_TX"
)

// NextSPI returns the successor in the complete 16-bit SPI space. SPI is an
// association selector, not a monotonic replay counter; the security epoch is
// what remains monotonic across the 0xFFFF -> 0x0000 boundary.
func NextSPI(spi uint16) uint16 {
	return spi + 1
}

type AssociationState string

const (
	AssociationCurrent  AssociationState = "CURRENT"
	AssociationNext     AssociationState = "NEXT"
	AssociationActive   AssociationState = "ACTIVE"
	AssociationDisabled AssociationState = "DISABLED"
)

var (
	ErrAssociationNotFound = errors.New("ccsds: security association not found")
	ErrAssociationState    = errors.New("ccsds: security association state forbids operation")
	ErrFrameInvalid        = errors.New("ccsds: invalid transfer frame")
	ErrCounterExhausted    = errors.New("ccsds: TC IV counter exhausted")
)

const (
	TCPrimaryHeaderLength  = 5
	TCSecurityHeaderLength = 6
	TCFECFLength           = 2
	TCMaxFrameLength       = 1024
	TCIVCounterLength      = 4
	TCNoncePrefixLength    = 6
	TCRecoveryTagLength    = 16
	TCRecoveryAADLength    = TCPrimaryHeaderLength + TCSecurityHeaderLength
)

// ManagedParameters are direction-specific TC mission wire parameters.
type ManagedParameters struct {
	SequenceNumberLength int
	TransmittedIVLength  int
	TagLength            int
	ReplayWindow         uint8
	NoncePrefix          []byte
}

// SecurityAssociation binds one direction and SPI to one immutable key and
// policy decision. Key rotation stages a new association/binding rather than
// silently changing the interpretation of historical frames.
type SecurityAssociation struct {
	ID            string
	TenantID      string
	SPI           uint16
	Direction     Direction
	KeyID         string
	KeyVersion    uint32
	SecurityEpoch uint32
	PolicyVersion uint32
	SuiteID       string
	State         AssociationState
	Parameters    ManagedParameters
}

func (sa SecurityAssociation) Validate() error {
	if sa.ID == "" || sa.TenantID == "" || sa.KeyID == "" || sa.KeyVersion == 0 || sa.PolicyVersion == 0 {
		return fmt.Errorf("%w: incomplete security association", ErrFrameInvalid)
	}
	if sa.Direction != DirectionTCTx && sa.Direction != DirectionTCRecoveryTx {
		return fmt.Errorf("%w: unsupported direction %q", ErrFrameInvalid, sa.Direction)
	}
	if sa.Direction == DirectionTCTx {
		if sa.SecurityEpoch == 0 {
			return fmt.Errorf("%w: TC security epoch is required", ErrFrameInvalid)
		}
		if sa.State != AssociationCurrent && sa.State != AssociationNext && sa.State != AssociationDisabled {
			return fmt.Errorf("%w: TC association state must be CURRENT, NEXT, or DISABLED", ErrFrameInvalid)
		}
	} else if sa.State != AssociationActive && sa.State != AssociationDisabled {
		return fmt.Errorf("%w: recovery association state must be ACTIVE or DISABLED", ErrFrameInvalid)
	}
	if sa.Direction != DirectionTCTx && sa.SecurityEpoch != 0 {
		return fmt.Errorf("%w: security epoch is only valid for ordinary TC", ErrFrameInvalid)
	}
	suiteID, err := suite.Parse(sa.SuiteID)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrFrameInvalid, err)
	}
	p := sa.Parameters
	if sa.Direction == DirectionTCTx {
		if suiteID != suite.SM4HCTR {
			return fmt.Errorf("%w: TC transmit profile requires SM4_HCTR", ErrFrameInvalid)
		}
		if p.SequenceNumberLength != 0 || p.TransmittedIVLength != TCIVCounterLength || p.TagLength != 0 || p.ReplayWindow != 0 {
			return fmt.Errorf("%w: TC transmit parameters must be sequence=0, IV=4, tag=0, replay=0", ErrFrameInvalid)
		}
		if len(p.NoncePrefix) != TCNoncePrefixLength {
			return fmt.Errorf("%w: TC nonce prefix must be 6 bytes", ErrFrameInvalid)
		}
		return nil
	}
	if sa.Direction == DirectionTCRecoveryTx {
		if suiteID != suite.SM4GCM {
			return fmt.Errorf("%w: TC recovery profile requires SM4_GCM", ErrFrameInvalid)
		}
		if p.SequenceNumberLength != 0 || p.TransmittedIVLength != TCIVCounterLength || p.TagLength != TCRecoveryTagLength || p.ReplayWindow != 0 {
			return fmt.Errorf("%w: TC recovery parameters must be sequence=0, IV=4, tag=16, replay=0", ErrFrameInvalid)
		}
		if len(p.NoncePrefix) != TCNoncePrefixLength {
			return fmt.Errorf("%w: TC recovery nonce prefix must be 6 bytes", ErrFrameInvalid)
		}
		return nil
	}
	return fmt.Errorf("%w: unsupported direction", ErrFrameInvalid)
}

type OperationMetadata struct {
	AssociationID string
	SPI           uint16
	Counter       uint64
	KeyID         string
	KeyVersion    uint32
	PolicyVersion uint32
	SuiteID       string
	ServiceType   suite.ServiceType
}

type ProtectedTCFrame struct {
	Frame    []byte
	Metadata OperationMetadata
}

type Options struct {
	MaxFrameLength int
	NodeID         string
	TCSpacecraftID uint16
}

func (o Options) validate() error {
	if o.MaxFrameLength <= 0 || o.NodeID == "" {
		return errors.New("ccsds: max frame length and node ID are required")
	}
	return nil
}
