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
	DirectionAOSRx        Direction = "AOS_RX"
)

type AssociationState string

const (
	AssociationPreinstalled AssociationState = "PREINSTALLED"
	AssociationActive       AssociationState = "ACTIVE"
	AssociationGrace        AssociationState = "GRACE"
	AssociationDisabled     AssociationState = "DISABLED"
)

var (
	ErrAssociationNotFound = errors.New("ccsds: security association not found")
	ErrAssociationState    = errors.New("ccsds: security association state forbids operation")
	ErrFrameInvalid        = errors.New("ccsds: invalid transfer frame")
	ErrReplay              = errors.New("ccsds: replay rejected")
	ErrCounterExhausted    = errors.New("ccsds: TC IV counter exhausted")
	ErrSequenceExhausted   = errors.New("ccsds: AOS sequence does not fit configured field")
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

// ManagedParameters are direction-specific mission wire parameters. TC uses a
// fixed four-byte counter plus an implicit six-byte prefix; AOS currently
// transmits its full suite IV and retains a separate replay sequence.
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
	PolicyVersion uint32
	SuiteID       string
	State         AssociationState
	Parameters    ManagedParameters
}

func (sa SecurityAssociation) Validate() error {
	if sa.ID == "" || sa.TenantID == "" || sa.KeyID == "" || sa.KeyVersion == 0 || sa.PolicyVersion == 0 {
		return fmt.Errorf("%w: incomplete security association", ErrFrameInvalid)
	}
	if sa.Direction != DirectionTCTx && sa.Direction != DirectionTCRecoveryTx && sa.Direction != DirectionAOSRx {
		return fmt.Errorf("%w: unsupported direction %q", ErrFrameInvalid, sa.Direction)
	}
	if sa.State != AssociationPreinstalled && sa.State != AssociationActive &&
		sa.State != AssociationGrace && sa.State != AssociationDisabled {
		return fmt.Errorf("%w: unsupported association state %q", ErrFrameInvalid, sa.State)
	}
	suiteID, err := suite.Parse(sa.SuiteID)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrFrameInvalid, err)
	}
	p := sa.Parameters
	if sa.Direction == DirectionTCTx {
		if suiteID != suite.AES256CTR && suiteID != suite.SM4CTR {
			return fmt.Errorf("%w: TC transmit profile requires AES_256_CTR or SM4_CTR", ErrFrameInvalid)
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
		if suiteID != suite.AES256GCM && suiteID != suite.SM4GCM {
			return fmt.Errorf("%w: TC recovery profile requires AES_256_GCM or SM4_GCM", ErrFrameInvalid)
		}
		if p.SequenceNumberLength != 0 || p.TransmittedIVLength != TCIVCounterLength || p.TagLength != TCRecoveryTagLength || p.ReplayWindow != 0 {
			return fmt.Errorf("%w: TC recovery parameters must be sequence=0, IV=4, tag=16, replay=0", ErrFrameInvalid)
		}
		if len(p.NoncePrefix) != TCNoncePrefixLength {
			return fmt.Errorf("%w: TC recovery nonce prefix must be 6 bytes", ErrFrameInvalid)
		}
		return nil
	}
	if p.SequenceNumberLength < 1 || p.SequenceNumberLength > 8 {
		return fmt.Errorf("%w: AOS sequence number length must be 1..8", ErrFrameInvalid)
	}
	if p.TransmittedIVLength != suiteID.NonceLen() || len(p.NoncePrefix) != 0 {
		return fmt.Errorf("%w: AOS transmits the full suite IV and has no implicit prefix", ErrFrameInvalid)
	}
	if p.TagLength != suiteID.TagLen() {
		return fmt.Errorf("%w: AOS tag length does not match suite", ErrFrameInvalid)
	}
	if p.ReplayWindow == 0 || p.ReplayWindow > 64 {
		return fmt.Errorf("%w: AOS replay window must be 1..64", ErrFrameInvalid)
	}
	return nil
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

type PlainAOSFrame struct {
	Frame    []byte
	Metadata OperationMetadata
}

type Options struct {
	AOSPrimaryHeaderLength int
	MaxFrameLength         int
	NodeID                 string
}

func (o Options) validate() error {
	if o.AOSPrimaryHeaderLength <= 0 || o.MaxFrameLength <= 0 || o.NodeID == "" {
		return errors.New("ccsds: AOS primary header length, max frame length, and node ID are required")
	}
	return nil
}
