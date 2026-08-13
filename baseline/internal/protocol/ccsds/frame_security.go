package ccsds

import (
	"context"
	"errors"
	"fmt"

	"github.com/kvlt/key-vault/internal/application/protection"
	"github.com/kvlt/key-vault/internal/crypto/suite"
	"github.com/kvlt/key-vault/internal/repository/models"
)

// ProtectionCore is the only cryptographic seam visible to the CCSDS module.
// It returns raw protection fields and owns key leases. The protocol module
// supplies its canonical nonce/counter bytes explicitly.
type ProtectionCore interface {
	ProtectDerived(ctx context.Context, req protection.ProtectRequest, derivation protection.Derivation) (*protection.ProtectResult, error)
	Unprotect(ctx context.Context, req protection.UnprotectRequest) (*protection.UnprotectResult, error)
}

// FrameSecurity is the concrete CCSDS deep module. It intentionally does not
// implement a generic protocol registry or dynamic plugin contract.
type FrameSecurity struct {
	core    ProtectionCore
	store   Store
	options Options
}

func New(core ProtectionCore, store Store, options Options) (*FrameSecurity, error) {
	if core == nil || store == nil {
		return nil, errors.New("ccsds: protection core and store are required")
	}
	if err := options.validate(); err != nil {
		return nil, err
	}
	return &FrameSecurity{core: core, store: store, options: options}, nil
}

// AdvanceTCTransmitEpoch is a ground-local state change. It emits no management
// frame: the next ProtectTCFrame call uses the unique NEXT association, and the
// flight receiver converges when that first valid next-SPI frame arrives.
func (s *FrameSecurity) AdvanceTCTransmitEpoch(ctx context.Context, tenantID string) error {
	return s.store.PromoteNextTC(ctx, tenantID)
}

// ProtectTCFrame transforms one complete plaintext TC transfer frame into the
// complete protected frame accepted by flight. It validates the caller's frame
// and FECF before allocating an IV, then owns security-header insertion, frame
// length rewriting, and the new FECF.
func (s *FrameSecurity) ProtectTCFrame(ctx context.Context, tenantID string, frame []byte) (*ProtectedTCFrame, error) {
	primaryHeader, data, err := splitPlainTCFrame(frame, s.options.MaxFrameLength)
	if err != nil {
		return nil, err
	}
	defer zeroizeBytes(data)
	sa, err := s.store.GetTransmitAssociation(ctx, tenantID, DirectionTCTx)
	if err != nil {
		return nil, err
	}
	if err := sa.Validate(); err != nil {
		return nil, err
	}
	if sa.Direction != DirectionTCTx || sa.State != AssociationCurrent {
		return nil, ErrAssociationState
	}
	counter, err := s.store.NextTransmitCounter(ctx, sa.ID)
	if err != nil {
		return nil, err
	}
	suiteID, _ := suite.Parse(sa.SuiteID)
	securityHeader := encodeTCSecurityHeader(sa.SPI, counter)
	tweak := tcHCTRTweak(sa.Parameters.NoncePrefix, sa.SPI, counter)
	result, err := s.core.ProtectDerived(ctx, protection.ProtectRequest{
		TenantID:      tenantID,
		KeyID:         sa.KeyID,
		UsageScope:    models.KeyUsageProtocol,
		KeyVersion:    sa.KeyVersion,
		PolicyVersion: sa.PolicyVersion,
		Data:          data,
		Nonce:         tweak,
		NodeID:        s.options.NodeID,
	}, protection.Derivation{Label: ordinaryKDFLabel,
		Context: ordinaryKDFContext(s.options.TCSpacecraftID, suiteID, sa.SPI, sa.SecurityEpoch, sa.KeyVersion)})
	if err != nil {
		return nil, err
	}
	if result == nil || result.SuiteID != suiteID || result.ServiceType != suite.ServiceEncryptOnly ||
		result.KeyVersion != sa.KeyVersion || result.PolicyVersion != sa.PolicyVersion ||
		len(result.Data) != len(data) || len(result.Tag) != 0 || !equalBytes(result.Nonce, tweak) {
		return nil, fmt.Errorf("%w: protection result does not match association binding", ErrFrameInvalid)
	}
	protectedFrame, err := assembleTCFrame(primaryHeader, join(securityHeader, result.Data), s.options.MaxFrameLength)
	if err != nil {
		return nil, err
	}
	if err := s.store.MarkTCRotationFrameProduced(ctx, tenantID, sa.ID); err != nil {
		return nil, err
	}
	return &ProtectedTCFrame{Frame: protectedFrame,
		Metadata: metadata(*sa, uint64(counter), result.ServiceType)}, nil
}

// ProtectRootPrepareFrame constructs the one authenticated transaction allowed
// to install the operational root for the next ordinary SPI. It returns a
// complete TC frame and authenticates its final primary and security headers.
func (s *FrameSecurity) ProtectRootPrepareFrame(ctx context.Context, tenantID string, primaryHeader []byte,
	command RootPrepareCommand) (*ProtectedTCFrame, error) {
	if len(primaryHeader) != TCPrimaryHeaderLength {
		return nil, ErrFrameInvalid
	}
	plaintext, err := command.MarshalBinary()
	if err != nil {
		return nil, err
	}
	defer zeroizeBytes(plaintext)
	current, err := s.store.GetTransmitAssociation(ctx, tenantID, DirectionTCTx)
	if err != nil {
		return nil, err
	}
	next, err := s.store.GetAssociationBySPI(ctx, tenantID, DirectionTCTx, command.NextSPI)
	if err != nil {
		return nil, err
	}
	if current.State != AssociationCurrent || next.State != AssociationNext ||
		command.ExpectedCurrentRootVersion != current.KeyVersion || command.NewRootVersion != next.KeyVersion ||
		command.NextSecurityEpoch != next.SecurityEpoch || command.NextSPI != NextSPI(current.SPI) ||
		command.OrdinarySuiteID.String() != next.SuiteID ||
		!equalBytes(current.Parameters.NoncePrefix, next.Parameters.NoncePrefix) {
		return nil, ErrAssociationState
	}
	finalPrimaryHeader, err := prepareTCPrimaryHeader(primaryHeader,
		TCSecurityHeaderLength+len(plaintext)+TCRecoveryTagLength, s.options.MaxFrameLength)
	if err != nil {
		return nil, ErrFrameInvalid
	}
	sa, err := s.store.GetTransmitAssociation(ctx, tenantID, DirectionTCRecoveryTx)
	if err != nil {
		return nil, err
	}
	if err := sa.Validate(); err != nil {
		return nil, err
	}
	if sa.Direction != DirectionTCRecoveryTx || sa.State != AssociationActive {
		return nil, ErrAssociationState
	}
	counter, err := s.store.NextTransmitCounter(ctx, sa.ID)
	if err != nil {
		return nil, err
	}
	securityHeader := encodeTCSecurityHeader(sa.SPI, counter)
	nonce := tcRecoveryNonce(sa.Parameters.NoncePrefix, sa.SPI, counter)
	aad := join(finalPrimaryHeader, securityHeader)
	suiteID, _ := suite.Parse(sa.SuiteID)
	result, err := s.core.ProtectDerived(ctx, protection.ProtectRequest{
		TenantID: tenantID, KeyID: sa.KeyID, UsageScope: models.KeyUsageProtocol,
		KeyVersion: sa.KeyVersion, PolicyVersion: sa.PolicyVersion,
		Data: plaintext, Nonce: nonce, AAD: aad, NodeID: s.options.NodeID,
	}, protection.Derivation{Label: recoveryKDFLabel,
		Context: recoveryKDFContext(s.options.TCSpacecraftID, suiteID, sa.SPI, sa.KeyVersion)})
	if err != nil {
		return nil, err
	}
	if result == nil || result.SuiteID != suiteID || result.ServiceType != suite.ServiceAuthEncrypt ||
		result.KeyVersion != sa.KeyVersion || result.PolicyVersion != sa.PolicyVersion ||
		len(result.Tag) != TCRecoveryTagLength || !equalBytes(result.Nonce, nonce) || len(result.Data) != len(plaintext) {
		return nil, fmt.Errorf("%w: recovery protection result does not match association binding", ErrFrameInvalid)
	}
	if err := s.store.MarkTCRotationPrepared(ctx, tenantID, TCRotationState{Phase: TCRotationPrepared,
		TransactionID: command.TransactionID, CurrentSPI: current.SPI, NextSPI: next.SPI,
		CurrentRootVersion: current.KeyVersion, NextRootVersion: next.KeyVersion}); err != nil {
		return nil, err
	}
	protectedFrame := appendTCFECF(join(finalPrimaryHeader, securityHeader, result.Data, result.Tag))
	return &ProtectedTCFrame{Frame: protectedFrame,
		Metadata: metadata(*sa, uint64(counter), result.ServiceType)}, nil
}

func metadata(sa SecurityAssociation, sequence uint64, serviceType suite.ServiceType) OperationMetadata {
	return OperationMetadata{
		AssociationID: sa.ID, SPI: sa.SPI, Counter: sequence, KeyID: sa.KeyID,
		KeyVersion: sa.KeyVersion, PolicyVersion: sa.PolicyVersion,
		SuiteID: sa.SuiteID, ServiceType: serviceType,
	}
}

func equalBytes(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func zeroizeBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func join(parts ...[]byte) []byte {
	total := 0
	for _, part := range parts {
		total += len(part)
	}
	out := make([]byte, 0, total)
	for _, part := range parts {
		out = append(out, part...)
	}
	return out
}
