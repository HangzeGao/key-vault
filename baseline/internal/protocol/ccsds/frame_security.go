package ccsds

import (
	"context"
	"encoding/binary"
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
// frame: the next ProtectTCData call uses the unique NEXT association, and the
// flight receiver converges when that first valid next-SPI frame arrives.
func (s *FrameSecurity) AdvanceTCTransmitEpoch(ctx context.Context, tenantID string) error {
	return s.store.PromoteNextTC(ctx, tenantID)
}

// ProtectTCData protects only the caller-owned TC data field. It selects the
// tenant's unique CURRENT association and owns SPI, IV, KDF, and ciphertext.
// The transport caller prepends its primary header and appends FECF.
func (s *FrameSecurity) ProtectTCData(ctx context.Context, tenantID string, data []byte) (*ProtectedTCData, error) {
	if len(data) == 0 || TCPrimaryHeaderLength+TCSecurityHeaderLength+len(data)+TCFECFLength > TCMaxFrameLength ||
		TCPrimaryHeaderLength+TCSecurityHeaderLength+len(data)+TCFECFLength > s.options.MaxFrameLength {
		return nil, ErrFrameInvalid
	}
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
	initialCounter := tcInitialCounter(sa.Parameters.NoncePrefix, sa.SPI, counter)
	result, err := s.core.ProtectDerived(ctx, protection.ProtectRequest{
		TenantID:      tenantID,
		KeyID:         sa.KeyID,
		UsageScope:    models.KeyUsageProtocol,
		KeyVersion:    sa.KeyVersion,
		PolicyVersion: sa.PolicyVersion,
		Data:          data,
		Nonce:         initialCounter,
		NodeID:        s.options.NodeID,
	}, protection.Derivation{Label: ordinaryKDFLabel,
		Context: ordinaryKDFContext(s.options.TCSpacecraftID, suiteID, sa.SPI, sa.SecurityEpoch, sa.KeyVersion)})
	if err != nil {
		return nil, err
	}
	if result.SuiteID != suiteID || result.KeyVersion != sa.KeyVersion || result.PolicyVersion != sa.PolicyVersion ||
		len(result.Tag) != 0 || !equalBytes(result.Nonce, initialCounter) {
		return nil, fmt.Errorf("%w: protection result does not match association binding", ErrFrameInvalid)
	}
	return &ProtectedTCData{Data: join(securityHeader, result.Data),
		Metadata: metadata(*sa, uint64(counter), result.ServiceType)}, nil
}

// ProtectRootPrepareData constructs the one authenticated transaction allowed
// to install the operational root for the next ordinary SPI. It returns only
// SPI||IV||ciphertext||tag and authenticates the six-byte security header.
func (s *FrameSecurity) ProtectRootPrepareData(ctx context.Context, tenantID string, command RootPrepareCommand) (*ProtectedTCData, error) {
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
	frameLength := TCPrimaryHeaderLength + TCSecurityHeaderLength + len(plaintext) + TCRecoveryTagLength + TCFECFLength
	if frameLength > TCMaxFrameLength || frameLength > s.options.MaxFrameLength {
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
	aad := append([]byte(nil), securityHeader...)
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
	if result.SuiteID != suiteID || result.ServiceType != suite.ServiceAuthEncrypt ||
		result.KeyVersion != sa.KeyVersion || result.PolicyVersion != sa.PolicyVersion ||
		len(result.Tag) != TCRecoveryTagLength || !equalBytes(result.Nonce, nonce) || len(result.Data) != len(plaintext) {
		return nil, fmt.Errorf("%w: recovery protection result does not match association binding", ErrFrameInvalid)
	}
	return &ProtectedTCData{Data: join(securityHeader, result.Data, result.Tag),
		Metadata: metadata(*sa, uint64(counter), result.ServiceType)}, nil
}

// UnprotectAOS verifies replay and authentication before releasing plaintext.
// A failed authenticator never advances the receive replay window.
func (s *FrameSecurity) UnprotectAOS(ctx context.Context, tenantID string, frame []byte) (*PlainAOSFrame, error) {
	headerLen := s.options.AOSPrimaryHeaderLength
	if len(frame) <= headerLen+2 || len(frame) > s.options.MaxFrameLength {
		return nil, ErrFrameInvalid
	}
	spi := binary.BigEndian.Uint16(frame[headerLen : headerLen+2])
	sa, err := s.store.GetAssociationBySPI(ctx, tenantID, DirectionAOSRx, spi)
	if err != nil {
		return nil, err
	}
	if err := sa.Validate(); err != nil {
		return nil, err
	}
	if sa.State != AssociationActive {
		return nil, ErrAssociationState
	}
	securityHeaderLen := 2 + sa.Parameters.SequenceNumberLength + sa.Parameters.TransmittedIVLength
	minimum := headerLen + securityHeaderLen + sa.Parameters.TagLength
	if len(frame) < minimum {
		return nil, ErrFrameInvalid
	}
	primaryHeader := append([]byte(nil), frame[:headerLen]...)
	securityHeader := append([]byte(nil), frame[headerLen:headerLen+securityHeaderLen]...)
	sequence, err := decodeSequence(securityHeader[2 : 2+sa.Parameters.SequenceNumberLength])
	if err != nil {
		return nil, err
	}
	if err := s.store.CheckReplay(ctx, sa.ID, sequence, sa.Parameters.ReplayWindow); err != nil {
		return nil, err
	}
	nonceStart := 2 + sa.Parameters.SequenceNumberLength
	nonce := append([]byte(nil), securityHeader[nonceStart:]...)
	dataEnd := len(frame) - sa.Parameters.TagLength
	data := append([]byte(nil), frame[headerLen+securityHeaderLen:dataEnd]...)
	tag := append([]byte(nil), frame[dataEnd:]...)
	suiteID, _ := suite.Parse(sa.SuiteID)
	var aad, authenticationInput []byte
	switch suiteID.ServiceType() {
	case suite.ServiceAuthOnly:
		authenticationInput = join(primaryHeader, securityHeader, data)
	case suite.ServiceAuthEncrypt:
		aad = join(primaryHeader, securityHeader)
	case suite.ServiceEncryptOnly:
	default:
		return nil, ErrFrameInvalid
	}
	result, err := s.core.Unprotect(ctx, protection.UnprotectRequest{
		TenantID: tenantID, KeyID: sa.KeyID, UsageScope: models.KeyUsageProtocol, KeyVersion: sa.KeyVersion,
		PolicyVersion: sa.PolicyVersion, Data: data, Nonce: nonce, Tag: tag,
		AAD: aad, AuthenticationInput: authenticationInput, NodeID: s.options.NodeID,
	})
	if err != nil {
		return nil, err
	}
	if result.SuiteID != suiteID || result.ServiceType != suiteID.ServiceType() {
		return nil, fmt.Errorf("%w: unprotection result does not match association binding", ErrFrameInvalid)
	}
	if err := s.store.CommitReplay(ctx, sa.ID, sequence, sa.Parameters.ReplayWindow); err != nil {
		return nil, err
	}
	return &PlainAOSFrame{
		Frame:    join(primaryHeader, result.Data),
		Metadata: metadata(*sa, sequence, result.ServiceType),
	}, nil
}

func encodeAOSSecurityHeader(spi uint16, sequence uint64, width int, nonce []byte) ([]byte, error) {
	if width < 1 || width > 8 || (width < 8 && sequence >= uint64(1)<<(uint(width)*8)) {
		return nil, ErrSequenceExhausted
	}
	out := make([]byte, 2+width+len(nonce))
	binary.BigEndian.PutUint16(out[:2], spi)
	for i := width - 1; i >= 0; i-- {
		out[2+i] = byte(sequence)
		sequence >>= 8
	}
	copy(out[2+width:], nonce)
	return out, nil
}

func decodeSequence(raw []byte) (uint64, error) {
	if len(raw) < 1 || len(raw) > 8 {
		return 0, ErrFrameInvalid
	}
	var out uint64
	for _, b := range raw {
		out = out<<8 | uint64(b)
	}
	return out, nil
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
