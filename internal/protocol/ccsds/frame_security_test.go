package ccsds

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/kvlt/key-vault/internal/application/protection"
	"github.com/kvlt/key-vault/internal/crypto/suite"
)

type fakeCore struct {
	lastDerivation protection.Derivation
	lastAAD        []byte
	protectErr     error
	unprotectErr   error
	nilProtect     bool
	nilUnprotect   bool
	wrongBinding   bool
	mutateProtect  func(*protection.ProtectResult)
}

func (f *fakeCore) ProtectDerived(_ context.Context, req protection.ProtectRequest,
	derivation protection.Derivation) (*protection.ProtectResult, error) {
	f.lastDerivation = protection.Derivation{
		Label: append([]byte(nil), derivation.Label...), Context: append([]byte(nil), derivation.Context...),
	}
	f.lastAAD = append([]byte(nil), req.AAD...)
	if f.protectErr != nil {
		return nil, f.protectErr
	}
	if f.nilProtect {
		return nil, nil
	}
	result, err := f.protect(req)
	if err == nil && f.wrongBinding {
		result.SuiteID = suite.AES256GCM
	}
	if err == nil && f.mutateProtect != nil {
		f.mutateProtect(result)
	}
	return result, err
}

func (f *fakeCore) protect(req protection.ProtectRequest) (*protection.ProtectResult, error) {
	data := append([]byte(nil), req.Data...)
	for i := range data {
		data[i] ^= 0x5a
	}
	if len(req.Nonce) == 12 && len(req.AAD) == TCRecoveryAADLength && len(req.AuthenticationInput) == 0 {
		return &protection.ProtectResult{
			Data: data, Nonce: append([]byte(nil), req.Nonce...), Tag: bytes.Repeat([]byte{0xa5}, 16),
			KeyVersion: req.KeyVersion, PolicyVersion: req.PolicyVersion, SuiteID: suite.SM4GCM,
			ServiceType: suite.ServiceAuthEncrypt,
		}, nil
	}
	if len(req.Nonce) != 16 || len(req.AAD) != 0 || len(req.AuthenticationInput) != 0 {
		return nil, errors.New("invalid TC protection context")
	}
	return &protection.ProtectResult{
		Data: data, Nonce: append([]byte(nil), req.Nonce...),
		KeyVersion: req.KeyVersion, PolicyVersion: req.PolicyVersion, SuiteID: suite.SM4HCTR,
		ServiceType: suite.ServiceEncryptOnly,
	}, nil
}

func (f *fakeCore) Unprotect(_ context.Context, req protection.UnprotectRequest) (*protection.UnprotectResult, error) {
	if f.unprotectErr != nil {
		return nil, f.unprotectErr
	}
	if f.nilUnprotect {
		return nil, nil
	}
	if !bytes.Equal(req.Tag, bytes.Repeat([]byte{0xa5}, 16)) || len(req.AAD) == 0 {
		return nil, errors.New("authentication failed")
	}
	data := append([]byte(nil), req.Data...)
	for i := range data {
		data[i] ^= 0x5a
	}
	result := &protection.UnprotectResult{Data: data, SuiteID: suite.AES256GCM, ServiceType: suite.ServiceAuthEncrypt}
	if f.wrongBinding {
		result.SuiteID = suite.SM4GCM
	}
	return result, nil
}

func recoveryAssociation() SecurityAssociation {
	return SecurityAssociation{
		ID: "recovery", TenantID: "tenant-1", SPI: 0x7001, Direction: DirectionTCRecoveryTx,
		KeyID: "key-recovery", KeyVersion: 3, PolicyVersion: 1,
		SuiteID: suite.SM4GCM.String(), State: AssociationActive,
		Parameters: ManagedParameters{TransmittedIVLength: TCIVCounterLength, TagLength: TCRecoveryTagLength,
			NoncePrefix: []byte{0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5}},
	}
}

func tcAssociation() SecurityAssociation {
	return SecurityAssociation{
		ID: "tx-current", TenantID: "tenant-1", SPI: 0x1001, Direction: DirectionTCTx,
		KeyID: "operational-root", KeyVersion: 7, SecurityEpoch: 9, PolicyVersion: 1,
		SuiteID: suite.SM4HCTR.String(), State: AssociationCurrent,
		Parameters: ManagedParameters{TransmittedIVLength: TCIVCounterLength,
			NoncePrefix: []byte{0x10, 0x20, 0x30, 0x40, 0x50, 0x60}},
	}
}

func nextTCAssociation() SecurityAssociation {
	sa := tcAssociation()
	sa.ID = "tx-next"
	sa.SPI++
	sa.SecurityEpoch++
	sa.KeyVersion++
	sa.State = AssociationNext
	return sa
}

func prepareTestRotation(t *testing.T, store Store, current, next SecurityAssociation) {
	t.Helper()
	err := store.MarkTCRotationPrepared(context.Background(), current.TenantID, TCRotationState{
		Phase: TCRotationPrepared, TransactionID: 1, CurrentSPI: current.SPI, NextSPI: next.SPI,
		CurrentRootVersion: current.KeyVersion, NextRootVersion: next.KeyVersion,
	})
	if err != nil {
		t.Fatal(err)
	}
}

func newTestSecurity(t *testing.T, core ProtectionCore, associations ...SecurityAssociation) (*FrameSecurity, *MemoryStore) {
	t.Helper()
	store, err := NewMemoryStore(associations...)
	if err != nil {
		t.Fatal(err)
	}
	digest := [32]byte{1}
	if err := store.BindMissionProfile("tenant-1", digest); err != nil {
		t.Fatal(err)
	}
	if len(associations) != 0 {
		status := FlightSecurityStatus{FormatVersion: FlightSecurityStatusVersion, ProfileDigest: digest,
			SelfTest: FlightSelfTestPassed, CryptoBackend: FlightBackendSoftware,
			CurrentSPI: tcAssociation().SPI, NextSPI: nextTCAssociation().SPI, RecoverySPI: recoveryAssociation().SPI,
			SecurityEpoch: tcAssociation().SecurityEpoch, RootVersion: tcAssociation().KeyVersion}
		if err := store.ObserveFlightSecurityStatus(context.Background(), "tenant-1", status); err != nil {
			t.Fatal(err)
		}
	}
	security, err := New(core, store, Options{MaxFrameLength: 2048, NodeID: "node-1", TCSpacecraftID: 0x1234})
	if err != nil {
		t.Fatal(err)
	}
	return security, store
}

func plainTCFrame(t *testing.T, data []byte) []byte {
	t.Helper()
	frame, err := assembleTCFrame([]byte{0x20, 0x01, 0, 0, 0x07}, data, TCMaxFrameLength)
	if err != nil {
		t.Fatal(err)
	}
	return frame
}

func TestProtectTCFrameOwnsFramingAndSelectsCurrent(t *testing.T) {
	core := &fakeCore{}
	security, _ := newTestSecurity(t, core, nextTCAssociation(), tcAssociation())
	plain := []byte("command-16-bytes")
	clearFrame := plainTCFrame(t, plain)
	protected, err := security.ProtectTCFrame(context.Background(), "tenant-1", clearFrame)
	if err != nil {
		t.Fatal(err)
	}
	if protected.Metadata.AssociationID != "tx-current" || protected.Metadata.Counter != 0 ||
		len(protected.Frame) != len(clearFrame)+TCSecurityHeaderLength {
		t.Fatalf("unexpected TC result: metadata=%+v len=%d", protected.Metadata, len(protected.Frame))
	}
	if validateTCFrame(protected.Frame) != nil ||
		!bytes.Equal(protected.Frame[TCPrimaryHeaderLength:TCPrimaryHeaderLength+TCSecurityHeaderLength],
			[]byte{0x10, 0x01, 0, 0, 0, 0}) {
		t.Fatalf("protected frame = %x", protected.Frame)
	}
	if bytes.Equal(protected.Frame[TCPrimaryHeaderLength+TCSecurityHeaderLength:len(protected.Frame)-TCFECFLength], plain) {
		t.Fatal("TC data field was not encrypted")
	}
	if !bytes.Equal(core.lastDerivation.Label, ordinaryKDFLabel) || len(core.lastDerivation.Context) != 15 {
		t.Fatalf("ordinary KDF binding = %x/%x", core.lastDerivation.Label, core.lastDerivation.Context)
	}
}

func TestAdvanceTCTransmitEpochIsLocalAndAtomic(t *testing.T) {
	current, next := tcAssociation(), nextTCAssociation()
	security, store := newTestSecurity(t, &fakeCore{}, current, next)
	prepareTestRotation(t, store, current, next)
	if err := security.AdvanceTCTransmitEpoch(context.Background(), "tenant-1"); err != nil {
		t.Fatal(err)
	}
	protected, err := security.ProtectTCFrame(context.Background(), "tenant-1", plainTCFrame(t, make([]byte, 16)))
	if err != nil {
		t.Fatal(err)
	}
	if protected.Metadata.AssociationID != "tx-next" || protected.Metadata.SPI != 0x1002 {
		t.Fatalf("post-promotion association = %+v", protected.Metadata)
	}
	old, _ := store.GetAssociation(context.Background(), "tenant-1", "tx-current")
	if old.State != AssociationDisabled {
		t.Fatalf("old state = %s", old.State)
	}
	if err := security.AdvanceTCTransmitEpoch(context.Background(), "tenant-1"); !errors.Is(err, ErrAssociationState) {
		t.Fatalf("promotion without NEXT = %v", err)
	}
}

func TestAdvanceTCTransmitEpochRejectsNonAdjacentWireState(t *testing.T) {
	current := tcAssociation()
	next := nextTCAssociation()
	next.SPI++
	security, _ := newTestSecurity(t, &fakeCore{}, current, next)
	if err := security.AdvanceTCTransmitEpoch(context.Background(), "tenant-1"); !errors.Is(err, ErrAssociationState) {
		t.Fatalf("non-adjacent SPI promotion error = %v", err)
	}
}

func TestAdvanceTCTransmitEpochWrapsCompleteSPISpace(t *testing.T) {
	current := tcAssociation()
	current.SPI = 0xffff
	next := nextTCAssociation()
	next.SPI = 0x0000
	security, store := newTestSecurity(t, &fakeCore{}, current, next)
	prepareTestRotation(t, store, current, next)
	if err := security.AdvanceTCTransmitEpoch(context.Background(), "tenant-1"); err != nil {
		t.Fatalf("0xFFFF -> 0x0000 promotion failed: %v", err)
	}
	protected, err := security.ProtectTCFrame(context.Background(), "tenant-1", plainTCFrame(t, make([]byte, 16)))
	if err != nil {
		t.Fatal(err)
	}
	if protected.Metadata.SPI != 0x0000 {
		t.Fatalf("promoted SPI = 0x%04X", protected.Metadata.SPI)
	}
}

func TestProtectRootPrepareFrameOwnsFramingAndAuthenticatesBothHeaders(t *testing.T) {
	core := &fakeCore{}
	current := tcAssociation()
	next := nextTCAssociation()
	next.KeyVersion = 8
	security, _ := newTestSecurity(t, core, recoveryAssociation(), current, next)
	command := RootPrepareCommand{
		TransactionID: 9, ExpectedCurrentRootVersion: 7, NewRootVersion: 8,
		NextSecurityEpoch: 10, NextSPI: 0x1002, OrdinarySuiteID: suite.SM4HCTR,
		NewOperationalRoot: bytes.Repeat([]byte{0x44}, 16),
	}
	protected, err := security.ProtectRootPrepareFrame(context.Background(), "tenant-1",
		[]byte{0x20, 0x01, 0, 0, 0x01}, command)
	if err != nil {
		t.Fatal(err)
	}
	wantLength := TCPrimaryHeaderLength + TCSecurityHeaderLength + rootPrepareFixedLength + 16 + TCRecoveryTagLength + TCFECFLength
	if len(protected.Frame) != wantLength || protected.Metadata.ServiceType != suite.ServiceAuthEncrypt ||
		validateTCFrame(protected.Frame) != nil {
		t.Fatalf("unexpected recovery result: len=%d metadata=%+v", len(protected.Frame), protected.Metadata)
	}
	securityStart := TCPrimaryHeaderLength
	tagEnd := len(protected.Frame) - TCFECFLength
	if !bytes.Equal(protected.Frame[securityStart:securityStart+TCSecurityHeaderLength], []byte{0x70, 0x01, 0, 0, 0, 0}) ||
		!bytes.Equal(protected.Frame[tagEnd-TCRecoveryTagLength:tagEnd], bytes.Repeat([]byte{0xa5}, 16)) ||
		!bytes.Equal(core.lastAAD, protected.Frame[:TCRecoveryAADLength]) {
		t.Fatalf("invalid recovery security fields: %x", protected.Frame)
	}
	if !bytes.Equal(core.lastDerivation.Label, recoveryKDFLabel) || len(core.lastDerivation.Context) != 10 {
		t.Fatalf("recovery KDF binding = %x/%x", core.lastDerivation.Label, core.lastDerivation.Context)
	}
}

func TestRootPrepareMustMatchProvisionedCurrentAndNext(t *testing.T) {
	current := tcAssociation()
	next := nextTCAssociation()
	next.KeyVersion = 8
	security, _ := newTestSecurity(t, &fakeCore{}, recoveryAssociation(), current, next)
	command := RootPrepareCommand{TransactionID: 1, ExpectedCurrentRootVersion: 7, NewRootVersion: 8,
		NextSecurityEpoch: 10, NextSPI: 0x1002, OrdinarySuiteID: suite.SM4HCTR,
		NewOperationalRoot: bytes.Repeat([]byte{1}, 16)}
	command.NextSecurityEpoch++
	if _, err := security.ProtectRootPrepareFrame(context.Background(), "tenant-1", make([]byte, 5), command); !errors.Is(err, ErrAssociationState) {
		t.Fatalf("mismatched next epoch error = %v", err)
	}
}

func TestRootPrepareFailsClosedOnMissingStateAndExhaustedRecoveryCounter(t *testing.T) {
	command := RootPrepareCommand{TransactionID: 1, ExpectedCurrentRootVersion: 7, NewRootVersion: 8,
		NextSecurityEpoch: 10, NextSPI: 0x1002, OrdinarySuiteID: suite.SM4HCTR,
		NewOperationalRoot: bytes.Repeat([]byte{1}, 16)}
	header := []byte{0x20, 1, 0, 0, 1}
	missingCurrent, _ := newTestSecurity(t, &fakeCore{}, recoveryAssociation(), nextTCAssociation())
	if _, err := missingCurrent.ProtectRootPrepareFrame(context.Background(), "tenant-1", header, command); !errors.Is(err, ErrAssociationNotFound) {
		t.Fatalf("missing current error=%v", err)
	}
	missingNext, _ := newTestSecurity(t, &fakeCore{}, recoveryAssociation(), tcAssociation())
	if _, err := missingNext.ProtectRootPrepareFrame(context.Background(), "tenant-1", header, command); !errors.Is(err, ErrAssociationNotFound) {
		t.Fatalf("missing next error=%v", err)
	}
	current, next := tcAssociation(), nextTCAssociation()
	next.KeyVersion = 8
	missingRecovery, _ := newTestSecurity(t, &fakeCore{}, current, next)
	if _, err := missingRecovery.ProtectRootPrepareFrame(context.Background(), "tenant-1", header, command); !errors.Is(err, ErrAssociationNotFound) {
		t.Fatalf("missing recovery error=%v", err)
	}
	exhausted, store := newTestSecurity(t, &fakeCore{}, recoveryAssociation(), current, next)
	store.txNext[recoveryAssociation().ID] = uint64(1) << 32
	if _, err := exhausted.ProtectRootPrepareFrame(context.Background(), "tenant-1", header, command); !errors.Is(err, ErrCounterExhausted) {
		t.Fatalf("exhausted recovery error=%v", err)
	}
}

func TestRootPrepareTransactionIsStrict(t *testing.T) {
	command := RootPrepareCommand{TransactionID: 1, ExpectedCurrentRootVersion: 1, NewRootVersion: 2,
		NextSecurityEpoch: 3, NextSPI: 0x1002, OrdinarySuiteID: suite.SM4HCTR,
		NewOperationalRoot: bytes.Repeat([]byte{7}, 16)}
	raw, err := command.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseRootPrepareCommand(raw)
	if err != nil || parsed.TransactionID != command.TransactionID || parsed.NextSPI != command.NextSPI ||
		!bytes.Equal(parsed.NewOperationalRoot, command.NewOperationalRoot) {
		t.Fatalf("parse = %+v, err=%v", parsed, err)
	}
	if _, err := ParseRootPrepareCommand(append(raw, 0)); !errors.Is(err, ErrFrameInvalid) {
		t.Fatalf("trailing byte error = %v", err)
	}
	command.OrdinarySuiteID = suite.SM4GCM
	if _, err := command.MarshalBinary(); !errors.Is(err, ErrFrameInvalid) {
		t.Fatalf("non-CTR ordinary suite error = %v", err)
	}
}

func TestTCProfilesAndStatesAreStrict(t *testing.T) {
	sa := tcAssociation()
	if err := sa.Validate(); err != nil {
		t.Fatalf("TC profile rejected %s: %v", suite.SM4HCTR, err)
	}
	for _, suiteID := range []suite.ID{suite.AES256CTR, suite.SM4CTR, suite.AES256GCM, suite.SM4GCM, suite.AES256CMAC, suite.SM4CMAC} {
		sa := tcAssociation()
		sa.SuiteID = suiteID.String()
		if err := sa.Validate(); err == nil {
			t.Fatalf("TC profile accepted unsupported suite %s", suiteID)
		}
	}
	legacy := tcAssociation()
	legacy.State = AssociationState("GRACE")
	if err := legacy.Validate(); err == nil {
		t.Fatal("obsolete GRACE state was accepted")
	}
}

func TestRecoveryAssociationAllowsOnlyGCM(t *testing.T) {
	sa := recoveryAssociation()
	if err := sa.Validate(); err != nil {
		t.Fatalf("recovery profile rejected %s: %v", suite.SM4GCM, err)
	}
	for _, suiteID := range []suite.ID{suite.AES256GCM, suite.AES256CTR, suite.SM4HCTR} {
		sa := recoveryAssociation()
		sa.SuiteID = suiteID.String()
		if err := sa.Validate(); err == nil {
			t.Fatalf("recovery profile accepted %s", suiteID)
		}
	}
}

func TestProtectTCFrameRejectsMalformedOrOversizedInput(t *testing.T) {
	security, _ := newTestSecurity(t, &fakeCore{}, tcAssociation())
	if _, err := security.ProtectTCFrame(context.Background(), "tenant-1", nil); !errors.Is(err, ErrFrameInvalid) {
		t.Fatalf("empty data error = %v", err)
	}
	if _, err := security.ProtectTCFrame(context.Background(), "tenant-1", make([]byte, TCMaxFrameLength)); !errors.Is(err, ErrFrameInvalid) {
		t.Fatalf("oversized data error = %v", err)
	}
	badFECF := plainTCFrame(t, make([]byte, 16))
	badFECF[len(badFECF)-1] ^= 1
	if _, err := security.ProtectTCFrame(context.Background(), "tenant-1", badFECF); !errors.Is(err, ErrFrameInvalid) {
		t.Fatalf("bad clear-frame FECF error = %v", err)
	}
	protected, err := security.ProtectTCFrame(context.Background(), "tenant-1", plainTCFrame(t, make([]byte, 16)))
	if err != nil {
		t.Fatal(err)
	}
	if protected.Metadata.Counter != 0 {
		t.Fatalf("invalid clear frame consumed IV counter: %d", protected.Metadata.Counter)
	}
}

func TestFrameSecurityPropagatesCoreAndBindingFailures(t *testing.T) {
	coreFailure := errors.New("core failure")
	security, _ := newTestSecurity(t, &fakeCore{protectErr: coreFailure}, tcAssociation())
	if _, err := security.ProtectTCFrame(context.Background(), "tenant-1", plainTCFrame(t, make([]byte, 16))); !errors.Is(err, coreFailure) {
		t.Fatalf("TC core error = %v", err)
	}
	security, _ = newTestSecurity(t, &fakeCore{wrongBinding: true}, tcAssociation())
	if _, err := security.ProtectTCFrame(context.Background(), "tenant-1", plainTCFrame(t, make([]byte, 16))); !errors.Is(err, ErrFrameInvalid) {
		t.Fatalf("TC binding error = %v", err)
	}
	security, _ = newTestSecurity(t, &fakeCore{nilProtect: true}, tcAssociation())
	if _, err := security.ProtectTCFrame(context.Background(), "tenant-1", plainTCFrame(t, make([]byte, 16))); !errors.Is(err, ErrFrameInvalid) {
		t.Fatalf("nil TC result error = %v", err)
	}
	for name, mutate := range map[string]func(*protection.ProtectResult){
		"wrong service": func(result *protection.ProtectResult) { result.ServiceType = suite.ServiceAuthEncrypt },
		"wrong length":  func(result *protection.ProtectResult) { result.Data = result.Data[:len(result.Data)-1] },
	} {
		t.Run(name, func(t *testing.T) {
			security, _ := newTestSecurity(t, &fakeCore{mutateProtect: mutate}, tcAssociation())
			if _, err := security.ProtectTCFrame(context.Background(), "tenant-1", plainTCFrame(t, make([]byte, 16))); !errors.Is(err, ErrFrameInvalid) {
				t.Fatalf("TC result binding error = %v", err)
			}
		})
	}
	security, _ = newTestSecurity(t, &fakeCore{}, tcAssociation())
	if _, err := security.ProtectTCFrame(context.Background(), "missing", plainTCFrame(t, make([]byte, 16))); !errors.Is(err, ErrAssociationNotFound) {
		t.Fatalf("missing TC association = %v", err)
	}

	current := tcAssociation()
	next := nextTCAssociation()
	next.KeyVersion = 8
	command := RootPrepareCommand{
		TransactionID: 1, ExpectedCurrentRootVersion: 7, NewRootVersion: 8,
		NextSecurityEpoch: 10, NextSPI: next.SPI, OrdinarySuiteID: suite.SM4HCTR,
		NewOperationalRoot: bytes.Repeat([]byte{1}, 16),
	}
	security, _ = newTestSecurity(t, &fakeCore{}, current, next, recoveryAssociation())
	if _, err := security.ProtectRootPrepareFrame(context.Background(), "tenant-1", nil, command); !errors.Is(err, ErrFrameInvalid) {
		t.Fatalf("invalid recovery primary header error = %v", err)
	}
	security, _ = newTestSecurity(t, &fakeCore{protectErr: coreFailure},
		current, next, recoveryAssociation())
	if _, err := security.ProtectRootPrepareFrame(context.Background(), "tenant-1", make([]byte, 5), command); !errors.Is(err, coreFailure) {
		t.Fatalf("recovery core error = %v", err)
	}
	security, _ = newTestSecurity(t, &fakeCore{wrongBinding: true},
		current, next, recoveryAssociation())
	if _, err := security.ProtectRootPrepareFrame(context.Background(), "tenant-1", make([]byte, 5), command); !errors.Is(err, ErrFrameInvalid) {
		t.Fatalf("recovery binding error = %v", err)
	}
	security, _ = newTestSecurity(t, &fakeCore{nilProtect: true},
		current, next, recoveryAssociation())
	if _, err := security.ProtectRootPrepareFrame(context.Background(), "tenant-1", make([]byte, 5), command); !errors.Is(err, ErrFrameInvalid) {
		t.Fatalf("nil recovery result error = %v", err)
	}
}

func TestTCFrameValidationBoundaries(t *testing.T) {
	if _, err := assembleTCFrame(nil, []byte{1}, TCMaxFrameLength); !errors.Is(err, ErrFrameInvalid) {
		t.Fatalf("invalid assembly error = %v", err)
	}
	frame := appendTCFECF([]byte{0x20, 0x01, 0, 0, 0x07, 0xaa})
	setTCFrameLength(frame, len(frame))
	// FECF must be regenerated after writing the encoded frame length.
	frame = appendTCFECF(frame[:len(frame)-TCFECFLength])
	if err := validateTCFrame(frame); err != nil {
		t.Fatalf("valid frame rejected: %v", err)
	}
	badLength := append([]byte(nil), frame...)
	badLength[3] ^= 1
	badCRC := append([]byte(nil), frame...)
	badCRC[len(badCRC)-1] ^= 1
	for _, invalid := range [][]byte{
		nil,
		make([]byte, TCMaxFrameLength+1),
		badLength,
		badCRC,
	} {
		if err := validateTCFrame(invalid); err == nil {
			t.Fatalf("invalid frame accepted: %x", invalid)
		}
	}
}

func TestAssociationAndOptionsValidationMatrix(t *testing.T) {
	expectInvalid := func(sa SecurityAssociation) {
		t.Helper()
		if err := sa.Validate(); err == nil {
			t.Fatalf("invalid association accepted: %+v", sa)
		}
	}
	mutateTC := []func(*SecurityAssociation){
		func(sa *SecurityAssociation) { sa.ID = "" },
		func(sa *SecurityAssociation) { sa.Direction = Direction("BAD") },
		func(sa *SecurityAssociation) { sa.SecurityEpoch = 0 },
		func(sa *SecurityAssociation) { sa.State = AssociationActive },
		func(sa *SecurityAssociation) { sa.SuiteID = "UNKNOWN" },
		func(sa *SecurityAssociation) { sa.Parameters.SequenceNumberLength = 1 },
		func(sa *SecurityAssociation) { sa.Parameters.NoncePrefix = nil },
	}
	for _, mutate := range mutateTC {
		sa := tcAssociation()
		mutate(&sa)
		expectInvalid(sa)
	}
	mutateRecovery := []func(*SecurityAssociation){
		func(sa *SecurityAssociation) { sa.State = AssociationCurrent },
		func(sa *SecurityAssociation) { sa.SecurityEpoch = 1 },
		func(sa *SecurityAssociation) { sa.Parameters.TagLength = 0 },
		func(sa *SecurityAssociation) { sa.Parameters.NoncePrefix = nil },
	}
	for _, mutate := range mutateRecovery {
		sa := recoveryAssociation()
		mutate(&sa)
		expectInvalid(sa)
	}
	if (Options{}).validate() == nil ||
		(Options{MaxFrameLength: 100, NodeID: "n"}).validate() != nil {
		t.Fatal("options validation mismatch")
	}
	if _, err := New(nil, nil, Options{}); err == nil {
		t.Fatal("New accepted nil dependencies")
	}
}

func TestRootPrepareAndKDFRejections(t *testing.T) {
	base := RootPrepareCommand{
		TransactionID: 1, ExpectedCurrentRootVersion: 1, NewRootVersion: 2,
		NextSecurityEpoch: 2, NextSPI: 2, OrdinarySuiteID: suite.SM4HCTR,
		NewOperationalRoot: bytes.Repeat([]byte{1}, 16),
	}
	for _, mutate := range []func(*RootPrepareCommand){
		func(c *RootPrepareCommand) { c.TransactionID = 0 },
		func(c *RootPrepareCommand) { c.ExpectedCurrentRootVersion = 0 },
		func(c *RootPrepareCommand) { c.NewRootVersion = c.ExpectedCurrentRootVersion },
		func(c *RootPrepareCommand) { c.NextSecurityEpoch = 0 },
		func(c *RootPrepareCommand) { c.OrdinarySuiteID = suite.SM4GCM },
		func(c *RootPrepareCommand) { c.NewOperationalRoot = nil },
	} {
		candidate := base
		mutate(&candidate)
		if candidate.Validate() == nil {
			t.Fatalf("invalid root prepare accepted: %+v", candidate)
		}
	}
	raw, err := base.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	raw[0] = 2
	if _, err := ParseRootPrepareCommand(raw); !errors.Is(err, ErrFrameInvalid) {
		t.Fatalf("invalid format version = %v", err)
	}
	if _, err := DeriveOrdinaryTrafficKey(make([]byte, 16), 1, suite.SM4GCM, 1, 1, 1); err == nil {
		t.Fatal("ordinary KDF accepted wrong suite")
	}
	if _, err := DeriveOrdinaryTrafficKey(make([]byte, 15), 1, suite.SM4HCTR, 1, 1, 1); err == nil {
		t.Fatal("ordinary KDF accepted short root")
	}
	if _, err := DeriveRecoveryGCMKey(make([]byte, 16), 1, suite.SM4HCTR, 1, 1); err == nil {
		t.Fatal("recovery KDF accepted wrong suite")
	}
	if _, err := DeriveRecoveryGCMKey(make([]byte, 15), 1, suite.SM4GCM, 1, 1); err == nil {
		t.Fatal("recovery KDF accepted short root")
	}
}
