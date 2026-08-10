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
	aosNonce       []byte
	lastDerivation protection.Derivation
}

func (f *fakeCore) ProtectDerived(_ context.Context, req protection.ProtectRequest,
	derivation protection.Derivation) (*protection.ProtectResult, error) {
	f.lastDerivation = protection.Derivation{
		Label: append([]byte(nil), derivation.Label...), Context: append([]byte(nil), derivation.Context...),
	}
	return f.protect(req)
}

func (f *fakeCore) protect(req protection.ProtectRequest) (*protection.ProtectResult, error) {
	data := append([]byte(nil), req.Data...)
	for i := range data {
		data[i] ^= 0x5a
	}
	if len(req.Nonce) == 12 && len(req.AAD) == TCRecoveryAADLength && len(req.AuthenticationInput) == 0 {
		return &protection.ProtectResult{
			Data: data, Nonce: append([]byte(nil), req.Nonce...), Tag: bytes.Repeat([]byte{0xa5}, 16),
			KeyVersion: req.KeyVersion, PolicyVersion: req.PolicyVersion, SuiteID: suite.AES256GCM,
			ServiceType: suite.ServiceAuthEncrypt,
		}, nil
	}
	if len(req.Nonce) != 16 || len(req.AAD) != 0 || len(req.AuthenticationInput) != 0 {
		return nil, errors.New("invalid TC protection context")
	}
	return &protection.ProtectResult{
		Data: data, Nonce: append([]byte(nil), req.Nonce...),
		KeyVersion: req.KeyVersion, PolicyVersion: req.PolicyVersion, SuiteID: suite.AES256CTR,
		ServiceType: suite.ServiceEncryptOnly,
	}, nil
}

func (f *fakeCore) Unprotect(_ context.Context, req protection.UnprotectRequest) (*protection.UnprotectResult, error) {
	if !bytes.Equal(req.Tag, bytes.Repeat([]byte{0xa5}, 16)) || len(req.AAD) == 0 {
		return nil, errors.New("authentication failed")
	}
	data := append([]byte(nil), req.Data...)
	for i := range data {
		data[i] ^= 0x5a
	}
	return &protection.UnprotectResult{Data: data, SuiteID: suite.AES256GCM, ServiceType: suite.ServiceAuthEncrypt}, nil
}

func recoveryAssociation() SecurityAssociation {
	return SecurityAssociation{
		ID: "recovery", TenantID: "tenant-1", SPI: 0x7001, Direction: DirectionTCRecoveryTx,
		KeyID: "key-recovery", KeyVersion: 3, PolicyVersion: 1,
		SuiteID: suite.AES256GCM.String(), State: AssociationActive,
		Parameters: ManagedParameters{TransmittedIVLength: TCIVCounterLength, TagLength: TCRecoveryTagLength,
			NoncePrefix: []byte{0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5}},
	}
}

func tcAssociation() SecurityAssociation {
	return SecurityAssociation{
		ID: "tx-current", TenantID: "tenant-1", SPI: 0x1001, Direction: DirectionTCTx,
		KeyID: "operational-root", KeyVersion: 7, SecurityEpoch: 9, PolicyVersion: 1,
		SuiteID: suite.AES256CTR.String(), State: AssociationCurrent,
		Parameters: ManagedParameters{TransmittedIVLength: TCIVCounterLength,
			NoncePrefix: []byte{0x10, 0x20, 0x30, 0x40, 0x50, 0x60}},
	}
}

func nextTCAssociation() SecurityAssociation {
	sa := tcAssociation()
	sa.ID = "tx-next"
	sa.SPI++
	sa.SecurityEpoch++
	sa.State = AssociationNext
	return sa
}

func aosAssociation() SecurityAssociation {
	return SecurityAssociation{
		ID: "rx", TenantID: "tenant-1", SPI: 0x1002, Direction: DirectionAOSRx,
		KeyID: "key-aos", KeyVersion: 1, PolicyVersion: 1,
		SuiteID: suite.AES256GCM.String(), State: AssociationActive,
		Parameters: ManagedParameters{SequenceNumberLength: 4, TransmittedIVLength: 12,
			TagLength: 16, ReplayWindow: 32},
	}
}

func newTestSecurity(t *testing.T, core ProtectionCore, associations ...SecurityAssociation) (*FrameSecurity, *MemoryStore) {
	t.Helper()
	store, err := NewMemoryStore(associations...)
	if err != nil {
		t.Fatal(err)
	}
	security, err := New(core, store, Options{
		AOSPrimaryHeaderLength: 6, MaxFrameLength: 2048, NodeID: "node-1", TCSpacecraftID: 0x1234,
	})
	if err != nil {
		t.Fatal(err)
	}
	return security, store
}

func TestProtectTCDataOwnsSecurityHeaderAndSelectsCurrent(t *testing.T) {
	core := &fakeCore{}
	security, _ := newTestSecurity(t, core, nextTCAssociation(), tcAssociation())
	plain := []byte("command")
	protected, err := security.ProtectTCData(context.Background(), "tenant-1", plain)
	if err != nil {
		t.Fatal(err)
	}
	if protected.Metadata.AssociationID != "tx-current" || protected.Metadata.Counter != 0 ||
		len(protected.Data) != TCSecurityHeaderLength+len(plain) {
		t.Fatalf("unexpected TC result: metadata=%+v len=%d", protected.Metadata, len(protected.Data))
	}
	if !bytes.Equal(protected.Data[:TCSecurityHeaderLength], []byte{0x10, 0x01, 0, 0, 0, 0}) {
		t.Fatalf("security header = %x", protected.Data[:TCSecurityHeaderLength])
	}
	if bytes.Equal(protected.Data[TCSecurityHeaderLength:], plain) {
		t.Fatal("TC data field was not encrypted")
	}
	if !bytes.Equal(core.lastDerivation.Label, ordinaryKDFLabel) || len(core.lastDerivation.Context) != 15 {
		t.Fatalf("ordinary KDF binding = %x/%x", core.lastDerivation.Label, core.lastDerivation.Context)
	}
}

func TestAdvanceTCTransmitEpochIsLocalAndAtomic(t *testing.T) {
	security, store := newTestSecurity(t, &fakeCore{}, tcAssociation(), nextTCAssociation())
	if err := security.AdvanceTCTransmitEpoch(context.Background(), "tenant-1"); err != nil {
		t.Fatal(err)
	}
	protected, err := security.ProtectTCData(context.Background(), "tenant-1", []byte{1})
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
	security, _ := newTestSecurity(t, &fakeCore{}, current, next)
	if err := security.AdvanceTCTransmitEpoch(context.Background(), "tenant-1"); err != nil {
		t.Fatalf("0xFFFF -> 0x0000 promotion failed: %v", err)
	}
	protected, err := security.ProtectTCData(context.Background(), "tenant-1", []byte{1})
	if err != nil {
		t.Fatal(err)
	}
	if protected.Metadata.SPI != 0x0000 {
		t.Fatalf("promoted SPI = 0x%04X", protected.Metadata.SPI)
	}
}

func TestProtectRootPrepareDataUsesRecoveryOnlyAndAADIsSecurityHeader(t *testing.T) {
	core := &fakeCore{}
	current := tcAssociation()
	next := nextTCAssociation()
	next.KeyVersion = 8
	security, _ := newTestSecurity(t, core, recoveryAssociation(), current, next)
	command := RootPrepareCommand{
		TransactionID: 9, ExpectedCurrentRootVersion: 7, NewRootVersion: 8,
		NextSecurityEpoch: 10, NextSPI: 0x1002, OrdinarySuiteID: suite.AES256CTR,
		NewOperationalRoot: bytes.Repeat([]byte{0x44}, 32),
	}
	protected, err := security.ProtectRootPrepareData(context.Background(), "tenant-1", command)
	if err != nil {
		t.Fatal(err)
	}
	wantLength := TCSecurityHeaderLength + rootPrepareFixedLength + 32 + TCRecoveryTagLength
	if len(protected.Data) != wantLength || protected.Metadata.ServiceType != suite.ServiceAuthEncrypt {
		t.Fatalf("unexpected recovery result: len=%d metadata=%+v", len(protected.Data), protected.Metadata)
	}
	if !bytes.Equal(protected.Data[:TCSecurityHeaderLength], []byte{0x70, 0x01, 0, 0, 0, 0}) ||
		!bytes.Equal(protected.Data[len(protected.Data)-TCRecoveryTagLength:], bytes.Repeat([]byte{0xa5}, 16)) {
		t.Fatalf("invalid recovery security fields: %x", protected.Data)
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
		NextSecurityEpoch: 10, NextSPI: 0x1002, OrdinarySuiteID: suite.AES256CTR,
		NewOperationalRoot: bytes.Repeat([]byte{1}, 32)}
	command.NextSecurityEpoch++
	if _, err := security.ProtectRootPrepareData(context.Background(), "tenant-1", command); !errors.Is(err, ErrAssociationState) {
		t.Fatalf("mismatched next epoch error = %v", err)
	}
}

func TestRootPrepareTransactionIsStrict(t *testing.T) {
	command := RootPrepareCommand{TransactionID: 1, ExpectedCurrentRootVersion: 1, NewRootVersion: 2,
		NextSecurityEpoch: 3, NextSPI: 0x1002, OrdinarySuiteID: suite.SM4CTR,
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

func TestUnprotectAOSAndRejectReplay(t *testing.T) {
	rx := aosAssociation()
	core := &fakeCore{aosNonce: bytes.Repeat([]byte{0x11}, 12)}
	security, _ := newTestSecurity(t, core, rx)
	header := []byte{1, 2, 3, 4, 5, 6}
	plain := []byte("command")
	securityHeader, _ := encodeAOSSecurityHeader(rx.SPI, 7, rx.Parameters.SequenceNumberLength, core.aosNonce)
	ciphertext := append([]byte(nil), plain...)
	for i := range ciphertext {
		ciphertext[i] ^= 0x5a
	}
	aos := join(header, securityHeader, ciphertext, bytes.Repeat([]byte{0xa5}, 16))
	opened, err := security.UnprotectAOS(context.Background(), "tenant-1", aos)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(opened.Frame, join(header, plain)) {
		t.Fatalf("AOS plaintext = %x", opened.Frame)
	}
	if _, err := security.UnprotectAOS(context.Background(), "tenant-1", aos); !errors.Is(err, ErrReplay) {
		t.Fatalf("replay error = %v, want %v", err, ErrReplay)
	}
}

func TestFailedAuthenticationDoesNotAdvanceAOSReplayWindow(t *testing.T) {
	rx := aosAssociation()
	security, _ := newTestSecurity(t, &fakeCore{aosNonce: bytes.Repeat([]byte{0x11}, 12)}, rx)
	header := []byte{1, 2, 3, 4, 5, 6}
	securityHeader, _ := encodeAOSSecurityHeader(rx.SPI, 9, 4, bytes.Repeat([]byte{0x11}, 12))
	bad := join(header, securityHeader, []byte("cipher"), bytes.Repeat([]byte{0x00}, 16))
	if _, err := security.UnprotectAOS(context.Background(), "tenant-1", bad); err == nil {
		t.Fatal("bad authenticator accepted")
	}
	good := join(header, securityHeader, []byte("cipher"), bytes.Repeat([]byte{0xa5}, 16))
	if _, err := security.UnprotectAOS(context.Background(), "tenant-1", good); err != nil {
		t.Fatalf("sequence was consumed by failed authentication: %v", err)
	}
}

func TestTCProfilesAndStatesAreStrict(t *testing.T) {
	for _, suiteID := range []suite.ID{suite.AES256CTR, suite.SM4CTR} {
		sa := tcAssociation()
		sa.SuiteID = suiteID.String()
		if err := sa.Validate(); err != nil {
			t.Fatalf("TC profile rejected %s: %v", suiteID, err)
		}
	}
	for _, suiteID := range []suite.ID{suite.AES256GCM, suite.SM4GCM, suite.AES256CMAC, suite.SM4CMAC} {
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
	for _, suiteID := range []suite.ID{suite.AES256GCM, suite.SM4GCM} {
		sa := recoveryAssociation()
		sa.SuiteID = suiteID.String()
		if err := sa.Validate(); err != nil {
			t.Fatalf("recovery profile rejected %s: %v", suiteID, err)
		}
	}
	sa := recoveryAssociation()
	sa.SuiteID = suite.AES256CTR.String()
	if err := sa.Validate(); err == nil {
		t.Fatal("recovery profile accepted CTR")
	}
}

func TestProtectTCDataRejectsEmptyOrOversizedInput(t *testing.T) {
	security, _ := newTestSecurity(t, &fakeCore{}, tcAssociation())
	if _, err := security.ProtectTCData(context.Background(), "tenant-1", nil); !errors.Is(err, ErrFrameInvalid) {
		t.Fatalf("empty data error = %v", err)
	}
	if _, err := security.ProtectTCData(context.Background(), "tenant-1", make([]byte, TCMaxFrameLength)); !errors.Is(err, ErrFrameInvalid) {
		t.Fatalf("oversized data error = %v", err)
	}
}
