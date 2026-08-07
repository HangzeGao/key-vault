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
	aosNonce []byte
}

func (f *fakeCore) Protect(_ context.Context, req protection.ProtectRequest) (*protection.ProtectResult, error) {
	data := append([]byte(nil), req.Data...)
	for i := range data {
		data[i] ^= 0x5a
	}
	if len(req.Nonce) == 12 && len(req.AAD) == TCRecoveryAADLength && len(req.AuthenticationInput) == 0 {
		return &protection.ProtectResult{
			Data: data, Nonce: append([]byte(nil), req.Nonce...), Tag: bytes.Repeat([]byte{0xa5}, 16),
			KeyVersion: 1, PolicyVersion: 1, SuiteID: suite.AES256GCM,
			ServiceType: suite.ServiceAuthEncrypt,
		}, nil
	}
	if len(req.Nonce) != 16 || len(req.AAD) != 0 || len(req.AuthenticationInput) != 0 {
		return nil, errors.New("invalid TC protection context")
	}
	return &protection.ProtectResult{
		Data: data, Nonce: append([]byte(nil), req.Nonce...),
		KeyVersion: 1, PolicyVersion: 1, SuiteID: suite.AES256CTR,
		ServiceType: suite.ServiceEncryptOnly,
	}, nil
}

func recoveryAssociation() SecurityAssociation {
	return SecurityAssociation{
		ID: "recovery", TenantID: "tenant-1", SPI: 0x7001, Direction: DirectionTCRecoveryTx,
		KeyID: "key-recovery", KeyVersion: 1, PolicyVersion: 1,
		SuiteID: "AES_256_GCM", State: AssociationActive,
		Parameters: ManagedParameters{TransmittedIVLength: TCIVCounterLength, TagLength: TCRecoveryTagLength,
			NoncePrefix: []byte{0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5}},
	}
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

func tcAssociation() SecurityAssociation {
	return SecurityAssociation{
		ID: "tx", TenantID: "tenant-1", SPI: 0x1001, Direction: DirectionTCTx,
		KeyID: "key-tc", KeyVersion: 1, PolicyVersion: 1,
		SuiteID: "AES_256_CTR", State: AssociationActive,
		Parameters: ManagedParameters{
			TransmittedIVLength: TCIVCounterLength,
			NoncePrefix:         []byte{0x10, 0x20, 0x30, 0x40, 0x50, 0x60},
		},
	}
}

func aosAssociation() SecurityAssociation {
	return SecurityAssociation{
		ID: "rx", TenantID: "tenant-1", SPI: 0x1002, Direction: DirectionAOSRx,
		KeyID: "key-aos", KeyVersion: 1, PolicyVersion: 1,
		SuiteID: "AES_256_GCM", State: AssociationActive,
		Parameters: ManagedParameters{
			SequenceNumberLength: 4, TransmittedIVLength: 12,
			TagLength: 16, ReplayWindow: 32,
		},
	}
}

func TestProtectTCFixedHeaderNoTag(t *testing.T) {
	tx := tcAssociation()
	store, err := NewMemoryStore(tx)
	if err != nil {
		t.Fatal(err)
	}
	security, err := New(&fakeCore{}, store, Options{AOSPrimaryHeaderLength: 6, MaxFrameLength: 2048, NodeID: "node-1"})
	if err != nil {
		t.Fatal(err)
	}
	plain := []byte("command")
	clearFrame := makeClearTCFrame(plain)
	protected, err := security.ProtectTC(context.Background(), "tenant-1", "tx", clearFrame)
	if err != nil {
		t.Fatal(err)
	}
	if protected.Metadata.Counter != 0 || len(protected.Frame) != len(clearFrame)+TCSecurityHeaderLength {
		t.Fatalf("unexpected TC metadata/frame length: %+v len=%d", protected.Metadata, len(protected.Frame))
	}
	if err := validateTCFrame(protected.Frame); err != nil {
		t.Fatalf("protected frame FECF/length invalid: %v", err)
	}
	wantSecurityHeader := []byte{0x10, 0x01, 0, 0, 0, 0}
	if !bytes.Equal(protected.Frame[TCPrimaryHeaderLength:TCPrimaryHeaderLength+TCSecurityHeaderLength], wantSecurityHeader) {
		t.Fatalf("security header = %x", protected.Frame[5:11])
	}
	if bytes.Equal(protected.Frame[11:len(protected.Frame)-2], plain) {
		t.Fatal("TC data field was not encrypted")
	}
}

func TestProtectRootRecoveryUsesDedicatedProfileAndAuthenticatesHeader(t *testing.T) {
	sa := recoveryAssociation()
	store, err := NewMemoryStore(sa)
	if err != nil {
		t.Fatal(err)
	}
	security, _ := New(&fakeCore{}, store, Options{AOSPrimaryHeaderLength: 6, MaxFrameLength: 2048, NodeID: "node-1"})
	command := RootRecoveryCommand{
		TransactionID: 9, ExpectedCurrentRootVersion: 4, NewRootVersion: 5,
		ActivationEpoch: 12, OrdinarySuiteID: suite.AES256CTR,
		NewOperationalRoot: bytes.Repeat([]byte{0x44}, 32),
	}
	protected, err := security.ProtectRootRecovery(context.Background(), "tenant-1", sa.ID,
		[]byte{0x20, 0x01, 0, 0, 1}, command)
	if err != nil {
		t.Fatal(err)
	}
	wantLength := TCPrimaryHeaderLength + TCSecurityHeaderLength + 55 + TCRecoveryTagLength + TCFECFLength
	if len(protected.Frame) != wantLength || protected.Metadata.ServiceType != suite.ServiceAuthEncrypt {
		t.Fatalf("unexpected recovery result: len=%d metadata=%+v", len(protected.Frame), protected.Metadata)
	}
	if err := validateTCFrame(protected.Frame); err != nil {
		t.Fatalf("recovery frame invalid: %v", err)
	}
	if got := protected.Frame[TCPrimaryHeaderLength : TCPrimaryHeaderLength+TCSecurityHeaderLength]; !bytes.Equal(got, []byte{0x70, 0x01, 0, 0, 0, 0}) {
		t.Fatalf("security header = %x", got)
	}
	if !bytes.Equal(protected.Frame[len(protected.Frame)-TCFECFLength-TCRecoveryTagLength:len(protected.Frame)-TCFECFLength], bytes.Repeat([]byte{0xa5}, 16)) {
		t.Fatal("full recovery tag was not emitted")
	}
}

func TestRootRecoveryTransactionIsStrict(t *testing.T) {
	command := RootRecoveryCommand{TransactionID: 1, ExpectedCurrentRootVersion: 1, NewRootVersion: 2,
		ActivationEpoch: 3, OrdinarySuiteID: suite.SM4CTR, NewOperationalRoot: bytes.Repeat([]byte{7}, 16)}
	raw, err := command.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseRootRecoveryCommand(raw)
	if err != nil || parsed.TransactionID != command.TransactionID || !bytes.Equal(parsed.NewOperationalRoot, command.NewOperationalRoot) {
		t.Fatalf("parse = %+v, err=%v", parsed, err)
	}
	if _, err := ParseRootRecoveryCommand(append(raw, 0)); !errors.Is(err, ErrFrameInvalid) {
		t.Fatalf("trailing byte error = %v", err)
	}
	command.OrdinarySuiteID = suite.SM4GCM
	if _, err := command.MarshalBinary(); !errors.Is(err, ErrFrameInvalid) {
		t.Fatalf("non-CTR ordinary suite error = %v", err)
	}
}

func TestUnprotectAOSAndRejectReplay(t *testing.T) {
	rx := aosAssociation()
	store, err := NewMemoryStore(rx)
	if err != nil {
		t.Fatal(err)
	}
	core := &fakeCore{aosNonce: bytes.Repeat([]byte{0x11}, 12)}
	security, err := New(core, store, Options{AOSPrimaryHeaderLength: 6, MaxFrameLength: 2048, NodeID: "node-1"})
	if err != nil {
		t.Fatal(err)
	}
	header := []byte{1, 2, 3, 4, 5, 6}
	plain := []byte("command")
	securityHeader, err := encodeAOSSecurityHeader(rx.SPI, 7, rx.Parameters.SequenceNumberLength, core.aosNonce)
	if err != nil {
		t.Fatal(err)
	}
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

func TestFailedAuthenticationDoesNotAdvanceReplayWindow(t *testing.T) {
	rx := aosAssociation()
	store, _ := NewMemoryStore(rx)
	security, _ := New(&fakeCore{aosNonce: bytes.Repeat([]byte{0x11}, 12)}, store,
		Options{AOSPrimaryHeaderLength: 6, MaxFrameLength: 2048, NodeID: "node-1"})
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

func TestTCAllowsOnlyAES256OrSM4CTR(t *testing.T) {
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

func TestProtectTCRejectsMalformedOrEmptyClearFrame(t *testing.T) {
	store, err := NewMemoryStore(tcAssociation())
	if err != nil {
		t.Fatal(err)
	}
	security, err := New(&fakeCore{}, store, Options{AOSPrimaryHeaderLength: 6, MaxFrameLength: 2048, NodeID: "node-1"})
	if err != nil {
		t.Fatal(err)
	}
	badFECF := makeClearTCFrame([]byte{0x01})
	badFECF[len(badFECF)-1] ^= 0x01
	if _, err := security.ProtectTC(context.Background(), "tenant-1", "tx", badFECF); !errors.Is(err, ErrFrameInvalid) {
		t.Fatalf("bad FECF error = %v, want %v", err, ErrFrameInvalid)
	}
	empty := makeClearTCFrame(nil)
	if _, err := security.ProtectTC(context.Background(), "tenant-1", "tx", empty); !errors.Is(err, ErrFrameInvalid) {
		t.Fatalf("empty data error = %v, want %v", err, ErrFrameInvalid)
	}
}

func TestAssociationRotationStatesAreStrict(t *testing.T) {
	prepared := tcAssociation()
	prepared.State = AssociationPreinstalled
	if err := prepared.Validate(); err != nil {
		t.Fatalf("preinstalled association rejected: %v", err)
	}
	store, err := NewMemoryStore(prepared)
	if err != nil {
		t.Fatal(err)
	}
	security, err := New(&fakeCore{}, store, Options{AOSPrimaryHeaderLength: 6, MaxFrameLength: 2048, NodeID: "node-1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := security.ProtectTC(context.Background(), "tenant-1", "tx", makeClearTCFrame([]byte{1})); !errors.Is(err, ErrAssociationState) {
		t.Fatalf("preinstalled TC transmit error = %v, want %v", err, ErrAssociationState)
	}
	legacy := tcAssociation()
	legacy.State = AssociationState("RX_ONLY")
	if err := legacy.Validate(); err == nil {
		t.Fatal("obsolete RX_ONLY state was accepted")
	}
}

func makeClearTCFrame(data []byte) []byte {
	header := []byte{0x20, 0x01, 0, 0, 1}
	setTCFrameLength(header, len(header)+len(data)+TCFECFLength)
	return appendTCFECF(join(header, data))
}
