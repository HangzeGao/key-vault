package provider

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"testing"

	"github.com/google/go-tpm-tools/simulator"
	legacy "github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

type nvWriteFault struct {
	io.ReadWriteCloser
	writingNV  bool
	before     bool
	after      bool
	writeCalls int
}

func (w *nvWriteFault) Write(data []byte) (int, error) {
	w.writingNV = tpm2.TPMCC(binary.BigEndian.Uint32(data[6:10])) == tpm2.TPMCCNVWrite
	if w.writingNV {
		w.writeCalls++
		if w.before {
			return 0, io.ErrUnexpectedEOF
		}
	}
	return w.ReadWriteCloser.Write(data)
}

func (w *nvWriteFault) Read(data []byte) (int, error) {
	n, err := w.ReadWriteCloser.Read(data)
	if w.writingNV && w.after {
		return 0, io.ErrUnexpectedEOF
	}
	return n, err
}

func defineTestCommissioningAnchor(t *testing.T, p *NativeProvider, index tpm2.TPMHandle, attrs tpm2.TPMANV) RegisteredCommissioningAnchor {
	t.Helper()
	srk, _, err := p.saltKey()
	if err != nil {
		t.Fatal(err)
	}
	tpm := transport.FromReadWriter(p.rw)
	session, _, err := p.policySession()
	if err != nil {
		t.Fatal(err)
	}
	if err := applyCommissioningNVPolicy(tpm, tpm2.TPMHandle(session)); err != nil {
		t.Fatal(err)
	}
	policy, err := legacy.PolicyGetDigest(p.rw, session)
	if err != nil {
		t.Fatal(err)
	}
	if err := legacy.FlushContext(p.rw, session); err != nil {
		t.Fatal(err)
	}
	public := tpm2.TPMSNVPublic{NVIndex: index, NameAlg: tpm2.TPMAlgSHA256, DataSize: 32, Attributes: attrs,
		AuthPolicy: tpm2.TPM2BDigest{Buffer: policy}}
	if _, err := (tpm2.NVDefineSpace{AuthHandle: tpm2.TPMRHPlatform, PublicInfo: tpm2.New2B(public)}).Execute(tpm); err != nil {
		t.Fatal(err)
	}
	name, err := tpm2.NVName(&public)
	if err != nil {
		t.Fatal(err)
	}
	registration := RegisteredCommissioningAnchor{Index: uint32(index)}
	copy(registration.Name[:], name.Buffer)
	copy(registration.StorageName[:], srk.Name.Buffer)
	return registration
}

func TestNativeCommissioningAnchorWriteOnceAndSurvivesRestart(t *testing.T) {
	sim, err := simulator.GetWithFixedSeedInsecure(45)
	if err != nil {
		t.Skipf("TPM simulator unavailable in this build: %v", err)
	}
	wire := &nvWriteFault{ReadWriteCloser: sim}
	p, err := newNativeProviderWithTransport(wire, []int{7})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	ctx := context.Background()
	registration := defineTestCommissioningAnchor(t, p, 0x01500020, commissioningNVAttributes)
	wrongAttrs := commissioningNVAttributes
	wrongAttrs.AuthWrite = true
	unsafe := defineTestCommissioningAnchor(t, p, 0x01500021, wrongAttrs)
	wrongName := registration
	wrongName.Name[2] ^= 1
	wrongSalt := registration
	wrongSalt.StorageName[2] ^= 1
	missing := registration
	missing.Index += 2
	for _, invalid := range []RegisteredCommissioningAnchor{unsafe, wrongName, wrongSalt, missing} {
		if got, err := p.ReadCommissioningAnchor(ctx, invalid); got != ([32]byte{}) || !errors.Is(err, errCommissioningAnchor) {
			t.Fatalf("untrusted anchor accepted: %v", err)
		}
	}
	if got, err := p.ReadCommissioningAnchor(ctx, registration); got != ([32]byte{}) || err != nil {
		t.Fatalf("read uninitialized anchor: %v", err)
	}
	digest := [32]byte{42}
	if err := legacy.PCRExtend(p.rw, 7, legacy.AlgSHA256, bytes.Repeat([]byte{9}, 32), ""); err != nil {
		t.Fatal(err)
	}
	if err := p.CommitCommissioningAnchor(ctx, registration, digest); !errors.Is(err, errCommissioningAnchor) {
		t.Fatalf("wrong PCR committed: %v", err)
	}
	if err := sim.Reset(); err != nil {
		t.Fatal(err)
	}
	wire.before = true
	if err := p.CommitCommissioningAnchor(ctx, registration, digest); !errors.Is(err, errCommissioningAnchor) {
		t.Fatalf("interrupted write reported success: %v", err)
	}
	wire.before = false
	wire.after = true
	if err := p.CommitCommissioningAnchor(ctx, registration, digest); err != nil {
		t.Fatalf("lost acknowledgment not recovered by readback: %v", err)
	}
	wire.after = false
	if err := sim.Reset(); err != nil {
		t.Fatal(err)
	}
	if got, err := p.ReadCommissioningAnchor(ctx, registration); got != digest || err != nil {
		t.Fatalf("committed digest lost after restart: %v", err)
	}
	count := wire.writeCalls
	if err := p.CommitCommissioningAnchor(ctx, registration, digest); err != nil {
		t.Fatalf("retry of committed digest: %v", err)
	}
	if err := p.CommitCommissioningAnchor(ctx, registration, [32]byte{43}); !errors.Is(err, errCommissioningAnchor) || wire.writeCalls != count {
		t.Fatalf("conflicting digest attempted a rewrite: %v", err)
	}
	tpm := transport.FromReadWriter(wire)
	index, written, err := readCommissioningNV(tpm, registration)
	if err != nil || !written {
		t.Fatalf("read committed index: %v", err)
	}
	if _, err := (tpm2.NVUndefineSpace{AuthHandle: tpm2.TPMRHPlatform, NVIndex: index}).Execute(tpm); err == nil {
		t.Fatal("platform hierarchy erased a policy-protected anchor")
	}
	_, salt, err := p.saltKey()
	if err != nil {
		t.Fatal(err)
	}
	p.writeCommissioningDigest(tpm, index, salt, [32]byte{44})
	if got, err := p.ReadCommissioningAnchor(ctx, registration); got != digest || err != nil {
		t.Fatalf("TPM accepted a second authorized write: %v", err)
	}
}
