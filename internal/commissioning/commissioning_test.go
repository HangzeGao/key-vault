package commissioning

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"testing"
)

type testPlatform struct {
	record                              Record
	loadError, verifyError, commitError error
}

func (p *testPlatform) Load() (Record, error)                       { return p.record, p.loadError }
func (p *testPlatform) Verify(_ Action, _ [32]byte, _ []byte) error { return p.verifyError }
func (p *testPlatform) Commit(old, next Record) error {
	if p.record != old {
		return ErrLifecycle
	}
	if p.commitError != nil {
		return p.commitError
	}
	p.record = next
	return nil
}

func TestEndToEndLifecycle(t *testing.T) {
	testTx, prodTx := [32]byte{1}, [32]byte{2}
	p := &testPlatform{record: Record{Phase: FactoryTest, TestTransaction: testTx}}
	evidence := []byte("verified by platform")
	advance := func(action Action, tx [32]byte, phase Phase, permissions Permissions) {
		t.Helper()
		if err := Advance(p, action, tx, evidence); err != nil || p.record.Phase != phase || p.record.Permissions() != permissions {
			t.Fatalf("transition %v: phase %v permissions %+v error %v", action, p.record.Phase, p.record.Permissions(), err)
		}
	}
	deny := func(action Action, tx [32]byte, proof []byte) {
		t.Helper()
		before := p.record
		if err := Advance(p, action, tx, proof); !errors.Is(err, ErrLifecycle) || p.record != before {
			t.Fatalf("unauthorized advance %v: %v", action, err)
		}
	}
	if p.record.Permissions() != (Permissions{Test: true}) {
		t.Fatal(p.record.Permissions())
	}
	deny(BeginInstallation, prodTx, evidence)
	deny(CloseTest, testTx, nil)
	p.verifyError = errors.New("denied")
	deny(CloseTest, testTx, evidence)
	p.verifyError = nil
	p.commitError = errors.New("interrupted write")
	deny(CloseTest, testTx, evidence)
	p.commitError = nil
	advance(CloseTest, testTx, TestClosing, Permissions{})
	// Restart with the durable record and keep both import paths disabled.
	p = &testPlatform{record: p.record}
	deny(CloseTest, testTx, evidence)
	deny(BeginInstallation, prodTx, evidence)
	advance(ConfirmTestClosed, testTx, ReadyForCommissioning, Permissions{})
	deny(BeginInstallation, testTx, evidence)
	advance(BeginInstallation, prodTx, Commissioning, Permissions{ProductionImport: true})
	deny(ConfirmInstallation, testTx, evidence)
	advance(ConfirmInstallation, prodTx, InstalledLocked, Permissions{})
	advance(ReleaseOperation, prodTx, Operational, Permissions{OperationalTC: true})
	deny(BeginInstallation, prodTx, evidence)
	deny(ReleaseOperation, prodTx, evidence)
	for _, record := range []Record{{}, {Phase: 255, TestTransaction: testTx},
		{Phase: Operational, TestTransaction: testTx}, {Phase: FactoryTest, TestTransaction: testTx, ProductionTransaction: prodTx}} {
		if record.Permissions() != (Permissions{}) {
			t.Fatalf("corrupt lifecycle allowed: %+v", record)
		}
		p.record = record
		deny(CloseTest, testTx, evidence)
	}
	p.loadError = errors.New("missing anchor")
	deny(CloseTest, testTx, evidence)
}

func TestImportBindsEnvelopeAndNeverReleasesOnFailure(t *testing.T) {
	device, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	other, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherIssuer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	binding := Binding{Purpose: GroundRoots, DeviceID: [32]byte{1}, ProfileDigest: [32]byte{2},
		Transaction: [32]byte{3}, RecipientKeyID: sha256.Sum256(device.PublicKey().Bytes())}
	var captured []byte
	var envelope Envelope
	err = GenerateRoots(context.Background(), GroundRoots, func(_ context.Context, roots []byte) error {
		for i := range roots {
			roots[i] = byte(i + 1)
		}
		return nil
	}, func(roots []byte) error {
		captured = roots
		var err error
		envelope, err = Seal(binding, device.PublicKey(), issuer, roots)
		return err
	})
	if err != nil || !bytes.Equal(captured, make([]byte, 48)) {
		t.Fatalf("generate and wipe: %v", err)
	}
	p := &testPlatform{record: Record{Phase: Commissioning, TestTransaction: [32]byte{8}, ProductionTransaction: binding.Transaction}}
	evidence := []byte("authorization")
	var installed []byte
	install := func(roots []byte) error {
		installed = roots
		for i, v := range roots {
			if v != byte(i+1) {
				t.Fatal("incorrect root material")
			}
		}
		return nil
	}
	if err := Import(p, binding, envelope, device, &issuer.PublicKey, evidence, install); err != nil || !bytes.Equal(installed, make([]byte, 48)) {
		t.Fatalf("authenticated import and wiping: %v", err)
	}
	wrongBinding := binding
	wrongBinding.ProfileDigest[0] ^= 1
	wrongPurpose := binding
	wrongPurpose.Purpose = FlightRoots
	wrongTx := binding
	wrongTx.Transaction[0] ^= 1
	changed := func(data []byte) []byte { c := bytes.Clone(data); c[0] ^= 1; return c }
	for _, tc := range []struct {
		name   string
		b      Binding
		e      Envelope
		key    *ecdh.PrivateKey
		issuer *ecdsa.PublicKey
	}{
		{"wrong profile", wrongBinding, envelope, device, &issuer.PublicKey},
		{"wrong purpose", wrongPurpose, envelope, device, &issuer.PublicKey},
		{"wrong transaction", wrongTx, envelope, device, &issuer.PublicKey},
		{"wrong device key", binding, envelope, other, &issuer.PublicKey},
		{"wrong issuer", binding, envelope, device, &otherIssuer.PublicKey},
		{"changed ephemeral key", binding, Envelope{changed(envelope.Enc), envelope.Ciphertext, envelope.Signature}, device, &issuer.PublicKey},
		{"changed ciphertext", binding, Envelope{envelope.Enc, changed(envelope.Ciphertext), envelope.Signature}, device, &issuer.PublicKey},
		{"changed signature", binding, Envelope{envelope.Enc, envelope.Ciphertext, changed(envelope.Signature)}, device, &issuer.PublicKey},
		{"truncated ciphertext", binding, Envelope{envelope.Enc, envelope.Ciphertext[:16], envelope.Signature}, device, &issuer.PublicKey},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fail := func([]byte) error { t.Fatal("released rejected roots"); return nil }
			if err := Import(p, tc.b, tc.e, tc.key, tc.issuer, evidence, fail); err == nil {
				t.Fatal("accepted rejected package")
			}
		})
	}
	if err := Import(p, binding, envelope, device, &issuer.PublicKey, evidence, func(secret []byte) error {
		installed = secret
		return errors.New("must not echo root")
	}); err == nil || err.Error() == "must not echo root" || !bytes.Equal(installed, make([]byte, 48)) {
		t.Fatalf("installer failure: %v", err)
	}
	p.record.Phase = Operational
	if err := Import(p, binding, envelope, device, &issuer.PublicKey, evidence, install); !errors.Is(err, ErrLifecycle) {
		t.Fatal(err)
	}
}

func TestTestRootsCannotCrossClosure(t *testing.T) {
	device, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b := Binding{Purpose: TestRoots, DeviceID: [32]byte{1}, ProfileDigest: [32]byte{2},
		Transaction: [32]byte{3}, RecipientKeyID: sha256.Sum256(device.PublicKey().Bytes())}
	p := &testPlatform{record: Record{Phase: FactoryTest, TestTransaction: b.Transaction}}
	roots := bytes.Repeat([]byte{4}, 32)
	if _, err := Seal(b, device.PublicKey(), issuer, roots[:16]); err == nil {
		t.Fatal("accepted incomplete roots")
	}
	invalid := b
	invalid.Purpose = 10
	if _, err := Seal(invalid, device.PublicKey(), issuer, roots); err == nil {
		t.Fatal("accepted invalid purpose")
	}
	invalid.ProfileDigest = [32]byte{}
	if _, err := Seal(invalid, device.PublicKey(), issuer, roots); err == nil {
		t.Fatal("accepted missing profile")
	}
	wrongIssuer, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Seal(b, device.PublicKey(), wrongIssuer, roots); err == nil {
		t.Fatal("accepted invalid signature curve")
	}
	e, err := Seal(b, device.PublicKey(), issuer, roots)
	if err != nil {
		t.Fatal(err)
	}
	proof := []byte("test authorization")
	if err := Import(p, b, e, device, &issuer.PublicKey, proof, func(got []byte) error {
		if !bytes.Equal(got, roots) {
			t.Fatal("unexpected test roots")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	neverInstall := func([]byte) error { t.Fatal("unexpected installation"); return nil }
	if err := Import(p, b, e, device, nil, proof, neverInstall); err == nil {
		t.Fatal("accepted missing issuer")
	}
	if err := Import(p, b, e, device, &issuer.PublicKey, nil, neverInstall); err == nil {
		t.Fatal("accepted missing proof")
	}
	// Authentication must still be enforced when the wrapper signature is valid.
	corrupt := Envelope{Enc: bytes.Clone(e.Enc), Ciphertext: bytes.Clone(e.Ciphertext)}
	corrupt.Ciphertext[0] ^= 1
	info, _ := b.info()
	digest := signatureDigest(info, corrupt)
	corrupt.Signature, err = ecdsa.SignASN1(rand.Reader, issuer, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	if err := Import(p, b, corrupt, device, &issuer.PublicKey, proof, neverInstall); err == nil {
		t.Fatal("accepted invalid HPKE tag")
	}
	clear(corrupt.Enc)
	digest = signatureDigest(info, corrupt)
	corrupt.Signature, err = ecdsa.SignASN1(rand.Reader, issuer, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	if err := Import(p, b, corrupt, device, &issuer.PublicKey, proof, neverInstall); err == nil {
		t.Fatal("accepted invalid HPKE point")
	}
	if err := Advance(p, CloseTest, b.Transaction, proof); err != nil {
		t.Fatal(err)
	}
	if err := Import(p, b, e, device, &issuer.PublicKey, proof, neverInstall); !errors.Is(err, ErrLifecycle) {
		t.Fatal(err)
	}
	p.loadError = errors.New("lost state")
	if err := Import(p, b, e, device, &issuer.PublicKey, proof, neverInstall); !errors.Is(err, ErrLifecycle) {
		t.Fatal(err)
	}
	if err := GenerateRoots(context.Background(), TestRoots, nil, neverInstall); err == nil {
		t.Fatal("accepted missing source")
	}
	var partial []byte
	if err := GenerateRoots(context.Background(), TestRoots, func(_ context.Context, buf []byte) error {
		buf[0] = 1
		partial = buf
		return errors.New("TPM failed")
	}, neverInstall); err == nil || !bytes.Equal(partial, make([]byte, 32)) {
		t.Fatalf("random source failure did not wipe buffer: %v", err)
	}
}
