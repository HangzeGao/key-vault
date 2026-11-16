package provider

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"testing"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/kvlt/key-vault/internal/crypto/aad"
)

type nativeWireCapture struct {
	io.ReadWriteCloser
	command    tpm2.TPMCC
	create     []byte
	responses  map[tpm2.TPMCC][][]byte
	corruptRNG bool
}

func (w *nativeWireCapture) Write(data []byte) (int, error) {
	w.command = tpm2.TPMCC(binary.BigEndian.Uint32(data[6:10]))
	if w.command == tpm2.TPMCCCreate {
		w.create = bytes.Clone(data)
	}
	return w.ReadWriteCloser.Write(data)
}

func (w *nativeWireCapture) Read(data []byte) (int, error) {
	n, err := w.ReadWriteCloser.Read(data)
	if w.command == tpm2.TPMCCGetRandom || w.command == tpm2.TPMCCUnseal || w.command == tpm2.TPMCCECDHZGen {
		w.responses[w.command] = append(w.responses[w.command], bytes.Clone(data[:n]))
	}
	if w.corruptRNG && w.command == tpm2.TPMCCGetRandom && n > 16 {
		// Header, parameter size and TPM2B length precede the ciphertext.
		data[16] ^= 1
	}
	return n, err
}

func requireEncryptedParameter(t *testing.T, packet, plaintext []byte) {
	t.Helper()
	if len(packet) < 10 || binary.BigEndian.Uint16(packet) != uint16(tpm2.TPMSTSessions) {
		t.Fatal("TPM packet did not carry an authorization session")
	}
	if bytes.Contains(packet, plaintext) {
		t.Fatal("sensitive parameter appeared in the TPM transport")
	}
}

func testPolicyContext() aad.SealContext {
	return aad.SealContext{Purpose: "test", ObjectID: "object-a", NodeID: "node-a",
		StorageName: "seal-a", BaselineDigest: bytes.Repeat([]byte{1}, 32), PolicyDigest: bytes.Repeat([]byte{2}, 32)}
}

func TestNativeProviderSealUnsealAndRestart(t *testing.T) {
	sim, err := simulator.GetWithFixedSeedInsecure(42)
	if err != nil {
		t.Skipf("TPM simulator unavailable in this build: %v", err)
	}
	wire := &nativeWireCapture{ReadWriteCloser: sim, responses: make(map[tpm2.TPMCC][][]byte)}
	p, err := newNativeProviderWithTransport(wire, []int{7})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	ctx := context.Background()
	random := make([]byte, 48)
	if err := p.FillRandom(ctx, random); err != nil || bytes.Equal(random, make([]byte, 48)) {
		t.Fatalf("48 bytes of TPM random: %v", err)
	}
	rngPackets := wire.responses[tpm2.TPMCCGetRandom]
	if len(rngPackets) != 2 {
		t.Fatalf("random response count = %d, want 2", len(rngPackets))
	}
	requireEncryptedParameter(t, rngPackets[0], random[:32])
	requireEncryptedParameter(t, rngPackets[1], random[32:])
	wire.corruptRNG = true
	if err := p.FillRandom(ctx, random); err == nil || !bytes.Equal(random, make([]byte, 48)) {
		t.Fatal("tampered random response was accepted or output was retained")
	}
	wire.corruptRNG = false
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	random[0] = 1
	if err := p.FillRandom(cancelled, random); err != context.Canceled || !bytes.Equal(random, make([]byte, 48)) {
		t.Fatalf("cancelled TPM random: %v", err)
	}
	a := testPolicyContext()
	storage, err := p.EnsureStorage(ctx, a.StorageName)
	if err != nil {
		t.Fatal(err)
	}
	secret := bytes.Repeat([]byte{0x5a}, 32)
	env, err := p.Seal(ctx, storage, secret, a)
	if err != nil {
		t.Fatal(err)
	}
	requireEncryptedParameter(t, wire.create, secret)
	got, err := p.Unseal(ctx, storage, env, a)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatal("unsealed secret mismatch")
	}
	unsealPackets := wire.responses[tpm2.TPMCCUnseal]
	if len(unsealPackets) != 1 {
		t.Fatalf("unseal response count = %d, want 1", len(unsealPackets))
	}
	requireEncryptedParameter(t, unsealPackets[0], secret)
	if err := sim.Reset(); err != nil {
		t.Fatal(err)
	}
	got, err = p.Unseal(ctx, storage, env, a)
	if err != nil {
		t.Fatalf("unseal after restart: %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatal("restart secret mismatch")
	}
}

func TestNativeProviderRejectsWrongContextAndCorruption(t *testing.T) {
	sim, err := simulator.GetWithFixedSeedInsecure(43)
	if err != nil {
		t.Skipf("TPM simulator unavailable in this build: %v", err)
	}
	p, err := newNativeProviderWithTransport(sim, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	a := testPolicyContext()
	storage, _ := p.EnsureStorage(context.Background(), a.StorageName)
	env, err := p.Seal(context.Background(), storage, []byte("secret"), a)
	if err != nil {
		t.Fatal(err)
	}
	wrong := a
	wrong.PolicyDigest = bytes.Repeat([]byte{9}, 32)
	if _, err := p.Unseal(context.Background(), storage, env, wrong); err == nil {
		t.Fatal("wrong policy context accepted")
	}
	var obsolete nativeSealedBundle
	if err := json.Unmarshal(env.Blob, &obsolete); err != nil {
		t.Fatal(err)
	}
	obsolete.FormatVersion--
	obsoleteBlob, err := json.Marshal(obsolete)
	if err != nil {
		t.Fatal(err)
	}
	obsoleteObject := *env
	obsoleteObject.Blob = obsoleteBlob
	if _, err := p.Unseal(context.Background(), storage, &obsoleteObject, a); err == nil {
		t.Fatal("obsolete native sealed-object format accepted")
	}
	env.Blob[0] ^= 0xff
	if _, err := p.Unseal(context.Background(), storage, env, a); err == nil {
		t.Fatal("corrupt envelope accepted")
	}
}

func TestNativeProviderRejectsIncompletePolicyContext(t *testing.T) {
	p := &NativeProvider{}
	if err := validateNativeInputs(context.Background(), &TPMObjectRef{Name: "n"}, aad.SealContext{}); err == nil {
		t.Fatal("incomplete context accepted")
	}
	_ = p
}
