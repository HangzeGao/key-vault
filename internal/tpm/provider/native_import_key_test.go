package provider

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

	"github.com/google/go-tpm-tools/simulator"
	legacy "github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/kvlt/key-vault/internal/commissioning"
)

type importTestPlatform struct{ record commissioning.Record }

func (p importTestPlatform) Load() (commissioning.Record, error) { return p.record, nil }
func (importTestPlatform) Commit(commissioning.Record, commissioning.Record) error {
	return errors.New("unexpected lifecycle commit")
}
func (p importTestPlatform) Verify(action commissioning.Action, transaction [32]byte, evidence []byte) error {
	if action != commissioning.InstallRoots || transaction != p.record.ProductionTransaction || !bytes.Equal(evidence, []byte("authorized")) {
		return errors.New("invalid authorization")
	}
	return nil
}

func registerTestImportKey(t *testing.T, p *NativeProvider, handle tpm2.TPMHandle, passwordBypass bool) RegisteredImportKey {
	t.Helper()
	salt, _, err := p.saltKey()
	if err != nil {
		t.Fatal(err)
	}
	tpm := transport.FromReadWriter(p.rw)
	session, _, err := p.policySession()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (tpm2.PolicyCommandCode{PolicySession: tpm2.TPMHandle(session), Code: tpm2.TPMCCECDHZGen}).Execute(tpm); err != nil {
		t.Fatal(err)
	}
	digest, err := legacy.PolicyGetDigest(p.rw, session)
	if err != nil {
		t.Fatal(err)
	}
	if err := legacy.FlushContext(p.rw, session); err != nil {
		t.Fatal(err)
	}
	key, err := (tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic: tpm2.New2B(tpm2.TPMTPublic{
			Type: tpm2.TPMAlgECC, NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{
				FixedTPM: true, FixedParent: true, SensitiveDataOrigin: true,
				UserWithAuth: passwordBypass, Decrypt: true,
			},
			AuthPolicy: tpm2.TPM2BDigest{Buffer: digest},
			Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
				CurveID: tpm2.TPMECCNistP256,
				Scheme: tpm2.TPMTECCScheme{Scheme: tpm2.TPMAlgECDH,
					Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgECDH, &tpm2.TPMSKeySchemeECDH{HashAlg: tpm2.TPMAlgSHA256})},
			}),
		}),
	}).Execute(tpm)
	if err != nil {
		t.Fatal(err)
	}
	defer (tpm2.FlushContext{FlushHandle: key.ObjectHandle}).Execute(tpm)
	if _, err := (tpm2.EvictControl{
		Auth: tpm2.TPMRHOwner, ObjectHandle: tpm2.NamedHandle{Handle: key.ObjectHandle, Name: key.Name},
		PersistentHandle: handle,
	}).Execute(tpm); err != nil {
		t.Fatal(err)
	}
	registration := RegisteredImportKey{Handle: uint32(handle)}
	copy(registration.ObjectName[:], key.Name.Buffer)
	copy(registration.StorageName[:], salt.Name.Buffer)
	return registration
}

func TestNativeImportKeyProtectsHPKEAndEnforcesPolicy(t *testing.T) {
	sim, err := simulator.GetWithFixedSeedInsecure(44)
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
	registered := registerTestImportKey(t, p, 0x81000002, false)
	passwordKey := registerTestImportKey(t, p, 0x81000003, true)
	wrongName := registered
	wrongName.ObjectName[2] ^= 1
	for _, invalid := range []RegisteredImportKey{{}, wrongName, passwordKey} {
		if err := p.WithImportKey(ctx, invalid, func(ecdh.KeyExchanger) error {
			t.Fatal("unregistered or password-authorized key accepted")
			return nil
		}); !errors.Is(err, errImportKey) {
			t.Fatalf("bad registration: %v", err)
		}
	}
	peer, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var expired ecdh.KeyExchanger
	var shared []byte
	if err := p.WithImportKey(ctx, registered, func(key ecdh.KeyExchanger) error {
		expired = key
		expected, err := peer.ECDH(key.PublicKey())
		if err != nil {
			return err
		}
		shared, err = key.ECDH(peer.PublicKey())
		if err != nil || !bytes.Equal(shared, expected) {
			t.Fatalf("TPM ECDH failed or produced a different secret: %v", err)
		}
		packets := wire.responses[tpm2.TPMCCECDHZGen]
		if len(packets) != 1 {
			t.Fatalf("ECDH response count = %d, want 1", len(packets))
		}
		requireEncryptedParameter(t, packets[0], shared)
		if again, err := key.ECDH(peer.PublicKey()); again != nil || !errors.Is(err, errImportKey) {
			t.Fatal("second exchange in a single import scope accepted")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(shared, make([]byte, 32)) {
		t.Fatal("ECDH shared secret retained after the scope ended")
	}
	if got, err := expired.ECDH(peer.PublicKey()); got != nil || !errors.Is(err, errImportKey) {
		t.Fatal("expired exchange accepted")
	}
	issuer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	platform := importTestPlatform{record: commissioning.Record{Phase: commissioning.Commissioning,
		TestTransaction: [32]byte{1}, ProductionTransaction: [32]byte{2}}}
	roots := bytes.Repeat([]byte{0xab}, 48)
	if err := p.WithImportKey(ctx, registered, func(key ecdh.KeyExchanger) error {
		binding := commissioning.Binding{Purpose: commissioning.GroundRoots, ProfileDigest: [32]byte{3},
			DeviceID: [32]byte{4}, RecipientKeyID: sha256.Sum256(key.PublicKey().Bytes()),
			Transaction: platform.record.ProductionTransaction}
		envelope, err := commissioning.Seal(binding, key.PublicKey(), issuer, roots)
		if err != nil {
			return err
		}
		exchanges := len(wire.responses[tpm2.TPMCCECDHZGen])
		if err := commissioning.Import(platform, binding, envelope, key, &issuer.PublicKey, nil, func([]byte) error {
			t.Fatal("unauthorized import reached the installer")
			return nil
		}); !errors.Is(err, commissioning.ErrLifecycle) || len(wire.responses[tpm2.TPMCCECDHZGen]) != exchanges {
			t.Fatal("authorization failure did not stop the import before ECDH")
		}
		tampered := envelope
		tampered.Signature = bytes.Clone(envelope.Signature)
		tampered.Signature[0] ^= 1
		if err := commissioning.Import(platform, binding, tampered, key, &issuer.PublicKey, []byte("authorized"), func([]byte) error {
			t.Fatal("invalid signature reached the installer")
			return nil
		}); !errors.Is(err, commissioning.ErrEnvelope) || len(wire.responses[tpm2.TPMCCECDHZGen]) != exchanges {
			t.Fatal("signature failure did not stop the import before ECDH")
		}
		return commissioning.Import(platform, binding, envelope, key, &issuer.PublicKey, []byte("authorized"), func(material []byte) error {
			if !bytes.Equal(material, roots) {
				t.Fatal("imported roots differ from sealed roots")
			}
			return nil
		})
	}); err != nil {
		t.Fatal(err)
	}
	wrongSalt := registered
	wrongSalt.StorageName[2] ^= 1
	requireDenied := func(registration RegisteredImportKey) {
		t.Helper()
		if err := p.WithImportKey(ctx, registration, func(key ecdh.KeyExchanger) error {
			got, err := key.ECDH(peer.PublicKey())
			if got != nil {
				t.Fatal("unauthorized exchange returned secret material")
			}
			return err
		}); !errors.Is(err, errImportKey) {
			t.Fatalf("unauthorized exchange: %v", err)
		}
	}
	requireDenied(wrongSalt)
	if err := legacy.PCRExtend(p.rw, 7, legacy.AlgSHA256, bytes.Repeat([]byte{9}, 32), ""); err != nil {
		t.Fatal(err)
	}
	requireDenied(registered)
}
