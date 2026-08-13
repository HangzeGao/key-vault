package downlink

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/kvlt/key-vault/internal/crypto/aad"
	"github.com/kvlt/key-vault/internal/securitystate"
	"github.com/kvlt/key-vault/internal/tpm/provider"
)

var errInjected = errors.New("injected failure")

type fakeStore struct {
	state   *securitystate.DownlinkKeyState
	readErr error
	opErr   error
}

func (s *fakeStore) ReadDownlinkKeyState(context.Context) (*securitystate.DownlinkKeyState, error) {
	return s.state, s.readErr
}
func (s *fakeStore) ProvisionDownlinkKEKSet(context.Context, []byte, uint8) error { return s.opErr }
func (s *fakeStore) SetActiveDownlinkKEKSlot(context.Context, uint8) error        { return s.opErr }
func (s *fakeStore) AdvanceDownlinkBatch(context.Context, uint32, []byte, [32]byte) error {
	return s.opErr
}
func (s *fakeStore) MarkCurrentDownlinkObserved(context.Context, uint32) error { return s.opErr }

type fakeSealer struct {
	plaintext []byte
	sealed    []byte
	sealErr   error
	unsealErr error
}

func (s *fakeSealer) SealKEKSet(context.Context, []byte) ([]byte, error) {
	return append([]byte(nil), s.sealed...), s.sealErr
}
func (s *fakeSealer) UnsealKEKSet(context.Context, []byte) ([]byte, error) {
	return append([]byte(nil), s.plaintext...), s.unsealErr
}

func TestServiceRejectsInvalidStateTransitions(t *testing.T) {
	ctx := context.Background()
	kekSet := sequence(KEKSetBytes)
	for name, serviceCall := range map[string]func(*Service) error{
		"short kek":              func(s *Service) error { return s.Provision(ctx, kekSet[:1], 0) },
		"invalid provision slot": func(s *Service) error { return s.Provision(ctx, kekSet, KEKSlots) },
		"invalid active slot":    func(s *Service) error { return s.SetActiveKEKSlot(ctx, KEKSlots) },
	} {
		t.Run(name, func(t *testing.T) {
			if err := serviceCall(NewService(&fakeStore{}, &fakeSealer{})); !errors.Is(err, ErrInvalid) {
				t.Fatalf("error=%v", err)
			}
		})
	}
	if err := NewService(&fakeStore{opErr: errInjected}, &fakeSealer{}).SetActiveKEKSlot(ctx, 7); !errors.Is(err, errInjected) {
		t.Fatalf("set slot error=%v", err)
	}
}

func TestServiceStatusProjection(t *testing.T) {
	ctx := context.Background()
	service := NewService(&fakeStore{readErr: securitystate.ErrNotFound}, &fakeSealer{})
	status, err := service.Status(ctx)
	if err != nil || status.Provisioned {
		t.Fatalf("unprovisioned status=%+v err=%v", status, err)
	}
	service.store = &fakeStore{state: &securitystate.DownlinkKeyState{
		ActiveKEKSlot: 4, CurrentGeneration: 9, CurrentObserved: true, PreviousGeneration: 8,
	}}
	status, err = service.Status(ctx)
	if err != nil || !status.Provisioned || status.ActiveKEKSlot != 4 || status.CurrentGeneration != 9 ||
		!status.CurrentObserved || status.PreviousGeneration != 8 {
		t.Fatalf("status=%+v err=%v", status, err)
	}
	service.store = &fakeStore{readErr: errInjected}
	if _, err := service.Status(ctx); !errors.Is(err, errInjected) {
		t.Fatalf("status read error=%v", err)
	}
}

func TestServicePropagatesProvisionAndLoadFailures(t *testing.T) {
	ctx := context.Background()
	kekSet := sequence(KEKSetBytes)
	state := &securitystate.DownlinkKeyState{ActiveKEKSlot: 0, SealedKEKSet: []byte("sealed")}
	for name, item := range map[string]struct {
		service   *Service
		provision bool
	}{
		"provision read":   {NewService(&fakeStore{readErr: errInjected}, &fakeSealer{}), true},
		"provision unseal": {NewService(&fakeStore{state: state}, &fakeSealer{unsealErr: errInjected}), true},
		"provision seal":   {NewService(&fakeStore{readErr: securitystate.ErrNotFound}, &fakeSealer{sealErr: errInjected}), true},
		"provision store":  {NewService(&fakeStore{readErr: securitystate.ErrNotFound, opErr: errInjected}, &fakeSealer{sealed: []byte("sealed")}), true},
		"load read":        {NewService(&fakeStore{readErr: errInjected}, &fakeSealer{}), false},
		"load unseal":      {NewService(&fakeStore{state: state}, &fakeSealer{unsealErr: errInjected}), false},
	} {
		t.Run(name, func(t *testing.T) {
			var err error
			if item.provision {
				err = item.service.Provision(ctx, kekSet, 0)
			} else {
				err = item.service.Load(ctx)
			}
			if !errors.Is(err, errInjected) {
				t.Fatalf("error=%v", err)
			}
		})
	}
	if err := NewService(&fakeStore{readErr: securitystate.ErrNotFound}, &fakeSealer{}).Load(ctx); err != nil {
		t.Fatalf("unprovisioned load=%v", err)
	}
}

func TestServiceGenerateAndExportFailureMatrix(t *testing.T) {
	ctx := context.Background()
	kekSet := sequence(KEKSetBytes)
	states := map[string]struct {
		state *securitystate.DownlinkKeyState
		err   error
	}{
		"not found":    {nil, securitystate.ErrNotFound},
		"read":         {nil, errInjected},
		"not observed": {&securitystate.DownlinkKeyState{CurrentGeneration: 1}, ErrNotObserved},
		"exhausted":    {&securitystate.DownlinkKeyState{CurrentGeneration: ^uint32(0), CurrentObserved: true}, nil},
	}
	for name, item := range states {
		t.Run("generate "+name, func(t *testing.T) {
			_, err := NewService(&fakeStore{state: item.state, readErr: item.err}, &fakeSealer{plaintext: kekSet}).GenerateNext(ctx)
			if err == nil {
				t.Fatal("generation unexpectedly succeeded")
			}
		})
	}
	ready := &securitystate.DownlinkKeyState{CurrentObserved: true, SealedKEKSet: []byte("sealed")}
	if _, err := NewService(&fakeStore{state: ready}, &fakeSealer{unsealErr: errInjected}).GenerateNext(ctx); !errors.Is(err, errInjected) {
		t.Fatalf("unseal error=%v", err)
	}
	if _, err := NewService(&fakeStore{state: ready, opErr: errInjected}, &fakeSealer{plaintext: kekSet}).GenerateNext(ctx); !errors.Is(err, errInjected) {
		t.Fatalf("advance error=%v", err)
	}

	for name, store := range map[string]*fakeStore{
		"not found": {readErr: securitystate.ErrNotFound},
		"read":      {readErr: errInjected},
		"nil":       {},
		"empty":     {state: &securitystate.DownlinkKeyState{}},
	} {
		t.Run("export "+name, func(t *testing.T) {
			if _, err := NewService(store, &fakeSealer{}).ExportCurrent(ctx); err == nil {
				t.Fatal("export unexpectedly succeeded")
			}
		})
	}
	encoded := []byte("stored")
	digest := Digest(encoded)
	valid := &securitystate.DownlinkKeyState{CurrentGeneration: 1, CurrentPackage: encoded, CurrentDigest: digest}
	got, err := NewService(&fakeStore{state: valid}, &fakeSealer{}).ExportCurrent(ctx)
	if err != nil || string(got) != "stored" {
		t.Fatalf("export=%q err=%v", got, err)
	}
	valid.CurrentDigest[0] ^= 1
	if _, err := NewService(&fakeStore{state: valid}, &fakeSealer{}).ExportCurrent(ctx); err == nil {
		t.Fatal("digest mismatch exported")
	}
}

func TestServiceRawInputAndObservationFailures(t *testing.T) {
	ctx := context.Background()
	service := NewService(&fakeStore{}, &fakeSealer{})
	if _, err := service.UnprotectRaw(ctx, []byte{1}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("short input=%v", err)
	}
	raw := make([]byte, 2+UploadNonceBytes+GCMTagBytes)
	if _, err := service.UnprotectRaw(ctx, raw); !errors.Is(err, ErrNotProvisioned) {
		t.Fatalf("empty cache=%v", err)
	}
	service.replaceCache(sequence(DEKSetBytes), nil, 1, false)
	raw = encryptRawForTest(t, service.current, 0, []byte("payload"), 9)
	service.store = &fakeStore{opErr: errInjected}
	if plaintext, err := service.UnprotectRaw(ctx, raw); !errors.Is(err, errInjected) || plaintext != nil {
		t.Fatalf("plaintext=%x err=%v", plaintext, err)
	}
	service.store = &fakeStore{}
	badSerial := append([]byte(nil), raw...)
	badSerial[0], badSerial[1] = 0xff, 0xff
	if _, err := service.UnprotectRaw(ctx, badSerial); !errors.Is(err, ErrNotProvisioned) {
		t.Fatalf("bad serial=%v", err)
	}
	service.Close()
}

func TestPackageAndTPMInputHardening(t *testing.T) {
	if _, err := EncryptPackage(nil, nil, 0, 0); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid encrypt=%v", err)
	}
	if _, err := (Package{KEKSlot: KEKSlots, Generation: 1}).Decrypt(sequence(KEKSetBytes)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid decrypt=%v", err)
	}
	encoded := make([]byte, PackageBytes)
	encoded[0], encoded[4] = KEKSlots, 1
	if _, err := ParsePackage(encoded); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid slot parse=%v", err)
	}
	if _, err := NewTPMSealer(context.Background(), nil, "", "", nil, nil); err == nil {
		t.Fatal("incomplete TPM context accepted")
	}
	fake := &fakeTPM{storage: &provider.TPMObjectRef{Name: "storage"}}
	sealer, err := NewTPMSealer(context.Background(), fake, "storage", "node", []byte{1}, []byte{2})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sealer.SealKEKSet(context.Background(), []byte{1}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("short KEK set=%v", err)
	}
	if _, err := sealer.UnsealKEKSet(context.Background(), []byte("bad json")); err == nil {
		t.Fatal("corrupt sealed object accepted")
	}
	fake.unsealed = []byte{1}
	object, _ := fake.Seal(context.Background(), fake.storage, []byte{1}, sealer.context)
	encodedObject, _ := marshalSealedObject(object)
	if _, err := sealer.UnsealKEKSet(context.Background(), encodedObject); err == nil {
		t.Fatal("short unsealed KEK set accepted")
	}
}

func TestPackageRandomFailureAndStoredCorruption(t *testing.T) {
	original := randomRead
	randomRead = func([]byte) (int, error) { return 0, errInjected }
	t.Cleanup(func() { randomRead = original })
	if deks, err := GenerateDEKSet(); !errors.Is(err, errInjected) || deks != nil {
		t.Fatalf("deks=%x err=%v", deks, err)
	}
	if _, err := EncryptPackage(sequence(KEKSetBytes), sequence(DEKSetBytes), 0, 1); !errors.Is(err, errInjected) {
		t.Fatalf("nonce failure=%v", err)
	}
	if _, err := decryptStoredPackage(nil, [32]byte{}, 1, sequence(KEKSetBytes)); err == nil {
		t.Fatal("missing stored package accepted")
	}
	encoded := make([]byte, PackageBytes)
	encoded[4] = 2
	digest := Digest(encoded)
	if _, err := decryptStoredPackage(encoded, digest, 1, sequence(KEKSetBytes)); err == nil {
		t.Fatal("stored generation mismatch accepted")
	}
}

func TestTPMSealerPropagatesProviderFailures(t *testing.T) {
	ctx := context.Background()
	if _, err := NewTPMSealer(ctx, &fakeTPM{ensureErr: errInjected}, "storage", "node", []byte{1}, []byte{2}); !errors.Is(err, errInjected) {
		t.Fatalf("ensure error=%v", err)
	}
	for name, item := range map[string]struct {
		fake          *fakeTPM
		sealOperation bool
	}{
		"seal":   {&fakeTPM{storage: &provider.TPMObjectRef{Name: "storage"}, sealErr: errInjected}, true},
		"unseal": {&fakeTPM{storage: &provider.TPMObjectRef{Name: "storage"}, unsealErr: errInjected}, false},
	} {
		t.Run(name, func(t *testing.T) {
			sealer, err := NewTPMSealer(ctx, item.fake, "storage", "node", []byte{1}, []byte{2})
			if err != nil {
				t.Fatal(err)
			}
			if item.sealOperation {
				_, err = sealer.SealKEKSet(ctx, sequence(KEKSetBytes))
			} else {
				encoded, marshalErr := json.Marshal(&provider.SealedObject{})
				if marshalErr != nil {
					t.Fatal(marshalErr)
				}
				_, err = sealer.UnsealKEKSet(ctx, encoded)
			}
			if !errors.Is(err, errInjected) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

type fakeTPM struct {
	storage   *provider.TPMObjectRef
	unsealed  []byte
	ensureErr error
	sealErr   error
	unsealErr error
}

func (f *fakeTPM) EnsureStorage(context.Context, string) (*provider.TPMObjectRef, error) {
	return f.storage, f.ensureErr
}
func (f *fakeTPM) Seal(_ context.Context, storage *provider.TPMObjectRef, plaintext []byte, seal aad.SealContext) (*provider.SealedObject, error) {
	return &provider.SealedObject{StorageName: storage.Name, Blob: append([]byte(nil), plaintext...), Purpose: seal.Purpose}, f.sealErr
}
func (f *fakeTPM) Unseal(context.Context, *provider.TPMObjectRef, *provider.SealedObject, aad.SealContext) ([]byte, error) {
	return append([]byte(nil), f.unsealed...), f.unsealErr
}
func (f *fakeTPM) Quote(context.Context, []byte, []int) ([]byte, error) { return nil, nil }
func (f *fakeTPM) Close() error                                         { return nil }

func marshalSealedObject(object *provider.SealedObject) ([]byte, error) {
	return json.Marshal(object)
}
