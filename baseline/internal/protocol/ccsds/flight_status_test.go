package ccsds

import (
	"context"
	"errors"
	"testing"
)

type flightStatusErrorStore struct {
	*MemoryStore
	readErr    error
	observeErr error
}

func (store *flightStatusErrorStore) ReadMissionProfileDigest(context.Context, string) ([32]byte, error) {
	return [32]byte{}, store.readErr
}

func (store *flightStatusErrorStore) ObserveFlightSecurityStatus(context.Context, string, FlightSecurityStatus) error {
	return store.observeErr
}

func validFlightStatus() FlightSecurityStatus {
	return FlightSecurityStatus{FormatVersion: FlightSecurityStatusVersion, ProfileDigest: [32]byte{1},
		SelfTest: FlightSelfTestPassed, CryptoBackend: FlightBackendSoftware,
		CurrentSPI: 0xffff, NextSPI: 0, RecoverySPI: 0x7001, SecurityEpoch: 1, RootVersion: 1}
}

func TestFlightSecurityStatusStrictValidation(t *testing.T) {
	valid := validFlightStatus()
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	cases := []FlightSecurityStatus{valid, valid, valid, valid, valid, valid, valid}
	cases[0].FormatVersion = 2
	cases[1].ProfileDigest = [32]byte{}
	cases[2].SelfTest = "UNKNOWN"
	cases[3].CryptoBackend = "UNKNOWN"
	cases[4].NextSPI = 1
	cases[5].SecurityEpoch = 0
	cases[6].RootVersion = 0
	for index, status := range cases {
		if err := status.Validate(); err == nil {
			t.Fatalf("invalid case %d accepted", index)
		}
	}
}

func TestObserveFlightSecurityStatusClosesStoreLoop(t *testing.T) {
	memory, _ := NewMemoryStore()
	digest := [32]byte{1}
	if err := memory.BindMissionProfile("", digest); !errors.Is(err, ErrAssociationState) {
		t.Fatalf("empty tenant error=%v", err)
	}
	if err := memory.BindMissionProfile("tenant-1", [32]byte{}); !errors.Is(err, ErrAssociationState) {
		t.Fatalf("zero digest error=%v", err)
	}
	if err := memory.BindMissionProfile("tenant-1", digest); err != nil {
		t.Fatal(err)
	}
	if err := memory.BindMissionProfile("tenant-1", [32]byte{2}); !errors.Is(err, ErrAssociationState) {
		t.Fatalf("changed digest error=%v", err)
	}
	if _, err := memory.ReadMissionProfileDigest(context.Background(), "missing"); !errors.Is(err, ErrAssociationNotFound) {
		t.Fatalf("missing digest error=%v", err)
	}
	if _, err := memory.ReadFlightSecurityStatus(context.Background(), "tenant-1"); !errors.Is(err, ErrAssociationNotFound) {
		t.Fatalf("missing status error=%v", err)
	}
	security := &FrameSecurity{store: memory}
	status := validFlightStatus()
	if err := security.ObserveFlightSecurityStatus(context.Background(), "tenant-1", status); err != nil {
		t.Fatal(err)
	}
	observed, err := memory.ReadFlightSecurityStatus(context.Background(), "tenant-1")
	if err != nil || observed.ProfileDigest != digest {
		t.Fatalf("observed=%+v err=%v", observed, err)
	}
	if err := security.ObserveFlightSecurityStatus(context.Background(), "", status); err == nil {
		t.Fatal("empty tenant accepted")
	}
	invalid := status
	invalid.RootVersion = 0
	if err := security.ObserveFlightSecurityStatus(context.Background(), "tenant-1", invalid); err == nil {
		t.Fatal("invalid status accepted")
	}
	if err := memory.ObserveFlightSecurityStatus(context.Background(), "", invalid); !errors.Is(err, ErrAssociationState) {
		t.Fatalf("memory invalid status error=%v", err)
	}
	wanted := errors.New("failed")
	readFailure := &FrameSecurity{store: &flightStatusErrorStore{MemoryStore: memory, readErr: wanted}}
	if err := readFailure.ObserveFlightSecurityStatus(context.Background(), "tenant-1", status); !errors.Is(err, wanted) {
		t.Fatalf("read error=%v", err)
	}
	observeFailure := &FrameSecurity{store: &flightStatusErrorStore{MemoryStore: memory, observeErr: wanted}}
	if err := observeFailure.ObserveFlightSecurityStatus(context.Background(), "tenant-1", status); !errors.Is(err, wanted) {
		t.Fatalf("observe error=%v", err)
	}
}
