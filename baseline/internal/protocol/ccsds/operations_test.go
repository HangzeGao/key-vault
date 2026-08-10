package ccsds

import (
	"context"
	"testing"
)

func TestOperationsStatusReportsReadyRuntimeStateWithoutMutation(t *testing.T) {
	security, store := newTestSecurity(t, &fakeCore{}, tcAssociation(), nextTCAssociation(), recoveryAssociation(), aosAssociation())
	if _, err := store.NextTransmitCounter(context.Background(), "tx-current"); err != nil {
		t.Fatal(err)
	}
	if err := store.CommitReplay(context.Background(), "rx", 19, 32); err != nil {
		t.Fatal(err)
	}

	status, err := security.OperationsStatus(context.Background(), "tenant-1")
	if err != nil {
		t.Fatal(err)
	}
	if !status.Ready || status.Status != "READY" || len(status.Warnings) != 0 || len(status.AOSActive) != 1 {
		t.Fatalf("unexpected operations status: %+v", status)
	}
	if status.TCCurrent == nil || status.TCCurrent.NextIVCounter == nil || *status.TCCurrent.NextIVCounter != 1 {
		t.Fatalf("unexpected TC current state: %+v", status.TCCurrent)
	}
	if !status.AOSActive[0].ReplaySeen || status.AOSActive[0].ReplayHighest == nil || *status.AOSActive[0].ReplayHighest != 19 {
		t.Fatalf("unexpected AOS replay state: %+v", status.AOSActive[0])
	}
	allocated, err := store.NextTransmitCounter(context.Background(), "tx-current")
	if err != nil || allocated != 1 {
		t.Fatalf("status read mutated counter: allocated=%d err=%v", allocated, err)
	}
}

func TestOperationsStatusReportsUnconfiguredTenant(t *testing.T) {
	security, _ := newTestSecurity(t, &fakeCore{})
	status, err := security.OperationsStatus(context.Background(), "tenant-1")
	if err != nil {
		t.Fatal(err)
	}
	if status.Status != "UNCONFIGURED" || status.Ready || len(status.Warnings) != 4 {
		t.Fatalf("unexpected unconfigured status: %+v", status)
	}
}
