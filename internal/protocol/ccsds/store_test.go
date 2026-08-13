package ccsds

import (
	"context"
	"errors"
	"testing"
)

func TestMemoryStoreTCLookupCounterAndRotation(t *testing.T) {
	ctx := context.Background()
	current, next := tcAssociation(), nextTCAssociation()
	store, err := NewMemoryStore(current, next, recoveryAssociation())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetAssociation(ctx, "wrong", current.ID); !errors.Is(err, ErrAssociationNotFound) {
		t.Fatalf("cross-tenant error=%v", err)
	}
	if counter, err := store.NextTransmitCounter(ctx, current.ID); err != nil || counter != 0 {
		t.Fatalf("counter=%d err=%v", counter, err)
	}
	store.txNext[current.ID] = uint64(1) << 32
	if _, err := store.NextTransmitCounter(ctx, current.ID); !errors.Is(err, ErrCounterExhausted) {
		t.Fatalf("counter exhaustion=%v", err)
	}
	prepared := TCRotationState{Phase: TCRotationPrepared, TransactionID: 1,
		CurrentSPI: current.SPI, NextSPI: next.SPI, CurrentRootVersion: current.KeyVersion, NextRootVersion: next.KeyVersion}
	if err := store.MarkTCRotationPrepared(ctx, current.TenantID, prepared); err != nil {
		t.Fatal(err)
	}
	if err := store.PromoteNextTC(ctx, current.TenantID); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkTCRotationFrameProduced(ctx, current.TenantID, next.ID); err != nil {
		t.Fatal(err)
	}
	state, err := store.ReadTCRotationState(ctx, current.TenantID)
	if err != nil || state.Phase != TCRotationActive {
		t.Fatalf("rotation=%+v err=%v", state, err)
	}
}

func TestMemoryStoreRejectsInvalidAndAmbiguousState(t *testing.T) {
	invalid := tcAssociation()
	invalid.ID = ""
	if _, err := NewMemoryStore(invalid); err == nil {
		t.Fatal("invalid association accepted")
	}
	first := tcAssociation()
	second := tcAssociation()
	second.ID = "second"
	second.SPI++
	store, err := NewMemoryStore(first, second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetTransmitAssociation(context.Background(), "tenant-1", DirectionTCTx); !errors.Is(err, ErrAssociationState) {
		t.Fatalf("ambiguous transmit=%v", err)
	}
}

func TestMemoryStoreStrictBoundaryMatrix(t *testing.T) {
	ctx := context.Background()
	store, err := NewMemoryStore()
	if err != nil {
		t.Fatal(err)
	}
	digest := [32]byte{1}
	if err := store.BindMissionProfile("", digest); !errors.Is(err, ErrAssociationState) {
		t.Fatalf("empty profile tenant error=%v", err)
	}
	if err := store.BindMissionProfile("tenant", [32]byte{}); !errors.Is(err, ErrAssociationState) {
		t.Fatalf("zero profile error=%v", err)
	}
	if err := store.BindMissionProfile("tenant", digest); err != nil {
		t.Fatal(err)
	}
	if err := store.BindMissionProfile("tenant", digest); err != nil {
		t.Fatal(err)
	}
	other := digest
	other[0]++
	if err := store.BindMissionProfile("tenant", other); !errors.Is(err, ErrAssociationState) {
		t.Fatalf("profile replacement error=%v", err)
	}
	if got, err := store.ReadMissionProfileDigest(ctx, "tenant"); err != nil || got != digest {
		t.Fatalf("digest=%x err=%v", got, err)
	}
	if _, err := store.ReadMissionProfileDigest(ctx, "missing"); !errors.Is(err, ErrAssociationNotFound) {
		t.Fatalf("missing profile error=%v", err)
	}
	if _, err := store.ReadFlightSecurityStatus(ctx, "tenant"); !errors.Is(err, ErrAssociationNotFound) {
		t.Fatalf("missing flight status error=%v", err)
	}
	if err := store.ObserveFlightSecurityStatus(ctx, "", FlightSecurityStatus{}); !errors.Is(err, ErrAssociationState) {
		t.Fatalf("invalid flight status error=%v", err)
	}
	status := FlightSecurityStatus{FormatVersion: 1, ProfileDigest: digest, SelfTest: FlightSelfTestPassed,
		CryptoBackend: FlightBackendSoftware, CurrentSPI: 1, NextSPI: 2, SecurityEpoch: 1, RootVersion: 1}
	if err := store.ObserveFlightSecurityStatus(ctx, "tenant", status); err != nil {
		t.Fatal(err)
	}
	observed, err := store.ReadFlightSecurityStatus(ctx, "tenant")
	if err != nil || observed.ObservedAt.IsZero() {
		t.Fatalf("observed=%+v err=%v", observed, err)
	}

	current, next, recovery := tcAssociation(), nextTCAssociation(), recoveryAssociation()
	if err := store.PutAssociation(current); err != nil {
		t.Fatal(err)
	}
	conflict := current
	conflict.ID = "other"
	if err := store.PutAssociation(conflict); err == nil {
		t.Fatal("duplicate SPI accepted")
	}
	updated := current
	updated.SPI = 0x2001
	if err := store.PutAssociation(updated); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetAssociationBySPI(ctx, current.TenantID, current.Direction, current.SPI); !errors.Is(err, ErrAssociationNotFound) {
		t.Fatalf("stale SPI binding error=%v", err)
	}
	if err := store.PutAssociation(current); err != nil {
		t.Fatal(err)
	}
	if err := store.PutAssociation(next); err != nil {
		t.Fatal(err)
	}
	if err := store.PutAssociation(recovery); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetAssociationBySPI(ctx, "tenant-1", DirectionTCTx, 0xffff); !errors.Is(err, ErrAssociationNotFound) {
		t.Fatalf("missing SPI error=%v", err)
	}
	states, err := store.ReadOperationsState(ctx, "tenant-1")
	if err != nil || len(states) != 3 || states[0].NextIVCounter == nil {
		t.Fatalf("states=%+v err=%v", states, err)
	}
	if _, err := store.ReadTCRotationState(ctx, "tenant-1"); !errors.Is(err, ErrAssociationNotFound) {
		t.Fatalf("missing rotation error=%v", err)
	}
	invalidRotation := TCRotationState{Phase: TCRotationPrepared, TransactionID: 0}
	if err := store.MarkTCRotationPrepared(ctx, "tenant-1", invalidRotation); !errors.Is(err, ErrAssociationState) {
		t.Fatalf("invalid prepare error=%v", err)
	}
	wrongVersion := TCRotationState{Phase: TCRotationPrepared, TransactionID: 1,
		CurrentSPI: current.SPI, NextSPI: next.SPI, CurrentRootVersion: current.KeyVersion, NextRootVersion: next.KeyVersion + 1}
	if err := store.MarkTCRotationPrepared(ctx, "tenant-1", wrongVersion); !errors.Is(err, ErrAssociationState) {
		t.Fatalf("wrong version prepare error=%v", err)
	}
	if err := store.MarkTCRotationFrameProduced(ctx, "missing", "missing"); err != nil {
		t.Fatalf("missing rotation completion should be idempotent: %v", err)
	}
	prepared := TCRotationState{Phase: TCRotationPrepared, TransactionID: 1,
		CurrentSPI: current.SPI, NextSPI: next.SPI, CurrentRootVersion: current.KeyVersion, NextRootVersion: next.KeyVersion}
	if err := store.MarkTCRotationPrepared(ctx, "tenant-1", prepared); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkTCRotationFrameProduced(ctx, "tenant-1", "tx-next"); !errors.Is(err, ErrAssociationState) {
		t.Fatalf("early completion error=%v", err)
	}
	if _, err := store.NextTransmitCounter(ctx, "missing"); !errors.Is(err, ErrAssociationNotFound) {
		t.Fatalf("missing counter error=%v", err)
	}
	if _, err := store.NextTransmitCounter(ctx, next.ID); !errors.Is(err, ErrAssociationState) {
		t.Fatalf("inactive counter error=%v", err)
	}
}
