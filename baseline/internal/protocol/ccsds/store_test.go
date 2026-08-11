package ccsds

import (
	"context"
	"errors"
	"testing"
)

func TestMemoryStoreStrictLookupAndBinding(t *testing.T) {
	ctx := context.Background()
	invalid := tcAssociation()
	invalid.ID = ""
	if _, err := NewMemoryStore(invalid); err == nil {
		t.Fatal("invalid association accepted")
	}
	store, err := NewMemoryStore(tcAssociation())
	if err != nil {
		t.Fatal(err)
	}
	duplicate := tcAssociation()
	duplicate.ID = "duplicate"
	if err := store.PutAssociation(duplicate); err == nil {
		t.Fatal("duplicate SPI accepted")
	}
	updated := tcAssociation()
	updated.SPI++
	originalPrefix := append([]byte(nil), updated.Parameters.NoncePrefix...)
	if err := store.PutAssociation(updated); err != nil {
		t.Fatal(err)
	}
	updated.Parameters.NoncePrefix[0] ^= 1
	if _, err := store.GetAssociationBySPI(ctx, "tenant-1", DirectionTCTx, 0x1001); !errors.Is(err, ErrAssociationNotFound) {
		t.Fatalf("old SPI lookup = %v", err)
	}
	got, err := store.GetAssociation(ctx, "tenant-1", updated.ID)
	if err != nil || got.Parameters.NoncePrefix[0] != originalPrefix[0] {
		t.Fatalf("stored association was not cloned: %+v/%v", got, err)
	}
	got.Parameters.NoncePrefix[0] ^= 1
	again, _ := store.GetAssociation(ctx, "tenant-1", updated.ID)
	if again.Parameters.NoncePrefix[0] != originalPrefix[0] {
		t.Fatal("returned association mutated store")
	}
	if _, err := store.GetAssociation(ctx, "wrong", updated.ID); !errors.Is(err, ErrAssociationNotFound) {
		t.Fatalf("cross-tenant lookup = %v", err)
	}
	if _, err := store.GetAssociation(ctx, "tenant-1", "missing"); !errors.Is(err, ErrAssociationNotFound) {
		t.Fatalf("missing lookup = %v", err)
	}
	if _, err := store.GetAssociationBySPI(ctx, "tenant-1", DirectionTCTx, 9); !errors.Is(err, ErrAssociationNotFound) {
		t.Fatalf("missing SPI lookup = %v", err)
	}
	if _, err := store.GetTransmitAssociation(ctx, "tenant-1", DirectionAOSRx); !errors.Is(err, ErrAssociationState) {
		t.Fatalf("invalid transmit direction = %v", err)
	}
	if _, err := store.GetTransmitAssociation(ctx, "missing", DirectionTCTx); !errors.Is(err, ErrAssociationNotFound) {
		t.Fatalf("missing transmit association = %v", err)
	}
}

func TestMemoryStoreRejectsAmbiguousAndInvalidTransitions(t *testing.T) {
	ctx := context.Background()
	second := tcAssociation()
	second.ID = "current-2"
	second.SPI = 0x2001
	store, err := NewMemoryStore(tcAssociation(), second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetTransmitAssociation(ctx, "tenant-1", DirectionTCTx); !errors.Is(err, ErrAssociationState) {
		t.Fatalf("ambiguous current = %v", err)
	}
	if err := store.PromoteNextTC(ctx, "tenant-1"); !errors.Is(err, ErrAssociationState) {
		t.Fatalf("ambiguous promotion = %v", err)
	}

	for _, mutate := range []func(*SecurityAssociation){
		func(next *SecurityAssociation) { next.SecurityEpoch++ },
		func(next *SecurityAssociation) { next.SPI++ },
		func(next *SecurityAssociation) { next.Parameters.NoncePrefix[0] ^= 1 },
	} {
		current := tcAssociation()
		next := nextTCAssociation()
		mutate(&next)
		candidate, err := NewMemoryStore(current, next)
		if err != nil {
			t.Fatal(err)
		}
		if err := candidate.PromoteNextTC(ctx, "tenant-1"); !errors.Is(err, ErrAssociationState) {
			t.Fatalf("invalid promotion accepted: %v", err)
		}
	}
}

func TestMemoryStoreCounterAndReplayFailures(t *testing.T) {
	ctx := context.Background()
	store, err := NewMemoryStore(tcAssociation(), nextTCAssociation(), aosAssociation())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.NextTransmitCounter(ctx, "missing"); !errors.Is(err, ErrAssociationNotFound) {
		t.Fatalf("missing counter = %v", err)
	}
	if _, err := store.NextTransmitCounter(ctx, "tx-next"); !errors.Is(err, ErrAssociationState) {
		t.Fatalf("NEXT counter = %v", err)
	}
	if _, err := store.NextTransmitCounter(ctx, "rx"); !errors.Is(err, ErrAssociationState) {
		t.Fatalf("AOS counter = %v", err)
	}
	store.txNext["tx-current"] = uint64(1) << 32
	if _, err := store.NextTransmitCounter(ctx, "tx-current"); !errors.Is(err, ErrCounterExhausted) {
		t.Fatalf("exhausted counter = %v", err)
	}
	if err := store.CheckReplay(ctx, "missing", 1, 32); !errors.Is(err, ErrAssociationNotFound) {
		t.Fatalf("missing replay = %v", err)
	}
	if err := store.CheckReplay(ctx, "tx-current", 1, 32); !errors.Is(err, ErrAssociationState) {
		t.Fatalf("TC replay check = %v", err)
	}
	if err := store.CommitReplay(ctx, "rx", 1, 0); !errors.Is(err, ErrReplay) {
		t.Fatalf("zero replay window = %v", err)
	}
	if err := store.CommitReplay(ctx, "rx", 10, 64); err != nil {
		t.Fatal(err)
	}
	if err := store.CommitReplay(ctx, "rx", 12, 64); err != nil {
		t.Fatal(err)
	}
	if err := store.CommitReplay(ctx, "rx", 11, 64); err != nil {
		t.Fatal(err)
	}
	if err := store.CommitReplay(ctx, "rx", 11, 64); !errors.Is(err, ErrReplay) {
		t.Fatalf("duplicate sequence = %v", err)
	}
	state := ReplayState{Highest: 1, Bitmap: 1, Seen: true}
	if err := state.Commit(70, 64); err != nil || state.Highest != 70 || state.Bitmap != 1 {
		t.Fatalf("large replay shift = %+v/%v", state, err)
	}
	if err := state.Check(1, 65); !errors.Is(err, ErrReplay) {
		t.Fatalf("oversized replay window = %v", err)
	}
}

func TestMemoryStoreRotationLifecycleIsClosed(t *testing.T) {
	ctx := context.Background()
	current, next := tcAssociation(), nextTCAssociation()
	store, err := NewMemoryStore(current, next)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReadTCRotationState(ctx, "tenant-1"); !errors.Is(err, ErrAssociationNotFound) {
		t.Fatalf("missing=%v", err)
	}
	invalid := TCRotationState{Phase: TCRotationPrepared, TransactionID: 1, CurrentSPI: current.SPI,
		NextSPI: next.SPI, CurrentRootVersion: current.KeyVersion, NextRootVersion: current.KeyVersion}
	if err := store.MarkTCRotationPrepared(ctx, "tenant-1", invalid); !errors.Is(err, ErrAssociationState) {
		t.Fatalf("invalid=%v", err)
	}
	prepared := TCRotationState{Phase: TCRotationPrepared, TransactionID: 2, CurrentSPI: current.SPI,
		NextSPI: next.SPI, CurrentRootVersion: current.KeyVersion, NextRootVersion: next.KeyVersion}
	if err := store.MarkTCRotationPrepared(ctx, "tenant-1", prepared); err != nil {
		t.Fatal(err)
	}
	if state, err := store.ReadTCRotationState(ctx, "tenant-1"); err != nil || state.TransactionID != 2 {
		t.Fatalf("state=%+v err=%v", state, err)
	}
	if err := store.MarkTCRotationFrameProduced(ctx, "tenant-1", current.ID); !errors.Is(err, ErrAssociationState) {
		t.Fatalf("early frame=%v", err)
	}
	if err := store.PromoteNextTC(ctx, "tenant-1"); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkTCRotationFrameProduced(ctx, "tenant-1", "missing"); !errors.Is(err, ErrAssociationState) {
		t.Fatalf("wrong frame=%v", err)
	}
	if err := store.MarkTCRotationFrameProduced(ctx, "tenant-1", next.ID); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkTCRotationFrameProduced(ctx, "tenant-1", next.ID); err != nil {
		t.Fatal(err)
	}
	state, err := store.ReadTCRotationState(ctx, "tenant-1")
	if err != nil || state.Phase != TCRotationActive {
		t.Fatalf("state=%+v err=%v", state, err)
	}
	empty, _ := NewMemoryStore(current)
	if err := empty.MarkTCRotationFrameProduced(ctx, "tenant-1", current.ID); err != nil {
		t.Fatal(err)
	}
}
