package securitystate

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/kvlt/key-vault/internal/protocol/ccsds"
)

func TestOrdinaryCounterLimitSurvivesDatabaseRestart(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state.db")
	store := openTestStore(t, path)
	provisionTestTC(t, store)
	for i := 0; i < ccsds.TCOrdinaryFrameLimit; i++ {
		n, err := store.NextTransmitCounter(ctx, "current")
		if err != nil || n != uint32(i) {
			t.Fatal(i, n, err)
		}
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store = openTestStore(t, path)
	defer store.Close()
	if _, err := store.NextTransmitCounter(ctx, "current"); !errors.Is(err, ccsds.ErrCounterExhausted) {
		t.Fatal("ordinary budget reset", err)
	}
	if n, err := store.NextTransmitCounter(ctx, "recovery"); err != nil || n != 0 {
		t.Fatal("ordinary cap blocked Recovery", n, err)
	}
}

func TestRoutineRotationPersistsFutureAssociationAndRollback(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t, filepath.Join(t.TempDir(), "state.db"))
	defer store.Close()
	provisionTestTC(t, store)
	rotation := ccsds.TCRotationState{Phase: ccsds.TCRotationPrepared, TransactionID: 1, CurrentSPI: 0x1001, NextSPI: 0x1002, CurrentRootVersion: 1, NextRootVersion: 2}
	if err := store.MarkTCRotationPrepared(ctx, "tenant-1", rotation); err != nil {
		t.Fatal(err)
	}
	if err := store.PromoteNextTC(ctx, "tenant-1"); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkTCRotationFrameProduced(ctx, "tenant-1", "next"); err != nil {
		t.Fatal(err)
	}
	if err := store.PromoteNextTC(ctx, "tenant-1"); !errors.Is(err, ccsds.ErrAssociationState) {
		t.Fatal("unconfirmed routine promotion allowed", err)
	}
	observed := ccsds.FlightSecurityStatus{FormatVersion: 2, ProfileDigest: [32]byte{1}, SelfTest: ccsds.FlightSelfTestPassed, CryptoBackend: ccsds.FlightBackendSoftware, CurrentSPI: 0x1002, NextSPI: 0x1003, SecurityEpoch: 2, RootVersion: 2, CurrentAuthUsed: 2048, NextAuthUsed: 10}
	if err := store.BindMissionProfile(ctx, "tenant-1", [32]byte{1}); err != nil {
		t.Fatal(err)
	}
	if err := store.ObserveFlightSecurityStatus(ctx, "tenant-1", observed); err != nil {
		t.Fatal(err)
	}
	if got, err := store.ReadFlightSecurityStatus(ctx, "tenant-1"); err != nil || got.CurrentAuthUsed != 2048 || got.NextAuthUsed != 10 {
		t.Fatal(got, err)
	}
	retired := *mustAssociation(t, store, "current")
	retired.ID = "retired-future-slot"
	retired.SPI = 0x1004
	retired.State = ccsds.AssociationDisabled
	if err := store.CreateAssociation(ctx, retired); err != nil {
		t.Fatal(err)
	}
	for _, trigger := range []string{
		`CREATE TRIGGER inject_future BEFORE INSERT ON security_associations BEGIN SELECT RAISE(ABORT,'injected future association'); END`,
		`CREATE TRIGGER inject_future BEFORE INSERT ON tx_states BEGIN SELECT RAISE(ABORT,'injected counter'); END`,
		`CREATE TRIGGER inject_future BEFORE INSERT ON tc_rotation_states BEGIN SELECT RAISE(ABORT,'injected preparation'); END`,
		`CREATE TRIGGER inject_future BEFORE DELETE ON security_associations BEGIN SELECT RAISE(ABORT,'injected retirement'); END`,
	} {
		if _, err := store.db.ExecContext(ctx, trigger); err != nil {
			t.Fatal(err)
		}
		if err := store.PromoteNextTC(ctx, "tenant-1"); err == nil {
			t.Fatal("write fault ignored")
		}
		current, err := store.GetTransmitAssociation(ctx, "tenant-1", ccsds.DirectionTCTx)
		if err != nil || current.SPI != 0x1002 {
			t.Fatal("partially committed routine rotation", current, err)
		}
		if _, err := store.db.ExecContext(ctx, `DROP TRIGGER inject_future`); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.PromoteNextTC(ctx, "tenant-1"); err != nil {
		t.Fatal(err)
	}
	current, err := store.GetTransmitAssociation(ctx, "tenant-1", ccsds.DirectionTCTx)
	if err != nil || current.SPI != 0x1003 || current.SecurityEpoch != 3 {
		t.Fatal(current, err)
	}
	future, err := store.GetAssociationBySPI(ctx, "tenant-1", ccsds.DirectionTCTx, 0x1004)
	if err != nil || future.SecurityEpoch != 4 || future.KeyID != current.KeyID || future.KeyVersion != 2 {
		t.Fatal(future, err)
	}
	if n, err := store.NextTransmitCounter(ctx, current.ID); err != nil || n != 0 {
		t.Fatal(n, err)
	}
}
