package ccsds

import (
	"context"
	"errors"
	"testing"
)

func TestRoutineWorkingKeyRotationAndCounterLimit(t *testing.T) {
	ctx := context.Background()
	current, next := tcAssociation(), nextTCAssociation()
	current.SPI = 0xfffe
	next.SPI = 0xffff
	next.KeyVersion = current.KeyVersion
	next.KeyID = current.KeyID
	retired := current
	retired.ID = "retired-wrapped"
	retired.SPI = 0
	retired.State = AssociationDisabled
	store, err := NewMemoryStore(current, next, retired)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.BindMissionProfile(current.TenantID, [32]byte{1}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < TCOrdinaryFrameLimit; i++ {
		n, err := store.NextTransmitCounter(ctx, current.ID)
		if err != nil || n != uint32(i) {
			t.Fatal(i, n, err)
		}
	}
	if _, err := store.NextTransmitCounter(ctx, current.ID); !errors.Is(err, ErrCounterExhausted) {
		t.Fatal(err)
	}
	if err := store.PromoteNextTC(ctx, current.TenantID); !errors.Is(err, ErrAssociationState) {
		t.Fatal("missing observation accepted", err)
	}
	observed := FlightSecurityStatus{FormatVersion: FlightSecurityStatusVersion, ProfileDigest: [32]byte{1}, SelfTest: FlightSelfTestPassed, CryptoBackend: FlightBackendSoftware, CurrentSPI: current.SPI, NextSPI: next.SPI, SecurityEpoch: current.SecurityEpoch, RootVersion: current.KeyVersion}
	for _, mutate := range []func(*FlightSecurityStatus){func(s *FlightSecurityStatus) { s.ReceptionPaused = true }, func(s *FlightSecurityStatus) { s.PendingRootPresent = true }, func(s *FlightSecurityStatus) { s.SecurityEpoch++ }, func(s *FlightSecurityStatus) { s.RootVersion++ }, func(s *FlightSecurityStatus) { s.SelfTest = FlightSelfTestLocked }, func(s *FlightSecurityStatus) { s.ProfileDigest[0]++ }, func(s *FlightSecurityStatus) { s.NextAuthUsed = 2048 }} {
		bad := observed
		mutate(&bad)
		if err := store.ObserveFlightSecurityStatus(ctx, current.TenantID, bad); err != nil {
			t.Fatal(err)
		}
		if err := store.PromoteNextTC(ctx, current.TenantID); !errors.Is(err, ErrAssociationState) {
			t.Fatal("unsafe observation accepted", err)
		}
	}
	if err := store.ObserveFlightSecurityStatus(ctx, current.TenantID, observed); err != nil {
		t.Fatal(err)
	}
	if err := store.PromoteNextTC(ctx, current.TenantID); err != nil {
		t.Fatal(err)
	}
	future, err := store.GetAssociationBySPI(ctx, current.TenantID, DirectionTCTx, 0)
	if err != nil || future.SecurityEpoch != next.SecurityEpoch+1 || future.KeyID != next.KeyID || future.State != AssociationNext {
		t.Fatal(future, err)
	}
	if _, err := store.GetAssociation(ctx, current.TenantID, retired.ID); !errors.Is(err, ErrAssociationNotFound) {
		t.Fatal("retired SPI binding remained", err)
	}
	n, err := store.NextTransmitCounter(ctx, next.ID)
	if err != nil || n != 0 {
		t.Fatal("new key counter was not independent", n, err)
	}
	if err := store.MarkTCRotationFrameProduced(ctx, current.TenantID, next.ID); err != nil {
		t.Fatal(err)
	}
	if err := store.PromoteNextTC(ctx, current.TenantID); !errors.Is(err, ErrAssociationState) {
		t.Fatal("advanced while flight remained behind", err)
	}
}

func TestAuthenticationBudgetTelemetryValidationAndWarnings(t *testing.T) {
	base := validFlightStatus()
	for _, edit := range []func(*FlightSecurityStatus){func(s *FlightSecurityStatus) { s.CurrentAuthUsed = 2049 }, func(s *FlightSecurityStatus) { s.NextAuthUsed = 2049 }, func(s *FlightSecurityStatus) { s.CurrentAuthUsed = 1 }, func(s *FlightSecurityStatus) { s.NextAuthUsed = 1 }} {
		bad := base
		edit(&bad)
		if bad.Validate() == nil {
			t.Fatal("overspent authentication budget accepted")
		}
	}
	security, store := newTestSecurity(t, &fakeCore{}, tcAssociation(), nextTCAssociation(), recoveryAssociation())
	prepareTestRotation(t, store, tcAssociation(), nextTCAssociation())
	status := store.flight["tenant-1"].FlightSecurityStatus
	status.CurrentAuthUsed = 1844
	status.NextAuthUsed = 2048
	status.ReceptionPaused = true
	if err := store.ObserveFlightSecurityStatus(context.Background(), "tenant-1", status); err != nil {
		t.Fatal(err)
	}
	result, err := security.OperationsStatus(context.Background(), "tenant-1")
	if err != nil {
		t.Fatal(err)
	}
	for _, warning := range []string{"FLIGHT_AUTH_BUDGET_LOW", "FLIGHT_NEXT_AUTH_BUDGET_LOW", "FLIGHT_RECEPTION_PAUSED"} {
		if !containsWarning(result.Warnings, warning) {
			t.Fatal("missing warning", warning)
		}
	}
	if result.Ready {
		t.Fatal("paused or depleted flight marked ready")
	}
}

type publicationFaultStore struct {
	Store
	failure error
}

func (s publicationFaultStore) MarkTCRotationFrameProduced(context.Context, string, string) error {
	return s.failure
}

func TestProtectionNeverReturnsFrameAfterDurablePublicationFailure(t *testing.T) {
	ctx := context.Background()
	memory, err := NewMemoryStore(tcAssociation())
	if err != nil {
		t.Fatal(err)
	}
	fault := errors.New("injected rotation evidence failure")
	service, err := New(&fakeCore{}, publicationFaultStore{Store: memory, failure: fault}, Options{MaxFrameLength: 1024, NodeID: "test", TCSpacecraftID: 1})
	if err != nil {
		t.Fatal(err)
	}
	frame := plainTCFrame(t, make([]byte, 16))
	got, err := service.ProtectTCFrame(ctx, "tenant-1", frame)
	if !errors.Is(err, fault) || got != nil || memory.txNext[tcAssociation().ID] != 1 {
		t.Fatal("failed publication exposed frame or refunded nonce", got, err)
	}
	memory.txNext[tcAssociation().ID] = TCOrdinaryFrameLimit
	got, err = service.ProtectTCFrame(ctx, "tenant-1", frame)
	if !errors.Is(err, ErrCounterExhausted) || got != nil {
		t.Fatal("spent key protected a frame", got, err)
	}
	corrupted := tcAssociation()
	corrupted.Parameters.TagLength = 16
	memory.byID[corrupted.ID] = corrupted
	got, err = service.ProtectTCFrame(ctx, "tenant-1", frame)
	if !errors.Is(err, ErrFrameInvalid) || got != nil {
		t.Fatal("ordinary association accepted full-tag parameters", got, err)
	}
}
