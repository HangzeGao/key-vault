package ccsds

import (
	"context"
	"testing"
)

func TestOperationsStatusReportsReadyRuntimeStateWithoutMutation(t *testing.T) {
	security, store := newTestSecurity(t, &fakeCore{}, tcAssociation(), nextTCAssociation(), recoveryAssociation())
	prepareTestRotation(t, store, tcAssociation(), nextTCAssociation())
	if _, err := store.NextTransmitCounter(context.Background(), "tx-current"); err != nil {
		t.Fatal(err)
	}

	status, err := security.OperationsStatus(context.Background(), "tenant-1")
	if err != nil {
		t.Fatal(err)
	}
	if !status.Ready || status.Status != "READY" || len(status.Warnings) != 0 {
		t.Fatalf("unexpected operations status: %+v", status)
	}
	if status.TCCurrent == nil || status.TCCurrent.NextIVCounter == nil || *status.TCCurrent.NextIVCounter != 1 {
		t.Fatalf("unexpected TC current state: %+v", status.TCCurrent)
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
	if status.Status != "UNCONFIGURED" || status.Ready || len(status.Warnings) != 4 ||
		!containsWarning(status.Warnings, "FLIGHT_STATUS_NOT_OBSERVED") {
		t.Fatalf("unexpected unconfigured status: %+v", status)
	}
}

func TestOperationsStatusReportsAmbiguityAndCounterWarning(t *testing.T) {
	current2 := tcAssociation()
	current2.ID = "tx-current-2"
	current2.SPI = 0x2001
	next2 := nextTCAssociation()
	next2.ID = "tx-next-2"
	next2.SPI = 0x2002
	recovery2 := recoveryAssociation()
	recovery2.ID = "recovery-2"
	recovery2.SPI = 0x7002
	security, store := newTestSecurity(t, &fakeCore{}, tcAssociation(), current2,
		nextTCAssociation(), next2, recoveryAssociation(), recovery2)
	store.txNext["tx-current"] = tcCounterCapacity * 9 / 10
	store.txNext["tx-current-2"] = tcCounterCapacity * 9 / 10
	status, err := security.OperationsStatus(context.Background(), "tenant-1")
	if err != nil {
		t.Fatal(err)
	}
	if status.Status != "DEGRADED" || status.Ready {
		t.Fatalf("unexpected ambiguous status: %+v", status)
	}
	want := map[string]bool{
		"TC_CURRENT_AMBIGUOUS":  false,
		"TC_NEXT_AMBIGUOUS":     false,
		"TC_RECOVERY_AMBIGUOUS": false,
		"TC_IV_NEAR_EXHAUSTION": false,
	}
	for _, warning := range status.Warnings {
		if _, ok := want[warning]; ok {
			want[warning] = true
		}
	}
	for warning, seen := range want {
		if !seen {
			t.Fatalf("warning %s missing from %v", warning, status.Warnings)
		}
	}
	if status.TCCurrent != nil && status.TCCurrent.NextIVCounter != nil {
		*status.TCCurrent.NextIVCounter = 0
		if store.txNext[status.TCCurrent.ID] == 0 {
			t.Fatal("status counter pointer aliased store")
		}
	}
}

func TestOperationsStatusReportsRotationClosureWarnings(t *testing.T) {
	current, next := tcAssociation(), nextTCAssociation()
	security, store := newTestSecurity(t, &fakeCore{}, current, next, recoveryAssociation())
	status, err := security.OperationsStatus(context.Background(), "tenant-1")
	if err != nil || !containsWarning(status.Warnings, "TC_ROTATION_NOT_PREPARED") {
		t.Fatalf("status=%+v err=%v", status, err)
	}
	prepareTestRotation(t, store, current, next)
	state := store.rotation["tenant-1"]
	state.NextSPI++
	store.rotation["tenant-1"] = state
	status, err = security.OperationsStatus(context.Background(), "tenant-1")
	if err != nil || !containsWarning(status.Warnings, "TC_ROTATION_STATE_MISMATCH") {
		t.Fatalf("status=%+v err=%v", status, err)
	}
	next.KeyVersion = current.KeyVersion
	legacy, _ := newTestSecurity(t, &fakeCore{}, current, next, recoveryAssociation())
	status, err = legacy.OperationsStatus(context.Background(), "tenant-1")
	if err != nil || !containsWarning(status.Warnings, "TC_NEXT_ROOT_NOT_ADVANCED") {
		t.Fatalf("status=%+v err=%v", status, err)
	}
}

func TestOperationsStatusDetectsFlightMismatchAndTelemetryWarnings(t *testing.T) {
	security, store := newTestSecurity(t, &fakeCore{}, tcAssociation(), nextTCAssociation(), recoveryAssociation())
	prepareTestRotation(t, store, tcAssociation(), nextTCAssociation())
	digest, err := store.ReadMissionProfileDigest(context.Background(), "tenant-1")
	if err != nil {
		t.Fatal(err)
	}
	digest[0] ^= 1
	digest[1] = 2
	flight := FlightSecurityStatus{FormatVersion: FlightSecurityStatusVersion, ProfileDigest: digest,
		SelfTest: FlightSelfTestLocked, CryptoBackend: FlightBackendARMv7NEON,
		CurrentSPI: 0x2222, NextSPI: 0x2223, RecoverySPI: recoveryAssociation().SPI,
		SecurityEpoch: 9, RootVersion: 7, CycleLimitExceededCount: 1, ClockAnomalyCount: 1}
	if err := store.ObserveFlightSecurityStatus(context.Background(), "tenant-1", flight); err != nil {
		t.Fatal(err)
	}
	status, err := security.OperationsStatus(context.Background(), "tenant-1")
	if err != nil || status.Ready || status.FlightReconciliation != "MISMATCH" {
		t.Fatalf("status=%+v err=%v", status, err)
	}
	for _, warning := range []string{"FLIGHT_PROFILE_MISMATCH", "FLIGHT_SELF_TEST_LOCKED",
		"FLIGHT_TC_STATE_MISMATCH", "FLIGHT_CYCLE_LIMIT_EXCEEDED", "FLIGHT_CLOCK_ANOMALY"} {
		if !containsWarning(status.Warnings, warning) {
			t.Fatalf("missing %s in %v", warning, status.Warnings)
		}
	}
}

func containsWarning(warnings []string, wanted string) bool {
	for _, warning := range warnings {
		if warning == wanted {
			return true
		}
	}
	return false
}
