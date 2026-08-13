package securitystate

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/kvlt/key-vault/internal/auditchain"
	"github.com/kvlt/key-vault/internal/protocol/ccsds"
	"github.com/kvlt/key-vault/internal/repository/models"
)

func TestProtocolTCAndDownlinkStateSurviveRestart(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "security.db")
	store := openTestStore(t, path)
	provisionTestTC(t, store)
	sealed := []byte("sealed-kek-set")
	if err := store.ProvisionDownlinkKEKSet(ctx, sealed, 3); err != nil {
		t.Fatal(err)
	}
	pkg := bytes.Repeat([]byte{0x42}, 16417)
	digest := [32]byte{1}
	if err := store.AdvanceDownlinkBatch(ctx, 0, pkg, digest); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkCurrentDownlinkObserved(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if err := store.SetActiveDownlinkKEKSlot(ctx, 7); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store = openTestStore(t, path)
	defer store.Close()
	state, err := store.ReadDownlinkKeyState(ctx)
	if err != nil || state.ActiveKEKSlot != 7 || state.CurrentGeneration != 1 || !state.CurrentObserved ||
		!bytes.Equal(state.SealedKEKSet, sealed) || !bytes.Equal(state.CurrentPackage, pkg) {
		t.Fatalf("restored downlink state=%+v err=%v", state, err)
	}
	current, err := store.GetTransmitAssociation(ctx, "tenant-1", ccsds.DirectionTCTx)
	if err != nil || current.ID != "current" {
		t.Fatalf("restored current=%+v err=%v", current, err)
	}
	diagnostics, err := store.Diagnostics(ctx)
	if err != nil || diagnostics.Schema != schemaVersion || !diagnostics.IntegrityOK {
		t.Fatalf("diagnostics=%+v err=%v", diagnostics, err)
	}
}

func TestDownlinkStateFailsClosed(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t, filepath.Join(t.TempDir(), "state.db"))
	defer store.Close()
	if _, err := store.ReadDownlinkKeyState(ctx); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unprovisioned error=%v", err)
	}
	if err := store.ProvisionDownlinkKEKSet(ctx, nil, 0); err == nil {
		t.Fatal("empty sealed KEK set accepted")
	}
	if err := store.ProvisionDownlinkKEKSet(ctx, []byte("sealed"), 8); err == nil {
		t.Fatal("invalid slot accepted")
	}
	if err := store.ProvisionDownlinkKEKSet(ctx, []byte("sealed"), 0); err != nil {
		t.Fatal(err)
	}
	if err := store.ProvisionDownlinkKEKSet(ctx, []byte("second"), 0); !errors.Is(err, ErrConflict) {
		t.Fatalf("replacement error=%v", err)
	}
	pkg := make([]byte, 16417)
	if err := store.AdvanceDownlinkBatch(ctx, 0, pkg, [32]byte{}); err == nil {
		t.Fatal("zero digest accepted")
	}
	if err := store.AdvanceDownlinkBatch(ctx, 0, pkg, [32]byte{1}); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvanceDownlinkBatch(ctx, 1, pkg, [32]byte{2}); !errors.Is(err, ErrConflict) {
		t.Fatalf("unobserved advance error=%v", err)
	}
	if err := store.MarkCurrentDownlinkObserved(ctx, 2); !errors.Is(err, ErrConflict) {
		t.Fatalf("wrong generation observe error=%v", err)
	}
	if _, err := store.db.ExecContext(ctx, `PRAGMA ignore_check_constraints=ON`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `UPDATE downlink_key_state SET current_digest=x'01'`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `PRAGMA ignore_check_constraints=OFF`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReadDownlinkKeyState(ctx); err == nil {
		t.Fatal("corrupt digest accepted")
	}
}

func TestTCStateTransitionsAndAudit(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t, filepath.Join(t.TempDir(), "state.db"))
	defer store.Close()
	provisionTestTC(t, store)
	current, _ := store.GetTransmitAssociation(ctx, "tenant-1", ccsds.DirectionTCTx)
	if counter, err := store.NextTransmitCounter(ctx, current.ID); err != nil || counter != 0 {
		t.Fatalf("counter=%d err=%v", counter, err)
	}
	rotation := ccsds.TCRotationState{Phase: ccsds.TCRotationPrepared, TransactionID: 1,
		CurrentSPI: 0x1001, NextSPI: 0x1002, CurrentRootVersion: 1, NextRootVersion: 2}
	if err := store.MarkTCRotationPrepared(ctx, "tenant-1", rotation); err != nil {
		t.Fatal(err)
	}
	if err := store.PromoteNextTC(ctx, "tenant-1"); err != nil {
		t.Fatal(err)
	}
	promoted, _ := store.GetTransmitAssociation(ctx, "tenant-1", ccsds.DirectionTCTx)
	if promoted.ID != "next" {
		t.Fatalf("promoted=%+v", promoted)
	}
	if err := store.MarkTCRotationFrameProduced(ctx, "tenant-1", promoted.ID); err != nil {
		t.Fatal(err)
	}
	chain := auditchain.New(store)
	if err := chain.Record(ctx, auditchain.RecordRequest{Action: "test", Result: "success"}); err != nil {
		t.Fatal(err)
	}
	broken, err := store.VerifyAuditChain(ctx, "system")
	if err != nil || broken != 0 {
		t.Fatalf("audit broken sequence=%d err=%v", broken, err)
	}
}

func openTestStore(t *testing.T, path string) *Store {
	t.Helper()
	store, err := Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func testKey(tenantID, id, suiteID string, versionNo uint32) (*models.Key, *models.KeyVersion) {
	key := &models.Key{ID: id, TenantID: tenantID, Name: id, Purpose: "encrypt_decrypt",
		UsageScope: models.KeyUsageProtocol, PolicyID: "default-v1", SuiteID: suiteID,
		CurrentVersion: versionNo, Status: "ACTIVE", Tags: map[string]string{"owner": "ccsds"}}
	version := &models.KeyVersion{ID: id + "-version", KeyID: id, VersionNo: versionNo,
		SuiteID: suiteID, SealedMaterial: []byte("sealed-material"), Status: "ACTIVE"}
	return key, version
}

func provisionTestTC(t *testing.T, store *Store) {
	t.Helper()
	ctx := context.Background()
	if err := store.EnsureTenant(ctx, "tenant-1", "Mission"); err != nil {
		t.Fatal(err)
	}
	for _, spec := range []struct {
		id, suite string
		version   uint32
	}{{"current-root", "SM4_HCTR", 1}, {"next-root", "SM4_HCTR", 2}, {"recovery-root", "SM4_GCM", 1}} {
		key, version := testKey("tenant-1", spec.id, spec.suite, spec.version)
		if err := store.CreateProtocolKey(ctx, key, version); err != nil {
			t.Fatal(err)
		}
	}
	prefix := []byte{1, 2, 3, 4, 5, 6}
	associations := []ccsds.SecurityAssociation{
		{ID: "current", TenantID: "tenant-1", SPI: 0x1001, Direction: ccsds.DirectionTCTx,
			KeyID: "current-root", KeyVersion: 1, SecurityEpoch: 1, PolicyVersion: 1, SuiteID: "SM4_HCTR",
			State: ccsds.AssociationCurrent, Parameters: ccsds.ManagedParameters{TransmittedIVLength: 4, NoncePrefix: prefix}},
		{ID: "next", TenantID: "tenant-1", SPI: 0x1002, Direction: ccsds.DirectionTCTx,
			KeyID: "next-root", KeyVersion: 2, SecurityEpoch: 2, PolicyVersion: 1, SuiteID: "SM4_HCTR",
			State: ccsds.AssociationNext, Parameters: ccsds.ManagedParameters{TransmittedIVLength: 4, NoncePrefix: prefix}},
		{ID: "recovery", TenantID: "tenant-1", SPI: 0x7001, Direction: ccsds.DirectionTCRecoveryTx,
			KeyID: "recovery-root", KeyVersion: 1, PolicyVersion: 1, SuiteID: "SM4_GCM",
			State: ccsds.AssociationActive, Parameters: ccsds.ManagedParameters{TransmittedIVLength: 4, TagLength: 16, NoncePrefix: prefix}},
	}
	for _, association := range associations {
		if err := store.CreateAssociation(ctx, association); err != nil {
			t.Fatal(err)
		}
	}
}
