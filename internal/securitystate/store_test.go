package securitystate

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/kvlt/key-vault/internal/auditchain"
	"github.com/kvlt/key-vault/internal/protocol/ccsds"
	"github.com/kvlt/key-vault/internal/repository/models"
)

func TestProtocolTCStateSurvivesRestart(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "security.db")
	store := openTestStore(t, path)
	provisionTestTC(t, store)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store = openTestStore(t, path)
	defer store.Close()
	current, err := store.GetTransmitAssociation(ctx, "tenant-1", ccsds.DirectionTCTx)
	if err != nil || current.ID != "current" {
		t.Fatalf("restored current=%+v err=%v", current, err)
	}
	diagnostics, err := store.Diagnostics(ctx)
	if err != nil || diagnostics.Schema != schemaVersion || !diagnostics.IntegrityOK {
		t.Fatalf("diagnostics=%+v err=%v", diagnostics, err)
	}
}

func TestUnsupportedDownlinkTableFailsClosed(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state.db")
	store := openTestStore(t, path)
	if _, err := store.db.ExecContext(ctx, `CREATE TABLE downlink_key_state (id INTEGER)`); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if opened, err := Open(ctx, path); err == nil {
		opened.Close()
		t.Fatal("database opened with unsupported downlink table")
	}
}

func TestSchemaVersionAndFilesystemFailures(t *testing.T) {
	ctx := context.Background()
	parentFile := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(parentFile, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if opened, err := Open(ctx, filepath.Join(parentFile, "state.db")); err == nil {
		opened.Close()
		t.Fatal("database created below a regular file")
	}
	path := filepath.Join(t.TempDir(), "state.db")
	store := openTestStore(t, path)
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err := store.migrate(cancelled); err == nil {
		t.Fatal("migration accepted cancelled context")
	}
	if _, err := store.db.ExecContext(ctx, `PRAGMA ignore_check_constraints=ON`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `UPDATE schema_meta SET version=4`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `PRAGMA ignore_check_constraints=OFF`); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if opened, err := Open(ctx, path); err == nil {
		opened.Close()
		t.Fatal("unsupported schema version accepted")
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
