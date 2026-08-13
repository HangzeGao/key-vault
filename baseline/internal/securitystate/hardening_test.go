package securitystate

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/kvlt/key-vault/internal/protocol/ccsds"
	"github.com/kvlt/key-vault/internal/repository/models"
)

type failingScanner struct{}

func (failingScanner) Scan(...any) error { return errors.New("scan failed") }

func TestStrictStoreContractAndProtocolKeyReads(t *testing.T) {
	ctx := context.Background()
	if _, err := Open(ctx, ""); err == nil {
		t.Fatal("empty database path accepted")
	}
	store := openTestStore(t, filepath.Join(t.TempDir(), "nested", "state.db"))
	defer store.Close()
	if err := store.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	if err := store.EnsureTenant(ctx, "", "mission"); err == nil {
		t.Fatal("empty tenant accepted")
	}
	if err := store.EnsureTenant(ctx, "tenant", "mission"); err != nil {
		t.Fatal(err)
	}
	if err := store.EnsureTenant(ctx, "tenant", "renamed mission"); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateProtocolKey(ctx, nil, nil); err == nil {
		t.Fatal("nil protocol key accepted")
	}
	key, version := testKey("tenant", "root", "SM4_HCTR", 1)
	if err := store.CreateProtocolKey(ctx, key, version); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateProtocolKey(ctx, key, version); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate key error=%v", err)
	}
	loaded, err := store.GetKey(ctx, "tenant", "root")
	if err != nil || loaded.Tags["owner"] != "ccsds" || loaded.UsageScope != models.KeyUsageProtocol {
		t.Fatalf("key=%+v err=%v", loaded, err)
	}
	if _, err := store.GetKey(ctx, "other", "root"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant error=%v", err)
	}
	byID, err := store.GetKeyVersion(ctx, version.ID)
	if err != nil || string(byID.SealedMaterial) != "sealed-material" {
		t.Fatalf("version=%+v err=%v", byID, err)
	}
	byNo, err := store.GetKeyVersionByNo(ctx, key.ID, 1)
	if err != nil || byNo.ID != version.ID {
		t.Fatalf("version=%+v err=%v", byNo, err)
	}
	if _, err := store.GetKeyVersion(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing version error=%v", err)
	}
	if _, err := scanKeyVersion(failingScanner{}); err == nil {
		t.Fatal("scan failure ignored")
	}
	if got := formatTime(time.Date(2026, 1, 2, 3, 4, 5, 123456789, time.FixedZone("x", 3600))); got != "2026-01-02T02:04:05.123456Z" {
		t.Fatalf("formatted time=%s", got)
	}
	if _, err := parseTime("not-a-time"); err == nil {
		t.Fatal("invalid timestamp accepted")
	}
	if wrap("noop", nil) != nil || conflict("noop", nil) != nil {
		t.Fatal("nil wrapper returned an error")
	}
	if !errors.Is(notFound("read", sql.ErrNoRows), ErrNotFound) {
		t.Fatal("sql no rows not mapped")
	}
}

func TestMissionBindingAndFlightObservationFailClosed(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t, filepath.Join(t.TempDir(), "state.db"))
	defer store.Close()
	if err := store.EnsureTenant(ctx, "tenant", "mission"); err != nil {
		t.Fatal(err)
	}
	digest := [32]byte{1, 2, 3}
	if err := store.BindMissionProfile(ctx, "", digest); !errors.Is(err, ccsds.ErrAssociationState) {
		t.Fatalf("empty tenant error=%v", err)
	}
	if err := store.BindMissionProfile(ctx, "tenant", [32]byte{}); !errors.Is(err, ccsds.ErrAssociationState) {
		t.Fatalf("zero digest error=%v", err)
	}
	if err := store.BindMissionProfile(ctx, "tenant", digest); err != nil {
		t.Fatal(err)
	}
	if err := store.BindMissionProfile(ctx, "tenant", digest); err != nil {
		t.Fatal(err)
	}
	other := digest
	other[0]++
	if err := store.BindMissionProfile(ctx, "tenant", other); !errors.Is(err, ccsds.ErrAssociationState) {
		t.Fatalf("changed binding error=%v", err)
	}
	if got, err := store.ReadMissionProfileDigest(ctx, "tenant"); err != nil || got != digest {
		t.Fatalf("digest=%x err=%v", got, err)
	}
	if _, err := store.ReadMissionProfileDigest(ctx, "missing"); !errors.Is(err, ccsds.ErrAssociationNotFound) {
		t.Fatalf("missing digest error=%v", err)
	}
	status := ccsds.FlightSecurityStatus{FormatVersion: 1, ProfileDigest: digest,
		SelfTest: ccsds.FlightSelfTestPassed, CryptoBackend: ccsds.FlightBackendARMv7NEON,
		CurrentSPI: 0xffff, NextSPI: 0, RecoverySPI: 0x7001, SecurityEpoch: 3, RootVersion: 2,
		PendingRootPresent: true, ReceiveCount: ^uint64(0), LastReceiveUS: 12, MaxReceiveUS: 44,
		CycleLimitExceededCount: 2, ClockAnomalyCount: 1}
	if err := store.ObserveFlightSecurityStatus(ctx, "", status); !errors.Is(err, ccsds.ErrAssociationState) {
		t.Fatalf("invalid observation error=%v", err)
	}
	if err := store.ObserveFlightSecurityStatus(ctx, "tenant", status); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.ReadFlightSecurityStatus(ctx, "tenant")
	if err != nil || loaded.ReceiveCount != ^uint64(0) || loaded.ProfileDigest != digest || !loaded.PendingRootPresent {
		t.Fatalf("status=%+v err=%v", loaded, err)
	}
	if _, err := store.ReadFlightSecurityStatus(ctx, "missing"); !errors.Is(err, ccsds.ErrAssociationNotFound) {
		t.Fatalf("missing status error=%v", err)
	}
	if _, err := store.db.ExecContext(ctx, `UPDATE flight_security_status SET receive_count='bad' WHERE tenant_id='tenant'`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReadFlightSecurityStatus(ctx, "tenant"); err == nil {
		t.Fatal("invalid flight counter accepted")
	}
	if _, err := store.db.ExecContext(ctx, `UPDATE flight_security_status SET receive_count='0',observed_at='bad' WHERE tenant_id='tenant'`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReadFlightSecurityStatus(ctx, "tenant"); err == nil {
		t.Fatal("invalid observation time accepted")
	}
}

func TestAssociationReadsOperationsAndRotationLifecycle(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t, filepath.Join(t.TempDir(), "state.db"))
	defer store.Close()
	provisionTestTC(t, store)
	current, err := store.GetAssociation(ctx, "tenant-1", "current")
	if err != nil || current.SPI != 0x1001 {
		t.Fatalf("current=%+v err=%v", current, err)
	}
	bySPI, err := store.GetAssociationBySPI(ctx, "tenant-1", ccsds.DirectionTCTx, 0x1002)
	if err != nil || bySPI.ID != "next" {
		t.Fatalf("next=%+v err=%v", bySPI, err)
	}
	if _, err := store.GetAssociation(ctx, "tenant-1", "missing"); !errors.Is(err, ccsds.ErrAssociationNotFound) {
		t.Fatalf("missing association error=%v", err)
	}
	if recovery, err := store.GetTransmitAssociation(ctx, "tenant-1", ccsds.DirectionTCRecoveryTx); err != nil || recovery.ID != "recovery" {
		t.Fatalf("recovery=%+v err=%v", recovery, err)
	}
	if _, err := store.GetTransmitAssociation(ctx, "tenant-1", "INVALID"); !errors.Is(err, ccsds.ErrAssociationState) {
		t.Fatalf("invalid direction error=%v", err)
	}
	states, err := store.ReadOperationsState(ctx, "tenant-1")
	if err != nil || len(states) != 3 || states[0].NextIVCounter == nil {
		t.Fatalf("states=%+v err=%v", states, err)
	}
	if _, err := scanAssociation(failingScanner{}); err == nil {
		t.Fatal("association scan error ignored")
	}
	if _, err := scanOperationsState(failingScanner{}); err == nil {
		t.Fatal("operations scan error ignored")
	}
	if _, err := store.ReadTCRotationState(ctx, "tenant-1"); !errors.Is(err, ccsds.ErrAssociationNotFound) {
		t.Fatalf("missing rotation error=%v", err)
	}
	invalid := ccsds.TCRotationState{Phase: ccsds.TCRotationPrepared, TransactionID: 1, CurrentSPI: 1, NextSPI: 3, CurrentRootVersion: 1, NextRootVersion: 2}
	if err := store.MarkTCRotationPrepared(ctx, "tenant-1", invalid); !errors.Is(err, ccsds.ErrAssociationState) {
		t.Fatalf("invalid rotation error=%v", err)
	}
	rotation := ccsds.TCRotationState{Phase: ccsds.TCRotationPrepared, TransactionID: 7,
		CurrentSPI: 0x1001, NextSPI: 0x1002, CurrentRootVersion: 1, NextRootVersion: 2}
	if err := store.MarkTCRotationPrepared(ctx, "tenant-1", rotation); err != nil {
		t.Fatal(err)
	}
	if got, err := store.ReadTCRotationState(ctx, "tenant-1"); err != nil || got.TransactionID != 7 {
		t.Fatalf("rotation=%+v err=%v", got, err)
	}
	if err := store.MarkTCRotationFrameProduced(ctx, "tenant-1", "current"); !errors.Is(err, ccsds.ErrAssociationState) {
		t.Fatalf("early completion error=%v", err)
	}
	if err := store.PromoteNextTC(ctx, "tenant-1"); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkTCRotationFrameProduced(ctx, "tenant-1", "next"); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkTCRotationFrameProduced(ctx, "tenant-1", "next"); err != nil {
		t.Fatalf("idempotent completion error=%v", err)
	}
	if got, err := store.ReadTCRotationState(ctx, "tenant-1"); err != nil || got.Phase != ccsds.TCRotationActive {
		t.Fatalf("active rotation=%+v err=%v", got, err)
	}
	if _, err := store.NextTransmitCounter(ctx, "current"); !errors.Is(err, ccsds.ErrAssociationState) {
		t.Fatalf("disabled counter error=%v", err)
	}
	if got, err := store.NextTransmitCounter(ctx, "next"); err != nil || got != 0 {
		t.Fatalf("next counter=%d err=%v", got, err)
	}
	if _, err := store.NextTransmitCounter(ctx, "missing"); !errors.Is(err, ccsds.ErrAssociationNotFound) {
		t.Fatalf("missing counter error=%v", err)
	}
	if _, err := store.db.ExecContext(ctx, `UPDATE tx_states SET next_iv=4294967296 WHERE association_id='next'`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.NextTransmitCounter(ctx, "next"); !errors.Is(err, ccsds.ErrCounterExhausted) {
		t.Fatalf("exhaustion error=%v", err)
	}
}

func TestAuditLifecycleAndTamperDetection(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t, filepath.Join(t.TempDir(), "state.db"))
	defer store.Close()
	if err := store.AppendAuditEvent(ctx, nil); err == nil {
		t.Fatal("nil audit event accepted")
	}
	first := &models.AuditEvent{EventID: "event-1", RequestID: "request", Action: "generate",
		Result: "success", Metadata: map[string]string{"slot": "3", "generation": "1"}}
	if err := store.AppendAuditEvent(ctx, first); err != nil {
		t.Fatal(err)
	}
	second := &models.AuditEvent{EventID: "event-2", Action: "decrypt", Result: "success", ChainName: "downlink"}
	if err := store.AppendAuditEvent(ctx, second); err != nil {
		t.Fatal(err)
	}
	if err := store.AppendAuditEvent(ctx, first); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate audit error=%v", err)
	}
	all, err := store.ListAuditEvents(ctx, "", 0)
	if err != nil || len(all) != 2 {
		t.Fatalf("events=%+v err=%v", all, err)
	}
	system, err := store.ListAuditEvents(ctx, "system", 900)
	if err != nil || len(system) != 1 || system[0].Metadata["slot"] != "3" {
		t.Fatalf("events=%+v err=%v", system, err)
	}
	head, err := store.GetAuditChainHead(ctx, "system")
	if err != nil || head.Sequence != 1 || head.HeadHash == "" {
		t.Fatalf("head=%+v err=%v", head, err)
	}
	if _, err := store.GetAuditChainHead(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing head error=%v", err)
	}
	heads, err := store.ListAuditChainHeads(ctx)
	if err != nil || len(heads) != 2 {
		t.Fatalf("heads=%+v err=%v", heads, err)
	}
	if broken, err := store.VerifyAuditChain(ctx, "system"); err != nil || broken != 0 {
		t.Fatalf("broken=%d err=%v", broken, err)
	}
	if _, err := store.db.ExecContext(ctx, `UPDATE audit_events SET current_hash='tampered' WHERE event_id='event-1'`); err != nil {
		t.Fatal(err)
	}
	if broken, err := store.VerifyAuditChain(ctx, "system"); err == nil || broken != 1 {
		t.Fatalf("tamper broken=%d err=%v", broken, err)
	}
	if count, err := store.DeleteAuditEvents(ctx, "system"); err != nil || count != 1 {
		t.Fatalf("delete count=%d err=%v", count, err)
	}
	if count, err := store.DeleteAuditEvents(ctx, ""); err != nil || count != 1 {
		t.Fatalf("delete all count=%d err=%v", count, err)
	}
	if _, err := scanAuditEvent(failingScanner{}); err == nil {
		t.Fatal("audit scan error ignored")
	}
}

func TestClosedDatabaseFailsAllPersistenceBoundaries(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t, filepath.Join(t.TempDir(), "state.db"))
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	key, version := testKey("tenant", "root", "SM4_HCTR", 1)
	association := ccsds.SecurityAssociation{ID: "sa", TenantID: "tenant", SPI: 1, Direction: ccsds.DirectionTCTx,
		KeyID: "root", KeyVersion: 1, SecurityEpoch: 1, PolicyVersion: 1, SuiteID: "SM4_HCTR",
		State: ccsds.AssociationCurrent, Parameters: ccsds.ManagedParameters{TransmittedIVLength: 4, NoncePrefix: []byte{1, 2, 3, 4, 5, 6}}}
	digest := [32]byte{1}
	status := ccsds.FlightSecurityStatus{FormatVersion: 1, ProfileDigest: digest, SelfTest: ccsds.FlightSelfTestPassed,
		CryptoBackend: ccsds.FlightBackendSoftware, CurrentSPI: 1, NextSPI: 2, SecurityEpoch: 1, RootVersion: 1}
	rotation := ccsds.TCRotationState{Phase: ccsds.TCRotationPrepared, TransactionID: 1,
		CurrentSPI: 1, NextSPI: 2, CurrentRootVersion: 1, NextRootVersion: 2}
	calls := []func() error{
		func() error { return store.Ping(ctx) },
		func() error { return store.EnsureTenant(ctx, "tenant", "mission") },
		func() error { return store.CreateProtocolKey(ctx, key, version) },
		func() error { _, err := store.GetKey(ctx, "tenant", "root"); return err },
		func() error { _, err := store.GetKeyVersion(ctx, "version"); return err },
		func() error { return store.CreateAssociation(ctx, association) },
		func() error { _, err := store.GetAssociation(ctx, "tenant", "sa"); return err },
		func() error { _, err := store.ReadOperationsState(ctx, "tenant"); return err },
		func() error { return store.BindMissionProfile(ctx, "tenant", digest) },
		func() error { _, err := store.ReadMissionProfileDigest(ctx, "tenant"); return err },
		func() error { return store.ObserveFlightSecurityStatus(ctx, "tenant", status) },
		func() error { _, err := store.ReadFlightSecurityStatus(ctx, "tenant"); return err },
		func() error { return store.MarkTCRotationPrepared(ctx, "tenant", rotation) },
		func() error { return store.MarkTCRotationFrameProduced(ctx, "tenant", "sa") },
		func() error { return store.PromoteNextTC(ctx, "tenant") },
		func() error { _, err := store.NextTransmitCounter(ctx, "sa"); return err },
		func() error { return store.AppendAuditEvent(ctx, &models.AuditEvent{EventID: "event"}) },
		func() error { _, err := store.ListAuditEvents(ctx, "", 1); return err },
		func() error { _, err := store.DeleteAuditEvents(ctx, ""); return err },
		func() error { _, err := store.GetAuditChainHead(ctx, "system"); return err },
		func() error { _, err := store.ListAuditChainHeads(ctx); return err },
		func() error { _, err := store.VerifyAuditChain(ctx, "system"); return err },
		func() error { _, err := store.Diagnostics(ctx); return err },
		func() error { _, err := store.ReadDownlinkKeyState(ctx); return err },
		func() error { return store.ProvisionDownlinkKEKSet(ctx, []byte("sealed"), 0) },
		func() error { return store.SetActiveDownlinkKEKSlot(ctx, 0) },
		func() error { return store.AdvanceDownlinkBatch(ctx, 0, make([]byte, 16417), digest) },
		func() error { return store.MarkCurrentDownlinkObserved(ctx, 1) },
	}
	for index, call := range calls {
		if err := call(); err == nil {
			t.Fatalf("closed database call %d succeeded", index)
		}
	}
}

func TestCorruptRowsAndTransactionalFailuresFailClosed(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t, filepath.Join(t.TempDir(), "state.db"))
	defer store.Close()
	provisionTestTC(t, store)
	if err := store.CreateAssociation(ctx, *mustAssociation(t, store, "current")); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate association error=%v", err)
	}
	if _, err := store.db.ExecContext(ctx, `UPDATE security_associations SET transmitted_iv_length=3 WHERE id='current'`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetAssociation(ctx, "tenant-1", "current"); err == nil {
		t.Fatal("corrupt association accepted")
	}
	if _, err := store.db.ExecContext(ctx, `UPDATE security_associations SET transmitted_iv_length=4 WHERE id='current'`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `UPDATE protocol_keys SET tags_json='{' WHERE id='current-root'`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetKey(ctx, "tenant-1", "current-root"); err == nil {
		t.Fatal("invalid tags accepted")
	}
	if _, err := store.db.ExecContext(ctx, `UPDATE protocol_keys SET tags_json='{}',created_at='bad' WHERE id='current-root'`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetKey(ctx, "tenant-1", "current-root"); err == nil {
		t.Fatal("invalid key time accepted")
	}
	if _, err := store.db.ExecContext(ctx, `UPDATE protocol_key_versions SET created_at='bad' WHERE id='current-root-version'`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetKeyVersion(ctx, "current-root-version"); err == nil {
		t.Fatal("invalid version time accepted")
	}

	if _, err := store.db.ExecContext(ctx, `CREATE TRIGGER reject_key_version BEFORE INSERT ON protocol_key_versions BEGIN SELECT RAISE(ABORT,'reject'); END`); err != nil {
		t.Fatal(err)
	}
	key, version := testKey("tenant-1", "rejected-root", "SM4_HCTR", 3)
	if err := store.CreateProtocolKey(ctx, key, version); !errors.Is(err, ErrConflict) {
		t.Fatalf("key transaction error=%v", err)
	}
	if _, err := store.GetKey(ctx, "tenant-1", key.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("partial key persisted: %v", err)
	}
	if _, err := store.db.ExecContext(ctx, `DROP TRIGGER reject_key_version`); err != nil {
		t.Fatal(err)
	}

	extraKey, extraVersion := testKey("tenant-1", "extra-root", "SM4_HCTR", 3)
	if err := store.CreateProtocolKey(ctx, extraKey, extraVersion); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `CREATE TRIGGER reject_tx_state BEFORE INSERT ON tx_states BEGIN SELECT RAISE(ABORT,'reject'); END`); err != nil {
		t.Fatal(err)
	}
	extra := ccsds.SecurityAssociation{ID: "extra", TenantID: "tenant-1", SPI: 0x3001, Direction: ccsds.DirectionTCTx,
		KeyID: extraKey.ID, KeyVersion: 3, SecurityEpoch: 3, PolicyVersion: 1, SuiteID: "SM4_HCTR",
		State: ccsds.AssociationNext, Parameters: ccsds.ManagedParameters{TransmittedIVLength: 4, NoncePrefix: []byte{1, 2, 3, 4, 5, 6}}}
	if err := store.CreateAssociation(ctx, extra); err == nil {
		t.Fatal("runtime-state trigger failure ignored")
	}
	if _, err := store.GetAssociation(ctx, "tenant-1", extra.ID); !errors.Is(err, ccsds.ErrAssociationNotFound) {
		t.Fatalf("partial association persisted: %v", err)
	}
}

func TestAuditCorruptionAndWriteFailures(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t, filepath.Join(t.TempDir(), "state.db"))
	defer store.Close()
	if _, err := store.db.ExecContext(ctx, `CREATE TRIGGER reject_head BEFORE INSERT ON audit_chain_heads BEGIN SELECT RAISE(ABORT,'reject'); END`); err != nil {
		t.Fatal(err)
	}
	if err := store.AppendAuditEvent(ctx, &models.AuditEvent{EventID: "head-rejected"}); err == nil {
		t.Fatal("head insertion failure ignored")
	}
	if _, err := store.db.ExecContext(ctx, `DROP TRIGGER reject_head`); err != nil {
		t.Fatal(err)
	}
	if err := store.AppendAuditEvent(ctx, &models.AuditEvent{EventID: "one", Metadata: map[string]string{}}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `CREATE TRIGGER reject_head_update BEFORE UPDATE ON audit_chain_heads BEGIN SELECT RAISE(ABORT,'reject'); END`); err != nil {
		t.Fatal(err)
	}
	if err := store.AppendAuditEvent(ctx, &models.AuditEvent{EventID: "two"}); err == nil {
		t.Fatal("head update failure ignored")
	}
	if _, err := store.db.ExecContext(ctx, `DROP TRIGGER reject_head_update`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `UPDATE audit_events SET metadata_json='{' WHERE event_id='one'`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ListAuditEvents(ctx, "system", 1); err == nil {
		t.Fatal("invalid audit metadata accepted")
	}
	if _, err := store.db.ExecContext(ctx, `UPDATE audit_events SET metadata_json='{}',timestamp='bad' WHERE event_id='one'`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.VerifyAuditChain(ctx, "system"); err == nil {
		t.Fatal("invalid audit timestamp accepted")
	}
	if _, err := store.db.ExecContext(ctx, `UPDATE audit_events SET timestamp=?,sequence=3 WHERE event_id='one'`, formatTime(time.Now())); err != nil {
		t.Fatal(err)
	}
	if _, err := store.VerifyAuditChain(ctx, "system"); err == nil {
		t.Fatal("audit sequence gap accepted")
	}
	if _, err := store.db.ExecContext(ctx, `UPDATE audit_events SET sequence=1,prev_hash='wrong' WHERE event_id='one'`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.VerifyAuditChain(ctx, "system"); err == nil {
		t.Fatal("audit previous hash tamper accepted")
	}
	if _, err := store.db.ExecContext(ctx, `UPDATE audit_chain_heads SET updated_at='bad' WHERE chain_name='system'`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetAuditChainHead(ctx, "system"); err == nil {
		t.Fatal("invalid head time accepted")
	}
	if _, err := store.ListAuditChainHeads(ctx); err == nil {
		t.Fatal("invalid head list time accepted")
	}
}

func TestStrictSchemaRejectsOldAndCorruptState(t *testing.T) {
	ctx := context.Background()
	if _, err := Open(ctx, string([]byte{'b', 'a', 'd', 0, 'p'})); err == nil {
		t.Fatal("invalid filesystem path accepted")
	}
	if _, err := Open(ctx, t.TempDir()); err == nil {
		t.Fatal("directory accepted as database")
	}
	original := schemaStatements
	schemaStatements = append(append([]string(nil), original...), `INVALID SQL`)
	if _, err := Open(ctx, filepath.Join(t.TempDir(), "invalid-schema.db")); err == nil {
		t.Fatal("invalid schema accepted")
	}
	schemaStatements = original
	t.Cleanup(func() { schemaStatements = original })

	path := filepath.Join(t.TempDir(), "old.db")
	store := openTestStore(t, path)
	if _, err := store.db.ExecContext(ctx, `PRAGMA ignore_check_constraints=ON`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `UPDATE schema_meta SET version=2`); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if reopened, err := Open(ctx, path); err == nil {
		reopened.Close()
		t.Fatal("old schema accepted")
	}
}

func TestPromotionRejectsCorruptNextAndDatabaseWriteFailure(t *testing.T) {
	ctx := context.Background()
	for _, mutation := range []string{
		`UPDATE security_associations SET spi=4099 WHERE id='next'`,
		`UPDATE security_associations SET security_epoch=9 WHERE id='next'`,
		`UPDATE security_associations SET nonce_prefix=x'090909090909' WHERE id='next'`,
	} {
		store := openTestStore(t, filepath.Join(t.TempDir(), "state.db"))
		provisionTestTC(t, store)
		rotation := ccsds.TCRotationState{Phase: ccsds.TCRotationPrepared, TransactionID: 1,
			CurrentSPI: 0x1001, NextSPI: 0x1002, CurrentRootVersion: 1, NextRootVersion: 2}
		if err := store.MarkTCRotationPrepared(ctx, "tenant-1", rotation); err != nil {
			t.Fatal(err)
		}
		if _, err := store.db.ExecContext(ctx, mutation); err != nil {
			t.Fatal(err)
		}
		if err := store.PromoteNextTC(ctx, "tenant-1"); !errors.Is(err, ccsds.ErrAssociationState) {
			t.Fatalf("mutation %q error=%v", mutation, err)
		}
		store.Close()
	}
	store := openTestStore(t, filepath.Join(t.TempDir(), "state.db"))
	defer store.Close()
	provisionTestTC(t, store)
	rotation := ccsds.TCRotationState{Phase: ccsds.TCRotationPrepared, TransactionID: 1,
		CurrentSPI: 0x1001, NextSPI: 0x1002, CurrentRootVersion: 1, NextRootVersion: 2}
	if err := store.MarkTCRotationPrepared(ctx, "tenant-1", rotation); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `CREATE TRIGGER reject_promotion BEFORE UPDATE ON security_associations BEGIN SELECT RAISE(ABORT,'reject'); END`); err != nil {
		t.Fatal(err)
	}
	if err := store.PromoteNextTC(ctx, "tenant-1"); err == nil {
		t.Fatal("promotion write failure ignored")
	}
}

func mustAssociation(t *testing.T, store *Store, id string) *ccsds.SecurityAssociation {
	t.Helper()
	association, err := store.GetAssociation(context.Background(), "tenant-1", id)
	if err != nil {
		t.Fatal(err)
	}
	return association
}

func TestDownlinkPersistenceBoundaryMatrix(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t, filepath.Join(t.TempDir(), "state.db"))
	defer store.Close()
	if err := store.SetActiveDownlinkKEKSlot(ctx, 0); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unprovisioned slot error=%v", err)
	}
	if err := store.SetActiveDownlinkKEKSlot(ctx, 8); err == nil {
		t.Fatal("invalid slot accepted")
	}
	if err := store.AdvanceDownlinkBatch(ctx, 0, nil, [32]byte{1}); err == nil {
		t.Fatal("invalid package accepted")
	}
	if err := store.AdvanceDownlinkBatch(ctx, ^uint32(0), make([]byte, 16417), [32]byte{1}); err == nil {
		t.Fatal("generation overflow accepted")
	}
	if err := store.ProvisionDownlinkKEKSet(ctx, []byte("sealed"), 0); err != nil {
		t.Fatal(err)
	}
	if err := store.SetActiveDownlinkKEKSlot(ctx, 7); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvanceDownlinkBatch(ctx, 0, make([]byte, 16417), [32]byte{1}); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkCurrentDownlinkObserved(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvanceDownlinkBatch(ctx, 1, make([]byte, 16417), [32]byte{2}); err != nil {
		t.Fatal(err)
	}
	state, err := store.ReadDownlinkKeyState(ctx)
	if err != nil || state.PreviousGeneration != 1 || state.CurrentGeneration != 2 {
		t.Fatalf("state=%+v err=%v", state, err)
	}
	if _, err := store.db.ExecContext(ctx, `PRAGMA ignore_check_constraints=ON`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `UPDATE downlink_key_state SET previous_digest=x'01'`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `PRAGMA ignore_check_constraints=OFF`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReadDownlinkKeyState(ctx); err == nil {
		t.Fatal("corrupt previous digest accepted")
	}
}

func TestRotationCorruptionAndPrepareWriteFailure(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t, filepath.Join(t.TempDir(), "state.db"))
	defer store.Close()
	provisionTestTC(t, store)
	rotation := ccsds.TCRotationState{Phase: ccsds.TCRotationPrepared, TransactionID: 1,
		CurrentSPI: 0x1001, NextSPI: 0x1002, CurrentRootVersion: 1, NextRootVersion: 2}
	if _, err := store.db.ExecContext(ctx, `CREATE TRIGGER reject_rotation BEFORE INSERT ON tc_rotation_states BEGIN SELECT RAISE(ABORT,'reject'); END`); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkTCRotationPrepared(ctx, "tenant-1", rotation); err == nil {
		t.Fatal("rotation write failure ignored")
	}
	if _, err := store.db.ExecContext(ctx, `DROP TRIGGER reject_rotation`); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkTCRotationPrepared(ctx, "tenant-1", rotation); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `PRAGMA ignore_check_constraints=ON`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `UPDATE tc_rotation_states SET transaction_id='bad'`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `PRAGMA ignore_check_constraints=OFF`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReadTCRotationState(ctx, "tenant-1"); err == nil {
		t.Fatal("corrupt rotation accepted")
	}
}

func TestAuditDeletionFailuresRollback(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t, filepath.Join(t.TempDir(), "state.db"))
	defer store.Close()
	if err := store.AppendAuditEvent(ctx, &models.AuditEvent{EventID: "one"}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `CREATE TRIGGER reject_event_delete BEFORE DELETE ON audit_events BEGIN SELECT RAISE(ABORT,'reject'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DeleteAuditEvents(ctx, "system"); err == nil {
		t.Fatal("event delete failure ignored")
	}
	if _, err := store.db.ExecContext(ctx, `DROP TRIGGER reject_event_delete`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `CREATE TRIGGER reject_head_delete BEFORE DELETE ON audit_chain_heads BEGIN SELECT RAISE(ABORT,'reject'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DeleteAuditEvents(ctx, ""); err == nil {
		t.Fatal("head delete failure ignored")
	}
}

func TestMigrationMetadataDiagnosticsAndMissingRotationState(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t, filepath.Join(t.TempDir(), "state.db"))
	provisionTestTC(t, store)
	rotation := ccsds.TCRotationState{Phase: ccsds.TCRotationPrepared, TransactionID: 1,
		CurrentSPI: 0x1001, NextSPI: 0x1002, CurrentRootVersion: 1, NextRootVersion: 2}
	if err := store.MarkTCRotationPrepared(ctx, "missing", rotation); !errors.Is(err, ccsds.ErrAssociationState) {
		t.Fatalf("missing association prepare error=%v", err)
	}
	if err := store.PromoteNextTC(ctx, "tenant-1"); !errors.Is(err, ccsds.ErrAssociationState) {
		t.Fatalf("promotion without prepare error=%v", err)
	}
	if _, err := store.db.ExecContext(ctx, `DROP TABLE security_associations`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Diagnostics(ctx); err == nil {
		t.Fatal("diagnostics ignored missing table")
	}
	store.Close()

	raw := openTestStore(t, filepath.Join(t.TempDir(), "missing-meta.db"))
	if _, err := raw.db.ExecContext(ctx, `DROP TABLE schema_meta`); err != nil {
		t.Fatal(err)
	}
	original := schemaStatements
	schemaStatements = nil
	if err := raw.migrate(ctx); err == nil {
		t.Fatal("missing schema metadata accepted")
	}
	schemaStatements = original
	raw.Close()
}
