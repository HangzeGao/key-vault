package securitystate

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kvlt/key-vault/internal/auditchain"
	"github.com/kvlt/key-vault/internal/protocol/ccsds"
	"github.com/kvlt/key-vault/internal/repository/models"
)

type failingScanner struct{}

func (failingScanner) Scan(...any) error { return errors.New("scan failed") }

func TestOpenRequiresPath(t *testing.T) {
	if _, err := Open(context.Background(), ""); err == nil {
		t.Fatal("Open accepted an empty path")
	}
}

func TestProtocolKeyCRKAndDiagnosticsSurviveRestart(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state", "security.db")
	store := openTestStore(t, path)
	if err := store.EnsureTenant(ctx, "tenant-1", "Mission 1"); err != nil {
		t.Fatal(err)
	}
	key, version := testKey("tenant-1", "operational-root", "SM4_HCTR")
	if err := store.CreateProtocolKey(ctx, key, version); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateProtocolKey(ctx, key, version); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate key error = %v", err)
	}
	loaded, err := store.GetKey(ctx, key.TenantID, key.ID)
	if err != nil || loaded.SuiteID != key.SuiteID || loaded.UsageScope != models.KeyUsageProtocol || loaded.Tags["owner"] != "ccsds" {
		t.Fatalf("loaded key = %+v, err=%v", loaded, err)
	}
	if _, err := store.GetKey(ctx, "other", key.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant key error = %v", err)
	}
	byID, err := store.GetKeyVersion(ctx, version.ID)
	if err != nil || string(byID.WrappedDEK) != "wrapped" {
		t.Fatalf("version by id = %+v, err=%v", byID, err)
	}
	byNo, err := store.GetKeyVersionByNo(ctx, key.ID, 1)
	if err != nil || byNo.ID != version.ID {
		t.Fatalf("version by number = %+v, err=%v", byNo, err)
	}

	crk := &models.CRKVersion{ID: "crk-v1", Version: 1, Status: "active"}
	envelope := &models.CRKNodeEnvelope{ID: "env-1", CRKVersionID: crk.ID, NodeID: "node-1", Envelope: []byte(`{"sealed":true}`)}
	if err := store.SaveCRK(ctx, crk, envelope); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveCRK(ctx, crk, envelope); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate CRK error = %v", err)
	}
	if _, _, err := store.LoadLatestCRK(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing CRK error = %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	store = openTestStore(t, path)
	defer store.Close()
	loadedCRK, loadedEnvelope, err := store.LoadLatestCRK(ctx, "node-1")
	if err != nil || loadedCRK.Version != 1 || string(loadedEnvelope.Envelope) != string(envelope.Envelope) {
		t.Fatalf("restored CRK = %+v envelope=%+v err=%v", loadedCRK, loadedEnvelope, err)
	}
	diagnostics, err := store.Diagnostics(ctx)
	if err != nil || !diagnostics.IntegrityOK || diagnostics.Schema != schemaVersion || diagnostics.DatabaseSize == 0 {
		t.Fatalf("diagnostics = %+v err=%v", diagnostics, err)
	}
	if err := store.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(path); err != nil || info.IsDir() {
		t.Fatalf("database file stat = %+v err=%v", info, err)
	}
}

func TestMissionProfileAndFlightStatusSurviveRestart(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "security.db")
	store := openTestStore(t, path)
	if err := store.EnsureTenant(ctx, "tenant-1", "Mission 1"); err != nil {
		t.Fatal(err)
	}
	digest := [32]byte{1, 2, 3}
	if err := store.BindMissionProfile(ctx, "tenant-1", digest); err != nil {
		t.Fatal(err)
	}
	other := digest
	other[0] ^= 1
	if err := store.BindMissionProfile(ctx, "tenant-1", other); !errors.Is(err, ccsds.ErrAssociationState) {
		t.Fatalf("changed profile binding error=%v", err)
	}
	status := ccsds.FlightSecurityStatus{FormatVersion: ccsds.FlightSecurityStatusVersion,
		ProfileDigest: digest, SelfTest: ccsds.FlightSelfTestPassed, CryptoBackend: ccsds.FlightBackendARMv7NEON,
		CurrentSPI: 0xffff, NextSPI: 0, RecoverySPI: 0x7001, SecurityEpoch: 5, RootVersion: 3,
		ReceiveCount: ^uint64(0), LastReceiveUS: 12, MaxReceiveUS: 44}
	if err := store.ObserveFlightSecurityStatus(ctx, "tenant-1", status); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store = openTestStore(t, path)
	defer store.Close()
	loadedDigest, err := store.ReadMissionProfileDigest(ctx, "tenant-1")
	if err != nil || loadedDigest != digest {
		t.Fatalf("digest=%x err=%v", loadedDigest, err)
	}
	loaded, err := store.ReadFlightSecurityStatus(ctx, "tenant-1")
	if err != nil || loaded.ReceiveCount != ^uint64(0) || loaded.ProfileDigest != digest || loaded.NextSPI != 0 {
		t.Fatalf("flight=%+v err=%v", loaded, err)
	}
}

func TestCCSDSCounterPromotionReplayAndPersistence(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "security.db")
	store := openTestStore(t, path)
	provisionTestAssociations(t, store)

	current, err := store.GetTransmitAssociation(ctx, "tenant-1", ccsds.DirectionTCTx)
	if err != nil || current.SPI != 0x1001 {
		t.Fatalf("current = %+v err=%v", current, err)
	}
	if _, err := store.GetTransmitAssociation(ctx, "tenant-1", ccsds.DirectionAOSRx); !errors.Is(err, ccsds.ErrAssociationState) {
		t.Fatalf("invalid transmit direction error = %v", err)
	}
	if recovery, err := store.GetTransmitAssociation(ctx, "tenant-1", ccsds.DirectionTCRecoveryTx); err != nil || recovery.ID != "recovery" {
		t.Fatalf("recovery transmit association=%+v err=%v", recovery, err)
	}
	if got, err := store.NextTransmitCounter(ctx, current.ID); err != nil || got != 0 {
		t.Fatalf("first IV=%d err=%v", got, err)
	}
	if got, err := store.NextTransmitCounter(ctx, current.ID); err != nil || got != 1 {
		t.Fatalf("second IV=%d err=%v", got, err)
	}
	states, err := store.ReadOperationsState(ctx, "tenant-1")
	if err != nil || len(states) != 4 {
		t.Fatalf("operations states=%+v err=%v", states, err)
	}

	if err := store.CheckReplay(ctx, "aos", 100, 64); err != nil {
		t.Fatal(err)
	}
	if err := store.CommitReplay(ctx, "aos", 100, 64); err != nil {
		t.Fatal(err)
	}
	if err := store.CheckReplay(ctx, "aos", 100, 64); !errors.Is(err, ccsds.ErrReplay) {
		t.Fatalf("replay error=%v", err)
	}
	if err := store.CommitReplay(ctx, "aos", 37, 64); err != nil {
		t.Fatalf("window edge commit error=%v", err)
	}
	if err := store.CommitReplay(ctx, "aos", 36, 64); !errors.Is(err, ccsds.ErrReplay) {
		t.Fatalf("old sequence error=%v", err)
	}
	if err := store.CheckReplay(ctx, "current", 1, 64); !errors.Is(err, ccsds.ErrAssociationState) {
		t.Fatalf("TC replay state error=%v", err)
	}
	prepareStoredRotation(t, store, 0x1001, 0x1002)

	if err := store.PromoteNextTC(ctx, "tenant-1"); err != nil {
		t.Fatal(err)
	}
	promoted, err := store.GetTransmitAssociation(ctx, "tenant-1", ccsds.DirectionTCTx)
	if err != nil || promoted.SPI != 0x1002 {
		t.Fatalf("promoted=%+v err=%v", promoted, err)
	}
	if _, err := store.NextTransmitCounter(ctx, current.ID); !errors.Is(err, ccsds.ErrAssociationState) {
		t.Fatalf("disabled current counter error=%v", err)
	}
	if err := store.PromoteNextTC(ctx, "tenant-1"); !errors.Is(err, ccsds.ErrAssociationState) {
		t.Fatalf("second promotion error=%v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store = openTestStore(t, path)
	defer store.Close()
	if got, err := store.NextTransmitCounter(ctx, promoted.ID); err != nil || got != 0 {
		t.Fatalf("persisted promoted IV=%d err=%v", got, err)
	}
	if err := store.MarkTCRotationFrameProduced(ctx, "tenant-1", promoted.ID); err != nil {
		t.Fatal(err)
	}
	rotation, err := store.ReadTCRotationState(ctx, "tenant-1")
	if err != nil || rotation.Phase != ccsds.TCRotationActive {
		t.Fatalf("rotation=%+v err=%v", rotation, err)
	}
	if err := store.CheckReplay(ctx, "aos", 100, 64); !errors.Is(err, ccsds.ErrReplay) {
		t.Fatalf("replay was forgotten after restart: %v", err)
	}

	if _, err := store.db.ExecContext(ctx, `UPDATE tx_states SET next_iv=4294967296 WHERE association_id=?`, promoted.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.NextTransmitCounter(ctx, promoted.ID); !errors.Is(err, ccsds.ErrCounterExhausted) {
		t.Fatalf("counter exhaustion error=%v", err)
	}
	if _, err := store.NextTransmitCounter(ctx, "missing"); !errors.Is(err, ccsds.ErrAssociationNotFound) {
		t.Fatalf("missing counter error=%v", err)
	}
}

func TestCCSDSPromotionWrapsCompleteSPISpace(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t, filepath.Join(t.TempDir(), "security.db"))
	defer store.Close()
	provisionTestAssociations(t, store)
	if _, err := store.db.ExecContext(ctx, `UPDATE security_associations SET spi=65535 WHERE id='current'`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `UPDATE security_associations SET spi=0 WHERE id='next'`); err != nil {
		t.Fatal(err)
	}
	prepareStoredRotation(t, store, 0xffff, 0x0000)
	if err := store.PromoteNextTC(ctx, "tenant-1"); err != nil {
		t.Fatalf("0xFFFF -> 0x0000 promotion failed: %v", err)
	}
	promoted, err := store.GetTransmitAssociation(ctx, "tenant-1", ccsds.DirectionTCTx)
	if err != nil || promoted.SPI != 0x0000 {
		t.Fatalf("promoted=%+v err=%v", promoted, err)
	}
}

func TestPersistedTCRotationLifecycleAndCorruption(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t, filepath.Join(t.TempDir(), "security.db"))
	provisionTestAssociations(t, store)
	if _, err := store.ReadTCRotationState(ctx, "tenant-1"); !errors.Is(err, ccsds.ErrAssociationNotFound) {
		t.Fatalf("missing=%v", err)
	}
	invalid := ccsds.TCRotationState{Phase: ccsds.TCRotationPrepared, TransactionID: 1,
		CurrentSPI: 0x1001, NextSPI: 0x1002, CurrentRootVersion: 1, NextRootVersion: 1}
	if err := store.MarkTCRotationPrepared(ctx, "tenant-1", invalid); !errors.Is(err, ccsds.ErrAssociationState) {
		t.Fatalf("invalid=%v", err)
	}
	invalid.NextRootVersion = 2
	invalid.NextSPI = 0x1003
	if err := store.MarkTCRotationPrepared(ctx, "tenant-1", invalid); !errors.Is(err, ccsds.ErrAssociationState) {
		t.Fatalf("mismatch=%v", err)
	}
	prepareStoredRotation(t, store, 0x1001, 0x1002)
	if err := store.MarkTCRotationFrameProduced(ctx, "tenant-1", "current"); !errors.Is(err, ccsds.ErrAssociationState) {
		t.Fatalf("early=%v", err)
	}
	if err := store.PromoteNextTC(ctx, "tenant-1"); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkTCRotationFrameProduced(ctx, "tenant-1", "current"); !errors.Is(err, ccsds.ErrAssociationState) {
		t.Fatalf("wrong=%v", err)
	}
	if err := store.MarkTCRotationFrameProduced(ctx, "tenant-1", "next"); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkTCRotationFrameProduced(ctx, "tenant-1", "next"); err != nil {
		t.Fatal(err)
	}
	state, err := store.ReadTCRotationState(ctx, "tenant-1")
	if err != nil || state.Phase != ccsds.TCRotationActive {
		t.Fatalf("state=%+v err=%v", state, err)
	}
	if _, err := store.db.ExecContext(ctx, `UPDATE tc_rotation_states SET transaction_id='bad' WHERE tenant_id='tenant-1'`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReadTCRotationState(ctx, "tenant-1"); err == nil {
		t.Fatal("corrupt rotation accepted")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReadTCRotationState(ctx, "tenant-1"); err == nil {
		t.Fatal("closed read succeeded")
	}
	if err := store.MarkTCRotationPrepared(ctx, "tenant-1", ccsds.TCRotationState{Phase: ccsds.TCRotationPrepared,
		TransactionID: 1, CurrentSPI: 1, NextSPI: 2, CurrentRootVersion: 1, NextRootVersion: 2}); err == nil {
		t.Fatal("closed prepare succeeded")
	}
	if err := store.MarkTCRotationFrameProduced(ctx, "tenant-1", "next"); err == nil {
		t.Fatal("closed completion succeeded")
	}
}

func TestAuditChainDetectsTamperAndDeletes(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t, filepath.Join(t.TempDir(), "security.db"))
	defer store.Close()
	service := auditchain.New(store)
	for _, action := range []string{"ccsds.provision", "ccsds.promote"} {
		if err := service.Record(ctx, auditchain.RecordRequest{TenantID: "tenant-1", ActorType: "system",
			ActorHash: "actor", Action: action, TargetType: "association", TargetIDHash: "target",
			Result: "success", Metadata: map[string]string{"spi": "1001"}}); err != nil {
			t.Fatal(err)
		}
	}
	events, err := service.ListEvents(ctx, "tenant:tenant-1", 100)
	if err != nil || len(events) != 2 || events[0].Sequence != 2 {
		t.Fatalf("events=%+v err=%v", events, err)
	}
	heads, err := service.ListChainHeads(ctx)
	if err != nil || len(heads) != 1 || heads[0].Sequence != 2 {
		t.Fatalf("heads=%+v err=%v", heads, err)
	}
	verified, err := service.VerifyChain(ctx, "tenant:tenant-1")
	if err != nil || !verified.Intact {
		t.Fatalf("verification=%+v err=%v", verified, err)
	}
	if _, err := store.db.ExecContext(ctx, `UPDATE audit_events SET result='tampered' WHERE chain_name=? AND sequence=1`, "tenant:tenant-1"); err != nil {
		t.Fatal(err)
	}
	if broken, err := store.VerifyAuditChain(ctx, "tenant:tenant-1"); err == nil || broken != 1 {
		t.Fatalf("tamper result broken=%d err=%v", broken, err)
	}
	if count, err := store.DeleteAuditEvents(ctx, "tenant:tenant-1"); err != nil || count != 2 {
		t.Fatalf("delete count=%d err=%v", count, err)
	}
	if _, err := store.GetAuditChainHead(ctx, "tenant:tenant-1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted head error=%v", err)
	}
	if count, err := store.DeleteAuditEvents(ctx, ""); err != nil || count != 0 {
		t.Fatalf("delete all count=%d err=%v", count, err)
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

func testKey(tenantID, id, suite string) (*models.Key, *models.KeyVersion) {
	key := &models.Key{ID: id, TenantID: tenantID, Name: id, Purpose: "encrypt_decrypt",
		UsageScope: models.KeyUsageProtocol, PolicyID: "default-v1", SuiteID: suite,
		CurrentVersion: 1, Status: "ACTIVE", Tags: map[string]string{"owner": "ccsds"}}
	version := &models.KeyVersion{ID: id + "-v1", KeyID: id, VersionNo: 1, SuiteID: suite,
		WrappedDEK: []byte("wrapped"), WrapMetadata: []byte(`{"wrap":"test"}`), Status: "ACTIVE"}
	return key, version
}

func testKeyAtVersion(tenantID, id, suite string, versionNo uint32) (*models.Key, *models.KeyVersion) {
	key, version := testKey(tenantID, id, suite)
	key.CurrentVersion = versionNo
	version.ID = fmt.Sprintf("%s-v%d", id, versionNo)
	version.VersionNo = versionNo
	return key, version
}

func provisionTestAssociations(t *testing.T, store *Store) {
	t.Helper()
	ctx := context.Background()
	if err := store.EnsureTenant(ctx, "tenant-1", "Mission 1"); err != nil {
		t.Fatal(err)
	}
	for _, spec := range []struct {
		id, suite string
		version   uint32
	}{{"operational", "SM4_HCTR", 1}, {"next-root", "SM4_HCTR", 2}, {"recovery-root", "SM4_GCM", 1}, {"aos-root", "SM4_GCM", 1}} {
		key, version := testKeyAtVersion("tenant-1", spec.id, spec.suite, spec.version)
		if err := store.CreateProtocolKey(ctx, key, version); err != nil {
			t.Fatal(err)
		}
	}
	prefix := []byte{1, 2, 3, 4, 5, 6}
	associations := []ccsds.SecurityAssociation{
		{ID: "current", TenantID: "tenant-1", SPI: 0x1001, Direction: ccsds.DirectionTCTx,
			KeyID: "operational", KeyVersion: 1, SecurityEpoch: 1, PolicyVersion: 1, SuiteID: "SM4_HCTR",
			State: ccsds.AssociationCurrent, Parameters: ccsds.ManagedParameters{TransmittedIVLength: 4, NoncePrefix: prefix}},
		{ID: "next", TenantID: "tenant-1", SPI: 0x1002, Direction: ccsds.DirectionTCTx,
			KeyID: "next-root", KeyVersion: 2, SecurityEpoch: 2, PolicyVersion: 1, SuiteID: "SM4_HCTR",
			State: ccsds.AssociationNext, Parameters: ccsds.ManagedParameters{TransmittedIVLength: 4, NoncePrefix: prefix}},
		{ID: "recovery", TenantID: "tenant-1", SPI: 0x7001, Direction: ccsds.DirectionTCRecoveryTx,
			KeyID: "recovery-root", KeyVersion: 1, PolicyVersion: 1, SuiteID: "SM4_GCM",
			State: ccsds.AssociationActive, Parameters: ccsds.ManagedParameters{TransmittedIVLength: 4, TagLength: 16, NoncePrefix: prefix}},
		{ID: "aos", TenantID: "tenant-1", SPI: 0x2001, Direction: ccsds.DirectionAOSRx,
			KeyID: "aos-root", KeyVersion: 1, PolicyVersion: 1, SuiteID: "SM4_GCM",
			State: ccsds.AssociationActive, Parameters: ccsds.ManagedParameters{SequenceNumberLength: 4, TransmittedIVLength: 12,
				TagLength: 16, ReplayWindow: 64, NoncePrefix: []byte{}}},
	}
	for _, association := range associations {
		if err := store.CreateAssociation(ctx, association); err != nil {
			t.Fatalf("create %s: %v", association.ID, err)
		}
	}
}

func prepareStoredRotation(t *testing.T, store *Store, currentSPI, nextSPI uint16) {
	t.Helper()
	if err := store.MarkTCRotationPrepared(context.Background(), "tenant-1", ccsds.TCRotationState{
		Phase: ccsds.TCRotationPrepared, TransactionID: 1, CurrentSPI: currentSPI, NextSPI: nextSPI,
		CurrentRootVersion: 1, NextRootVersion: 2,
	}); err != nil {
		t.Fatal(err)
	}
}

func TestInvalidInputsAndAssociationConflicts(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t, filepath.Join(t.TempDir(), "security.db"))
	defer store.Close()
	if err := store.EnsureTenant(ctx, "", "name"); err == nil {
		t.Fatal("empty tenant accepted")
	}
	if err := store.CreateProtocolKey(ctx, nil, nil); err == nil {
		t.Fatal("nil key accepted")
	}
	if err := store.SaveCRK(ctx, nil, nil); err == nil {
		t.Fatal("nil CRK accepted")
	}
	provisionTestAssociations(t, store)
	current, err := store.GetAssociationBySPI(ctx, "tenant-1", ccsds.DirectionTCTx, 0x1001)
	if err != nil || current.ID != "current" {
		t.Fatalf("association by SPI=%+v err=%v", current, err)
	}
	if _, err := store.GetAssociation(ctx, "tenant-1", "missing"); !errors.Is(err, ccsds.ErrAssociationNotFound) {
		t.Fatalf("missing association error=%v", err)
	}
	if err := store.CreateAssociation(ctx, *current); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate association error=%v", err)
	}
	invalid := *current
	invalid.ID = "invalid"
	invalid.Parameters.TransmittedIVLength = 3
	if err := store.CreateAssociation(ctx, invalid); err == nil {
		t.Fatal("invalid association accepted")
	}
	if err := store.CommitReplay(ctx, "missing", 1, 64); !errors.Is(err, ccsds.ErrAssociationState) {
		t.Fatalf("missing replay commit error=%v", err)
	}
	if err := store.AppendAuditEvent(ctx, nil); err == nil {
		t.Fatal("nil audit event accepted")
	}

	// Ensure timestamp parsing fails closed for corrupted persistent state.
	if _, err := store.db.ExecContext(ctx, `UPDATE protocol_keys SET created_at='bad' WHERE id='operational'`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetKey(ctx, "tenant-1", "operational"); err == nil {
		t.Fatal("corrupt timestamp accepted")
	}
}

func TestCorruptPersistentStateFailsClosed(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t, filepath.Join(t.TempDir(), "security.db"))
	defer store.Close()
	provisionTestAssociations(t, store)

	if _, err := store.db.ExecContext(ctx, `UPDATE security_associations SET transmitted_iv_length=3 WHERE id='current'`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetAssociation(ctx, "tenant-1", "current"); err == nil {
		t.Fatal("invalid persisted association was accepted")
	}
	if _, err := store.db.ExecContext(ctx, `UPDATE security_associations SET transmitted_iv_length=4 WHERE id='current'`); err != nil {
		t.Fatal(err)
	}

	if _, err := store.db.ExecContext(ctx, `UPDATE rx_states SET seen=1,highest_sequence='bad' WHERE association_id='aos'`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReadOperationsState(ctx, "tenant-1"); err == nil {
		t.Fatal("invalid replay projection was accepted")
	}
	if err := store.CheckReplay(ctx, "aos", 1, 64); err == nil {
		t.Fatal("invalid replay sequence was accepted")
	}
	if _, err := store.db.ExecContext(ctx, `PRAGMA ignore_check_constraints=ON`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `UPDATE rx_states SET highest_sequence='0',bitmap=x'01' WHERE association_id='aos'`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `PRAGMA ignore_check_constraints=OFF`); err != nil {
		t.Fatal(err)
	}
	if err := store.CheckReplay(ctx, "aos", 1, 64); err == nil {
		t.Fatal("invalid replay bitmap was accepted")
	}

	event := &models.AuditEvent{EventID: "event-1", ChainName: "system", Timestamp: time.Now(), Metadata: map[string]string{"mode": "test"}}
	if err := store.AppendAuditEvent(ctx, event); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `UPDATE audit_events SET metadata_json='{' WHERE event_id='event-1'`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ListAuditEvents(ctx, "system", 1); err == nil {
		t.Fatal("invalid audit metadata was accepted")
	}
	if _, err := store.db.ExecContext(ctx, `UPDATE audit_events SET metadata_json='{}',timestamp='bad' WHERE event_id='event-1'`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.VerifyAuditChain(ctx, "system"); err == nil {
		t.Fatal("invalid audit timestamp was accepted")
	}
	if _, err := store.db.ExecContext(ctx, `UPDATE audit_chain_heads SET updated_at='bad' WHERE chain_name='system'`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetAuditChainHead(ctx, "system"); err == nil {
		t.Fatal("invalid audit head timestamp was accepted")
	}
	if _, err := store.ListAuditChainHeads(ctx); err == nil {
		t.Fatal("invalid audit head list timestamp was accepted")
	}
}

func TestDatabaseFailuresAreReturnedByEverySecurityStateBoundary(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t, filepath.Join(t.TempDir(), "security.db"))
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	key, version := testKey("tenant-1", "root", "SM4_HCTR")
	association := ccsds.SecurityAssociation{ID: "sa", TenantID: "tenant-1", SPI: 1, Direction: ccsds.DirectionTCTx,
		KeyID: "root", KeyVersion: 1, SecurityEpoch: 1, PolicyVersion: 1, SuiteID: "SM4_HCTR",
		State: ccsds.AssociationCurrent, Parameters: ccsds.ManagedParameters{TransmittedIVLength: 4, NoncePrefix: []byte{1, 2, 3, 4, 5, 6}}}
	crk := &models.CRKVersion{ID: "crk", Version: 1, Status: "active"}
	envelope := &models.CRKNodeEnvelope{ID: "env", CRKVersionID: "crk", NodeID: "node", Envelope: []byte("sealed")}
	event := &models.AuditEvent{EventID: "event", ChainName: "system"}

	checks := []func() error{
		func() error { return store.Ping(ctx) },
		func() error { return store.migrate(ctx) },
		func() error { return store.EnsureTenant(ctx, "tenant-1", "mission") },
		func() error { return store.CreateProtocolKey(ctx, key, version) },
		func() error { _, err := store.GetKey(ctx, "tenant-1", "root"); return err },
		func() error { _, err := store.GetKeyVersion(ctx, "root-v1"); return err },
		func() error { _, err := store.GetKeyVersionByNo(ctx, "root", 1); return err },
		func() error { _, _, err := store.LoadLatestCRK(ctx, "node"); return err },
		func() error { return store.SaveCRK(ctx, crk, envelope) },
		func() error { _, err := store.Diagnostics(ctx); return err },
		func() error { return store.CreateAssociation(ctx, association) },
		func() error { _, err := store.GetAssociation(ctx, "tenant-1", "sa"); return err },
		func() error { _, err := store.GetAssociationBySPI(ctx, "tenant-1", ccsds.DirectionTCTx, 1); return err },
		func() error { _, err := store.GetTransmitAssociation(ctx, "tenant-1", ccsds.DirectionTCTx); return err },
		func() error { _, err := store.ReadOperationsState(ctx, "tenant-1"); return err },
		func() error { return store.PromoteNextTC(ctx, "tenant-1") },
		func() error { _, err := store.NextTransmitCounter(ctx, "sa"); return err },
		func() error { return store.CheckReplay(ctx, "sa", 1, 64) },
		func() error { return store.CommitReplay(ctx, "sa", 1, 64) },
		func() error { return store.AppendAuditEvent(ctx, event) },
		func() error { _, err := store.ListAuditEvents(ctx, "", 0); return err },
		func() error { _, err := store.DeleteAuditEvents(ctx, ""); return err },
		func() error { _, err := store.GetAuditChainHead(ctx, "system"); return err },
		func() error { _, err := store.ListAuditChainHeads(ctx); return err },
		func() error { _, err := store.VerifyAuditChain(ctx, "system"); return err },
	}
	for index, check := range checks {
		if err := check(); err == nil {
			t.Fatalf("boundary %d ignored closed database", index)
		}
	}
}

func TestTransactionalWriteFailuresRollBack(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t, filepath.Join(t.TempDir(), "security.db"))
	defer store.Close()
	provisionTestAssociations(t, store)

	if _, err := store.db.ExecContext(ctx, `CREATE TRIGGER reject_audit BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT,'reject audit'); END`); err != nil {
		t.Fatal(err)
	}
	if err := store.AppendAuditEvent(ctx, &models.AuditEvent{EventID: "rejected"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("audit trigger error=%v", err)
	}
	if _, err := store.db.ExecContext(ctx, `DROP TRIGGER reject_audit`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `CREATE TRIGGER reject_replay BEFORE UPDATE ON rx_states BEGIN SELECT RAISE(ABORT,'reject replay'); END`); err != nil {
		t.Fatal(err)
	}
	if err := store.CommitReplay(ctx, "aos", 1, 64); err == nil {
		t.Fatal("replay trigger failure was ignored")
	}
	if _, err := store.db.ExecContext(ctx, `DROP TRIGGER reject_replay`); err != nil {
		t.Fatal(err)
	}

	key, version := testKey("tenant-1", "extra-root", "SM4_HCTR")
	if err := store.CreateProtocolKey(ctx, key, version); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `CREATE TRIGGER reject_tx_state BEFORE INSERT ON tx_states BEGIN SELECT RAISE(ABORT,'reject tx'); END`); err != nil {
		t.Fatal(err)
	}
	association := ccsds.SecurityAssociation{ID: "extra", TenantID: "tenant-1", SPI: 0x3001, Direction: ccsds.DirectionTCTx,
		KeyID: key.ID, KeyVersion: 1, SecurityEpoch: 9, PolicyVersion: 1, SuiteID: "SM4_HCTR",
		State: ccsds.AssociationNext, Parameters: ccsds.ManagedParameters{TransmittedIVLength: 4, NoncePrefix: []byte{1, 2, 3, 4, 5, 6}}}
	if err := store.CreateAssociation(ctx, association); err == nil {
		t.Fatal("runtime-state trigger failure was ignored")
	}
	if _, err := store.GetAssociation(ctx, "tenant-1", association.ID); !errors.Is(err, ccsds.ErrAssociationNotFound) {
		t.Fatalf("failed association transaction persisted: %v", err)
	}
}

func TestSchemaAndPersistedKeyCorruptionAreRejected(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "security.db")
	store := openTestStore(t, path)
	if err := store.EnsureTenant(ctx, "tenant-1", "mission"); err != nil {
		t.Fatal(err)
	}
	key, version := testKey("tenant-1", "root", "SM4_HCTR")
	if err := store.CreateProtocolKey(ctx, key, version); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `UPDATE protocol_keys SET tags_json='{' WHERE id='root'`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetKey(ctx, "tenant-1", "root"); err == nil {
		t.Fatal("invalid key tags were accepted")
	}
	if _, err := store.db.ExecContext(ctx, `PRAGMA ignore_check_constraints=ON`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `UPDATE protocol_keys SET tags_json='{}',usage_scope='GENERIC' WHERE id='root'`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `PRAGMA ignore_check_constraints=OFF`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetKey(ctx, "tenant-1", "root"); err == nil {
		t.Fatal("non-protocol key was accepted")
	}
	if _, err := store.db.ExecContext(ctx, `UPDATE protocol_keys SET usage_scope='PROTOCOL',updated_at='bad' WHERE id='root'`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetKey(ctx, "tenant-1", "root"); err == nil {
		t.Fatal("invalid key update timestamp was accepted")
	}
	if _, err := store.db.ExecContext(ctx, `UPDATE protocol_key_versions SET created_at='bad' WHERE id='root-v1'`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetKeyVersion(ctx, "root-v1"); err == nil {
		t.Fatal("invalid key-version timestamp was accepted")
	}
	if _, err := store.db.ExecContext(ctx, `PRAGMA ignore_check_constraints=ON`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `UPDATE schema_meta SET version=99 WHERE singleton=1`); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if reopened, err := Open(ctx, path); err == nil {
		reopened.Close()
		t.Fatal("unknown schema version was accepted")
	}
}

func TestPromotionRejectsInvalidNextAndWriteFailure(t *testing.T) {
	ctx := context.Background()
	for _, mutation := range []string{
		`UPDATE security_associations SET spi=4099 WHERE id='next'`,
		`UPDATE security_associations SET security_epoch=9 WHERE id='next'`,
		`UPDATE security_associations SET nonce_prefix=x'090909090909' WHERE id='next'`,
	} {
		store := openTestStore(t, filepath.Join(t.TempDir(), "security.db"))
		provisionTestAssociations(t, store)
		prepareStoredRotation(t, store, 0x1001, 0x1002)
		if _, err := store.db.ExecContext(ctx, mutation); err != nil {
			t.Fatal(err)
		}
		if err := store.PromoteNextTC(ctx, "tenant-1"); !errors.Is(err, ccsds.ErrAssociationState) {
			t.Fatalf("mutation %q error=%v", mutation, err)
		}
		store.Close()
	}

	store := openTestStore(t, filepath.Join(t.TempDir(), "security.db"))
	defer store.Close()
	provisionTestAssociations(t, store)
	prepareStoredRotation(t, store, 0x1001, 0x1002)
	if _, err := store.db.ExecContext(ctx, `CREATE TRIGGER reject_promotion BEFORE UPDATE ON security_associations BEGIN SELECT RAISE(ABORT,'reject promotion'); END`); err != nil {
		t.Fatal(err)
	}
	if err := store.PromoteNextTC(ctx, "tenant-1"); err == nil {
		t.Fatal("promotion write failure was ignored")
	}
	if _, err := store.db.ExecContext(ctx, `DROP TRIGGER reject_promotion`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `CREATE TRIGGER reject_next_promotion BEFORE UPDATE ON security_associations WHEN NEW.state='CURRENT' BEGIN SELECT RAISE(ABORT,'reject next'); END`); err != nil {
		t.Fatal(err)
	}
	if err := store.PromoteNextTC(ctx, "tenant-1"); err == nil {
		t.Fatal("next promotion write failure was ignored")
	}
}

func TestAuditVerificationRejectsSequenceAndPreviousHashTamper(t *testing.T) {
	ctx := context.Background()
	for _, mutation := range []string{
		`UPDATE audit_events SET sequence=3 WHERE event_id='one'`,
		`UPDATE audit_events SET prev_hash='wrong' WHERE event_id='one'`,
	} {
		store := openTestStore(t, filepath.Join(t.TempDir(), "security.db"))
		event := &models.AuditEvent{EventID: "one", ChainName: "system", Timestamp: time.Now(), Metadata: map[string]string{}}
		if err := store.AppendAuditEvent(ctx, event); err != nil {
			t.Fatal(err)
		}
		if _, err := store.db.ExecContext(ctx, mutation); err != nil {
			t.Fatal(err)
		}
		if _, err := store.VerifyAuditChain(ctx, "system"); err == nil {
			t.Fatalf("audit mutation %q was accepted", mutation)
		}
		store.Close()
	}
	if boolInt(false) != 0 || boolInt(true) != 1 || conflict("noop", nil) != nil {
		t.Fatal("boolean or error helper contract changed")
	}
}

func TestOpenMigrationDiagnosticsAndCRKFailurePaths(t *testing.T) {
	ctx := context.Background()
	if _, err := Open(ctx, string([]byte{'b', 'a', 'd', 0, 'p', 'a', 't', 'h'})); err == nil {
		t.Fatal("invalid filesystem path was accepted")
	}
	if _, err := Open(ctx, t.TempDir()); err == nil {
		t.Fatal("directory was accepted as a SQLite database file")
	}

	original := schemaStatements
	schemaStatements = append(append([]string(nil), original...), `INVALID SQL`)
	if _, err := Open(ctx, filepath.Join(t.TempDir(), "invalid-schema.db")); err == nil {
		t.Fatal("schema application error was ignored")
	}
	schemaStatements = original
	raw := openTestStore(t, filepath.Join(t.TempDir(), "missing-meta.db"))
	if _, err := raw.db.ExecContext(ctx, `DROP TABLE schema_meta`); err != nil {
		t.Fatal(err)
	}
	schemaStatements = nil
	if err := raw.migrate(ctx); err == nil {
		t.Fatal("missing schema metadata was ignored")
	}
	schemaStatements = original
	raw.Close()

	store := openTestStore(t, filepath.Join(t.TempDir(), "diagnostics.db"))
	if err := store.migrate(ctx); err != nil {
		t.Fatal(err)
	}
	crk := &models.CRKVersion{ID: "crk", Version: 1, Status: "active"}
	envelope := &models.CRKNodeEnvelope{ID: "env", CRKVersionID: "crk", NodeID: "node", Envelope: []byte("sealed")}
	if err := store.SaveCRK(ctx, crk, envelope); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `UPDATE crk_versions SET created_at='bad' WHERE id='crk'`); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.LoadLatestCRK(ctx, "node"); err == nil {
		t.Fatal("invalid CRK timestamp was accepted")
	}
	if _, err := store.db.ExecContext(ctx, `DROP TABLE security_associations`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Diagnostics(ctx); err == nil {
		t.Fatal("missing diagnostics table was ignored")
	}
	store.Close()
}

func TestKeyAndAuditInnerTransactionFailures(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t, filepath.Join(t.TempDir(), "security.db"))
	defer store.Close()
	if err := store.EnsureTenant(ctx, "tenant-1", "mission"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `CREATE TRIGGER reject_key_version BEFORE INSERT ON protocol_key_versions BEGIN SELECT RAISE(ABORT,'reject version'); END`); err != nil {
		t.Fatal(err)
	}
	key, version := testKey("tenant-1", "rejected-root", "SM4_HCTR")
	if err := store.CreateProtocolKey(ctx, key, version); !errors.Is(err, ErrConflict) {
		t.Fatalf("key-version trigger error=%v", err)
	}
	if _, err := store.GetKey(ctx, "tenant-1", key.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("failed key transaction persisted: %v", err)
	}
	if _, err := store.db.ExecContext(ctx, `DROP TRIGGER reject_key_version`); err != nil {
		t.Fatal(err)
	}

	if _, err := store.db.ExecContext(ctx, `CREATE TRIGGER reject_head BEFORE INSERT ON audit_chain_heads BEGIN SELECT RAISE(ABORT,'reject head'); END`); err != nil {
		t.Fatal(err)
	}
	if err := store.AppendAuditEvent(ctx, &models.AuditEvent{EventID: "head-rejected"}); err == nil {
		t.Fatal("audit-head insert failure was ignored")
	}
	if _, err := store.db.ExecContext(ctx, `DROP TRIGGER reject_head`); err != nil {
		t.Fatal(err)
	}
	if err := store.AppendAuditEvent(ctx, &models.AuditEvent{EventID: "one"}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `CREATE TRIGGER reject_head_update BEFORE UPDATE ON audit_chain_heads BEGIN SELECT RAISE(ABORT,'reject head update'); END`); err != nil {
		t.Fatal(err)
	}
	if err := store.AppendAuditEvent(ctx, &models.AuditEvent{EventID: "two"}); err == nil {
		t.Fatal("audit-head update failure was ignored")
	}
	if _, err := store.db.ExecContext(ctx, `DROP TRIGGER reject_head_update`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `CREATE TRIGGER reject_audit_delete BEFORE DELETE ON audit_events BEGIN SELECT RAISE(ABORT,'reject delete'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DeleteAuditEvents(ctx, "system"); err == nil {
		t.Fatal("audit delete failure was ignored")
	}
	if _, err := store.db.ExecContext(ctx, `DROP TRIGGER reject_audit_delete`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `CREATE TRIGGER reject_head_delete BEFORE DELETE ON audit_chain_heads BEGIN SELECT RAISE(ABORT,'reject head delete'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DeleteAuditEvents(ctx, "system"); err == nil {
		t.Fatal("audit-head delete failure was ignored")
	}

	first := &models.CRKVersion{ID: "crk-1", Version: 1, Status: "active"}
	firstEnvelope := &models.CRKNodeEnvelope{ID: "same-envelope", CRKVersionID: "crk-1", NodeID: "node", Envelope: []byte("one")}
	if err := store.SaveCRK(ctx, first, firstEnvelope); err != nil {
		t.Fatal(err)
	}
	second := &models.CRKVersion{ID: "crk-2", Version: 2, Status: "active"}
	secondEnvelope := &models.CRKNodeEnvelope{ID: "same-envelope", CRKVersionID: "crk-2", NodeID: "node", Envelope: []byte("two")}
	if err := store.SaveCRK(ctx, second, secondEnvelope); !errors.Is(err, ErrConflict) {
		t.Fatalf("CRK envelope conflict error=%v", err)
	}
}

func TestRemainingDecodeAndAuditHeadFailures(t *testing.T) {
	if _, err := scanAuditEvent(failingScanner{}); err == nil {
		t.Fatal("row scan failure was ignored")
	}
	if _, err := scanOperationsState(failingScanner{}); err == nil {
		t.Fatal("operations row scan failure was ignored")
	}
	ctx := context.Background()
	store := openTestStore(t, filepath.Join(t.TempDir(), "security.db"))
	defer store.Close()
	if _, err := store.db.ExecContext(ctx, `CREATE TRIGGER remove_new_head AFTER INSERT ON audit_chain_heads BEGIN DELETE FROM audit_chain_heads WHERE chain_name=NEW.chain_name; END`); err != nil {
		t.Fatal(err)
	}
	if err := store.AppendAuditEvent(ctx, &models.AuditEvent{EventID: "orphaned-head"}); err == nil {
		t.Fatal("missing audit head after creation was ignored")
	}
	if _, err := store.db.ExecContext(ctx, `DROP TRIGGER remove_new_head`); err != nil {
		t.Fatal(err)
	}
}
