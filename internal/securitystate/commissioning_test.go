package securitystate

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/kvlt/key-vault/internal/protocol/ccsds"
)

func TestStageGroundCommissioningCannotCreateRuntimeState(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "db.sqlite")
	store, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { store.Close() }()
	if err := store.EnsureTenant(ctx, "tenant", "tn"); err != nil {
		t.Fatal(err)
	}
	txn, binding := [32]byte{1}, [32]byte{2}
	if err := store.StageGroundCommissioning(ctx, "tenant", txn, binding, nil); !errors.Is(err, ErrConflict) {
		t.Fatalf("empty installation accepted: %v", err)
	}
	if _, err := store.db.ExecContext(ctx, `CREATE TRIGGER interrupted_install BEFORE INSERT ON ground_commissioning
		BEGIN SELECT RAISE(ABORT, 'simulated interrupted commit'); END`); err != nil {
		t.Fatal(err)
	}
	if err := store.StageGroundCommissioning(ctx, "tenant", txn, binding, []byte("failed installation")); err == nil {
		t.Fatal("failed write reported success")
	}
	if _, err := store.db.ExecContext(ctx, `DROP TRIGGER interrupted_install`); err != nil {
		t.Fatal(err)
	}
	if err := store.StageGroundCommissioning(ctx, "tenant", txn, binding, []byte("sealed originals")); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.StageGroundCommissioning(ctx, "tenant", txn, binding, []byte("resealed on retry")); err != nil {
		t.Fatal(err)
	}
	var staged []byte
	if err := store.db.QueryRowContext(ctx, `SELECT sealed_installation FROM ground_commissioning WHERE tenant_id='tenant'`).Scan(&staged); err != nil || !bytes.Equal(staged, []byte("sealed originals")) {
		t.Fatalf("first installation not preserved: %v", err)
	}
	if _, err := store.ReadMissionProfileDigest(ctx, "tenant"); !errors.Is(err, ccsds.ErrAssociationNotFound) {
		t.Fatalf("staging wrote a live mission binding: %v", err)
	}
	if _, err := store.GetAssociation(ctx, "tenant", "current"); !errors.Is(err, ccsds.ErrAssociationNotFound) {
		t.Fatalf("staging made an association available: %v", err)
	}
	if err := store.StageGroundCommissioning(ctx, "tenant", txn, [32]byte{3}, []byte("conflict")); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed installation accepted: %v", err)
	}
	if _, err := store.db.ExecContext(ctx, `UPDATE ground_commissioning SET sealed_installation=x'1234' WHERE tenant_id='tenant'`); err != nil {
		t.Fatal(err)
	}
	if err := store.StageGroundCommissioning(ctx, "tenant", txn, binding, []byte("repair")); !errors.Is(err, ErrConflict) {
		t.Fatalf("corrupt installation was reused: %v", err)
	}
	if err := store.EnsureTenant(ctx, "other", "other"); err != nil {
		t.Fatal(err)
	}
	if err := store.StageGroundCommissioning(ctx, "other", txn, binding, []byte("reused transaction")); err == nil {
		t.Fatal("transaction reused by another tenant")
	}
	if err := store.BindMissionProfile(ctx, "other", [32]byte{7}); err != nil {
		t.Fatal(err)
	}
	if err := store.StageGroundCommissioning(ctx, "other", [32]byte{3}, binding, []byte("operational tenant")); !errors.Is(err, ErrConflict) {
		t.Fatalf("staged to a live tenant: %v", err)
	}
}
