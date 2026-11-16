package securitystate

import (
	"context"
	"crypto/sha256"
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
	prepare := func(existing []byte) ([]byte, error) {
		if len(existing) != 0 && string(existing) != "sealed originals" {
			return nil, errors.New("candidate contents not authorized")
		}
		return []byte("sealed originals"), nil
	}
	unexpected := func([]byte) ([]byte, error) {
		t.Fatal("anchored operation attempted to use the import key")
		return nil, nil
	}
	if _, err := store.StageGroundCommissioning(ctx, "tenant", txn, binding, [32]byte{3}, unexpected); !errors.Is(err, ErrConflict) {
		t.Fatalf("missing anchored record accepted: %v", err)
	}
	empty := func([]byte) ([]byte, error) { return nil, nil }
	if _, err := store.StageGroundCommissioning(ctx, "tenant", txn, binding, [32]byte{}, empty); !errors.Is(err, ErrConflict) {
		t.Fatalf("empty installation accepted: %v", err)
	}
	failedPrepare := func([]byte) ([]byte, error) { return nil, ErrConflict }
	if _, err := store.StageGroundCommissioning(ctx, "tenant", txn, binding, [32]byte{}, failedPrepare); !errors.Is(err, ErrConflict) {
		t.Fatalf("preparation failure discarded: %v", err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := store.StageGroundCommissioning(cancelled, "tenant", txn, binding, [32]byte{}, unexpected); err == nil {
		t.Fatal("cancelled operation staged successfully")
	}
	if _, err := store.db.ExecContext(ctx, `CREATE TRIGGER interrupted_install BEFORE INSERT ON ground_commissioning
		BEGIN SELECT RAISE(ABORT, 'simulated interrupted commit'); END`); err != nil {
		t.Fatal(err)
	}
	if got, err := store.StageGroundCommissioning(ctx, "tenant", txn, binding, [32]byte{}, prepare); err == nil || got != ([32]byte{}) {
		t.Fatal("failed write reported success")
	}
	if _, err := store.db.ExecContext(ctx, `DROP TRIGGER interrupted_install`); err != nil {
		t.Fatal(err)
	}
	commitment, err := store.StageGroundCommissioning(ctx, "tenant", txn, binding, [32]byte{}, prepare)
	if err != nil || commitment == ([32]byte{}) {
		t.Fatalf("initial stage: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := store.StageGroundCommissioning(ctx, "tenant", txn, binding, [32]byte{}, prepare); err != nil || got != commitment {
		t.Fatalf("pre-anchor recovery: %v", err)
	}
	if got, err := store.StageGroundCommissioning(ctx, "tenant", txn, binding, commitment, unexpected); err != nil || got != commitment {
		t.Fatalf("post-anchor recovery: %v", err)
	}
	if payload, err := store.ReadAnchoredGroundCommissioning(ctx, "tenant", txn, binding, commitment); err != nil || string(payload) != "sealed originals" {
		t.Fatalf("ground confirmation could not read the committed stage: %v", err)
	}
	if _, err := store.ReadAnchoredGroundCommissioning(ctx, "tenant", txn, binding, [32]byte{}); !errors.Is(err, ErrConflict) {
		t.Fatalf("an empty anchor opened the stage: %v", err)
	}
	if _, err := store.ReadMissionProfileDigest(ctx, "tenant"); !errors.Is(err, ccsds.ErrAssociationNotFound) {
		t.Fatalf("staging wrote a live mission binding: %v", err)
	}
	if _, err := store.GetAssociation(ctx, "tenant", "current"); !errors.Is(err, ccsds.ErrAssociationNotFound) {
		t.Fatalf("staging made an association available: %v", err)
	}
	if _, err := store.StageGroundCommissioning(ctx, "tenant", txn, [32]byte{3}, commitment, unexpected); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed installation accepted: %v", err)
	}
	if _, err := store.db.ExecContext(ctx, `UPDATE ground_commissioning SET sealed_installation=x'1234' WHERE tenant_id='tenant'`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.StageGroundCommissioning(ctx, "tenant", txn, binding, commitment, unexpected); !errors.Is(err, ErrConflict) {
		t.Fatalf("corrupt installation was reused: %v", err)
	}
	rehashed := sha256.Sum256([]byte{0x12, 0x34})
	if _, err := store.db.ExecContext(ctx, `UPDATE ground_commissioning SET installation_digest=? WHERE tenant_id='tenant'`, rehashed[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := store.StageGroundCommissioning(ctx, "tenant", txn, binding, [32]byte{}, prepare); !errors.Is(err, ErrConflict) {
		t.Fatalf("unanchored rehashed installation accepted: %v", err)
	}
	if _, err := store.StageGroundCommissioning(ctx, "tenant", txn, binding, commitment, unexpected); !errors.Is(err, ErrConflict) {
		t.Fatalf("anchored rehashed installation accepted: %v", err)
	}
	if _, err := store.ReadAnchoredGroundCommissioning(ctx, "tenant", txn, binding, commitment); !errors.Is(err, ErrConflict) {
		t.Fatalf("ground confirmation accepted tampered roots: %v", err)
	}
	if err := store.EnsureTenant(ctx, "other", "other"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.StageGroundCommissioning(ctx, "other", txn, binding, [32]byte{}, prepare); err == nil {
		t.Fatal("transaction reused by another tenant")
	}
	if err := store.BindMissionProfile(ctx, "other", [32]byte{7}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.StageGroundCommissioning(ctx, "other", [32]byte{3}, binding, [32]byte{}, prepare); !errors.Is(err, ErrConflict) {
		t.Fatalf("staged to a live tenant: %v", err)
	}
	if _, err := store.db.ExecContext(ctx, `DELETE FROM ground_commissioning WHERE tenant_id='tenant'`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.StageGroundCommissioning(ctx, "tenant", txn, binding, commitment, unexpected); !errors.Is(err, ErrConflict) {
		t.Fatalf("deleted anchored record reinstalled: %v", err)
	}
	if _, err := store.ReadAnchoredGroundCommissioning(ctx, "tenant", txn, binding, commitment); err == nil {
		t.Fatal("missing stage accepted by confirmation")
	}
	var count int
	if err := store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM ground_commissioning`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("database recreated an anchored record: count=%d err=%v", count, err)
	}
}

func TestConcurrentCommissioningCommitments(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "db.sqlite")
	first := openTestStore(t, path)
	second := openTestStore(t, path)
	if err := first.EnsureTenant(ctx, "tenant", "tn"); err != nil {
		t.Fatal(err)
	}
	type result struct {
		commitment [32]byte
		err        error
	}
	start := make(chan struct{})
	results := make(chan result, 2)
	for i, store := range []*Store{first, second} {
		go func() {
			<-start
			got, err := store.StageGroundCommissioning(ctx, "tenant", [32]byte{1}, [32]byte{2}, [32]byte{},
				func(existing []byte) ([]byte, error) {
					if existing != nil {
						return existing, nil
					}
					return []byte{byte(i + 1)}, nil
				})
			results <- result{got, err}
		}()
	}
	close(start)
	a, b := <-results, <-results
	if a.err != nil || b.err != nil || a.commitment == ([32]byte{}) || a.commitment != b.commitment {
		t.Fatalf("concurrent requests did not select one candidate: %v %v", a.err, b.err)
	}
}
