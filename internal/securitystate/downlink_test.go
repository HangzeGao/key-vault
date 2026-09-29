//go:build downlink

package securitystate

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"testing"
)

func TestDownlinkStateSurvivesRestart(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "security.db")
	store := openTestStore(t, path)
	sealed := []byte("sealed-kek-set")
	if err := store.ProvisionDownlinkKEKSet(ctx, sealed, 3); err != nil {
		t.Fatal(err)
	}
	pkg := bytes.Repeat([]byte{0x42}, 16417)
	if err := store.AdvanceDownlinkBatch(ctx, 0, pkg, [32]byte{1}); err != nil {
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

func TestClosedDownlinkStoreFailsClosed(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t, filepath.Join(t.TempDir(), "state.db"))
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	for index, call := range []func() error{
		func() error { _, err := store.ReadDownlinkKeyState(ctx); return err },
		func() error { return store.ProvisionDownlinkKEKSet(ctx, []byte("sealed"), 0) },
		func() error { return store.SetActiveDownlinkKEKSlot(ctx, 0) },
		func() error { return store.AdvanceDownlinkBatch(ctx, 0, make([]byte, 16417), [32]byte{1}) },
		func() error { return store.MarkCurrentDownlinkObserved(ctx, 1) },
	} {
		if err := call(); err == nil {
			t.Fatalf("closed downlink call %d succeeded", index)
		}
	}
}
