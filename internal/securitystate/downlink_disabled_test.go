//go:build !downlink

package securitystate

import (
	"context"
	"path/filepath"
	"testing"
)

func TestTCOnlySchemaHasNoDownlinkTable(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t, filepath.Join(t.TempDir(), "state.db"))
	defer store.Close()
	var tables int
	if err := store.db.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE name='downlink_key_state'`).Scan(&tables); err != nil || tables != 0 {
		t.Fatalf("TC-only schema includes downlink table: count=%d err=%v", tables, err)
	}
}
