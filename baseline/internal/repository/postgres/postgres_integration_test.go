package postgres

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/kvlt/key-vault/internal/repository/models"
)

// Run with KVLT_TEST_POSTGRES_DSN pointing at an isolated disposable database.
func TestPostgresMigrationTransactionAndConcurrentVersioning(t *testing.T) {
	dsn := os.Getenv("KVLT_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("KVLT_TEST_POSTGRES_DSN not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	store, err := New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := store.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	tenant := &models.Tenant{ID: "integration-tenant", Name: "Integration", Status: "active"}
	if err := store.UpsertTenant(ctx, tenant); err != nil {
		t.Fatal(err)
	}
	base := &models.TenantEnvelopeConfig{TenantID: tenant.ID, DefaultFormat: "kvlt-binary-v1", AllowedFormats: []string{"kvlt-binary-v1"}, UpdatedBy: "test"}
	if err := store.UpsertTenantEnvelopeConfig(ctx, base); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cfg := *base
			cfg.Version = base.Version
			cfg.UpdatedBy = "concurrent"
			results <- store.UpsertTenantEnvelopeConfig(ctx, &cfg)
		}()
	}
	wg.Wait()
	close(results)
	success, conflicts := 0, 0
	for err := range results {
		if err == nil {
			success++
		} else {
			conflicts++
		}
	}
	if success != 1 || conflicts != 1 {
		t.Fatalf("success=%d conflicts=%d", success, conflicts)
	}
}
