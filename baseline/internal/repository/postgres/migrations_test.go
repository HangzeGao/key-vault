package postgres

import (
	"strings"
	"testing"
)

func TestSchemaMigrationsAreOrderedAndPurposeIsEnforcedSeparately(t *testing.T) {
	if len(schemaMigrations) != 3 {
		t.Fatalf("migration count = %d, want 3", len(schemaMigrations))
	}
	if schemaMigrations[0].version != 1 || schemaMigrations[1].version != 2 || schemaMigrations[2].version != 3 {
		t.Fatalf("migration versions = %d, %d, %d, want 1, 2, 3", schemaMigrations[0].version, schemaMigrations[1].version, schemaMigrations[2].version)
	}
	if strings.Contains(migrationV1SQL, "keys_purpose_check") {
		t.Fatal("initial schema must not enforce purpose before historical values are normalized")
	}
	if !strings.Contains(migrationV2PurposeSQL, "UPDATE keys SET purpose = 'encrypt_decrypt'") || !strings.Contains(migrationV2PurposeSQL, "CHECK (purpose = 'encrypt_decrypt')") {
		t.Fatal("purpose migration must normalize then enforce the supported purpose")
	}
	if !strings.Contains(migrationV3ArchiveDestroyedKeysSQL, "archived_at") {
		t.Fatal("archive migration must add archived_at")
	}
}
