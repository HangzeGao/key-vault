package postgres

import (
	"strings"
	"testing"
)

func TestSchemaMigrationsAreOrderedAndPurposeIsEnforcedSeparately(t *testing.T) {
	if len(schemaMigrations) != 4 {
		t.Fatalf("migration count = %d, want 4", len(schemaMigrations))
	}
	if schemaMigrations[0].version != 1 || schemaMigrations[1].version != 2 ||
		schemaMigrations[2].version != 3 || schemaMigrations[3].version != 4 {
		t.Fatalf("migration versions are not ordered through version 4")
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
	if !strings.Contains(migrationV4KeyUploadDownloadSQL, "'key_wrap'") ||
		!strings.Contains(migrationV4KeyUploadDownloadSQL, "key_uploads") ||
		!strings.Contains(migrationV4KeyUploadDownloadSQL, "key_downloads") {
		t.Fatal("key transfer migration must allow key_wrap and create upload/download storage")
	}
}
