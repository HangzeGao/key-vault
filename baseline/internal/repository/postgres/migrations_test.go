package postgres

import (
	"os"
	"strings"
	"testing"
)

func TestSchemaMigrationsAreOrderedAndPurposeIsEnforcedSeparately(t *testing.T) {
	if len(schemaMigrations) != 7 {
		t.Fatalf("migration count = %d, want 7", len(schemaMigrations))
	}
	if schemaMigrations[0].version != 1 || schemaMigrations[1].version != 2 ||
		schemaMigrations[2].version != 3 || schemaMigrations[3].version != 4 ||
		schemaMigrations[4].version != 5 || schemaMigrations[5].version != 6 || schemaMigrations[6].version != 7 {
		t.Fatalf("migration versions are not ordered through version 7")
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
	if !strings.Contains(migrationV5AuthenticationKeyPurposeSQL, "'authenticate_verify'") {
		t.Fatal("authentication purpose migration must allow authenticate_verify")
	}
	if !strings.Contains(migrationV6KeyUsageScopeSQL, "'GENERIC', 'PROTOCOL'") ||
		!strings.Contains(migrationV6KeyUsageScopeSQL, "DROP DEFAULT") {
		t.Fatal("usage scope migration must isolate generic and protocol keys")
	}
	if !strings.Contains(migrationV7CCSDSSecurityStateSQL, "ccsds_security_associations") ||
		!strings.Contains(migrationV7CCSDSSecurityStateSQL, "ccsds_rx_replay_states") ||
		!strings.Contains(migrationV7CCSDSSecurityStateSQL, "next_iv_counter") ||
		!strings.Contains(migrationV7CCSDSSecurityStateSQL, "'AES_256_CTR', 'SM4_CTR'") ||
		!strings.Contains(migrationV7CCSDSSecurityStateSQL, "'AES_256_GCM', 'SM4_GCM'") ||
		!strings.Contains(migrationV7CCSDSSecurityStateSQL, "'TC_RECOVERY_TX'") ||
		!strings.Contains(migrationV7CCSDSSecurityStateSQL, "octet_length(nonce_prefix) = 6") ||
		!strings.Contains(migrationV7CCSDSSecurityStateSQL, "'PREINSTALLED', 'ACTIVE', 'GRACE', 'DISABLED'") {
		t.Fatal("CCSDS migration must persist associations and replay state")
	}
}

func TestExternalCCSDSMigrationMatchesEmbeddedMigration(t *testing.T) {
	external, err := os.ReadFile("../../../migrations/007_ccsds_security_state.sql")
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(external)) != strings.TrimSpace(migrationV7CCSDSSecurityStateSQL) {
		t.Fatal("external CCSDS migration diverges from the embedded runtime migration")
	}
}
