package admin

import (
	"strings"
	"testing"

	"github.com/kvlt/key-vault/internal/api/middleware"
)

func TestImportKeyRequestAcceptsOnlyExternalKey(t *testing.T) {
	var canonical importKeyReq
	if err := middleware.DecodeJSONStrict(
		[]byte(`{"name":"demo","external_key":"AA=="}`),
		&canonical,
	); err != nil {
		t.Fatalf("canonical external_key rejected: %v", err)
	}
	if canonical.ExternalKey != "AA==" {
		t.Fatalf("ExternalKey = %q, want %q", canonical.ExternalKey, "AA==")
	}

	var unsupported importKeyReq
	err := middleware.DecodeJSONStrict(
		[]byte(`{"name":"demo","external_dek":"AA=="}`),
		&unsupported,
	)
	if err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unsupported external_dek error = %v, want unknown-field rejection", err)
	}
}
