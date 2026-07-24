package ops

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kvlt/key-vault/internal/api/middleware"
	"github.com/kvlt/key-vault/internal/auditchain"
	"github.com/kvlt/key-vault/internal/auth/principal"
	"github.com/kvlt/key-vault/internal/config"
	"github.com/kvlt/key-vault/internal/repository"
	"github.com/kvlt/key-vault/internal/repository/memory"
	"github.com/kvlt/key-vault/internal/repository/models"
)

type failingAudit struct{}

func (failingAudit) Record(context.Context, auditchain.RecordRequest) error {
	return errors.New("audit offline")
}

type diagnosticStore struct {
	*memory.Store
	diagnostics *repository.DatabaseDiagnostics
	err         error
}

func (s *diagnosticStore) DatabaseDiagnostics(context.Context) (*repository.DatabaseDiagnostics, error) {
	return s.diagnostics, s.err
}

func opsTestHandler(t *testing.T, recorder auditRecorder) http.Handler {
	t.Helper()
	store := memory.New()
	now := time.Now().UTC()
	if err := store.CreateLifecycleJob(context.Background(), &models.LifecycleJob{ID: "job-1", Type: "key_expiry_check", Status: "FAILED", CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	return opsTestHandlerForStore(store, recorder)
}

func opsTestHandlerForStore(store repository.Repository, recorder auditRecorder) http.Handler {
	h := New(Deps{Store: store, AuditChain: recorder, Cfg: config.Default()})
	mux := http.NewServeMux()
	h.Routes(mux)
	auth := middleware.Auth(middleware.AuthConfig{StaticTokens: map[string]*principal.Principal{"ops-token": &principal.Principal{ID: "operator", Plane: principal.PlaneOps, Scopes: []string{"ops:repair", "ops:breakglass"}}}})
	return middleware.ReadBody(auth(middleware.APIAccess(mux)))
}

func performOpsRequest(handler http.Handler, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer ops-token")
	req.Header.Set("Content-Type", "application/json")
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func TestOpsMutationGovernanceNegativeCases(t *testing.T) {
	h := opsTestHandler(t, auditchain.New(memory.New()))
	path := "/ui/api/v1/ops/lifecycle/jobs/job-1/retry"
	tests := []struct {
		name, body string
		headers    map[string]string
		want       int
	}{
		{"missing reason", `{"ticket_id":"INC-1"}`, map[string]string{"Idempotency-Key": "i1"}, 400},
		{"missing ticket", `{"reason":"retry"}`, map[string]string{"Idempotency-Key": "i2"}, 400},
		{"missing idempotency", `{"reason":"retry","ticket_id":"INC-1"}`, nil, 400},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if rec := performOpsRequest(h, path, tt.body, tt.headers); rec.Code != tt.want {
				t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestBreakglassRequiresImpactAndConfirmation(t *testing.T) {
	h := opsTestHandler(t, auditchain.New(memory.New()))
	rec := performOpsRequest(h, "/ui/api/v1/ops/breakglass/lifecycle/jobs/job-1/retry", `{"reason":"emergency","ticket_id":"INC-2"}`, map[string]string{"Idempotency-Key": "bg-1"})
	if rec.Code != 400 || !strings.Contains(rec.Body.String(), "BREAKGLASS_CONFIRMATION_REQUIRED") {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestOpsAuditFailureIsFailClosed(t *testing.T) {
	h := opsTestHandler(t, failingAudit{})
	rec := performOpsRequest(h, "/ui/api/v1/ops/lifecycle/jobs/job-1/retry", `{"reason":"retry","ticket_id":"INC-3"}`, map[string]string{"Idempotency-Key": "audit-1"})
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "AUDIT_UNAVAILABLE") {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestDBStatusReturnsStructuredRedactedDiagnostics(t *testing.T) {
	h := opsTestHandler(t, auditchain.New(memory.New()))
	req := httptest.NewRequest(http.MethodGet, "/ui/api/v1/ops/db/status", nil)
	req.Header.Set("Authorization", "Bearer ops-token")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var response dbStatusResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if !response.Connected || response.Driver != "memory" || response.Status != "warn" {
		t.Fatalf("unexpected database status: %+v", response)
	}
	if response.Connection.Reason != "" || response.Integrity.Status != "ok" {
		t.Fatalf("healthy diagnostics must not contain an error reason: %+v", response)
	}
	if len(response.Capacity.Tables) == 0 || response.Capacity.Tables[0].Name == "" {
		t.Fatalf("expected structured table diagnostics: %+v", response.Capacity)
	}
	body := rec.Body.String()
	for _, forbidden := range []string{"postgres://", "wrapped_dek", "wrap_metadata", "SELECT "} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("response leaked forbidden database detail %q: %s", forbidden, body)
		}
	}
}

func TestDBStatusAppliesBackendThresholds(t *testing.T) {
	store := &diagnosticStore{Store: memory.New(), diagnostics: &repository.DatabaseDiagnostics{
		ObservedAt: time.Now().UTC(), Role: "primary", Latency: 600 * time.Millisecond,
		Pool:       repository.DatabasePoolStats{Max: 20, Total: 18, Acquired: 17},
		Schema:     repository.DatabaseSchemaStats{Current: 3, Expected: 3},
		Protection: repository.DatabaseProtectionStats{BackupStatus: "managed_externally"},
	}}
	h := opsTestHandlerForStore(store, auditchain.New(store))
	req := httptest.NewRequest(http.MethodGet, "/ui/api/v1/ops/db/status", nil)
	req.Header.Set("Authorization", "Bearer ops-token")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"status":"degraded"`) || !strings.Contains(rec.Body.String(), "DB_LATENCY_CRITICAL") {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestDBStatusNeverReturnsRawRepositoryErrors(t *testing.T) {
	store := &diagnosticStore{Store: memory.New(), err: errors.New("postgres://operator:secret@db SELECT wrapped_dek")}
	h := opsTestHandlerForStore(store, auditchain.New(store))
	req := httptest.NewRequest(http.MethodGet, "/ui/api/v1/ops/db/status", nil)
	req.Header.Set("Authorization", "Bearer ops-token")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "DB_UNREACHABLE") {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	for _, forbidden := range []string{"postgres://", "operator", "secret", "SELECT", "wrapped_dek"} {
		if strings.Contains(rec.Body.String(), forbidden) {
			t.Fatalf("response leaked repository error detail %q: %s", forbidden, rec.Body.String())
		}
	}
}
