package ops

import (
	"context"
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
	"github.com/kvlt/key-vault/internal/repository/memory"
	"github.com/kvlt/key-vault/internal/repository/models"
)

type failingAudit struct{}

func (failingAudit) Record(context.Context, auditchain.RecordRequest) error {
	return errors.New("audit offline")
}

func opsTestHandler(t *testing.T, recorder auditRecorder) http.Handler {
	t.Helper()
	store := memory.New()
	now := time.Now().UTC()
	if err := store.CreateLifecycleJob(context.Background(), &models.LifecycleJob{ID: "job-1", Type: "key_expiry_check", Status: "FAILED", CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
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
