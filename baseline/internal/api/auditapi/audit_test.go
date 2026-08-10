package auditapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/kvlt/key-vault/internal/api/middleware"
	"github.com/kvlt/key-vault/internal/auditchain"
	"github.com/kvlt/key-vault/internal/auth/principal"
	"github.com/kvlt/key-vault/internal/securitystate"
)

func TestReadOnlyAuditRoutes(t *testing.T) {
	store, err := securitystate.Open(context.Background(), filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	audit := auditchain.New(store)
	if err := audit.Record(context.Background(), auditchain.RecordRequest{TenantID: "t-default", ActorType: "system",
		ActorHash: "actor", Action: "ccsds.provision", TargetType: "association", TargetIDHash: "target", Result: "success"}); err != nil {
		t.Fatal(err)
	}
	handler := New(audit)
	for _, path := range []string{"/ui/api/v1/audit/events?action=provision", "/ui/api/v1/audit/chain/heads", "/ui/api/v1/audit/chain/verify"} {
		recorder := perform(handler, path, true)
		if recorder.Code != http.StatusOK {
			t.Fatalf("%s status=%d body=%s", path, recorder.Code, recorder.Body.String())
		}
	}
	mux := http.NewServeMux()
	handler.Routes(mux)
	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, httptest.NewRequest(http.MethodDelete, "/ui/api/v1/audit/events", nil))
	if recorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf("delete status=%d", recorder.Code)
	}
}

func TestAuditRequiresScope(t *testing.T) {
	store, err := securitystate.Open(context.Background(), filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	handler := New(auditchain.New(store))
	if recorder := perform(handler, "/ui/api/v1/audit/events", false); recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d", recorder.Code)
	}
}

func perform(handler *Handler, path string, authenticated bool) *httptest.ResponseRecorder {
	mux := http.NewServeMux()
	handler.Routes(mux)
	var target http.Handler = mux
	if authenticated {
		target = middleware.ReadBody(middleware.Auth(middleware.AuthConfig{StaticTokens: map[string]*principal.Principal{
			"test-token": {ID: "auditor", TenantID: "t-default", Plane: principal.PlaneManagement, Scopes: []string{"audit:read"}},
		}})(middleware.APIAccess(mux)))
	}
	request := httptest.NewRequest(http.MethodGet, path, nil)
	if authenticated {
		request.Header.Set("Authorization", "Bearer test-token")
	}
	recorder := httptest.NewRecorder()
	target.ServeHTTP(recorder, request)
	return recorder
}
