package ops

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kvlt/key-vault/internal/api/middleware"
	"github.com/kvlt/key-vault/internal/auth/principal"
	"github.com/kvlt/key-vault/internal/securitystate"
)

type fakeState struct{ failure bool }

func (state fakeState) Ping(context.Context) error {
	if state.failure {
		return errors.New("offline")
	}
	return nil
}
func (state fakeState) Diagnostics(context.Context) (*securitystate.Diagnostics, error) {
	if state.failure {
		return nil, errors.New("sensitive sqlite path")
	}
	return &securitystate.Diagnostics{ObservedAt: time.Now(), Schema: 1, DatabaseSize: 1024,
		WALSize: 12, Associations: 4, AuditEvents: 2, IntegrityOK: true}, nil
}
func TestDatabaseStatusIsSQLiteSpecificAndRedacted(t *testing.T) {
	handler := New(Deps{Store: fakeState{}})
	recorder := request(t, handler, "/ui/api/v1/ops/db/status", true)
	if recorder.Code != http.StatusOK || !contains(recorder.Body.String(), `"driver":"sqlite"`) ||
		!contains(recorder.Body.String(), `"journal_mode":"WAL"`) || contains(recorder.Body.String(), "path") {
		t.Fatalf("response %d: %s", recorder.Code, recorder.Body.String())
	}
}

func TestDatabaseFailureDoesNotExposeRawError(t *testing.T) {
	handler := New(Deps{Store: fakeState{failure: true}})
	recorder := request(t, handler, "/ui/api/v1/ops/db/status", true)
	if recorder.Code != http.StatusServiceUnavailable || contains(recorder.Body.String(), "sensitive") {
		t.Fatalf("response %d: %s", recorder.Code, recorder.Body.String())
	}
}

func TestOpsScopeIsRequired(t *testing.T) {
	handler := New(Deps{Store: fakeState{}})
	if recorder := request(t, handler, "/ui/api/v1/ops/db/status", false); recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d", recorder.Code)
	}
}

func request(t *testing.T, handler *Handler, path string, authenticated bool) *httptest.ResponseRecorder {
	t.Helper()
	mux := http.NewServeMux()
	handler.Routes(mux)
	var target http.Handler = mux
	if authenticated {
		target = middleware.ReadBody(middleware.Auth(middleware.AuthConfig{StaticTokens: map[string]*principal.Principal{
			"test-token": {ID: "ops", TenantID: "t-default", Plane: principal.PlaneOps, Scopes: []string{"ops:read"}},
		}})(middleware.APIAccess(mux)))
	}
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if authenticated {
		req.Header.Set("Authorization", "Bearer test-token")
	}
	recorder := httptest.NewRecorder()
	target.ServeHTTP(recorder, req)
	return recorder
}

func contains(value, fragment string) bool {
	for index := 0; index+len(fragment) <= len(value); index++ {
		if value[index:index+len(fragment)] == fragment {
			return true
		}
	}
	return false
}
