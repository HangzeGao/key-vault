package ops

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kvlt/key-vault/internal/api/middleware"
	"github.com/kvlt/key-vault/internal/auth/principal"
	"github.com/kvlt/key-vault/internal/operations"
)

type fakeSnapshot struct{ failure bool }

func (f fakeSnapshot) Snapshot(context.Context, string) (*operations.Snapshot, error) {
	if f.failure {
		return nil, errors.New("sensitive internal path")
	}
	return &operations.Snapshot{Status: "READY", Ready: true, Warnings: []string{}}, nil
}

func TestStatusIsTenantBoundAndRedacted(t *testing.T) {
	recorder := request(t, New(fakeSnapshot{}), true)
	if recorder.Code != http.StatusOK || !contains(recorder.Body.String(), `"status":"READY"`) || !contains(recorder.Body.String(), `"warnings":[]`) {
		t.Fatalf("response %d: %s", recorder.Code, recorder.Body.String())
	}
}
func TestStatusFailureIsRedacted(t *testing.T) {
	recorder := request(t, New(fakeSnapshot{true}), true)
	if recorder.Code != 503 || contains(recorder.Body.String(), "sensitive") {
		t.Fatalf("%d %s", recorder.Code, recorder.Body.String())
	}
}
func TestStatusRequiresAuthentication(t *testing.T) {
	if recorder := request(t, New(fakeSnapshot{}), false); recorder.Code != 401 {
		t.Fatalf("status=%d", recorder.Code)
	}
}

func request(t *testing.T, handler *Handler, authenticated bool) *httptest.ResponseRecorder {
	t.Helper()
	mux := http.NewServeMux()
	handler.Routes(mux)
	var target http.Handler = mux
	if authenticated {
		target = middleware.ReadBody(middleware.Auth(middleware.AuthConfig{Verifier: opsVerifier{}})(middleware.APIAccess(mux)))
	}
	req := httptest.NewRequest(http.MethodGet, "/ops/v1/status", nil)
	if authenticated {
		req.Header.Set("Authorization", "Bearer test-token")
	}
	recorder := httptest.NewRecorder()
	target.ServeHTTP(recorder, req)
	return recorder
}

type opsVerifier struct{}

func (opsVerifier) Authenticate(token string) *principal.Principal {
	if token != "test-token" {
		return nil
	}
	return &principal.Principal{ID: "ops", TenantID: "t-default", Plane: principal.PlaneOps, Scopes: []string{"ops:read"}}
}
func contains(value, fragment string) bool {
	for index := 0; index+len(fragment) <= len(value); index++ {
		if value[index:index+len(fragment)] == fragment {
			return true
		}
	}
	return false
}
