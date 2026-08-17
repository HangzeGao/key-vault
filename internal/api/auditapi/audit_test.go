package auditapi

import (
	"context"
	"encoding/json"
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
	for _, event := range []auditchain.RecordRequest{
		{TenantID: "t-default", ActorType: "system", ActorHash: "actor-default", Action: "ccsds.provision", TargetType: "association", TargetIDHash: "target", Result: "success"},
		{TenantID: "t-other", ActorType: "system", ActorHash: "actor-other", Action: "ccsds.provision", TargetType: "association", TargetIDHash: "target", Result: "success"},
	} {
		if err := audit.Record(context.Background(), event); err != nil {
			t.Fatal(err)
		}
	}
	handler := New(audit)
	for _, path := range []string{"/ops/v1/audit/events?action=provision", "/ops/v1/audit/heads", "/ops/v1/audit/verify"} {
		recorder := perform(handler, path, true)
		if recorder.Code != http.StatusOK {
			t.Fatalf("%s status=%d body=%s", path, recorder.Code, recorder.Body.String())
		}
	}
	events := perform(handler, "/ops/v1/audit/events", true)
	var eventBody struct {
		Events []struct {
			ActorHash string
			ChainName string
		} `json:"events"`
	}
	if err := json.Unmarshal(events.Body.Bytes(), &eventBody); err != nil {
		t.Fatal(err)
	}
	if len(eventBody.Events) != 1 || eventBody.Events[0].ActorHash != "actor-default" ||
		eventBody.Events[0].ChainName != "tenant:t-default" {
		t.Fatalf("cross-tenant events exposed: %+v", eventBody.Events)
	}
	heads := perform(handler, "/ops/v1/audit/heads", true)
	var headBody struct {
		Heads []struct{ ChainName string } `json:"heads"`
	}
	if err := json.Unmarshal(heads.Body.Bytes(), &headBody); err != nil {
		t.Fatal(err)
	}
	if len(headBody.Heads) != 1 || headBody.Heads[0].ChainName != "tenant:t-default" {
		t.Fatalf("cross-tenant heads exposed: %+v", headBody.Heads)
	}
	verify := perform(handler, "/ops/v1/audit/verify", true)
	var verifyBody struct {
		Results []*auditchain.VerifyResult `json:"results"`
	}
	if err := json.Unmarshal(verify.Body.Bytes(), &verifyBody); err != nil {
		t.Fatal(err)
	}
	if len(verifyBody.Results) != 1 || verifyBody.Results[0].ChainName != "tenant:t-default" || !verifyBody.Results[0].Intact {
		t.Fatalf("cross-tenant verification exposed: %+v", verifyBody.Results)
	}
	for _, path := range []string{
		"/ops/v1/audit/events?chain=tenant:t-other",
		"/ops/v1/audit/heads?chain=tenant:t-other",
		"/ops/v1/audit/verify?chain=tenant:t-other",
	} {
		if recorder := perform(handler, path, true); recorder.Code != http.StatusBadRequest {
			t.Fatalf("%s status=%d body=%s", path, recorder.Code, recorder.Body.String())
		}
	}
	mux := http.NewServeMux()
	handler.Routes(mux)
	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, httptest.NewRequest(http.MethodDelete, "/ops/v1/audit/events", nil))
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
	if recorder := perform(handler, "/ops/v1/audit/events", false); recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d", recorder.Code)
	}
	for _, actor := range []*principal.Principal{
		{ID: "no-scope", TenantID: "t-default", Plane: principal.PlaneOps},
		{ID: "no-tenant", Plane: principal.PlaneOps, Scopes: []string{"audit:read"}},
	} {
		if recorder := performAs(handler, "/ops/v1/audit/events", actor); recorder.Code != http.StatusForbidden {
			t.Fatalf("actor=%s status=%d", actor.ID, recorder.Code)
		}
	}
}

func perform(handler *Handler, path string, authenticated bool) *httptest.ResponseRecorder {
	if !authenticated {
		return performAs(handler, path, nil)
	}
	return performAs(handler, path, &principal.Principal{ID: "auditor", TenantID: "t-default", Plane: principal.PlaneOps, Scopes: []string{"audit:read"}})
}

func performAs(handler *Handler, path string, actor *principal.Principal) *httptest.ResponseRecorder {
	mux := http.NewServeMux()
	handler.Routes(mux)
	var target http.Handler = mux
	if actor != nil {
		target = middleware.ReadBody(middleware.Auth(middleware.AuthConfig{Verifier: staticVerifier{actor}})(middleware.APIAccess(mux)))
	}
	request := httptest.NewRequest(http.MethodGet, path, nil)
	if actor != nil {
		request.Header.Set("Authorization", "Bearer test-token")
	}
	recorder := httptest.NewRecorder()
	target.ServeHTTP(recorder, request)
	return recorder
}

type staticVerifier struct{ principal *principal.Principal }

func (v staticVerifier) Authenticate(token string) *principal.Principal {
	if token == "test-token" {
		return v.principal
	}
	return nil
}
