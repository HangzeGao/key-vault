package middleware

import (
	"bytes"
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/kvlt/key-vault/internal/auth/access"
	"github.com/kvlt/key-vault/internal/auth/principal"
)

func TestAPIAccessStrictCCSDSMatrix(t *testing.T) {
	tests := []struct {
		name, method, path string
		principal          *principal.Principal
		want               int
	}{
		{"TC protect", http.MethodPost, "/api/v1/tc:protect", &principal.Principal{Plane: principal.PlaneData, Scopes: []string{"ccsds:tc:protect"}}, 204},
		{"flight status observe", http.MethodPost, "/api/v1/flight-status:observe", &principal.Principal{Plane: principal.PlaneData, Scopes: []string{"ccsds:flight-status:observe"}}, 204},
		{"wrong data scope", http.MethodPost, "/api/v1/tc:protect", &principal.Principal{Plane: principal.PlaneData, Scopes: []string{"ccsds:downlink:unprotect"}}, 403},
		{"unsupported hardware downlink", http.MethodPost, "/api/v1/downlink:unprotect", &principal.Principal{Plane: principal.PlaneData, Scopes: []string{"ccsds:downlink:unprotect"}}, 403},
		{"wrong plane", http.MethodPost, "/api/v1/tc:protect", &principal.Principal{Plane: principal.PlaneOps, Scopes: []string{"ccsds:tc:protect"}}, 403},
		{"audit read", http.MethodGet, "/ops/v1/audit/events", &principal.Principal{Plane: principal.PlaneOps, Scopes: []string{"audit:read"}}, 204},
		{"audit delete removed", http.MethodDelete, "/ops/v1/audit/events", &principal.Principal{Plane: principal.PlaneOps, Scopes: []string{"audit:read"}}, 403},
		{"ops status", http.MethodGet, "/ops/v1/status", &principal.Principal{Plane: principal.PlaneOps, Scopes: []string{"ops:read"}}, 204},
		{"old database removed", http.MethodGet, "/ops/v1/database", &principal.Principal{Plane: principal.PlaneOps, Scopes: []string{"ops:read"}}, 403},
		{"old health removed", http.MethodGet, "/ops/v1/health", &principal.Principal{Plane: principal.PlaneOps, Scopes: []string{"ops:read"}}, 403},
		{"old crypto removed", http.MethodPost, "/api/v1/crypto/encrypt", &principal.Principal{Plane: principal.PlaneData, Scopes: []string{"crypto:encrypt"}}, 403},
		{"old keys removed", http.MethodGet, "/ops/v1/keys", &principal.Principal{Plane: principal.PlaneOps, Scopes: []string{"keys:read"}}, 403},
		{"mutation removed", http.MethodPost, "/ops/v1/state:repair", &principal.Principal{Plane: principal.PlaneOps, Scopes: []string{"ops:repair"}}, 403},
	}
	next := APIAccess(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			req = req.WithContext(context.WithValue(req.Context(), ctxKeyPrincipal, tt.principal))
			rec := httptest.NewRecorder()
			next.ServeHTTP(rec, req)
			if rec.Code != tt.want {
				t.Fatalf("status = %d, want %d; body=%s", rec.Code, tt.want, rec.Body.String())
			}
		})
	}
}

func TestAPIAccessRejectsUnassignedAPIRoute(t *testing.T) {
	next := APIAccess(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("next called") }))
	req := httptest.NewRequest(http.MethodGet, "/ops/v1/unassigned", nil)
	req = req.WithContext(context.WithValue(req.Context(), ctxKeyPrincipal, &principal.Principal{Plane: principal.PlaneOps, Scopes: []string{"audit:read"}}))
	rec := httptest.NewRecorder()
	next.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

func TestDecodeJSONStrictRejectsDuplicateFieldsAtEveryLevel(t *testing.T) {
	type entry struct {
		Value string `json:"value"`
	}
	type payload struct {
		Name     string           `json:"name"`
		Nested   entry            `json:"nested"`
		Entries  []entry          `json:"entries"`
		Profiles map[string]entry `json:"profiles"`
	}
	for _, body := range []string{
		`{"name":"a","name":"b","nested":{"value":"x"},"entries":[],"profiles":{}}`,
		`{"name":"a","nested":{"value":"x","value":"y"},"entries":[],"profiles":{}}`,
		`{"name":"a","nested":{"value":"x"},"entries":[{"value":"x","value":"y"}],"profiles":{}}`,
		`{"name":"a","nested":{"value":"x"},"entries":[],"profiles":{"p":{"value":"x","value":"y"}}}`,
	} {
		var got payload
		if err := DecodeJSONStrict([]byte(body), &got); err == nil {
			t.Fatalf("accepted duplicate: %s", body)
		}
	}
}

func TestDecodeJSONStrictRejectsTrailingValue(t *testing.T) {
	var got struct {
		Name string `json:"name"`
	}
	if err := DecodeJSONStrict([]byte(`{"name":"ok"} {"name":"second"}`), &got); err == nil {
		t.Fatal("expected trailing JSON value rejection")
	}
}

func TestSourceIPUsesRemoteAddrAndIgnoresForwardedHeaders(t *testing.T) {
	counters := &access.Counters{}
	handler := SourceIP(netip.MustParseAddr("192.0.2.10"), counters)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	allowed := httptest.NewRequest(http.MethodPost, "/api/v1/tc:protect", nil)
	allowed.RemoteAddr = "192.0.2.10:1234"
	allowed.Header.Set("X-Forwarded-For", "203.0.113.9")
	allowedResponse := httptest.NewRecorder()
	handler.ServeHTTP(allowedResponse, allowed)
	if allowedResponse.Code != http.StatusNoContent {
		t.Fatalf("allowed status=%d", allowedResponse.Code)
	}
	denied := httptest.NewRequest(http.MethodPost, "/api/v1/tc:protect", nil)
	denied.RemoteAddr = "203.0.113.9:1234"
	denied.Header.Set("X-Forwarded-For", "192.0.2.10")
	deniedResponse := httptest.NewRecorder()
	handler.ServeHTTP(deniedResponse, denied)
	if deniedResponse.Code != http.StatusForbidden || counters.Snapshot().SourceIPRejected != 1 {
		t.Fatalf("denied status=%d counters=%+v", deniedResponse.Code, counters.Snapshot())
	}
}

func TestAuthRejectsDuplicateHeadersAndCountsFailures(t *testing.T) {
	dataToken := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, access.TokenBytes))
	opsToken := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{2}, access.TokenBytes))
	verifier, err := access.NewVerifier("t-default", dataToken, opsToken)
	if err != nil {
		t.Fatal(err)
	}
	counters := &access.Counters{}
	handler := Auth(AuthConfig{Verifier: verifier, Counters: counters})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if PrincipalFromContext(r.Context()) == nil {
			t.Fatal("missing principal")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	valid := httptest.NewRequest(http.MethodGet, "/", nil)
	valid.Header.Set("Authorization", "Bearer "+dataToken)
	validResponse := httptest.NewRecorder()
	handler.ServeHTTP(validResponse, valid)
	if validResponse.Code != http.StatusNoContent {
		t.Fatalf("valid status=%d", validResponse.Code)
	}
	duplicate := httptest.NewRequest(http.MethodGet, "/", nil)
	duplicate.Header.Add("Authorization", "Bearer "+dataToken)
	duplicate.Header.Add("Authorization", "Bearer "+opsToken)
	duplicateResponse := httptest.NewRecorder()
	handler.ServeHTTP(duplicateResponse, duplicate)
	if duplicateResponse.Code != http.StatusUnauthorized || counters.Snapshot().TokenRejected != 1 {
		t.Fatalf("duplicate status=%d counters=%+v", duplicateResponse.Code, counters.Snapshot())
	}
}
