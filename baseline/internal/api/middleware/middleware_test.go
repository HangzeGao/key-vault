package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kvlt/key-vault/internal/auth/principal"
)

func TestAPIAccessStrictCCSDSMatrix(t *testing.T) {
	tests := []struct {
		name, method, path string
		principal          *principal.Principal
		want               int
	}{
		{"TC protect", http.MethodPost, "/ui/api/v1/ccsds/tc:protect", &principal.Principal{Plane: principal.PlaneData, Scopes: []string{"ccsds:tc:protect"}}, 204},
		{"AOS unprotect", http.MethodPost, "/ui/api/v1/ccsds/aos:unprotect", &principal.Principal{Plane: principal.PlaneData, Scopes: []string{"ccsds:aos:unprotect"}}, 204},
		{"flight status observe", http.MethodPost, "/ui/api/v1/ccsds/flight-status:observe", &principal.Principal{Plane: principal.PlaneData, Scopes: []string{"ccsds:aos:unprotect"}}, 204},
		{"wrong data scope", http.MethodPost, "/ui/api/v1/ccsds/tc:protect", &principal.Principal{Plane: principal.PlaneData, Scopes: []string{"ccsds:aos:unprotect"}}, 403},
		{"wrong plane", http.MethodPost, "/ui/api/v1/ccsds/tc:protect", &principal.Principal{Plane: principal.PlaneOps, Scopes: []string{"ccsds:tc:protect"}}, 403},
		{"audit read", http.MethodGet, "/ui/api/v1/audit/events", &principal.Principal{Plane: principal.PlaneOps, Scopes: []string{"audit:read"}}, 204},
		{"audit delete removed", http.MethodDelete, "/ui/api/v1/audit/events", &principal.Principal{Plane: principal.PlaneOps, Scopes: []string{"audit:read"}}, 403},
		{"ops health", http.MethodGet, "/ui/api/v1/ops/health", &principal.Principal{Plane: principal.PlaneOps, Scopes: []string{"ops:read"}}, 204},
		{"ops database", http.MethodGet, "/ui/api/v1/ops/db/status", &principal.Principal{Plane: principal.PlaneOps, Scopes: []string{"ops:read"}}, 204},
		{"ops CCSDS", http.MethodGet, "/ui/api/v1/ops/ccsds/status", &principal.Principal{Plane: principal.PlaneOps, Scopes: []string{"ops:read"}}, 204},
		{"old crypto removed", http.MethodPost, "/ui/api/v1/crypto/encrypt", &principal.Principal{Plane: principal.PlaneData, Scopes: []string{"crypto:encrypt"}}, 403},
		{"old keys removed", http.MethodGet, "/ui/api/v1/keys", &principal.Principal{Plane: principal.PlaneOps, Scopes: []string{"keys:read"}}, 403},
		{"old repair removed", http.MethodPost, "/ui/api/v1/ops/crk/envelope:repair-aad-digest", &principal.Principal{Plane: principal.PlaneOps, Scopes: []string{"ops:repair"}}, 403},
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
	req := httptest.NewRequest(http.MethodGet, "/ui/api/v1/unassigned", nil)
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
