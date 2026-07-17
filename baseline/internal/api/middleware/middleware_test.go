package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kvlt/key-vault/internal/auth/principal"
)

func TestAPIAccessPlaneAndScopeMatrix(t *testing.T) {
	tests := []struct {
		name       string
		method     string
		path       string
		principal  *principal.Principal
		wantStatus int
	}{
		{
			name:   "data plane can encrypt with crypto scope",
			method: http.MethodPost,
			path:   "/ui/api/v1/crypto/encrypt",
			principal: &principal.Principal{
				Plane:  principal.PlaneData,
				Scopes: []string{"crypto:encrypt"},
			},
			wantStatus: http.StatusNoContent,
		},
		{
			name:   "management plane cannot encrypt even with crypto scope",
			method: http.MethodPost,
			path:   "/ui/api/v1/crypto/encrypt",
			principal: &principal.Principal{
				Plane:  principal.PlaneManagement,
				Scopes: []string{"crypto:encrypt"},
			},
			wantStatus: http.StatusForbidden,
		},
		{
			name:   "explicit multi-plane test principal can encrypt",
			method: http.MethodPost,
			path:   "/ui/api/v1/crypto/encrypt",
			principal: &principal.Principal{
				Plane:  principal.PlaneManagement,
				Planes: []principal.Plane{principal.PlaneManagement, principal.PlaneData, principal.PlaneOps},
				Scopes: []string{"crypto:encrypt"},
			},
			wantStatus: http.StatusNoContent,
		},
		{
			name:   "data plane missing decrypt scope is denied",
			method: http.MethodPost,
			path:   "/ui/api/v1/crypto/decrypt",
			principal: &principal.Principal{
				Plane:  principal.PlaneData,
				Scopes: []string{"crypto:encrypt"},
			},
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "data plane can inspect and convert with decrypt scope",
			method:     http.MethodPost,
			path:       "/ui/api/v1/crypto/envelopes:inspect",
			principal:  &principal.Principal{Plane: principal.PlaneData, Scopes: []string{"crypto:decrypt"}},
			wantStatus: http.StatusNoContent,
		},
		{
			name:       "data plane can convert with decrypt scope",
			method:     http.MethodPost,
			path:       "/ui/api/v1/crypto/envelopes:convert",
			principal:  &principal.Principal{Plane: principal.PlaneData, Scopes: []string{"crypto:decrypt"}},
			wantStatus: http.StatusNoContent,
		},
		{
			name:   "data plane cannot list keys",
			method: http.MethodGet,
			path:   "/ui/api/v1/keys",
			principal: &principal.Principal{
				Plane:  principal.PlaneData,
				Scopes: []string{"keys:read"},
			},
			wantStatus: http.StatusForbidden,
		},
		{
			name:   "management plane can list keys with key read scope",
			method: http.MethodGet,
			path:   "/ui/api/v1/keys",
			principal: &principal.Principal{
				Plane:  principal.PlaneManagement,
				Scopes: []string{"keys:read"},
			},
			wantStatus: http.StatusNoContent,
		},
		{
			name:       "management plane can archive destroyed key with destroy scope",
			method:     http.MethodPost,
			path:       "/ui/api/v1/keys/key-1/archive",
			principal:  &principal.Principal{Plane: principal.PlaneManagement, Scopes: []string{"keys:destroy"}},
			wantStatus: http.StatusNoContent,
		},
		{
			name:       "management plane cannot archive destroyed key with read scope",
			method:     http.MethodPost,
			path:       "/ui/api/v1/keys/key-1/archive",
			principal:  &principal.Principal{Plane: principal.PlaneManagement, Scopes: []string{"keys:read"}},
			wantStatus: http.StatusForbidden,
		},
		{
			name:   "ops plane can read crk envelope with ops scope",
			method: http.MethodGet,
			path:   "/ui/api/v1/ops/crk/envelope",
			principal: &principal.Principal{
				Plane:  principal.PlaneOps,
				Scopes: []string{"ops:read"},
			},
			wantStatus: http.StatusNoContent,
		},
		{
			name:   "test super admin can read crk envelope with ops plane grant",
			method: http.MethodGet,
			path:   "/ui/api/v1/ops/crk/envelope",
			principal: &principal.Principal{
				Plane:  principal.PlaneManagement,
				Planes: []principal.Plane{principal.PlaneManagement, principal.PlaneData, principal.PlaneOps},
				Scopes: []string{"ops:read"},
			},
			wantStatus: http.StatusNoContent,
		},
		{
			name:   "management plane cannot repair crk envelope",
			method: http.MethodPost,
			path:   "/ui/api/v1/ops/crk/envelope:repair-aad-digest",
			principal: &principal.Principal{
				Plane:  principal.PlaneManagement,
				Scopes: []string{"ops:repair", "keys:manage"},
			},
			wantStatus: http.StatusForbidden,
		},
		{
			name:   "ops plane missing repair scope is denied",
			method: http.MethodPost,
			path:   "/ui/api/v1/ops/crk/envelope:repair-aad-digest",
			principal: &principal.Principal{
				Plane:  principal.PlaneOps,
				Scopes: []string{"ops:read"},
			},
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "ordinary repair scope cannot use breakglass route",
			method:     http.MethodPost,
			path:       "/ui/api/v1/ops/breakglass/lifecycle/jobs/job-1/retry",
			principal:  &principal.Principal{Plane: principal.PlaneOps, Scopes: []string{"ops:repair"}},
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "management plane cannot use breakglass even with scope",
			method:     http.MethodPost,
			path:       "/ui/api/v1/ops/breakglass/lifecycle/jobs/job-1/retry",
			principal:  &principal.Principal{Plane: principal.PlaneManagement, Scopes: []string{"ops:breakglass"}},
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "ops breakglass principal reaches whitelisted route",
			method:     http.MethodPost,
			path:       "/ui/api/v1/ops/breakglass/lifecycle/jobs/job-1/retry",
			principal:  &principal.Principal{Plane: principal.PlaneOps, Scopes: []string{"ops:breakglass"}},
			wantStatus: http.StatusNoContent,
		},
	}

	next := APIAccess(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			ctx := context.WithValue(req.Context(), ctxKeyPrincipal, tt.principal)
			rec := httptest.NewRecorder()

			next.ServeHTTP(rec, req.WithContext(ctx))

			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d; body=%s", rec.Code, tt.wantStatus, rec.Body.String())
			}
		})
	}
}

func TestAPIAccessRejectsUnassignedAPIRoute(t *testing.T) {
	next := APIAccess(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next handler should not be called")
	}))
	req := httptest.NewRequest(http.MethodGet, "/ui/api/v1/unassigned", nil)
	ctx := context.WithValue(req.Context(), ctxKeyPrincipal, &principal.Principal{
		Plane:  principal.PlaneManagement,
		Scopes: []string{"tenant:manage"},
	})
	rec := httptest.NewRecorder()

	next.ServeHTTP(rec, req.WithContext(ctx))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusForbidden, rec.Body.String())
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
	tests := []string{
		`{"name":"a","name":"b","nested":{"value":"x"},"entries":[],"profiles":{}}`,
		`{"name":"a","nested":{"value":"x","value":"y"},"entries":[],"profiles":{}}`,
		`{"name":"a","nested":{"value":"x"},"entries":[{"value":"x","value":"y"}],"profiles":{}}`,
		`{"name":"a","nested":{"value":"x"},"entries":[],"profiles":{"p":{"value":"x","value":"y"}}}`,
	}
	for _, body := range tests {
		var got payload
		if err := DecodeJSONStrict([]byte(body), &got); err == nil {
			t.Fatalf("expected duplicate rejection for %s", body)
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
