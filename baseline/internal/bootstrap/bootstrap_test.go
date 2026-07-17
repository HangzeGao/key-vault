package bootstrap

import (
	"testing"

	"github.com/kvlt/key-vault/internal/auth/principal"
)

func TestStaticTokenPlanes(t *testing.T) {
	tests := []struct {
		name       string
		plane      string
		rawPlanes  []string
		wantPlane  principal.Plane
		wantPlanes []principal.Plane
	}{
		{
			name:       "default management",
			wantPlane:  principal.PlaneManagement,
			wantPlanes: []principal.Plane{principal.PlaneManagement},
		},
		{
			name:       "single data plane",
			plane:      "data",
			wantPlane:  principal.PlaneData,
			wantPlanes: []principal.Plane{principal.PlaneData},
		},
		{
			name:       "single ops plane",
			plane:      "ops",
			wantPlane:  principal.PlaneOps,
			wantPlanes: []principal.Plane{principal.PlaneOps},
		},
		{
			name:       "explicit multi-plane",
			rawPlanes:  []string{"management", "data", "ops"},
			wantPlane:  principal.PlaneManagement,
			wantPlanes: []principal.Plane{principal.PlaneManagement, principal.PlaneData, principal.PlaneOps},
		},
		{
			name:       "unknown plane falls back to management",
			plane:      "unknown",
			wantPlane:  principal.PlaneManagement,
			wantPlanes: []principal.Plane{principal.PlaneManagement},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPlane, gotPlanes := staticTokenPlanes(tt.plane, tt.rawPlanes)
			if gotPlane != tt.wantPlane {
				t.Fatalf("plane = %q, want %q", gotPlane, tt.wantPlane)
			}
			if len(gotPlanes) != len(tt.wantPlanes) {
				t.Fatalf("planes = %v, want %v", gotPlanes, tt.wantPlanes)
			}
			for i := range tt.wantPlanes {
				if gotPlanes[i] != tt.wantPlanes[i] {
					t.Fatalf("planes = %v, want %v", gotPlanes, tt.wantPlanes)
				}
			}
		})
	}
}

func TestLoadStaticTokensSupportsPlanes(t *testing.T) {
	t.Setenv("KVLT_STATIC_TOKENS", `[
		{"token":"admin-token-baseline","tenant_id":"t-default","scopes":["keys:manage"],"roles":["admin"],"plane":"management"},
		{"token":"data-token-baseline","tenant_id":"t-default","scopes":["crypto:encrypt"],"roles":["data"],"plane":"data"},
		{"token":"ops-token-baseline","tenant_id":"t-default","scopes":["ops:read","ops:repair"],"roles":["ops"],"plane":"ops"},
		{"token":"admin-data-token-baseline","tenant_id":"t-default","scopes":["keys:manage","crypto:encrypt","ops:read","ops:repair"],"roles":["admin","data","ops"],"planes":["management","data","ops"]}
	]`)

	tokens := loadStaticTokens()
	if len(tokens) != 4 {
		t.Fatalf("token count = %d, want 4", len(tokens))
	}

	admin := tokens["admin-token-baseline"]
	if admin == nil || !admin.CanAccessPlane(principal.PlaneManagement) || admin.CanAccessPlane(principal.PlaneData) {
		t.Fatalf("admin token planes not management-only: %#v", admin)
	}
	data := tokens["data-token-baseline"]
	if data == nil || !data.CanAccessPlane(principal.PlaneData) || data.CanAccessPlane(principal.PlaneManagement) {
		t.Fatalf("data token planes not data-only: %#v", data)
	}
	both := tokens["admin-data-token-baseline"]
	if both == nil || !both.CanAccessPlane(principal.PlaneManagement) || !both.CanAccessPlane(principal.PlaneData) || !both.CanAccessPlane(principal.PlaneOps) {
		t.Fatalf("multi-plane token cannot access expected planes: %#v", both)
	}
	ops := tokens["ops-token-baseline"]
	if ops == nil || !ops.CanAccessPlane(principal.PlaneOps) || ops.CanAccessPlane(principal.PlaneManagement) || ops.CanAccessPlane(principal.PlaneData) {
		t.Fatalf("ops token planes not ops-only: %#v", ops)
	}
	if both.AuthMethod != "static_token" {
		t.Fatalf("AuthMethod = %q, want static_token", both.AuthMethod)
	}
}

func TestLoadStaticTokensInvalidJSONDisablesStaticAuth(t *testing.T) {
	t.Setenv("KVLT_STATIC_TOKENS", `[{invalid-json}]`)

	tokens := loadStaticTokens()
	if len(tokens) != 0 {
		t.Fatalf("token count = %d, want 0", len(tokens))
	}
}
