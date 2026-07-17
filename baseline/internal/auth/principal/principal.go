// Package principal defines the authenticated caller identity.
package principal

import "strings"

// Plane enumerates the API planes a principal may access.
type Plane string

const (
	PlaneManagement Plane = "management"
	PlaneData       Plane = "data"
	PlaneOps        Plane = "ops"
)

// Role enumerates service roles.
type Role string

const (
	RoleAdmin     Role = "admin"
	RoleKeyPlane  Role = "key"
	RoleDataPlane Role = "data"
	RoleOps       Role = "ops"
	RoleNode      Role = "node"
)

// Principal is the authenticated caller. Constructed by auth middleware.
type Principal struct {
	ID         string   // stable principal ID (sub or service ID)
	TenantID   string   // tenant scope
	Scopes     []string // e.g. "keys:manage", "crypto:encrypt"
	Roles      []string
	Plane      Plane   // primary plane this principal may access
	Planes     []Plane // optional explicit multi-plane test/development access
	NodeID     string  // if role=node
	AuthMethod string  // "jwt" | "hmac" | "static_token"
}

// HasScope returns whether the principal holds a given scope.
func (p *Principal) HasScope(s string) bool {
	for _, sc := range p.Scopes {
		if sc == s {
			return true
		}
	}
	return false
}

// HasAnyScope returns whether the principal holds any of the given scopes.
func (p *Principal) HasAnyScope(scopes ...string) bool {
	for _, want := range scopes {
		if p.HasScope(want) {
			return true
		}
	}
	return false
}

// HasRole returns whether the principal has a given role.
func (p *Principal) HasRole(r string) bool {
	for _, x := range p.Roles {
		if x == r {
			return true
		}
	}
	return false
}

// CanAccessPlane returns whether the principal may access the given plane.
// Plane access is intentionally strict: cross-plane access requires a separate
// principal/token for the target plane unless a development static token
// explicitly lists multiple planes.
func (p *Principal) CanAccessPlane(plane Plane) bool {
	if p == nil {
		return false
	}
	if p.Plane == plane {
		return true
	}
	for _, candidate := range p.Planes {
		if candidate == plane {
			return true
		}
	}
	return false
}

// ScopesString returns scopes as a space-joined string.
func (p *Principal) ScopesString() string {
	return strings.Join(p.Scopes, " ")
}
