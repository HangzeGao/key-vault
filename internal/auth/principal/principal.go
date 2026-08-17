// Package principal defines the authenticated caller identity.
package principal

import "strings"

// Plane is the fixed remote entry point assigned to one machine identity.
type Plane string

const (
	PlaneData Plane = "data"
	PlaneOps  Plane = "ops"
)

// Principal is the authenticated caller. Constructed by auth middleware.
type Principal struct {
	ID         string   // stable principal ID (sub or service ID)
	TenantID   string   // tenant scope
	Scopes     []string // e.g. "ccsds:tc:protect", "ops:read"
	Plane      Plane    // exactly one of data or ops
	AuthMethod string   // "access_token"
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

// CanAccessPlane returns whether the principal may access the given plane.
func (p *Principal) CanAccessPlane(plane Plane) bool {
	return p != nil && p.Plane == plane
}

// ScopesString returns scopes as a space-joined string.
func (p *Principal) ScopesString() string {
	return strings.Join(p.Scopes, " ")
}
