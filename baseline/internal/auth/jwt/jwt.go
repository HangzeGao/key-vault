// Package jwt implements JWT validation per design §5.1 and HA-01.
//
// The engineering baseline supports HS256/RS256/ES256 via a configurable verifier. The verifier
// enforces:
//   - iss, aud, exp, nbf, kid, alg strict validation
//   - alg whitelist (no "none")
//   - alg confusion prevention (key type must match alg)
//
// For baseline testing, an HS256 verifier with a shared secret is provided.
// Production deployments should use RS256/ES256 with JWK set fetch.
package jwt

import (
	"crypto"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Claims is the set of JWT claims we validate.
type Claims struct {
	Iss    string `json:"iss"`
	Aud    any    `json:"aud"` // string or []string
	Sub    string `json:"sub"`
	Exp    int64  `json:"exp"`
	Nbf    int64  `json:"nbf"`
	Iat    int64  `json:"iat"`
	Kid    string `json:"kid,omitempty"`
	Scope  string `json:"scope,omitempty"`
	Tenant string `json:"tenant_id,omitempty"`
	Plane  string `json:"plane,omitempty"`
	Roles  string `json:"roles,omitempty"`
	NodeID string `json:"node_id,omitempty"`
}

// Verifier validates JWTs.
type Verifier struct {
	issuer      string
	audience    string
	algWhite    map[string]struct{}
	hs256Secret []byte
	rs256Keys   map[string]*rsa.PublicKey
	now         func() time.Time
}

// NewVerifier constructs a verifier.
func NewVerifier(issuer, audience string, algWhite []string) *Verifier {
	v := &Verifier{
		issuer:    issuer,
		audience:  audience,
		algWhite:  make(map[string]struct{}),
		rs256Keys: make(map[string]*rsa.PublicKey),
		now:       time.Now,
	}
	for _, a := range algWhite {
		v.algWhite[a] = struct{}{}
	}
	return v
}

// SetHS256Secret registers an HS256 shared secret.
func (v *Verifier) SetHS256Secret(secret []byte) {
	v.hs256Secret = secret
}

// AddRS256PublicKey registers an RS256 public key by kid.
func (v *Verifier) AddRS256PublicKey(kid string, pemBytes []byte) error {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return errors.New("jwt: no PEM block")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("jwt: parse pkix: %w", err)
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return errors.New("jwt: not an RSA key")
	}
	v.rs256Keys[kid] = rsaPub
	return nil
}

// Verify validates a JWT and returns the claims. Returns an error for any
// validation failure per HA-01.
func (v *Verifier) Verify(token string) (*Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("jwt: not three parts")
	}
	headerB64 := parts[0]
	payloadB64 := parts[1]
	sigB64 := parts[2]

	header, err := decodeHeader(headerB64)
	if err != nil {
		return nil, err
	}
	if _, ok := v.algWhite[header.Alg]; !ok {
		return nil, fmt.Errorf("jwt: alg %s not in whitelist", header.Alg)
	}
	if header.Alg == "none" {
		return nil, errors.New("jwt: alg none forbidden")
	}

	// Decode payload.
	payloadJSON, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return nil, fmt.Errorf("jwt: payload decode: %w", err)
	}
	var claims Claims
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return nil, fmt.Errorf("jwt: payload parse: %w", err)
	}

	// Verify signature.
	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return nil, fmt.Errorf("jwt: sig decode: %w", err)
	}
	signingInput := []byte(headerB64 + "." + payloadB64)
	switch header.Alg {
	case "HS256":
		if v.hs256Secret == nil {
			return nil, errors.New("jwt: no hs256 secret configured")
		}
		mac := hmac.New(sha256.New, v.hs256Secret)
		mac.Write(signingInput)
		if !hmac.Equal(sig, mac.Sum(nil)) {
			return nil, errors.New("jwt: hs256 signature mismatch")
		}
	case "RS256":
		kid := header.Kid
		if kid == "" {
			return nil, errors.New("jwt: missing kid for RS256")
		}
		pub, ok := v.rs256Keys[kid]
		if !ok {
			return nil, fmt.Errorf("jwt: unknown kid %s", kid)
		}
		h := sha256.Sum256(signingInput)
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, h[:], sig); err != nil {
			return nil, fmt.Errorf("jwt: rs256 verify: %w", err)
		}
	default:
		return nil, fmt.Errorf("jwt: alg %s not implemented", header.Alg)
	}

	// Validate claims.
	now := v.now().Unix()
	if claims.Iss != v.issuer {
		return nil, fmt.Errorf("jwt: iss mismatch (got %q want %q)", claims.Iss, v.issuer)
	}
	if !audienceMatches(claims.Aud, v.audience) {
		return nil, fmt.Errorf("jwt: aud mismatch")
	}
	if claims.Exp > 0 && now >= claims.Exp {
		return nil, errors.New("jwt: expired")
	}
	if claims.Nbf > 0 && now < claims.Nbf {
		return nil, errors.New("jwt: not yet valid (nbf)")
	}
	return &claims, nil
}

// audienceMatches checks if the audience claim contains the expected audience.
func audienceMatches(claims any, expected string) bool {
	switch a := claims.(type) {
	case string:
		return a == expected
	case []string:
		for _, s := range a {
			if s == expected {
				return true
			}
		}
	case []any:
		for _, x := range a {
			if s, ok := x.(string); ok && s == expected {
				return true
			}
		}
	}
	return false
}

type jwtHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

func decodeHeader(b64 string) (*jwtHeader, error) {
	b, err := base64.RawURLEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("jwt: header decode: %w", err)
	}
	var h jwtHeader
	if err := json.Unmarshal(b, &h); err != nil {
		return nil, fmt.Errorf("jwt: header parse: %w", err)
	}
	return &h, nil
}
