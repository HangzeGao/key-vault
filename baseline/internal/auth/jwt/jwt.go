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
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
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
	mu          sync.RWMutex
	issuer      string
	audience    string
	algWhite    map[string]struct{}
	hs256Secret []byte
	rs256Keys   map[string]*rsa.PublicKey
	es256Keys   map[string]*ecdsa.PublicKey
	keySet      PublicKeySet
	maxTokenTTL time.Duration
	now         func() time.Time
}

// PublicKeySet is the seam between JWT verification and key distribution.
// Production uses a cached remote JWKS adapter; tests may use static keys.
type PublicKeySet interface {
	Key(ctx context.Context, kid, alg string) (crypto.PublicKey, error)
}

// NewVerifier constructs a verifier.
func NewVerifier(issuer, audience string, algWhite []string) *Verifier {
	v := &Verifier{
		issuer:    issuer,
		audience:  audience,
		algWhite:  make(map[string]struct{}),
		rs256Keys: make(map[string]*rsa.PublicKey),
		es256Keys: make(map[string]*ecdsa.PublicKey),
		now:       time.Now,
	}
	for _, a := range algWhite {
		v.algWhite[a] = struct{}{}
	}
	return v
}

// SetHS256Secret registers an HS256 shared secret.
func (v *Verifier) SetHS256Secret(secret []byte) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.hs256Secret = append([]byte(nil), secret...)
}

// SetPublicKeySet configures the production key-distribution adapter.
func (v *Verifier) SetPublicKeySet(keySet PublicKeySet) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.keySet = keySet
}

// SetMaxTokenTTL rejects tokens whose issued lifetime exceeds the configured
// cryptoperiod. Zero leaves the check disabled for isolated tests.
func (v *Verifier) SetMaxTokenTTL(ttl time.Duration) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.maxTokenTTL = ttl
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
	if kid == "" || rsaPub.N.BitLen() < 2048 || rsaPub.E < 3 || rsaPub.E%2 == 0 {
		return errors.New("jwt: RSA key is below production strength")
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	v.rs256Keys[kid] = rsaPub
	return nil
}

// AddES256PublicKey registers a P-256 ECDSA public key by kid.
func (v *Verifier) AddES256PublicKey(kid string, pub *ecdsa.PublicKey) error {
	if kid == "" || pub == nil || pub.Curve != elliptic.P256() || !pub.Curve.IsOnCurve(pub.X, pub.Y) {
		return errors.New("jwt: invalid ES256 public key")
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	v.es256Keys[kid] = pub
	return nil
}

// Verify validates a JWT and returns the claims. Returns an error for any
// validation failure per HA-01.
func (v *Verifier) Verify(token string) (*Claims, error) {
	return v.VerifyContext(context.Background(), token)
}

// VerifyContext validates a JWT and permits a remote key adapter to honor
// request cancellation and deadlines.
func (v *Verifier) VerifyContext(ctx context.Context, token string) (*Claims, error) {
	if len(token) == 0 || len(token) > 16*1024 {
		return nil, errors.New("jwt: token length is invalid")
	}
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
	if header.Typ != "JWT" {
		return nil, errors.New("jwt: typ must be JWT")
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
		v.mu.RLock()
		secret := append([]byte(nil), v.hs256Secret...)
		v.mu.RUnlock()
		if secret == nil {
			return nil, errors.New("jwt: no hs256 secret configured")
		}
		mac := hmac.New(sha256.New, secret)
		mac.Write(signingInput)
		if !hmac.Equal(sig, mac.Sum(nil)) {
			return nil, errors.New("jwt: hs256 signature mismatch")
		}
	case "RS256":
		pub, err := v.publicKey(ctx, header.Kid, header.Alg)
		if err != nil {
			return nil, err
		}
		rsaPub, ok := pub.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("jwt: RS256 key type mismatch")
		}
		h := sha256.Sum256(signingInput)
		if err := rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, h[:], sig); err != nil {
			return nil, fmt.Errorf("jwt: rs256 verify: %w", err)
		}
	case "ES256":
		pub, err := v.publicKey(ctx, header.Kid, header.Alg)
		if err != nil {
			return nil, err
		}
		ecPub, ok := pub.(*ecdsa.PublicKey)
		if !ok || ecPub.Curve != elliptic.P256() {
			return nil, errors.New("jwt: ES256 key type mismatch")
		}
		if len(sig) != 64 {
			return nil, errors.New("jwt: ES256 signature must be 64 bytes")
		}
		h := sha256.Sum256(signingInput)
		r := new(big.Int).SetBytes(sig[:32])
		s := new(big.Int).SetBytes(sig[32:])
		if !ecdsa.Verify(ecPub, h[:], r, s) {
			return nil, errors.New("jwt: es256 signature mismatch")
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
	if claims.Sub == "" {
		return nil, errors.New("jwt: missing sub")
	}
	if claims.Exp <= 0 {
		return nil, errors.New("jwt: missing exp")
	}
	if now >= claims.Exp {
		return nil, errors.New("jwt: expired")
	}
	if claims.Nbf > 0 && now < claims.Nbf {
		return nil, errors.New("jwt: not yet valid (nbf)")
	}
	if claims.Iat > now+60 {
		return nil, errors.New("jwt: issued in the future")
	}
	if claims.Iat > 0 && claims.Exp <= claims.Iat {
		return nil, errors.New("jwt: exp must be after iat")
	}
	v.mu.RLock()
	maxTTL := v.maxTokenTTL
	v.mu.RUnlock()
	if maxTTL > 0 {
		if claims.Iat <= 0 {
			return nil, errors.New("jwt: missing iat")
		}
		if claims.Exp-claims.Iat > int64(maxTTL.Seconds()) {
			return nil, errors.New("jwt: lifetime exceeds configured maximum")
		}
	}
	return &claims, nil
}

func (v *Verifier) publicKey(ctx context.Context, kid, alg string) (crypto.PublicKey, error) {
	if kid == "" {
		return nil, fmt.Errorf("jwt: missing kid for %s", alg)
	}
	v.mu.RLock()
	keySet := v.keySet
	var static crypto.PublicKey
	switch alg {
	case "RS256":
		static = v.rs256Keys[kid]
	case "ES256":
		static = v.es256Keys[kid]
	}
	v.mu.RUnlock()
	if keySet != nil {
		return keySet.Key(ctx, kid, alg)
	}
	if static == nil {
		return nil, fmt.Errorf("jwt: unknown kid %s", kid)
	}
	return static, nil
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
