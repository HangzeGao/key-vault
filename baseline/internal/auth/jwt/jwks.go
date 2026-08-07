package jwt

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const maxJWKSBytes = 1 << 20

// RemoteKeySet is a bounded, cached HTTPS JWKS adapter. A cache miss or expiry
// triggers one refresh, allowing issuer key rotation without accepting keys
// from an unconfigured origin.
type RemoteKeySet struct {
	url       *url.URL
	client    *http.Client
	cacheTTL  time.Duration
	now       func() time.Time
	refreshMu sync.Mutex
	mu        sync.RWMutex
	keys      map[string]crypto.PublicKey
	expiresAt time.Time
	lastFetch time.Time
}

// NewRemoteKeySet validates the configured HTTPS endpoint. A nil client uses a
// client with bounded time and no redirects; tests may inject a TLS test client.
func NewRemoteKeySet(rawURL string, cacheTTL time.Duration, client *http.Client) (*RemoteKeySet, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return nil, errors.New("jwt: JWKS URL must be HTTPS without userinfo or fragment")
	}
	if cacheTTL <= 0 {
		return nil, errors.New("jwt: JWKS cache TTL must be positive")
	}
	if client == nil {
		client = &http.Client{
			Timeout: 5 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return errors.New("jwt: JWKS redirects are forbidden")
			},
		}
	}
	return &RemoteKeySet{
		url:      parsed,
		client:   client,
		cacheTTL: cacheTTL,
		now:      time.Now,
		keys:     make(map[string]crypto.PublicKey),
	}, nil
}

// Key returns a key bound to both kid and alg. Unknown keys cause one bounded
// refresh so rotations become visible before the normal cache expiry.
func (s *RemoteKeySet) Key(ctx context.Context, kid, alg string) (crypto.PublicKey, error) {
	if kid == "" || (alg != "RS256" && alg != "ES256") {
		return nil, errors.New("jwt: invalid JWKS key request")
	}
	key, ok, fresh, lastFetch := s.lookup(kid, alg)
	if ok && fresh {
		return key, nil
	}
	force := false
	if fresh {
		// A valid cache containing no matching kid may be refreshed early for
		// rotations, but never on every attacker-controlled unknown kid.
		force = s.now().Sub(lastFetch) >= s.unknownKeyRefreshInterval()
		if !force {
			return nil, fmt.Errorf("jwt: unknown kid %s for %s", kid, alg)
		}
	}
	if err := s.refresh(ctx, force); err != nil {
		return nil, err
	}
	if key, ok, _, _ := s.lookup(kid, alg); ok {
		return key, nil
	}
	return nil, fmt.Errorf("jwt: unknown kid %s for %s", kid, alg)
}

func (s *RemoteKeySet) lookup(kid, alg string) (crypto.PublicKey, bool, bool, time.Time) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	key, ok := s.keys[alg+"|"+kid]
	return key, ok, s.now().Before(s.expiresAt), s.lastFetch
}

// Refresh downloads and atomically replaces the cached key set.
func (s *RemoteKeySet) Refresh(ctx context.Context) error {
	return s.refresh(ctx, true)
}

func (s *RemoteKeySet) refresh(ctx context.Context, force bool) error {
	s.refreshMu.Lock()
	defer s.refreshMu.Unlock()

	s.mu.RLock()
	fresh := s.now().Before(s.expiresAt)
	s.mu.RUnlock()
	if fresh && !force {
		return nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url.String(), nil)
	if err != nil {
		return fmt.Errorf("jwt: create JWKS request: %w", err)
	}
	req.Header.Set("Accept", "application/json, application/jwk-set+json")
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("jwt: fetch JWKS: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("jwt: JWKS returned status %d", resp.StatusCode)
	}
	if contentType := resp.Header.Get("Content-Type"); contentType != "" && !strings.Contains(strings.ToLower(contentType), "json") {
		return errors.New("jwt: JWKS response is not JSON")
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSBytes+1))
	if err != nil {
		return fmt.Errorf("jwt: read JWKS: %w", err)
	}
	if len(body) > maxJWKSBytes {
		return errors.New("jwt: JWKS response exceeds size limit")
	}
	keys, err := parseJWKS(body)
	if err != nil {
		return err
	}
	if len(keys) == 0 {
		return errors.New("jwt: JWKS contains no usable signing keys")
	}

	s.mu.Lock()
	s.keys = keys
	s.lastFetch = s.now()
	s.expiresAt = s.lastFetch.Add(s.cacheTTL)
	s.mu.Unlock()
	return nil
}

func (s *RemoteKeySet) unknownKeyRefreshInterval() time.Duration {
	const maximum = 30 * time.Second
	if s.cacheTTL < maximum {
		return s.cacheTTL
	}
	return maximum
}

type jwkSetDocument struct {
	Keys []jwkDocument `json:"keys"`
}

type jwkDocument struct {
	Kty     string   `json:"kty"`
	Use     string   `json:"use,omitempty"`
	KeyOps  []string `json:"key_ops,omitempty"`
	Alg     string   `json:"alg"`
	Kid     string   `json:"kid"`
	X5U     string   `json:"x5u,omitempty"`
	X5C     []string `json:"x5c,omitempty"`
	X5T     string   `json:"x5t,omitempty"`
	X5TS256 string   `json:"x5t#S256,omitempty"`
	N       string   `json:"n,omitempty"`
	E       string   `json:"e,omitempty"`
	Crv     string   `json:"crv,omitempty"`
	X       string   `json:"x,omitempty"`
	Y       string   `json:"y,omitempty"`
}

func parseJWKS(body []byte) (map[string]crypto.PublicKey, error) {
	var doc jwkSetDocument
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&doc); err != nil {
		return nil, fmt.Errorf("jwt: parse JWKS: %w", err)
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return nil, errors.New("jwt: trailing JWKS data")
	}
	out := make(map[string]crypto.PublicKey, len(doc.Keys))
	for _, raw := range doc.Keys {
		if raw.Kid == "" || (raw.Alg != "RS256" && raw.Alg != "ES256") {
			return nil, errors.New("jwt: every JWK must have kid and an explicit supported alg")
		}
		if raw.Use != "" && raw.Use != "sig" {
			continue
		}
		if len(raw.KeyOps) > 0 && !containsString(raw.KeyOps, "verify") {
			continue
		}
		cacheKey := raw.Alg + "|" + raw.Kid
		if _, duplicate := out[cacheKey]; duplicate {
			return nil, fmt.Errorf("jwt: duplicate JWK %s", raw.Kid)
		}
		var (
			key crypto.PublicKey
			err error
		)
		switch raw.Alg {
		case "RS256":
			key, err = rsaJWK(raw)
		case "ES256":
			key, err = ecJWK(raw)
		}
		if err != nil {
			return nil, fmt.Errorf("jwt: JWK %s: %w", raw.Kid, err)
		}
		out[cacheKey] = key
	}
	return out, nil
}

func rsaJWK(raw jwkDocument) (*rsa.PublicKey, error) {
	if raw.Kty != "RSA" || raw.N == "" || raw.E == "" {
		return nil, errors.New("RS256 key shape mismatch")
	}
	nBytes, err := base64.RawURLEncoding.DecodeString(raw.N)
	if err != nil {
		return nil, errors.New("invalid RSA modulus")
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(raw.E)
	if err != nil || len(eBytes) == 0 || len(eBytes) > 4 {
		return nil, errors.New("invalid RSA exponent")
	}
	exponent := 0
	for _, b := range eBytes {
		exponent = exponent<<8 | int(b)
	}
	n := new(big.Int).SetBytes(nBytes)
	if n.BitLen() < 2048 || exponent < 3 || exponent%2 == 0 {
		return nil, errors.New("RSA key is below production strength")
	}
	return &rsa.PublicKey{N: n, E: exponent}, nil
}

func ecJWK(raw jwkDocument) (*ecdsa.PublicKey, error) {
	if raw.Kty != "EC" || raw.Crv != "P-256" || raw.X == "" || raw.Y == "" {
		return nil, errors.New("ES256 key shape mismatch")
	}
	xBytes, err := base64.RawURLEncoding.DecodeString(raw.X)
	if err != nil {
		return nil, errors.New("invalid EC x coordinate")
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(raw.Y)
	if err != nil {
		return nil, errors.New("invalid EC y coordinate")
	}
	pub := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}
	if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
		return nil, errors.New("EC point is not on P-256")
	}
	return pub, nil
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
