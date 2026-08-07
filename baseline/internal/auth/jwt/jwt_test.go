package jwt

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestVerifierUsesCachedRemoteJWKSAndEnforcesLifetime(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	jwks := rsaJWKS(t, "key-1", &privateKey.PublicKey)
	issuer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/jwk-set+json")
		_, _ = w.Write(jwks)
	}))
	defer issuer.Close()

	keySet, err := NewRemoteKeySet(issuer.URL, time.Minute, issuer.Client())
	if err != nil {
		t.Fatalf("NewRemoteKeySet: %v", err)
	}
	verifier := NewVerifier(issuer.URL, "key-vault", []string{"RS256"})
	verifier.SetPublicKeySet(keySet)
	verifier.SetMaxTokenTTL(15 * time.Minute)
	now := time.Now().UTC().Truncate(time.Second)
	verifier.now = func() time.Time { return now }

	claims := Claims{
		Iss: issuer.URL, Aud: "key-vault", Sub: "operator",
		Iat: now.Unix(), Exp: now.Add(5 * time.Minute).Unix(),
	}
	token := signRS256(t, privateKey, "key-1", claims)
	if _, err := verifier.VerifyContext(context.Background(), token); err != nil {
		t.Fatalf("VerifyContext: %v", err)
	}
	if requests.Load() != 1 {
		t.Fatalf("JWKS requests = %d, want 1", requests.Load())
	}
	if _, err := verifier.VerifyContext(context.Background(), token); err != nil {
		t.Fatalf("VerifyContext cached: %v", err)
	}
	if requests.Load() != 1 {
		t.Fatalf("cached verification fetched JWKS again: %d", requests.Load())
	}

	tooLong := claims
	tooLong.Exp = now.Add(16 * time.Minute).Unix()
	if _, err := verifier.Verify(signRS256(t, privateKey, "key-1", tooLong)); err == nil {
		t.Fatal("accepted token exceeding maximum lifetime")
	}
}

func TestRemoteJWKSUnknownKidRefreshIsThrottled(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	jwks := rsaJWKS(t, "known", &privateKey.PublicKey)
	issuer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwks)
	}))
	defer issuer.Close()

	keySet, err := NewRemoteKeySet(issuer.URL, time.Minute, issuer.Client())
	if err != nil {
		t.Fatal(err)
	}
	if err := keySet.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := keySet.Key(context.Background(), "attacker-controlled", "RS256"); err == nil {
			t.Fatal("unknown kid was accepted")
		}
	}
	if requests.Load() != 1 {
		t.Fatalf("unknown kid caused refresh amplification: requests=%d", requests.Load())
	}
}

func rsaJWKS(t *testing.T, kid string, publicKey *rsa.PublicKey) []byte {
	t.Helper()
	exponent := new(big.Int).SetInt64(int64(publicKey.E)).Bytes()
	document := map[string]any{"keys": []any{map[string]any{
		"kty": "RSA",
		"use": "sig",
		"alg": "RS256",
		"kid": kid,
		"n":   base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(exponent),
	}}}
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func signRS256(t *testing.T, privateKey *rsa.PrivateKey, kid string, claims Claims) string {
	t.Helper()
	header, err := json.Marshal(map[string]string{"alg": "RS256", "kid": kid, "typ": "JWT"})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	headerPart := base64.RawURLEncoding.EncodeToString(header)
	payloadPart := base64.RawURLEncoding.EncodeToString(payload)
	signingInput := headerPart + "." + payloadPart
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}
