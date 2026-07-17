// Package hmacsign implements HMAC request signing per design §5.1 and HA-02.
//
// Signature covers: method, path, body hash, timestamp, nonce, node_id.
// Verification order: time window first, then signature, then atomic
// nonce registration.
package hmacsign

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Header names.
const (
	HeaderSignature = "X-KV-Signature"
	HeaderTimestamp = "X-KV-Timestamp"
	HeaderNonce     = "X-KV-Nonce"
	HeaderNodeID    = "X-KV-Node-ID"
	HeaderKeyID     = "X-KV-Key-ID"
)

// Verifier validates HMAC-signed requests.
type Verifier struct {
	mu        sync.Mutex
	secrets   map[string][]byte // keyID -> secret
	seenNonce map[string]int64  // nonce -> expiry (unix nano)
	maxSkew   time.Duration
}

// NewVerifier constructs a verifier.
func NewVerifier(maxSkew time.Duration) *Verifier {
	return &Verifier{
		secrets:   make(map[string][]byte),
		seenNonce: make(map[string]int64),
		maxSkew:   maxSkew,
	}
}

// AddKey registers a signing key.
func (v *Verifier) AddKey(keyID string, secret []byte) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.secrets[keyID] = secret
}

// VerifyRequest validates an HMAC-signed request. Returns the keyID on success.
// Per HA-02: time window first, then signature, then atomic nonce registration.
func (v *Verifier) VerifyRequest(r *http.Request, body []byte) (string, error) {
	tsStr := r.Header.Get(HeaderTimestamp)
	nonce := r.Header.Get(HeaderNonce)
	nodeID := r.Header.Get(HeaderNodeID)
	keyID := r.Header.Get(HeaderKeyID)
	sigB64 := r.Header.Get(HeaderSignature)

	if tsStr == "" || nonce == "" || nodeID == "" || keyID == "" || sigB64 == "" {
		return "", errors.New("hmac: missing header")
	}
	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return "", errors.New("hmac: bad timestamp")
	}
	// Time window check.
	now := time.Now().Unix()
	if now-ts > int64(v.maxSkew.Seconds()) {
		return "", errors.New("hmac: timestamp too old")
	}
	if ts-now > int64(v.maxSkew.Seconds()) {
		return "", errors.New("hmac: timestamp in future")
	}

	v.mu.Lock()
	secret, ok := v.secrets[keyID]
	v.mu.Unlock()
	if !ok {
		return "", errors.New("hmac: unknown key id")
	}

	// Compute expected signature.
	bodyHash := sha256.Sum256(body)
	canonical := canonicalString(r.Method, r.URL.Path, hex.EncodeToString(bodyHash[:]), tsStr, nonce, nodeID)
	expected := computeSignature(secret, canonical)

	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return "", errors.New("hmac: bad signature encoding")
	}
	if !hmac.Equal(sig, expected) {
		return "", errors.New("hmac: signature mismatch")
	}

	// Atomic nonce registration (per nodeID namespace).
	v.mu.Lock()
	defer v.mu.Unlock()
	nonceKey := nodeID + ":" + nonce
	if exp, ok := v.seenNonce[nonceKey]; ok && exp > time.Now().UnixNano() {
		return "", errors.New("hmac: nonce reused")
	}
	v.seenNonce[nonceKey] = time.Now().Add(v.maxSkew * 2).UnixNano()
	// GC old nonces.
	nowNano := time.Now().UnixNano()
	for k, exp := range v.seenNonce {
		if exp < nowNano {
			delete(v.seenNonce, k)
		}
	}
	return keyID, nil
}

// canonicalString builds the canonical string to sign.
// Format: METHOD\nPATH\nBODY_HASH\nTIMESTAMP\nNONCE\nNODE_ID
func canonicalString(method, path, bodyHash, ts, nonce, nodeID string) string {
	return strings.Join([]string{method, path, bodyHash, ts, nonce, nodeID}, "\n")
}

// computeSignature returns HMAC-SHA256(secret, canonical) as raw bytes.
func computeSignature(secret []byte, canonical string) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(canonical))
	return mac.Sum(nil)
}

// SignRequest signs a request with the given key. Used by SDK and tests.
func SignRequest(r *http.Request, body []byte, keyID string, secret []byte, nodeID string) error {
	ts := time.Now().Unix()
	nonce, err := randomNonce()
	if err != nil {
		return err
	}
	bodyHash := sha256.Sum256(body)
	canonical := canonicalString(r.Method, r.URL.Path, hex.EncodeToString(bodyHash[:]),
		strconv.FormatInt(ts, 10), nonce, nodeID)
	sig := computeSignature(secret, canonical)

	r.Header.Set(HeaderTimestamp, strconv.FormatInt(ts, 10))
	r.Header.Set(HeaderNonce, nonce)
	r.Header.Set(HeaderNodeID, nodeID)
	r.Header.Set(HeaderKeyID, keyID)
	r.Header.Set(HeaderSignature, base64.StdEncoding.EncodeToString(sig))
	return nil
}

// randomNonce generates a random 16-byte hex nonce.
func randomNonce() (string, error) {
	b := make([]byte, 16)
	if _, err := readRandom(b); err != nil {
		return "", fmt.Errorf("hmac: rand: %w", err)
	}
	return hex.EncodeToString(b), nil
}
