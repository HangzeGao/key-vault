package hmacsign

import (
	"net/http/httptest"
	"testing"
	"time"
)

func TestVerifierRejectsReplay(t *testing.T) {
	secret := []byte("test-secret-with-enough-entropy")
	v := NewVerifier(time.Minute)
	v.AddKey("key-1", secret)
	req := httptest.NewRequest("POST", "/ui/api/v1/crypto/encrypt", nil)
	if err := SignRequest(req, nil, "key-1", secret, "node-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := v.VerifyRequest(req, nil); err != nil {
		t.Fatalf("first request rejected: %v", err)
	}
	if _, err := v.VerifyRequest(req, nil); err == nil {
		t.Fatal("replayed nonce accepted")
	}
}
