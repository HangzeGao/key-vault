package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestCapacityGuardLimitsBatchRequests(t *testing.T) {
	h := CapacityGuard(CapacityConfig{Window: time.Minute, SigmaThreshold: 1})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	for i := 0; i < 21; i++ {
		req := httptest.NewRequest(http.MethodPost, "/ui/api/v1/crypto/encrypt-batch", nil)
		req.RemoteAddr = "client"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("request %d status=%d", i, rec.Code)
		}
	}
	req := httptest.NewRequest(http.MethodPost, "/ui/api/v1/crypto/encrypt-batch", nil)
	req.RemoteAddr = "client"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("status=%d retry-after=%q", rec.Code, rec.Header().Get("Retry-After"))
	}
}
