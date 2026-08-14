package middleware

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func TestCapacityGuardLimitsCCSDSRequests(t *testing.T) {
	h := CapacityGuard(CapacityConfig{Window: time.Minute, SigmaThreshold: 1})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	for i := 0; i < 121; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tc:protect", nil)
		req.RemoteAddr = "client"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("request %d status=%d", i, rec.Code)
		}
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tc:protect", nil)
	req.RemoteAddr = "client"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("status=%d retry-after=%q", rec.Code, rec.Header().Get("Retry-After"))
	}
}

func TestPreAuthCapacityGuardUsesRemoteHostAndIsolatesClients(t *testing.T) {
	h := PreAuthCapacityGuard(CapacityConfig{Window: time.Minute, SigmaThreshold: 1})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	for i := 0; i < 121; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tc:protect", nil)
		req.RemoteAddr = "192.0.2.1:" + strconv.Itoa(1000+i)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("request %d status=%d", i, rec.Code)
		}
	}
	limited := httptest.NewRequest(http.MethodPost, "/api/v1/tc:protect", nil)
	limited.RemoteAddr = "192.0.2.1:9999"
	limitedResponse := httptest.NewRecorder()
	h.ServeHTTP(limitedResponse, limited)
	if limitedResponse.Code != http.StatusTooManyRequests {
		t.Fatalf("limited status=%d", limitedResponse.Code)
	}
	independent := httptest.NewRequest(http.MethodPost, "/api/v1/tc:protect", nil)
	independent.RemoteAddr = "192.0.2.2:9999"
	independentResponse := httptest.NewRecorder()
	h.ServeHTTP(independentResponse, independent)
	if independentResponse.Code != http.StatusUnauthorized {
		t.Fatalf("independent status=%d", independentResponse.Code)
	}
}

func TestPreAuthCapacityGuardRejectsNewBucketsAtFixedCapacity(t *testing.T) {
	h := PreAuthCapacityGuard(CapacityConfig{Window: time.Hour, SigmaThreshold: 1})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	for i := 0; i < maxCapacityBuckets; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tc:protect", nil)
		req.RemoteAddr = "client-" + strconv.Itoa(i)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("bucket %d status=%d", i, rec.Code)
		}
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tc:protect", nil)
	req.RemoteAddr = "overflow-client"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("overflow status=%d", rec.Code)
	}
}
