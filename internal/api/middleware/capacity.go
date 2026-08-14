package middleware

import (
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const maxCapacityBuckets = 4096

// CapacityConfig controls the in-process admission guard. Multi-node
// deployments should additionally enforce a distributed/global limit at the
// gateway, while this guard remains the last line of defense per process.
type CapacityConfig struct {
	Window         time.Duration
	SigmaThreshold float64
}

type rateBucket struct {
	windowStart time.Time
	count       int
}

// CapacityGuard bounds expensive API classes and hot-key traffic. It emits
// standard Retry-After and rate-limit headers and never logs request bodies.
func CapacityGuard(cfg CapacityConfig) func(http.Handler) http.Handler {
	return capacityGuard(cfg, false)
}

// PreAuthCapacityGuard bounds unauthenticated work by remote IP before any
// credential processing or request-body read. Its state is strictly bounded.
func PreAuthCapacityGuard(cfg CapacityConfig) func(http.Handler) http.Handler {
	return capacityGuard(cfg, true)
}

func capacityGuard(cfg CapacityConfig, preAuth bool) func(http.Handler) http.Handler {
	if cfg.Window <= 0 {
		cfg.Window = time.Minute
	}
	if cfg.SigmaThreshold <= 0 {
		cfg.SigmaThreshold = 3
	}
	var mu sync.Mutex
	buckets := make(map[string]rateBucket)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			limit := routeLimit(r.Method, r.URL.Path)
			if limit == 0 {
				next.ServeHTTP(w, r)
				return
			}
			// Sigma is intentionally consumed as a conservative burst multiplier.
			limit += int(cfg.SigmaThreshold)
			identity := remoteIdentity(r.RemoteAddr)
			if !preAuth {
				if p := PrincipalFromContext(r.Context()); p != nil && p.ID != "" {
					identity = p.ID
				}
			}
			key := identity + "\x00" + r.Method + "\x00" + r.URL.Path
			now := time.Now()
			mu.Lock()
			bucket := buckets[key]
			if bucket.windowStart.IsZero() && len(buckets) >= maxCapacityBuckets {
				for existingKey, existing := range buckets {
					if now.Sub(existing.windowStart) >= cfg.Window {
						delete(buckets, existingKey)
					}
				}
				if len(buckets) >= maxCapacityBuckets {
					mu.Unlock()
					w.Header().Set("Retry-After", strconv.Itoa(max(int(cfg.Window.Seconds()), 1)))
					WriteJSON(w, http.StatusTooManyRequests, map[string]any{"error": map[string]any{
						"code": "RATE_LIMITED", "message": "admission capacity exhausted", "retryable": true,
					}})
					return
				}
			}
			if bucket.windowStart.IsZero() || now.Sub(bucket.windowStart) >= cfg.Window {
				bucket = rateBucket{windowStart: now}
			}
			bucket.count++
			buckets[key] = bucket
			remaining := limit - bucket.count
			mu.Unlock()
			if remaining < 0 {
				retry := int(time.Until(bucket.windowStart.Add(cfg.Window)).Seconds()) + 1
				w.Header().Set("Retry-After", strconv.Itoa(max(retry, 1)))
				WriteJSON(w, http.StatusTooManyRequests, map[string]any{"error": map[string]any{
					"code": "RATE_LIMITED", "message": "request rate exceeded", "retryable": true,
				}})
				return
			}
			w.Header().Set("X-RateLimit-Limit", strconv.Itoa(limit))
			w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(max(remaining, 0)))
			next.ServeHTTP(w, r)
		})
	}
}

func remoteIdentity(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err == nil && host != "" {
		return host
	}
	return remoteAddr
}

func routeLimit(method, path string) int {
	if method == http.MethodPost && strings.HasPrefix(path, "/api/v1/") {
		return 120
	}
	if method == http.MethodGet && strings.HasPrefix(path, "/ops/v1/audit/") {
		return 60
	}
	return 0
}
