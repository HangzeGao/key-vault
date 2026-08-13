// Package middleware implements HTTP middleware: auth, request ID, body limits,
// plane isolation, idempotency, audit.
package middleware

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/kvlt/key-vault/internal/auth/principal"
	"github.com/kvlt/key-vault/internal/errorsx"
	"github.com/kvlt/key-vault/internal/logging"
)

type ctxKey string

const (
	ctxKeyPrincipal ctxKey = "principal"
	ctxKeyRequestID ctxKey = "request_id"
	ctxKeyBody      ctxKey = "body"
)

// AuthConfig configures the auth middleware.
type AuthConfig struct {
	AccessTokens map[string]*principal.Principal // token -> one data or ops identity
}

// RequestID middleware injects a request ID.
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rid := r.Header.Get("X-Request-Id")
		if rid == "" {
			rid = newRequestID()
		}
		w.Header().Set("X-Request-Id", rid)
		ctx := context.WithValue(r.Context(), ctxKeyRequestID, rid)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// BodyLimit enforces a max request body size per design §12.1.
func BodyLimit(maxBytes int) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Body = http.MaxBytesReader(w, r.Body, int64(maxBytes))
			next.ServeHTTP(w, r)
		})
	}
}

// ReadBody reads the bounded request body once for strict downstream decoding.
func ReadBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body == nil {
			next.ServeHTTP(w, r)
			return
		}
		b, err := io.ReadAll(r.Body)
		if err != nil {
			writeError(w, errorsx.New(errorsx.CodeBadRequest, "read body failed", false), "")
			return
		}
		r.Body.Close()
		ctx := context.WithValue(r.Context(), ctxKeyBody, b)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Auth authenticates the request and injects the principal into context.
func Auth(cfg AuthConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var p *principal.Principal
			authz := r.Header.Get("Authorization")
			if strings.HasPrefix(authz, "Bearer ") {
				token := strings.TrimPrefix(authz, "Bearer ")
				if cfg.AccessTokens != nil {
					if sp, ok := cfg.AccessTokens[token]; ok {
						p = sp
					}
				}
			}
			if p == nil {
				writeError(w, errorsx.New(errorsx.CodeAuthFailed, "no credentials", false), requestID(r))
				return
			}
			ctx := context.WithValue(r.Context(), ctxKeyPrincipal, p)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireScope returns a middleware that requires the given scope.
func RequireScope(scope string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p := PrincipalFromContext(r.Context())
			if p == nil || !p.HasScope(scope) {
				writeError(w, errorsx.New(errorsx.CodePermissionDenied, "missing scope "+scope, false), requestID(r))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequirePlane returns a middleware that requires the given plane.
func RequirePlane(plane principal.Plane) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p := PrincipalFromContext(r.Context())
			if p == nil || !p.CanAccessPlane(plane) {
				writeError(w, errorsx.New(errorsx.CodePermissionDenied, "plane access denied", false), requestID(r))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// APIAccess enforces the externally exposed API plane/scope matrix in one
// place. Handlers keep their local checks as defense-in-depth, but every
// API route must pass this guard first.
func APIAccess(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/v1/") && !strings.HasPrefix(r.URL.Path, "/ops/v1/") {
			next.ServeHTTP(w, r)
			return
		}
		rule, ok := accessRuleFor(r.Method, r.URL.Path)
		if !ok {
			writeError(w, errorsx.New(errorsx.CodePermissionDenied, "api route not assigned to a plane", false), requestID(r))
			return
		}
		p := PrincipalFromContext(r.Context())
		if p == nil {
			writeError(w, errorsx.New(errorsx.CodeAuthFailed, "no principal", false), requestID(r))
			return
		}
		if !rule.allowsPrincipal(p) {
			writeError(w, errorsx.New(errorsx.CodePermissionDenied, "plane access denied", false), requestID(r))
			return
		}
		if len(rule.scopes) > 0 && !p.HasAnyScope(rule.scopes...) {
			writeError(w, errorsx.New(errorsx.CodePermissionDenied, "missing required scope", false), requestID(r))
			return
		}
		next.ServeHTTP(w, r)
	})
}

type accessRule struct {
	plane  principal.Plane
	scopes []string
}

func (r accessRule) allowsPrincipal(p *principal.Principal) bool {
	return p.CanAccessPlane(r.plane)
}

func accessRuleFor(method, path string) (accessRule, bool) {
	if method == http.MethodPost {
		switch path {
		case "/api/v1/tc:protect":
			return accessRule{plane: principal.PlaneData, scopes: []string{"ccsds:tc:protect"}}, true
		case "/api/v1/downlink:unprotect":
			return accessRule{plane: principal.PlaneData, scopes: []string{"ccsds:downlink:unprotect"}}, true
		case "/api/v1/flight-status:observe":
			return accessRule{plane: principal.PlaneData, scopes: []string{"ccsds:downlink:unprotect"}}, true
		}
	}

	if strings.HasPrefix(path, "/ops/v1/audit/") && method == http.MethodGet {
		return accessRule{plane: principal.PlaneOps, scopes: []string{"audit:read"}}, true
	}
	if method == http.MethodGet {
		switch path {
		case "/ops/v1/status":
			return accessRule{plane: principal.PlaneOps, scopes: []string{"ops:read"}}, true
		}
	}

	return accessRule{}, false
}

// PrincipalFromContext extracts the principal from context.
func PrincipalFromContext(ctx context.Context) *principal.Principal {
	v, _ := ctx.Value(ctxKeyPrincipal).(*principal.Principal)
	return v
}

// RequestIDFromContext extracts the request ID from context.
func RequestIDFromContext(ctx context.Context) string {
	v, _ := ctx.Value(ctxKeyRequestID).(string)
	return v
}

// BodyFromContext extracts the cached body from context.
func BodyFromContext(ctx context.Context) []byte {
	v, _ := ctx.Value(ctxKeyBody).([]byte)
	return v
}

func requestID(r *http.Request) string {
	if v, ok := r.Context().Value(ctxKeyRequestID).(string); ok {
		return v
	}
	return ""
}

// writeError writes a structured error response.
func writeError(w http.ResponseWriter, e *errorsx.Error, requestID string) {
	status := errorsx.HTTPStatus(e.Code)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	resp := map[string]any{
		"error": map[string]any{
			"code":       string(e.Code),
			"message":    e.Message,
			"request_id": requestID,
			"retryable":  e.Retryable,
		},
	}
	b, _ := json.Marshal(resp)
	w.Write(b)
}

// WriteJSON writes a JSON response.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	b, _ := json.Marshal(v)
	w.Write(b)
}

// DecodeJSONStrict decodes JSON strictly (no unknown fields, no duplicates).
func DecodeJSONStrict(b []byte, v any) error {
	if err := rejectDuplicateJSONFields(b); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		if err == nil {
			return errorsx.New(errorsx.CodeBadRequest, "trailing data in JSON", false)
		}
		return err
	}
	return nil
}

// rejectDuplicateJSONFields walks the JSON token stream and rejects duplicate
// object member names at every nesting level. encoding/json otherwise silently
// keeps the last value, which is unsafe for authorization and policy payloads.
func rejectDuplicateJSONFields(b []byte) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if err := scanJSONValue(dec); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		if err == nil {
			return errorsx.New(errorsx.CodeBadRequest, "trailing data in JSON", false)
		}
		return err
	}
	return nil
}

func scanJSONValue(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for dec.More() {
			keyToken, err := dec.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errorsx.New(errorsx.CodeBadRequest, "invalid JSON object key", false)
			}
			if _, exists := seen[key]; exists {
				return errorsx.New(errorsx.CodeBadRequest, "duplicate JSON field: "+key, false)
			}
			seen[key] = struct{}{}
			if err := scanJSONValue(dec); err != nil {
				return err
			}
		}
		end, err := dec.Token()
		if err != nil || end != json.Delim('}') {
			return errorsx.New(errorsx.CodeBadRequest, "invalid JSON object", false)
		}
	case '[':
		for dec.More() {
			if err := scanJSONValue(dec); err != nil {
				return err
			}
		}
		end, err := dec.Token()
		if err != nil || end != json.Delim(']') {
			return errorsx.New(errorsx.CodeBadRequest, "invalid JSON array", false)
		}
	default:
		return errorsx.New(errorsx.CodeBadRequest, "invalid JSON delimiter", false)
	}
	return nil
}

// newRequestID generates a request ID.
func newRequestID() string {
	return "req_" + time.Now().Format("20060102T150405.000000000")
}

// Logger returns the package logger.
var Logger = logging.New(0)
