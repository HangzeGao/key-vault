// Package logging provides structured logging with mandatory sensitive-field redaction.
// Per design §18.2 and INV-09, the following must never appear in logs:
//   - raw tokens / Authorization header
//   - plaintext, plaintext_data_key
//   - DEK / CRK material
//   - full wrapped_dek
//   - full Envelope bytes
package logging

import (
	"context"
	"log/slog"
	"os"
	"strings"
)

// sensitiveKeys are field names that must be redacted when present in records.
var sensitiveKeys = map[string]struct{}{
	"token":               {},
	"authorization":       {},
	"plaintext":           {},
	"plaintext_data_key":  {},
	"dek":                 {},
	"crk":                 {},
	"wrapped_dek":         {},
	"envelope":            {},
	"password":            {},
	"secret":              {},
	"private_key":         {},
	"signature":           {},
	"x-kv-signature":      {},
	"service_token":       {},
}

// redactHandler wraps a slog.Handler to redact sensitive fields.
type redactHandler struct {
	inner slog.Handler
}

func (h *redactHandler) Enabled(ctx context.Context, lvl slog.Level) bool {
	return h.inner.Enabled(ctx, lvl)
}

func (h *redactHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &redactHandler{inner: h.inner.WithAttrs(redactAttrs(attrs))}
}

func (h *redactHandler) WithGroup(name string) slog.Handler {
	return &redactHandler{inner: h.inner.WithGroup(name)}
}

func (h *redactHandler) Handle(ctx context.Context, r slog.Record) error {
	r2 := slog.NewRecord(r.Time, r.Level, r.Message, r.PC)
	r.Attrs(func(a slog.Attr) bool {
		r2.AddAttrs(redactAttr(a))
		return true
	})
	return h.inner.Handle(ctx, r2)
}

func redactAttrs(attrs []slog.Attr) []slog.Attr {
	out := make([]slog.Attr, len(attrs))
	for i, a := range attrs {
		out[i] = redactAttr(a)
	}
	return out
}

func redactAttr(a slog.Attr) slog.Attr {
	key := strings.ToLower(a.Key)
	if _, ok := sensitiveKeys[key]; ok {
		return slog.String(a.Key, "[REDACTED]")
	}
	// Recurse into groups.
	if a.Value.Kind() == slog.KindGroup {
		g := a.Value.Group()
		red := redactAttrs(g)
		return slog.Attr{Key: a.Key, Value: slog.GroupValue(red...)}
	}
	return a
}

// New constructs a *slog.Logger writing to stderr with sensitive-field redaction.
func New(level slog.Level) *slog.Logger {
	h := slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level})
	return slog.New(&redactHandler{inner: h})
}
