// Package aad provides caller-side helpers for producing stable opaque AAD
// bytes. The service never parses or canonicalizes the returned bytes.
package aad

import (
	"bytes"
	"errors"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

var ErrInvalid = errors.New("sdk/aad: invalid input")

// CanonicalJSON implements RFC 8785 JSON Canonicalization Scheme (JCS).
func CanonicalJSON(input []byte) ([]byte, error) {
	if len(bytes.TrimSpace(input)) == 0 {
		return nil, ErrInvalid
	}
	out, err := jsoncanonicalizer.Transform(input)
	if err != nil {
		return nil, errors.Join(ErrInvalid, err)
	}
	return out, nil
}

// Raw returns an owned copy suitable for aad_b64 encoding.
func Raw(input []byte) ([]byte, error) {
	if input == nil {
		return nil, ErrInvalid
	}
	return append([]byte(nil), input...), nil
}

// Protobuf accepts deterministic protobuf wire bytes. Callers must enable
// deterministic marshaling in their protobuf runtime before invoking it.
func Protobuf(deterministicWireBytes []byte) ([]byte, error) { return Raw(deterministicWireBytes) }

// HTTPHeaders canonicalizes an explicit header allowlist. Names are lower-case,
// values are trimmed, entries are sorted, and CR/LF is rejected.
func HTTPHeaders(headers map[string][]string, allowlist []string) ([]byte, error) {
	allowed := make(map[string]struct{}, len(allowlist))
	for _, name := range allowlist {
		name = strings.ToLower(strings.TrimSpace(name))
		if name == "" {
			return nil, ErrInvalid
		}
		allowed[name] = struct{}{}
	}
	lines := make([]string, 0, len(allowed))
	for name := range allowed {
		values, ok := findHeader(headers, name)
		if !ok {
			return nil, errors.Join(ErrInvalid, errors.New("missing required header: "+name))
		}
		clean := make([]string, len(values))
		for i, value := range values {
			value = strings.TrimSpace(value)
			if !utf8.ValidString(value) || strings.ContainsAny(value, "\r\n") {
				return nil, ErrInvalid
			}
			clean[i] = value
		}
		lines = append(lines, name+":"+strings.Join(clean, ","))
	}
	sort.Strings(lines)
	return []byte(strings.Join(lines, "\n")), nil
}

func findHeader(headers map[string][]string, wanted string) ([]string, bool) {
	for name, values := range headers {
		if strings.ToLower(strings.TrimSpace(name)) == wanted {
			return values, true
		}
	}
	return nil, false
}
