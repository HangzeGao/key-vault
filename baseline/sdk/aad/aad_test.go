package aad

import (
	"encoding/json"
	"os"
	"testing"
)

func TestCrossLanguageVectors(t *testing.T) {
	var vector struct {
		JSONInput        string              `json:"json_input"`
		JSONCanonical    string              `json:"json_canonical_utf8"`
		Headers          map[string][]string `json:"headers"`
		Allowlist        []string            `json:"header_allowlist"`
		HeadersCanonical string              `json:"headers_canonical_utf8"`
	}
	b, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &vector); err != nil {
		t.Fatal(err)
	}
	got, err := CanonicalJSON([]byte(vector.JSONInput))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != vector.JSONCanonical {
		t.Fatalf("canonical JSON = %q", got)
	}
	headers, err := HTTPHeaders(vector.Headers, vector.Allowlist)
	if err != nil {
		t.Fatal(err)
	}
	if string(headers) != vector.HeadersCanonical {
		t.Fatalf("canonical headers = %q", headers)
	}
}

func TestHTTPHeadersRejectsInjectionAndMissingValues(t *testing.T) {
	if _, err := HTTPHeaders(map[string][]string{"X-ID": {"ok\r\nbad: yes"}}, []string{"x-id"}); err == nil {
		t.Fatal("header injection accepted")
	}
	if _, err := HTTPHeaders(map[string][]string{}, []string{"x-id"}); err == nil {
		t.Fatal("missing header accepted")
	}
}
