package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStatusAndDoctorExitContracts(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer 0123456789abcdef0123456789abcdef" {
			w.WriteHeader(401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/ops/v1/status":
			_, _ = w.Write([]byte(`{"status":"READY","ready":true,"checks":{"tc":{"status":"ok"}},"database":{"audit_events":2},"downlink":{"current_generation":8},"warnings":[]}`))
		case "/ops/v1/audit/verify":
			_, _ = w.Write([]byte(`{"results":[{"chain_name":"system","intact":true}]}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	token := tokenFile(t)
	for _, args := range [][]string{{"--addr", server.URL, "--token-file", token, "status"}, {"--addr", server.URL, "--token-file", token, "status", "--json"}, {"--addr", server.URL, "--token-file", token, "doctor"}, {"--addr", server.URL, "--token-file", token, "audit", "verify"}} {
		var stdout, stderr strings.Builder
		if code := run(context.Background(), args, &stdout, &stderr); code != exitReady {
			t.Fatalf("args=%v code=%d stderr=%s", args, code, stderr.String())
		}
	}
}

func TestExitCodesFailClosed(t *testing.T) {
	var stdout, stderr strings.Builder
	if code := run(context.Background(), []string{"status"}, &stdout, &stderr); code != exitConfiguration {
		t.Fatalf("missing token code=%d", code)
	}
	token := tokenFile(t)
	if code := run(context.Background(), []string{"--addr", "http://127.0.0.1:1", "--timeout", "10ms", "--token-file", token, "status"}, &stdout, &stderr); code != exitUnreachable {
		t.Fatalf("unreachable code=%d", code)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ops/v1/status" {
			_, _ = w.Write([]byte(`{"status":"READY","ready":true}`))
			return
		}
		_, _ = w.Write([]byte(`{"results":[{"chain_name":"system","intact":false}]}`))
	}))
	defer server.Close()
	if code := run(context.Background(), []string{"--addr", server.URL, "--token-file", token, "audit", "verify"}, &stdout, &stderr); code != exitAuditCorrupt {
		t.Fatalf("corrupt code=%d", code)
	}
}

func TestTokenFileValidation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readToken(path); err == nil {
		t.Fatal("short token accepted")
	}
}

func tokenFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ops.token")
	if err := os.WriteFile(path, []byte("0123456789abcdef0123456789abcdef\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
