package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/kvlt/key-vault/internal/auth/access"
)

var testOpsToken = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{2}, access.TokenBytes))

func TestStatusAndDoctorExitContracts(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+testOpsToken {
			w.WriteHeader(401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/ops/v1/status":
			_, _ = w.Write([]byte(`{"status":"READY","ready":true,"checks":{"tc":{"status":"ok"}},"database":{"audit_events":2},"warnings":[]}`))
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
		if args[len(args)-1] == "status" && !slices.Contains(args, "--json") && !strings.Contains(stdout.String(), "access_rejections source_ip=0 token=0 plane=0 rate_limited=0") {
			t.Fatalf("status omitted access counters: %s", stdout.String())
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
	if err := os.WriteFile(path, []byte(testOpsToken+"\n\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readToken(path); err == nil {
		t.Fatal("token file with trailing blank line accepted")
	}
	if runtime.GOOS != "windows" {
		link := filepath.Join(t.TempDir(), "token-link")
		if err := os.Symlink(path, link); err != nil {
			t.Fatal(err)
		}
		if _, err := readToken(link); err == nil {
			t.Fatal("symlink token accepted")
		}
	}
}

func TestHTTPSRequiresAndUsesPinnedCertificate(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"status":"READY","ready":true,"checks":{"tc":{"status":"ok"}},"database":{},"warnings":[]}`))
	}))
	defer server.Close()
	token := tokenFile(t)
	var stdout, stderr strings.Builder
	if code := run(context.Background(), []string{"--addr", server.URL, "--token-file", token, "status"}, &stdout, &stderr); code != exitConfiguration {
		t.Fatalf("missing CA code=%d stderr=%s", code, stderr.String())
	}
	caPath := filepath.Join(t.TempDir(), "server.crt")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if err := os.WriteFile(caPath, pemBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := run(context.Background(), []string{"--addr", server.URL, "--token-file", token, "--ca-file", caPath, "status"}, &stdout, &stderr); code != exitReady {
		t.Fatalf("pinned TLS code=%d stderr=%s", code, stderr.String())
	}
}

func TestOperationsAddressMustBeLoopback(t *testing.T) {
	var stdout, stderr strings.Builder
	if code := run(context.Background(), []string{"--addr", "https://192.0.2.1:8443", "--token-file", tokenFile(t), "--ca-file", "missing", "status"}, &stdout, &stderr); code != exitConfiguration {
		t.Fatalf("remote operations address code=%d", code)
	}
	if code := run(context.Background(), []string{"--addr", "http://127.0.0.1:8080?redirect=1", "--token-file", tokenFile(t), "status"}, &stdout, &stderr); code != exitConfiguration {
		t.Fatalf("query-bearing operations origin code=%d", code)
	}
}

func tokenFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ops.token")
	if err := os.WriteFile(path, []byte(testOpsToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
