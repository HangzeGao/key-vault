package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kvlt/key-vault/internal/auth/access"
)

func TestRunCreatesBundleWithoutPrintingSecrets(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "auth")
	var stdout, stderr strings.Builder
	if code := run([]string{"--output-dir", directory}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit=%d", code)
	}
	dataRaw, _ := os.ReadFile(filepath.Join(directory, access.DataTokenFile))
	opsRaw, _ := os.ReadFile(filepath.Join(directory, access.OpsTokenFile))
	if strings.Contains(stdout.String(), strings.TrimSpace(string(dataRaw))) || strings.Contains(stdout.String(), strings.TrimSpace(string(opsRaw))) || stderr.Len() != 0 {
		t.Fatal("generator disclosed a token or emitted unexpected diagnostics")
	}
	for _, name := range []string{access.DataTokenFile, access.OpsTokenFile, access.VerifierFile} {
		if _, err := os.Stat(filepath.Join(directory, name)); err != nil {
			t.Fatal(err)
		}
	}
}

func TestRunRejectsInvalidArgumentsAndExistingFiles(t *testing.T) {
	var stdout, stderr strings.Builder
	if code := run(nil, &stdout, &stderr); code != 2 {
		t.Fatalf("missing args exit=%d", code)
	}
	directory := filepath.Join(t.TempDir(), "auth")
	if code := run([]string{"--output-dir", directory, "--tenant-id", "bad tenant"}, &stdout, &stderr); code != 1 {
		t.Fatalf("invalid tenant exit=%d", code)
	}
	if code := run([]string{"--output-dir", directory}, &stdout, &stderr); code != 0 {
		t.Fatalf("first generation exit=%d", code)
	}
	if code := run([]string{"--output-dir", directory}, &stdout, &stderr); code != 1 {
		t.Fatalf("overwrite exit=%d", code)
	}
}
