//go:build !windows

package provider

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNativeTPMDeviceBoundaryRejectsUnsafePaths(t *testing.T) {
	regular := filepath.Join(t.TempDir(), "tpmrm0")
	if err := os.WriteFile(regular, []byte("not a device"), 0o600); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(t.TempDir(), "tpm-link")
	if err := os.Symlink(regular, symlink); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"device:/dev/tpmrm0", regular, symlink, "/dev/null"} {
		if err := validateNativeTPMDevice(path); err == nil {
			t.Fatalf("unsafe TPM path accepted: %s", path)
		}
	}
}
