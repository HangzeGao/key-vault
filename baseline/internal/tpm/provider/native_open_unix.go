//go:build !windows

package provider

import (
	"io"

	legacy "github.com/google/go-tpm/legacy/tpm2"
)

func openNativeTPM(tcti string) (io.ReadWriteCloser, error) {
	if tcti == "" { tcti = "/dev/tpmrm0" }
	return legacy.OpenTPM(tcti)
}
