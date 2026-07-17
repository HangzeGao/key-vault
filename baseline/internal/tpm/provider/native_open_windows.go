//go:build windows

package provider

import (
	"fmt"
	"io"

	legacy "github.com/google/go-tpm/legacy/tpm2"
)

func openNativeTPM(tcti string) (io.ReadWriteCloser, error) {
	if tcti != "" && tcti != "windows" && tcti != "tbs" {
		return nil, fmt.Errorf("unsupported Windows TCTI %q", tcti)
	}
	return legacy.OpenTPM()
}
