//go:build windows

package config

import (
	"errors"
	"os"
)

func validateRestrictedFilePlatform(os.FileInfo) error {
	return errors.New("owner-only production file validation requires a POSIX deployment")
}

func openCommissioningTrust(string) (*os.File, error) {
	return nil, errors.New("commissioning trust requires a POSIX deployment")
}
