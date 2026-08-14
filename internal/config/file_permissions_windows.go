//go:build windows

package config

import (
	"errors"
	"os"
)

func validateRestrictedFilePlatform(os.FileInfo) error {
	return errors.New("owner-only production file validation requires a POSIX deployment")
}
