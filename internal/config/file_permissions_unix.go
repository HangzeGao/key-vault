//go:build !windows

package config

import (
	"fmt"
	"os"
	"syscall"
)

func validateRestrictedFilePlatform(info os.FileInfo) error {
	if permissions := info.Mode().Perm(); permissions&0o077 != 0 {
		return fmt.Errorf("permissions %04o allow group or other access", permissions)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("file owner is unavailable")
	}
	if stat.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("file is not owned by the service account")
	}
	return nil
}
