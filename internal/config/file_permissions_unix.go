//go:build !windows

package config

import (
	"fmt"
	"os"
	"syscall"
)

func openCommissioningTrust(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	var stat syscall.Stat_t
	if err := syscall.Fstat(fd, &stat); err != nil || stat.Uid != 0 || stat.Mode&syscall.S_IFMT != syscall.S_IFREG || stat.Mode&0o022 != 0 {
		file.Close()
		return nil, fmt.Errorf("commissioning trust must be a root-owned regular file with restricted writes")
	}
	return file, nil
}

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
