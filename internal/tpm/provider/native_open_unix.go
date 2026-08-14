//go:build !windows

package provider

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	legacy "github.com/google/go-tpm/legacy/tpm2"
)

func openNativeTPM(tcti string) (io.ReadWriteCloser, error) {
	if err := validateNativeTPMDevice(tcti); err != nil {
		return nil, err
	}
	return legacy.OpenTPM(tcti)
}

func validateNativeTPMDevice(path string) error {
	if !filepath.IsAbs(path) {
		return errors.New("native TPM path must be absolute")
	}
	if os.Geteuid() == 0 {
		return errors.New("native TPM provider must run as a non-root service account")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect native TPM device: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return errors.New("native TPM device must not be a symbolic link")
	}
	if info.Mode()&os.ModeDevice == 0 || info.Mode()&os.ModeCharDevice == 0 {
		return errors.New("native TPM path is not a character device")
	}
	if info.Mode().Perm()&0o007 != 0 {
		return errors.New("native TPM device must not be accessible by other users")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("native TPM device ownership is unavailable")
	}
	if stat.Uid == uint32(os.Geteuid()) && info.Mode().Perm()&0o600 == 0o600 {
		return nil
	}
	if stat.Gid == uint32(os.Getegid()) && info.Mode().Perm()&0o060 == 0o060 {
		return nil
	}
	groups, err := os.Getgroups()
	if err != nil {
		return fmt.Errorf("read service account groups: %w", err)
	}
	for _, group := range groups {
		if uint32(group) == stat.Gid && info.Mode().Perm()&0o060 == 0o060 {
			return nil
		}
	}
	return errors.New("service account lacks dedicated read/write access to native TPM device")
}
