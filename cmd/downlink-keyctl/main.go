// Command downlink-keyctl is the only batch-management interface. It is
// intentionally offline-only and exposes no KEK or plaintext DEK material.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/kvlt/key-vault/internal/bootstrap"
	"github.com/kvlt/key-vault/internal/config"
)

func main() {
	if err := run(context.Background(), os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "downlink-keyctl:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return usageError()
	}
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	configPath := flags.String("config", "", "path to YAML configuration")
	output := flags.String("output", "", "private output package path")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	app, err := bootstrap.Build(ctx, cfg)
	if err != nil {
		return err
	}
	defer app.Downlink.Close()
	defer app.TPM.Close()
	defer app.Store.Close()

	switch args[0] {
	case "set-active-kek-slot":
		if flags.NArg() != 1 || *output != "" {
			return usageError()
		}
		value, err := strconv.ParseUint(flags.Arg(0), 10, 8)
		if err != nil || value > 7 {
			return errors.New("KEK slot must be 0..7")
		}
		return app.Downlink.SetActiveKEKSlot(ctx, uint8(value))
	case "generate-next-dek-batch":
		if flags.NArg() != 0 || *output == "" {
			return usageError()
		}
		encoded, err := app.Downlink.GenerateNext(ctx)
		if err != nil {
			return err
		}
		defer zeroize(encoded)
		return writeAtomicPrivate(*output, encoded)
	case "export-current-dek-batch":
		if flags.NArg() != 0 || *output == "" {
			return usageError()
		}
		encoded, err := app.Downlink.ExportCurrent(ctx)
		if err != nil {
			return err
		}
		defer zeroize(encoded)
		return writeAtomicPrivate(*output, encoded)
	default:
		return usageError()
	}
}

func usageError() error {
	return errors.New("usage: downlink-keyctl <set-active-kek-slot|generate-next-dek-batch|export-current-dek-batch> --config FILE [--output FILE] [slot]")
}

func writeAtomicPrivate(path string, data []byte) error {
	if path == "" {
		return errors.New("output path is required")
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".downlink-package-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}

func zeroize(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
