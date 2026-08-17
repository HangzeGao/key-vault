// Command kvlt-authgen creates the fixed Data/Ops access credential bundle.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/kvlt/key-vault/internal/auth/access"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("kvlt-authgen", flag.ContinueOnError)
	flags.SetOutput(stderr)
	outputDir := flags.String("output-dir", "", "new or empty controlled output directory")
	tenantID := flags.String("tenant-id", "t-default", "fixed tenant identity")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *outputDir == "" {
		fmt.Fprintln(stderr, "usage: kvlt-authgen --output-dir DIR [--tenant-id t-default]")
		return 2
	}
	bundle, err := access.GenerateBundle(*tenantID)
	if err != nil {
		fmt.Fprintf(stderr, "credential generation failed: %v\n", err)
		return 1
	}
	if err := bundle.Write(*outputDir); err != nil {
		fmt.Fprintf(stderr, "credential write failed: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "created %s, %s, and %s in %s\n", access.DataTokenFile, access.OpsTokenFile, access.VerifierFile, *outputDir)
	return 0
}
