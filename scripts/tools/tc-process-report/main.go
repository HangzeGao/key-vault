// Command tc-process-report rejects missing, skipped or unregistered TC scenarios.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

type group struct {
	Test      string   `json:"test"`
	Scenarios []string `json:"scenarios"`
}
type manifest struct {
	Version int     `json:"format_version"`
	Scope   string  `json:"scope"`
	Groups  []group `json:"groups"`
}
type event struct{ Action, Package, Test string }
type report struct {
	Version   int      `json:"format_version"`
	Scope     string   `json:"scope"`
	Variant   string   `json:"variant"`
	Count     int      `json:"scenario_count"`
	Passed    int      `json:"passed"`
	Failed    int      `json:"failed"`
	Skipped   int      `json:"skipped"`
	Scenarios []string `json:"passed_scenarios"`
}

func evaluate(events io.Reader, spec manifest, variant string) (report, error) {
	r := report{Version: 1, Scope: spec.Scope, Variant: variant}
	if spec.Version != 1 || spec.Scope == "" || len(spec.Groups) == 0 || (variant != "optimized" && variant != "sanitized") {
		return r, errors.New("invalid scenario manifest or execution variant")
	}
	required := map[string]bool{}
	for _, g := range spec.Groups {
		if !strings.HasPrefix(g.Test, "TestTC") || len(g.Scenarios) == 0 {
			return r, errors.New("empty or invalid scenario group")
		}
		for _, name := range g.Scenarios {
			test := g.Test
			if name != "" {
				test += "/" + name
			}
			if required[test] {
				return r, errors.New("duplicate required scenario")
			}
			required[test] = true
		}
	}
	passed := map[string]bool{}
	packagePassed := false
	decoder := json.NewDecoder(events)
	for {
		var e event
		if err := decoder.Decode(&e); err == io.EOF {
			break
		} else if err != nil {
			return r, err
		}
		if e.Package != "github.com/kvlt/key-vault/internal/api/ccsds" {
			continue
		}
		if e.Action == "skip" || e.Action == "fail" {
			return r, fmt.Errorf("scenario/package %s: %s", e.Test, e.Action)
		}
		if e.Action == "pass" && e.Test == "" {
			packagePassed = true
		}
		if e.Action == "pass" && e.Test != "" {
			passed[e.Test] = true
		}
	}
	if !packagePassed {
		return r, errors.New("test package did not finish successfully")
	}
	for test := range required {
		if !passed[test] {
			return r, fmt.Errorf("required scenario not passed: %s", test)
		}
		r.Scenarios = append(r.Scenarios, test)
	}
	// Parent passes are expected. Every leaf must be explicitly in the manifest.
	for test := range passed {
		parent := false
		for other := range passed {
			if strings.HasPrefix(other, test+"/") {
				parent = true
				break
			}
		}
		if !parent && !required[test] {
			return r, fmt.Errorf("unregistered scenario: %s", test)
		}
	}
	sort.Strings(r.Scenarios)
	r.Count = len(required)
	r.Passed = r.Count
	return r, nil
}
func run(eventsPath, manifestPath, output, variant string) error {
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		return err
	}
	var spec manifest
	if err = json.Unmarshal(raw, &spec); err != nil {
		return err
	}
	events, err := os.Open(eventsPath)
	if err != nil {
		return err
	}
	defer events.Close()
	result, err := evaluate(events, spec, variant)
	if err != nil {
		return err
	}
	raw, err = json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	if err = os.WriteFile(output, append(raw, '\n'), 0600); err != nil {
		return err
	}
	fmt.Printf("TC process scenario gate passed: variant=%s scenarios=%d skipped=0\n", variant, result.Count)
	return nil
}
func main() {
	events := flag.String("events", "", "Go test -json log")
	spec := flag.String("manifest", "testdata/tc-process-scenarios.json", "required scenario manifest")
	output := flag.String("output", "", "JSON report path")
	variant := flag.String("variant", "", "optimized or sanitized")
	flag.Parse()
	if *events == "" || *output == "" || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "events and output are required")
		os.Exit(2)
	}
	if err := run(*events, *spec, *output, *variant); err != nil {
		fmt.Fprintln(os.Stderr, "TC process report:", err)
		os.Exit(1)
	}
}
