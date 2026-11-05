package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestScenarioEvidenceFailsClosed(t *testing.T) {
	spec := manifest{Version: 1, Scope: "TEST ONLY", Groups: []group{{Test: "TestTCFlight", Scenarios: []string{"a", "b"}}}}
	events := func(actions ...event) string {
		var b strings.Builder
		for _, e := range actions {
			e.Package = "github.com/kvlt/key-vault/internal/api/ccsds"
			raw, _ := json.Marshal(e)
			b.Write(raw)
			b.WriteByte('\n')
		}
		return b.String()
	}
	good := events(event{Action: "pass", Test: "TestTCFlight/a"}, event{Action: "pass", Test: "TestTCFlight/b"}, event{Action: "pass", Test: "TestTCFlight"}, event{Action: "pass"})
	r, err := evaluate(strings.NewReader(good), spec, "optimized")
	if err != nil || r.Count != 2 || r.Passed != 2 || r.Skipped != 0 {
		t.Fatalf("valid report: %+v %v", r, err)
	}
	for _, bad := range []string{"", strings.ReplaceAll(good, "/b", "/c"), strings.ReplaceAll(good, `"Test":""`, `"Test":"unfinished"`), good + events(event{Action: "skip", Test: "TestTCFlight/b"}), good + events(event{Action: "fail"}), good + events(event{Action: "pass", Test: "TestTCFlight/extra"}), good + `{broken`} {
		if _, err = evaluate(strings.NewReader(bad), spec, "sanitized"); err == nil {
			t.Fatal("incomplete/invalid scenario evidence accepted")
		}
	}
	spec.Groups[0].Scenarios = append(spec.Groups[0].Scenarios, "a")
	if _, err = evaluate(strings.NewReader(good), spec, "optimized"); err == nil {
		t.Fatal("duplicate manifest accepted")
	}
}
