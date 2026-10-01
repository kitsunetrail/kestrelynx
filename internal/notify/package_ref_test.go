package notify

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/analyze"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
	"github.com/kitsunetrail/kestrelynx/internal/state"
)

// TestChannel_EcosystemTag pins the Slack tag of a package card: a known
// ecosystem replaces the generic "[lang]", an unmapped/unset one keeps it,
// and an OS package never gets a bracket tag at all (unchanged from before
// ecosystems existed).
func TestChannel_EcosystemTag(t *testing.T) {
	// All three findings are "affected" (no fix yet): the Watch section
	// renders every package as a card, unlike Actionable, which collapses
	// low-risk fixes into a summary line that shows names only — using that section here would make the bracket tag
	// invisible for reasons unrelated to what this test checks.
	r := analyze.Build([]scanner.ImageScan{{
		Image: "demo:1.0",
		Findings: []scanner.Finding{
			{Image: "demo:1.0", Class: scanner.ClassLang, Package: "pip", InstalledVer: "21.0.1", Status: scanner.StatusAffected, Severity: scanner.SeverityHigh, VulnID: "CVE-KNOWN", Type: "python-pkg"},
			{Image: "demo:1.0", Class: scanner.ClassLang, Package: "some-lib", InstalledVer: "1.0", Status: scanner.StatusAffected, Severity: scanner.SeverityHigh, VulnID: "CVE-UNKNOWN", Type: "some-future-analyzer"},
			{Image: "demo:1.0", Class: scanner.ClassOS, Package: "openssl", InstalledVer: "3.0.7", Status: scanner.StatusAffected, Severity: scanner.SeverityHigh, VulnID: "CVE-OS", Type: "debian"},
		},
	}}, nil, analyze.Triage{}, genTime)

	out := renderFull(r)
	if !strings.Contains(out, "*◆ pip* [python-pkg]") {
		t.Errorf("known ecosystem must render its own tag:\n%s", out)
	}
	if !strings.Contains(out, "*◆ some-lib*") {
		t.Fatalf("some-lib line missing:\n%s", out)
	}
	// The unmapped ecosystem's line must fall back to the generic tag, not
	// leak the raw unrecognized Type string or drop the tag entirely.
	if !containsLine(out, "some-lib", "[lang]") {
		t.Errorf("unmapped ecosystem must fall back to [lang]:\n%s", out)
	}
	if containsLine(out, "openssl", "[") {
		t.Errorf("an OS package line must never carry a bracket tag:\n%s", out)
	}
}

// containsLine reports whether some line of s contains both needles (used
// here so "some-lib ... [lang]" doesn't accidentally match against a
// different package's bracket tag elsewhere in the report).
func containsLine(s, a, b string) bool {
	for _, line := range strings.Split(s, "\n") {
		if strings.Contains(line, a) && strings.Contains(line, b) {
			return true
		}
	}
	return false
}

// TestBuildWebhookPayload_FindingClassAndEcosystem pins the two new
// per-finding fields: class always mirrors PackageRef.Class, and ecosystem
// is the parsed Trivy Type — "" for an OS package whose Type Build never saw
// in this test's fixture, and the mapped value for a language package with a
// known one.
func TestBuildWebhookPayload_FindingClassAndEcosystem(t *testing.T) {
	r := analyze.Build([]scanner.ImageScan{{
		Image: "demo:1.0",
		Findings: []scanner.Finding{
			{Image: "demo:1.0", Class: scanner.ClassOS, Package: "openssl", InstalledVer: "3.0.7", FixedVer: "3.0.11", Status: scanner.StatusFixed, Severity: scanner.SeverityHigh, VulnID: "CVE-OS", Type: "debian"},
			{Image: "demo:1.0", Class: scanner.ClassLang, Package: "pip", InstalledVer: "21.0.1", FixedVer: "24.0", Status: scanner.StatusFixed, Severity: scanner.SeverityHigh, VulnID: "CVE-LANG", Type: "python-pkg"},
		},
	}}, nil, analyze.Triage{}, genTime)

	data, err := json.Marshal(BuildWebhookPayload(r, nil))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var p map[string]any
	if err := json.Unmarshal(data, &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	act := p["actionable"].([]any)[0].(map[string]any)
	byPkg := map[string]map[string]any{}
	for _, raw := range act["findings"].([]any) {
		fnd := raw.(map[string]any)
		byPkg[fnd["package"].(string)] = fnd
	}
	if byPkg["openssl"]["class"] != "os" || byPkg["openssl"]["ecosystem"] != "debian" {
		t.Errorf("openssl finding = %v, want class os / ecosystem debian", byPkg["openssl"])
	}
	if byPkg["pip"]["class"] != "lang" || byPkg["pip"]["ecosystem"] != "python-pkg" {
		t.Errorf("pip finding = %v, want class lang / ecosystem python-pkg", byPkg["pip"])
	}
}

// TestBuildWebhookPayload_DiffEcosystemsDedupSortedOnCollision covers the
// (image, package) collision case end to end: state.Compute merges an OS
// package and a same-named language package under one key
// (internal/state/package_ref_test.go asserts the merge itself), and this
// diff change's ecosystems field must list both, deduplicated and sorted,
// not just the last group buildDiffPayload happened to iterate.
func TestBuildWebhookPayload_DiffEcosystemsDedupSortedOnCollision(t *testing.T) {
	r := analyze.Build([]scanner.ImageScan{{
		Image: "demo:1.0",
		Findings: []scanner.Finding{
			{Image: "demo:1.0", Class: scanner.ClassOS, Package: "openssl", InstalledVer: "3.0.7", Status: scanner.StatusAffected, Severity: scanner.SeverityHigh, VulnID: "CVE-OS-1", Type: "debian"},
			{Image: "demo:1.0", Class: scanner.ClassLang, Package: "openssl", InstalledVer: "0.10.55", Status: scanner.StatusAffected, Severity: scanner.SeverityCritical, VulnID: "CVE-RUST-1", Type: "cargo"},
		},
	}}, nil, analyze.Triage{}, genTime)
	d, _ := state.Compute(state.State{}, r)

	data, err := json.Marshal(BuildWebhookPayload(r, &d))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var p map[string]any
	if err := json.Unmarshal(data, &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	newChanges := p["diff"].(map[string]any)["new"].([]any)
	if len(newChanges) != 1 {
		t.Fatalf("diff.new = %d entries, want 1 (state merges the collision under one key)", len(newChanges))
	}
	change := newChanges[0].(map[string]any)
	if change["package"] != "openssl" {
		t.Fatalf("change.package = %v, want openssl", change["package"])
	}
	ecosystems := change["ecosystems"].([]any)
	if len(ecosystems) != 2 || ecosystems[0] != "cargo" || ecosystems[1] != "debian" {
		t.Errorf("change.ecosystems = %v, want [\"cargo\",\"debian\"] (deduplicated and sorted)", ecosystems)
	}
}

// TestBuildWebhookPayload_DiffEcosystemsIncludesEmptyString: a collision
// where one side's Type never parsed (EcosystemUnknown, "") must still show
// up in ecosystems — "" is dropped by emptyIfNil elsewhere in this payload
// (an unset list), but here it means something different: "at least one of
// the merged groups has no recognized ecosystem", which is itself the
// information a receiver needs and must not be silently omitted.
func TestBuildWebhookPayload_DiffEcosystemsIncludesEmptyString(t *testing.T) {
	r := analyze.Build([]scanner.ImageScan{{
		Image: "demo:1.0",
		Findings: []scanner.Finding{
			{Image: "demo:1.0", Class: scanner.ClassOS, Package: "curl", InstalledVer: "7.81.0", Status: scanner.StatusAffected, Severity: scanner.SeverityHigh, VulnID: "CVE-OS-1"},
			{Image: "demo:1.0", Class: scanner.ClassLang, Package: "curl", InstalledVer: "0.4.44", Status: scanner.StatusAffected, Severity: scanner.SeverityHigh, VulnID: "CVE-LANG-1", Type: "python-pkg"},
		},
	}}, nil, analyze.Triage{}, genTime)
	d, _ := state.Compute(state.State{}, r)

	data, err := json.Marshal(BuildWebhookPayload(r, &d))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var p map[string]any
	if err := json.Unmarshal(data, &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	newChanges := p["diff"].(map[string]any)["new"].([]any)
	if len(newChanges) != 1 {
		t.Fatalf("diff.new = %d entries, want 1", len(newChanges))
	}
	ecosystems := newChanges[0].(map[string]any)["ecosystems"].([]any)
	if len(ecosystems) != 2 || ecosystems[0] != "" || ecosystems[1] != "python-pkg" {
		t.Errorf(`change.ecosystems = %v, want ["","python-pkg"] (the unrecognized/empty one kept, sorted first)`, ecosystems)
	}
}
