package notify

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/analyze"
	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

// wantSlackTextUnnamed is the frozen full-text output of
// FormatSlackText(sampleReport()) for the unnamed default environment,
// captured before any environment-model header change could touch it. A
// full-string comparison (not just the header prefix) catches a regression
// anywhere in the body, not only in the header line the environment name is
// inserted into.
const wantSlackTextUnnamed = "🛡️ *KestreLynx* — scan results for 2026-06-24 09:00\n2 images scanned, 1 affected\n*Priority:* ⛔ 1 EOL base · 🔴 1 CRITICAL · 🟠 1 need care\n\n*⛔ Base OS end-of-life (top priority)*\n• web:1.0 — identity unconfirmed: scanned by reference — base OS is EOL (no more security updates coming)\n\n*✅ Actionable now (fixed)*\n🔴 web:1.0 — identity unconfirmed: scanned by reference  CRITICAL 1 / HIGH 1\n   • libc-bin 2.28-10 → 2.28-10+deb10u2 (CRITICAL 1 / HIGH 0)  🟢 upgrade: distro security patch\n   • setuptools 53.0.0 → 78.1.1 (CRITICAL 0 / HIGH 1)  🟠 upgrade: major version bump — needs care [lang]\n\n*ℹ️ No fix yet (affected / waiting on upstream)*\n🟠 web:1.0 — identity unconfirmed: scanned by reference  CRITICAL 0 / HIGH 1\n   • e2fsprogs 1.44 (no fix available) (CRITICAL 0 / HIGH 1)\n\n*🔕 Upstream won't fix (will_not_fix)*\n🟠 web:1.0 — identity unconfirmed: scanned by reference  CRITICAL 0 / HIGH 1\n   • gcc-8-base 8.3 (no fix available) (CRITICAL 0 / HIGH 1)\n\n*⚠️ Scan failures*\n• broken:1 — identity unconfirmed: scanned by reference — pull failed\n\n⚠️ identity unconfirmed: scanned by reference — broken:1, web:1.0\n"

// wantSlackDiffTextUnnamed is the diff-mode counterpart of
// wantSlackTextUnnamed: the frozen full-text output of
// FormatSlackDiffText(r, d, false) for diffFixture()'s unnamed-environment
// report.
const wantSlackDiffTextUnnamed = "🛡️ *KestreLynx* — scan results for 2026-06-24 09:00\n2 images scanned, 1 affected\n\n*⛔ New: base OS end-of-life (top priority)*\n• web:1.0 — identity unconfirmed: scanned by reference — base OS is EOL (no more security updates coming)\n\n*🆕 New since last scan (4)*\n🔴 web:1.0 — identity unconfirmed: scanned by reference\n   • libc-bin 2.28-10 → 2.28-10+deb10u2 (CRITICAL 1 / HIGH 0)  🟢 upgrade: distro security patch\n   • setuptools 53.0.0 → 78.1.1 (CRITICAL 0 / HIGH 1)  🟠 upgrade: major version bump — needs care [lang]\n   • e2fsprogs 1.44 (no fix available) (CRITICAL 0 / HIGH 1)\n   • gcc-8-base 8.3 (no fix available) (CRITICAL 0 / HIGH 1)\n\n*⚠️ Scan failures*\n• broken:1 — identity unconfirmed: scanned by reference — pull failed\n\n📌 Open now: CRITICAL 1 / HIGH 3 across 1 image(s)\n_Details in the generic webhook payload, or in the weekly full report._\n\n⚠️ identity unconfirmed: scanned by reference — broken:1, web:1.0\n"

// TestFormatSlackText_UnnamedEnvironmentUnchanged pins the exact,
// full-message output for the unnamed default environment: a single-host
// deployment that never set environment.name must see byte-identical output
// from before the environment model existed, in the header and everywhere
// else in the message.
func TestFormatSlackText_UnnamedEnvironmentUnchanged(t *testing.T) {
	if out := FormatSlackText(sampleReport()); out != wantSlackTextUnnamed {
		t.Errorf("output changed for the unnamed environment:\ngot:  %q\nwant: %q", out, wantSlackTextUnnamed)
	}
}

// TestFormatSlackDiffText_UnnamedEnvironmentUnchanged is the diff-mode
// counterpart of TestFormatSlackText_UnnamedEnvironmentUnchanged.
func TestFormatSlackDiffText_UnnamedEnvironmentUnchanged(t *testing.T) {
	r, d := diffFixture()
	if out := FormatSlackDiffText(r, d, false); out != wantSlackDiffTextUnnamed {
		t.Errorf("output changed for the unnamed environment:\ngot:  %q\nwant: %q", out, wantSlackDiffTextUnnamed)
	}
}

// TestFormatSlackText_NamedEnvironment checks that a named environment is
// inserted once into the header, and nowhere else in the message.
func TestFormatSlackText_NamedEnvironment(t *testing.T) {
	r := sampleReport()
	r.Environment = inventory.Environment{Name: "prod-vps", Kind: inventory.KindDocker}
	out := FormatSlackText(r)

	want := "🛡️ *KestreLynx* [prod-vps] — scan results for 2026-06-24 09:00\n"
	if !strings.HasPrefix(out, want) {
		t.Errorf("header = %q, want prefix %q", out, want)
	}
	if n := strings.Count(out, "prod-vps"); n != 1 {
		t.Errorf("environment name must appear exactly once, got %d occurrence(s):\n%s", n, out)
	}
}

// TestFormatSlackDiffText_NamedEnvironment is the diff-mode counterpart of
// TestFormatSlackText_NamedEnvironment.
func TestFormatSlackDiffText_NamedEnvironment(t *testing.T) {
	r, d := diffFixture()
	r.Environment = inventory.Environment{Name: "prod-vps", Kind: inventory.KindDocker}
	out := FormatSlackDiffText(r, d, false)

	want := "🛡️ *KestreLynx* [prod-vps] — scan results for 2026-06-24 09:00\n"
	if !strings.HasPrefix(out, want) {
		t.Errorf("header = %q, want prefix %q", out, want)
	}
	if n := strings.Count(out, "prod-vps"); n != 1 {
		t.Errorf("environment name must appear exactly once, got %d occurrence(s):\n%s", n, out)
	}
}

// TestBuildThreadMessages_EnvironmentUnaffected checks that the thread report
// renderer — which has no header line and is documented (judgment 5 of the
// environment/workload model) as unaffected by the environment model — really
// does render identically whether or not the report carries a named
// environment, and never leaks the name into its output.
func TestBuildThreadMessages_EnvironmentUnaffected(t *testing.T) {
	unnamed := BuildThreadMessages(sampleReport(), seenDaysAgo(3), 0)

	named := sampleReport()
	named.Environment = inventory.Environment{Name: "prod-vps", Kind: inventory.KindDocker}
	withEnv := BuildThreadMessages(named, seenDaysAgo(3), 0)

	if !reflect.DeepEqual(unnamed, withEnv) {
		t.Errorf("thread report changed with a named environment:\nunnamed: %#v\nnamed:   %#v", unnamed, withEnv)
	}
	for _, msg := range withEnv {
		if strings.Contains(msg, "prod-vps") {
			t.Errorf("thread report must never render the environment name:\n%s", msg)
		}
	}
}

// TestBuildWebhookPayload_EnvironmentUnnamed checks the unnamed default
// environment's webhook shape: kind is always present, name is omitted
// entirely (not sent as "").
func TestBuildWebhookPayload_EnvironmentUnnamed(t *testing.T) {
	r := sampleReport()
	r.Environment = inventory.Environment{Kind: inventory.KindDocker}
	data, err := json.Marshal(BuildWebhookPayload(r, nil))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var p map[string]any
	if err := json.Unmarshal(data, &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	env, ok := p["environment"].(map[string]any)
	if !ok {
		t.Fatalf("environment missing/wrong type: %T", p["environment"])
	}
	if env["kind"] != "docker" {
		t.Errorf("environment.kind = %v, want docker", env["kind"])
	}
	if _, ok := env["name"]; ok {
		t.Errorf("unnamed environment must omit the name key, got %v", env)
	}
}

// TestBuildWebhookPayload_EnvironmentNamed checks the named-environment
// webhook shape: both kind and name present.
func TestBuildWebhookPayload_EnvironmentNamed(t *testing.T) {
	r := sampleReport()
	r.Environment = inventory.Environment{Name: "prod-vps", Kind: inventory.KindDocker}
	data, err := json.Marshal(BuildWebhookPayload(r, nil))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var p map[string]any
	if err := json.Unmarshal(data, &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	env, ok := p["environment"].(map[string]any)
	if !ok {
		t.Fatalf("environment missing/wrong type: %T", p["environment"])
	}
	if env["kind"] != "docker" {
		t.Errorf("environment.kind = %v, want docker", env["kind"])
	}
	if env["name"] != "prod-vps" {
		t.Errorf("environment.name = %v, want prod-vps", env["name"])
	}
}

// containersReport builds a report for one image, "web:1.0", whose entity
// (ref+ContentID) has findings under two different statuses (fixed and
// affected — StatusAffected has no fix, so it lands in Watch) and is backed
// by two observed containers: one with a full pair of Compose labels, one
// without any (WorkloadUnknown). Used to exercise both container.workload
// shapes and the per-status-section duplication rule together.
func containersReport() analyze.Report {
	const contentID = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	scans := []scanner.ImageScan{
		{
			Image:             "web:1.0",
			ExpectedContentID: contentID,
			IdentityResolved:  true,
			Findings: []scanner.Finding{
				{Image: "web:1.0", Class: scanner.ClassOS, Package: "libc-bin", InstalledVer: "2.28-10", FixedVer: "2.28-10+deb10u2", Status: scanner.StatusFixed, Severity: scanner.SeverityCritical, VulnID: "CVE-1"},
				{Image: "web:1.0", Class: scanner.ClassOS, Package: "e2fsprogs", InstalledVer: "1.44", Status: scanner.StatusAffected, Severity: scanner.SeverityHigh, VulnID: "CVE-3"},
			},
		},
	}
	containers := []inventory.Container{
		{
			Name:     "proj-web-1",
			Workload: inventory.Workload{Kind: inventory.WorkloadCompose, Group: "proj", Name: "web"},
			Image:    inventory.RunningImage{Ref: "web:1.0", ContentID: contentID},
		},
		{
			Name:     "stray",
			Workload: inventory.Workload{Kind: inventory.WorkloadUnknown},
			Image:    inventory.RunningImage{Ref: "web:1.0", ContentID: contentID},
		},
	}
	return analyze.Build(scans, containers, analyze.Triage{}, genTime)
}

// containerPayloadsFrom extracts the "containers" array of the first entry
// of the named top-level section ("actionable" or "watch") from a marshaled
// webhook payload.
func containerPayloadsFrom(t *testing.T, data []byte, section string) []map[string]any {
	t.Helper()
	var p map[string]any
	if err := json.Unmarshal(data, &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	imgs, ok := p[section].([]any)
	if !ok || len(imgs) != 1 {
		t.Fatalf("%s = %v, want exactly 1 entry", section, p[section])
	}
	img := imgs[0].(map[string]any)
	cs, ok := img["containers"].([]any)
	if !ok {
		t.Fatalf("%s[0].containers missing/wrong type: %T", section, img["containers"])
	}
	out := make([]map[string]any, len(cs))
	for i, c := range cs {
		out[i] = c.(map[string]any)
	}
	return out
}

// TestBuildWebhookPayload_Containers checks the two container/workload
// shapes (compose, unknown) and that the same entity's container list is
// duplicated verbatim across every status section it appears in (mirroring
// the existing registry_digests behavior for the same reason: each section
// entry is self-contained).
func TestBuildWebhookPayload_Containers(t *testing.T) {
	r := containersReport()
	data, err := json.Marshal(BuildWebhookPayload(r, nil))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	for _, section := range []string{"actionable", "watch"} {
		cs := containerPayloadsFrom(t, data, section)
		if len(cs) != 2 {
			t.Fatalf("%s containers = %d entries, want 2", section, len(cs))
		}

		byName := map[string]map[string]any{}
		for _, c := range cs {
			byName[c["name"].(string)] = c
		}

		compose, ok := byName["proj-web-1"]
		if !ok {
			t.Fatalf("%s: missing container proj-web-1: %v", section, cs)
		}
		wl := compose["workload"].(map[string]any)
		if wl["kind"] != "compose" || wl["group"] != "proj" || wl["name"] != "web" {
			t.Errorf("%s: proj-web-1.workload = %v, want kind=compose group=proj name=web", section, wl)
		}

		unknown, ok := byName["stray"]
		if !ok {
			t.Fatalf("%s: missing container stray: %v", section, cs)
		}
		uwl := unknown["workload"].(map[string]any)
		if uwl["kind"] != "unknown" {
			t.Errorf("%s: stray.workload.kind = %v, want unknown (must not be omitted)", section, uwl["kind"])
		}
		if _, ok := uwl["group"]; ok {
			t.Errorf("%s: stray.workload must omit group when unknown, got %v", section, uwl)
		}
		if _, ok := uwl["name"]; ok {
			t.Errorf("%s: stray.workload must omit name when unknown, got %v", section, uwl)
		}
	}
}

// wantWebhookJSONUnnamedNoContainers is the frozen JSON shape of
// BuildWebhookPayload(sampleReport(), nil) for the unnamed default
// environment, captured before the environment/containers additions existed
// and then stripped of the "environment" key and every imagePayload's
// "containers" key (see TestBuildWebhookPayload_NoEnvironmentNoContainersUnchanged).
// It pins every other field — summary, findings, severity counts, the three
// status sections, scan_errors — so a change to any of them, not just the
// two new fields, fails this test.
const wantWebhookJSONUnnamedNoContainers = `{"actionable":[{"findings":[{"fixed":"2.28-10+deb10u2","installed":"2.28-10","package":"libc-bin","severity_counts":{"CRITICAL":1,"HIGH":0},"status":"fixed","upgrade_risk":"distro_update","vuln_ids":["CVE-1"],"vulns":[{"epss":null,"id":"CVE-1","kev":false,"severity":"CRITICAL"}]},{"fixed":"78.1.1","installed":"53.0.0","package":"setuptools","severity_counts":{"CRITICAL":0,"HIGH":1},"status":"fixed","upgrade_risk":"caution","vuln_ids":["CVE-2"],"vulns":[{"epss":null,"id":"CVE-2","kev":false,"severity":"HIGH"}]}],"identity_resolved":false,"image":"web:1.0","registry_digests":[],"scan_target_kind":"reference","severity_counts":{"CRITICAL":1,"HIGH":1}}],"eosl_images":["web:1.0"],"generated_at":"2026-06-24T09:00:00Z","scan_errors":[{"error":"pull failed","image":"broken:1"}],"summary":{"images_affected":1,"images_total":2},"watch":[{"findings":[{"fixed":"","installed":"1.44","package":"e2fsprogs","severity_counts":{"CRITICAL":0,"HIGH":1},"status":"affected","upgrade_risk":"","vuln_ids":["CVE-3"],"vulns":[{"epss":null,"id":"CVE-3","kev":false,"severity":"HIGH"}]}],"identity_resolved":false,"image":"web:1.0","registry_digests":[],"scan_target_kind":"reference","severity_counts":{"CRITICAL":0,"HIGH":1}}],"wont_fix":[{"findings":[{"fixed":"","installed":"8.3","package":"gcc-8-base","severity_counts":{"CRITICAL":0,"HIGH":1},"status":"will_not_fix","upgrade_risk":"","vuln_ids":["CVE-4"],"vulns":[{"epss":null,"id":"CVE-4","kev":false,"severity":"HIGH"}]}],"identity_resolved":false,"image":"web:1.0","registry_digests":[],"scan_target_kind":"reference","severity_counts":{"CRITICAL":0,"HIGH":1}}]}`

// TestBuildWebhookPayload_NoEnvironmentNoContainersUnchanged checks that, for
// an unnamed environment and a report built with no containers (the nil
// path every caller of analyze.Build without a wired-up adapter exercises),
// every field other than the new "environment" and "containers" additions
// renders exactly as it did before those additions existed. It marshals the
// live payload, decodes it to a generic map, deletes the "environment" key
// and every imagePayload's "containers" key, and requires the remainder to
// deep-equal the frozen pre-addition shape — so a change anywhere else in
// the payload (not just the two new fields) fails this test.
func TestBuildWebhookPayload_NoEnvironmentNoContainersUnchanged(t *testing.T) {
	data, err := json.Marshal(BuildWebhookPayload(sampleReport(), nil))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	env, ok := got["environment"].(map[string]any)
	if !ok {
		t.Fatalf("environment missing/wrong type: %T", got["environment"])
	}
	if _, ok := env["name"]; ok {
		t.Errorf("unnamed environment must omit name, got %v", env)
	}
	delete(got, "environment")

	for _, section := range []string{"actionable", "watch", "wont_fix"} {
		arr, ok := got[section].([]any)
		if !ok {
			t.Fatalf("%s missing/wrong type: %T", section, got[section])
		}
		for _, item := range arr {
			im, ok := item.(map[string]any)
			if !ok {
				t.Fatalf("%s entry wrong type: %T", section, item)
			}
			if _, ok := im["containers"]; !ok {
				t.Errorf("%s entry missing containers key: %v", section, im)
			}
			delete(im, "containers")
		}
	}

	var want map[string]any
	if err := json.Unmarshal([]byte(wantWebhookJSONUnnamedNoContainers), &want); err != nil {
		t.Fatalf("unmarshal frozen fixture: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("payload changed beyond the environment/containers additions:\ngot:  %#v\nwant: %#v", got, want)
	}
}
