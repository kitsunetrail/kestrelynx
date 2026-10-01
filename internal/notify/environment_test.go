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

// TestChannel_UnnamedEnvironmentHeader pins the header section for the unnamed
// default environment: a single-host deployment that never set
// environment.name must see no environment marker anywhere in the message.
func TestChannel_UnnamedEnvironmentHeader(t *testing.T) {
	msgs := BuildChannelMessages(Message{Report: sampleReport()}, ChannelFooter{}, LanguageEN)
	want := "🛡️ *KestreLynx* — scan results for 2026-06-24 09:00\n2 images scanned, 1 affected\n_Everything currently open._"
	if got := msgs[0].Blocks[0].Text; got != want {
		t.Errorf("header = %q, want %q", got, want)
	}
	if strings.Contains(msgs[0].Text, "[") {
		t.Errorf("fallback text carries an environment marker: %q", msgs[0].Text)
	}
}

// TestChannel_UnnamedEnvironmentDiffHeader is the diff-mode counterpart.
func TestChannel_UnnamedEnvironmentDiffHeader(t *testing.T) {
	r, d := diffFixture()
	msgs := BuildChannelMessages(Message{Report: r, Diff: &d}, ChannelFooter{}, LanguageEN)
	want := "🛡️ *KestreLynx* — scan results for 2026-06-24 09:00\n2 images scanned, 1 affected\n_Changes since the last scan._"
	if got := msgs[0].Blocks[0].Text; got != want {
		t.Errorf("header = %q, want %q", got, want)
	}
}

// TestChannel_NamedEnvironment checks that a named environment is inserted
// once into the header, and nowhere else in the message body.
func TestChannel_NamedEnvironment(t *testing.T) {
	r := sampleReport()
	r.Environment = inventory.Environment{Name: "prod-vps", Kind: inventory.KindDocker}
	msgs := BuildChannelMessages(Message{Report: r}, ChannelFooter{}, LanguageEN)

	want := "🛡️ *KestreLynx* [prod-vps] — scan results for 2026-06-24 09:00\n"
	if got := msgs[0].Blocks[0].Text; !strings.HasPrefix(got, want) {
		t.Errorf("header = %q, want prefix %q", got, want)
	}
	if n := strings.Count(allBlocksText(msgs), "prod-vps"); n != 1 {
		t.Errorf("environment name must appear exactly once in the body, got %d", n)
	}
}

// TestChannel_NamedEnvironmentDiff is the diff-mode counterpart of
// TestChannel_NamedEnvironment.
func TestChannel_NamedEnvironmentDiff(t *testing.T) {
	r, d := diffFixture()
	r.Environment = inventory.Environment{Name: "prod-vps", Kind: inventory.KindDocker}
	msgs := BuildChannelMessages(Message{Report: r, Diff: &d}, ChannelFooter{}, LanguageEN)

	want := "🛡️ *KestreLynx* [prod-vps] — scan results for 2026-06-24 09:00\n"
	if got := msgs[0].Blocks[0].Text; !strings.HasPrefix(got, want) {
		t.Errorf("header = %q, want prefix %q", got, want)
	}
	if n := strings.Count(allBlocksText(msgs), "prod-vps"); n != 1 {
		t.Errorf("environment name must appear exactly once in the body, got %d", n)
	}
}

// TestThread_EnvironmentUnaffected checks that the thread report — which has
// no header line — renders identically whether or not the report carries a
// named environment, and never leaks the name into its output.
func TestThread_EnvironmentUnaffected(t *testing.T) {
	unnamed := BuildThreadBlockMessages(sampleReport(), Ages{Finding: seenDaysAgo(3)}, LanguageEN)

	named := sampleReport()
	named.Environment = inventory.Environment{Name: "prod-vps", Kind: inventory.KindDocker}
	withEnv := BuildThreadBlockMessages(named, Ages{Finding: seenDaysAgo(3)}, LanguageEN)

	if !reflect.DeepEqual(unnamed, withEnv) {
		t.Errorf("thread report changed with a named environment:\nunnamed: %#v\nnamed:   %#v", unnamed, withEnv)
	}
	for _, m := range withEnv {
		if strings.Contains(allBlocksText([]SlackMessage{m}), "prod-vps") || strings.Contains(m.Text, "prod-vps") {
			t.Errorf("thread report must never render the environment name:\n%s", dumpMessages([]SlackMessage{m}))
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
	configDigest, ok := inventory.ParseDigest(inventory.DigestConfig, contentID)
	if !ok {
		panic("test fixture: invalid digest " + contentID)
	}
	key := inventory.EntityKey{Digest: configDigest}
	scans := []scanner.ImageScan{
		{
			Image:      "web:1.0",
			Subject:    inventory.ImageSubject{Ref: "web:1.0", Key: key, Resolved: true},
			ScannedKey: key,
			Pinned:     true,
			Source:     scanner.SourceLocal,
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
			Image:    inventory.RunningImage{Ref: "web:1.0", Config: configDigest},
		},
		{
			Name:     "stray",
			Workload: inventory.Workload{Kind: inventory.WorkloadUnknown},
			Image:    inventory.RunningImage{Ref: "web:1.0", Config: configDigest},
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
// The later "eol_packages" key is stripped too.
// It pins every other field — summary, findings, severity counts, the three
// status sections, scan_errors — so a change to any of them, not just the
// two new fields, fails this test.
const wantWebhookJSONUnnamedNoContainers = `{"actionable":[{"findings":[{"class":"os","ecosystem":"","fixed":"2.28-10+deb10u2","installed":"2.28-10","package":"libc-bin","severity_counts":{"CRITICAL":1,"HIGH":0},"status":"fixed","upgrade_risk":"distro_update","vuln_ids":["CVE-1"],"vulns":[{"epss":null,"id":"CVE-1","kev":false,"severity":"CRITICAL"}]},{"class":"lang","ecosystem":"","fixed":"78.1.1","installed":"53.0.0","package":"setuptools","severity_counts":{"CRITICAL":0,"HIGH":1},"status":"fixed","upgrade_risk":"caution","vuln_ids":["CVE-2"],"vulns":[{"epss":null,"id":"CVE-2","kev":false,"severity":"HIGH"}]}],"identity_resolved":false,"image":"web:1.0","registry_digests":[],"scan_target_kind":"reference","severity_counts":{"CRITICAL":1,"HIGH":1}}],"eosl_images":["web:1.0"],"generated_at":"2026-06-24T09:00:00Z","scan_errors":[{"error":"pull failed","image":"broken:1"}],"summary":{"images_affected":1,"images_total":2},"watch":[{"findings":[{"class":"os","ecosystem":"","fixed":"","installed":"1.44","package":"e2fsprogs","severity_counts":{"CRITICAL":0,"HIGH":1},"status":"affected","upgrade_risk":"","vuln_ids":["CVE-3"],"vulns":[{"epss":null,"id":"CVE-3","kev":false,"severity":"HIGH"}]}],"identity_resolved":false,"image":"web:1.0","registry_digests":[],"scan_target_kind":"reference","severity_counts":{"CRITICAL":0,"HIGH":1}}],"wont_fix":[{"findings":[{"class":"os","ecosystem":"","fixed":"","installed":"8.3","package":"gcc-8-base","severity_counts":{"CRITICAL":0,"HIGH":1},"status":"will_not_fix","upgrade_risk":"","vuln_ids":["CVE-4"],"vulns":[{"epss":null,"id":"CVE-4","kev":false,"severity":"HIGH"}]}],"identity_resolved":false,"image":"web:1.0","registry_digests":[],"scan_target_kind":"reference","severity_counts":{"CRITICAL":0,"HIGH":1}}]}`

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
	// Always present, empty here: sampleReport has no end-of-life packages.
	if eol, ok := got["eol_packages"].([]any); !ok || len(eol) != 0 {
		t.Errorf("eol_packages = %#v, want an empty array", got["eol_packages"])
	}
	delete(got, "eol_packages")

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
