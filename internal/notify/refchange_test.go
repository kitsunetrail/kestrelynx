package notify

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/analyze"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
	"github.com/kitsunetrail/kestrelynx/internal/state"
)

func TestRefTagLabel(t *testing.T) {
	hex := strings.Repeat("ab", 32)
	cases := map[string]string{
		"repo/app:v1":                   "v1",
		"repo/app:v1@sha256:" + hex:     "v1",
		"repo/app@sha256:" + hex:        "abababababab",
		"repo/app":                      "latest",
		"registry.example:5000/app:1.4": "1.4",
	}
	for ref, want := range cases {
		if got := refTagLabel(ref); got != want {
			t.Errorf("refTagLabel(%q) = %q, want %q", ref, got, want)
		}
	}
}

// A reference change alone is a change: no "no changes" line, and the line
// appears in both languages.
func TestChannelDiff_RefChangeOnly(t *testing.T) {
	r := analyze.Build([]scanner.ImageScan{{Image: "ghcr.io/acme/web:sha-bbbb"}}, nil, analyze.Triage{}, genTime)
	d := state.Diff{RefChanges: []state.RefChange{{
		Repository: "ghcr.io/acme/web", PreviousRef: "ghcr.io/acme/web:sha-aaaa", Ref: "ghcr.io/acme/web:sha-bbbb",
		Workloads: []string{"compose/p/web"},
	}}}
	if !d.HasChanges() {
		t.Fatal("HasChanges must include reference changes")
	}
	out := renderDiff(r, d, false, false)
	if !strings.Contains(out, "🔄 Image reference updated: ghcr.io/acme/web sha-aaaa → sha-bbbb (history carried over)") {
		t.Errorf("missing reference change line:\n%s", out)
	}
	if strings.Contains(out, "No changes since last scan") {
		t.Errorf("a reference-change-only diff must not report No changes:\n%s", out)
	}
}

func TestBuildWebhookPayload_ReferenceChanges(t *testing.T) {
	r, d := diffFixture()
	data, _ := json.Marshal(BuildWebhookPayload(r, &d))
	if strings.Contains(string(data), "reference_changes") {
		t.Errorf("reference_changes must be absent when there are none: %s", data)
	}
	d.RefChanges = []state.RefChange{{Repository: "r/a", PreviousRef: "r/a:1", Ref: "r/a:2", Workloads: []string{"compose/p/s"}}}
	data, _ = json.Marshal(BuildWebhookPayload(r, &d))
	var p struct {
		Diff struct {
			RC []map[string]any `json:"reference_changes"`
		} `json:"diff"`
	}
	if err := json.Unmarshal(data, &p); err != nil || len(p.Diff.RC) != 1 {
		t.Fatalf("diff.reference_changes = %v (%v)", p.Diff.RC, err)
	}
	e := p.Diff.RC[0]
	if e["repository"] != "r/a" || e["previous_ref"] != "r/a:1" || e["ref"] != "r/a:2" {
		t.Errorf("entry = %v", e)
	}
}
