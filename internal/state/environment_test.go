package state

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/analyze"
	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

// legacyStateShape is the pre-Environment State layout: the identical field
// set and JSON tags, minus the Environment field. It stands in for whatever
// struct an older kestrelynx binary would decode/encode a state file with,
// so a test built against this type can prove a claim about that older
// shape without depending on State itself (which now includes Environment).
type legacyStateShape struct {
	Version        int                  `json:"version"`
	Findings       map[string]Entry     `json:"findings"`
	EOSL           map[string]time.Time `json:"eosl"`
	Images         map[string]ImageMeta `json:"images,omitempty"`
	LastFullReport *ReportRef           `json:"last_full_report,omitempty"`
}

// legacyFixtureJSON is a hand-written state file exactly as an older
// (pre-Environment) binary would have left it on disk after a prior cycle:
// version 1, no "environment" key, one open finding, one EOSL image, one
// tracked reference, and a thread-report pointer. It is the starting point
// for every test below, so each one begins from a real on-disk shape rather
// than one produced by the current code under test.
const legacyFixtureJSON = `{
  "version": 1,
  "findings": {
    "web:1\topenssl": {
      "first_seen": "2026-06-20T09:00:00Z",
      "fixable": true,
      "vuln_ids": ["CVE-1"]
    }
  },
  "eosl": {
    "old:1": "2026-06-18T09:00:00Z"
  },
  "images": {
    "web:1": {
      "last_seen": "2026-06-23T09:00:00Z"
    }
  },
  "last_full_report": {
    "channel_id": "C0123456",
    "ts": "1719219600.000100",
    "permalink": "https://slack.example/archives/C0123456/p1719219600000100"
  }
}`

var (
	legacyFirstSeen = time.Date(2026, 6, 20, 9, 0, 0, 0, time.UTC)
	legacyEOSLSeen  = time.Date(2026, 6, 18, 9, 0, 0, 0, time.UTC)
	legacyLastFull  = &ReportRef{
		Channel:   "C0123456",
		TS:        "1719219600.000100",
		Permalink: "https://slack.example/archives/C0123456/p1719219600000100",
	}
)

// writeLegacyFixture writes legacyFixtureJSON to a fresh temp file and
// returns its path.
func writeLegacyFixture(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte(legacyFixtureJSON), 0o644); err != nil {
		t.Fatalf("write legacy fixture: %v", err)
	}
	return path
}

// unchangedCycleReport builds a report reproducing exactly the finding and
// EOSL image legacyFixtureJSON already has on record, so Compute sees an
// ordinary "nothing changed" cycle rather than first-observation noise.
func unchangedCycleReport(now time.Time) analyze.Report {
	return report(now,
		scanner.ImageScan{Image: "web:1", Findings: []scanner.Finding{
			finding("web:1", "openssl", "CVE-1", scanner.StatusFixed),
		}},
		scanner.ImageScan{Image: "old:1", OSEOSL: true},
	)
}

// (a) unnamed default environment, starting from a real pre-Environment
// state file: Load -> Compute (an unchanged cycle) -> Save must produce a
// file with no "environment" key, byte-identical to what marshaling the
// equivalent legacyStateShape value would produce. legacyStateShape has no
// Environment field at all, so a byte match against it is proof by
// construction that Save wrote nothing extra for the unnamed case — not a
// comparison against the same value Save was handed (which any Environment
// bug would trivially still pass).
func TestFileStore_UnnamedEnvironmentOutputByteIdenticalToPreEnvironmentFormat(t *testing.T) {
	path := writeLegacyFixture(t)
	store := FileStore{Path: path} // zero-value Env: unnamed default

	prev, err := store.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	cycleTime := day2
	d, next := Compute(prev, unchangedCycleReport(cycleTime))
	if d.HasChanges() {
		t.Fatalf("an unchanged cycle over the legacy fixture must report no changes: %+v", d)
	}
	next.LastFullReport = prev.LastFullReport // runner.sendDiff's carry-over

	if err := store.Save(next); err != nil {
		t.Fatalf("Save: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read saved state: %v", err)
	}
	if strings.Contains(string(data), "environment") {
		t.Errorf("unnamed environment must not appear in the state file, got:\n%s", data)
	}

	want, err := json.MarshalIndent(legacyStateShape{
		Version: version,
		Findings: map[string]Entry{
			"web:1\topenssl": {FirstSeen: legacyFirstSeen, Fixable: true, VulnIDs: []string{"CVE-1"}},
		},
		EOSL: map[string]time.Time{"old:1": legacyEOSLSeen},
		// Images carries one entry per scanned reference regardless of
		// findings (the Phase 2 identity model): old:1 is scanned too (it's
		// the EOSL image in unchangedCycleReport), so it gets a fresh
		// LastSeen here alongside web:1.
		Images:         map[string]ImageMeta{"web:1": {LastSeen: cycleTime}, "old:1": {LastSeen: cycleTime}},
		LastFullReport: legacyLastFull,
	}, "", "  ")
	if err != nil {
		t.Fatalf("MarshalIndent: %v", err)
	}
	if string(data) != string(want) {
		t.Errorf("Save output diverges from the pre-Environment shape's expected bytes:\ngot:  %s\nwant: %s", data, want)
	}
}

// (b)(c)(d) naming ("" -> prod), renaming (prod -> prod-vps), and un-naming
// (prod-vps -> "") must each be pure metadata updates over a real
// pre-Environment fixture: with the underlying report unchanged at every
// step, every cycle's Diff must report zero change events, the key space
// (Findings/EOSL) must stay identical to the fixture's, and every FirstSeen
// must stay pinned to the value the fixture already recorded — proving no
// code path re-notifies purely because the environment name changed.
func TestFileStore_EnvironmentRenameProducesNoChangeEvents(t *testing.T) {
	path := writeLegacyFixture(t)
	loader := FileStore{Path: path}
	unnamed := FileStore{Path: path}
	prod := FileStore{Path: path, Env: inventory.Environment{Name: "prod", Kind: inventory.KindDocker}}
	prodVPS := FileStore{Path: path, Env: inventory.Environment{Name: "prod-vps", Kind: inventory.KindDocker}}

	wantKeys := func(t *testing.T, next State) {
		t.Helper()
		if _, ok := next.Findings["web:1\topenssl"]; !ok || len(next.Findings) != 1 {
			t.Errorf("Findings = %+v, want exactly the fixture's web:1\\topenssl key", next.Findings)
		}
		if _, ok := next.EOSL["old:1"]; !ok || len(next.EOSL) != 1 {
			t.Errorf("EOSL = %+v, want exactly the fixture's old:1 key", next.EOSL)
		}
		if got := next.Findings["web:1\topenssl"].FirstSeen; !got.Equal(legacyFirstSeen) {
			t.Errorf("FirstSeen = %v, want the fixture's original %v preserved", got, legacyFirstSeen)
		}
	}

	// Cycle 1: naming the environment ("" -> "prod") over the pristine
	// fixture, same finding/EOSL content the fixture already has.
	prev1, err := loader.Load()
	if err != nil {
		t.Fatalf("cycle1 Load: %v", err)
	}
	d1, next1 := Compute(prev1, unchangedCycleReport(day2))
	if d1.HasChanges() {
		t.Errorf("naming the environment must produce no change events, got %+v", d1)
	}
	wantKeys(t, next1)
	if err := prod.Save(next1); err != nil {
		t.Fatalf("cycle1 Save: %v", err)
	}
	assertEnvironmentRecorded(t, path, "prod", "docker")

	// Cycle 2: renaming ("prod" -> "prod-vps"), same content.
	prev2, err := loader.Load()
	if err != nil {
		t.Fatalf("cycle2 Load: %v", err)
	}
	d2, next2 := Compute(prev2, unchangedCycleReport(day2.AddDate(0, 0, 1)))
	if d2.HasChanges() {
		t.Errorf("renaming the environment must produce no change events, got %+v", d2)
	}
	wantKeys(t, next2)
	if err := prodVPS.Save(next2); err != nil {
		t.Fatalf("cycle2 Save: %v", err)
	}
	assertEnvironmentRecorded(t, path, "prod-vps", "docker")

	// Cycle 3: un-naming ("prod-vps" -> ""), same content.
	prev3, err := loader.Load()
	if err != nil {
		t.Fatalf("cycle3 Load: %v", err)
	}
	d3, next3 := Compute(prev3, unchangedCycleReport(day2.AddDate(0, 0, 2)))
	if d3.HasChanges() {
		t.Errorf("un-naming the environment must produce no change events, got %+v", d3)
	}
	wantKeys(t, next3)
	if err := unnamed.Save(next3); err != nil {
		t.Fatalf("cycle3 Save: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read final state: %v", err)
	}
	if strings.Contains(string(data), "environment") {
		t.Errorf("un-naming must drop the environment field entirely, got:\n%s", data)
	}

	// The Diff as a whole must be equal across every step (the underlying
	// report never changed; only the environment name did).
	if !reflect.DeepEqual(d1, d2) {
		t.Errorf("Diff for naming (d1) != Diff for renaming (d2):\n%+v\n%+v", d1, d2)
	}
	if !reflect.DeepEqual(d2, d3) {
		t.Errorf("Diff for renaming (d2) != Diff for un-naming (d3):\n%+v\n%+v", d2, d3)
	}
}

// assertEnvironmentRecorded checks the raw JSON on disk carries the expected
// environment name/kind.
func assertEnvironmentRecorded(t *testing.T, path, wantName, wantKind string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read state: %v", err)
	}
	var st State
	if err := json.Unmarshal(data, &st); err != nil {
		t.Fatalf("unmarshal state: %v", err)
	}
	if st.Environment == nil || st.Environment.Name != wantName || st.Environment.Kind != wantKind {
		t.Errorf("State.Environment = %+v, want {Name:%q Kind:%q}", st.Environment, wantName, wantKind)
	}
}

// (e) downgrade compatibility: a new binary's state (Environment set) must
// decode cleanly under legacyStateShape (no Environment field at all) with
// Findings/EOSL/Images unaffected — json.Unmarshal silently ignores the
// unknown "environment" key.
func TestFileStore_DowngradeIgnoresEnvironmentField(t *testing.T) {
	path := writeLegacyFixture(t)
	loader := FileStore{Path: path}
	store := FileStore{Path: path, Env: inventory.Environment{Name: "prod", Kind: inventory.KindDocker}}

	prev, err := loader.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	_, next := Compute(prev, unchangedCycleReport(day2))
	next.LastFullReport = prev.LastFullReport
	if err := store.Save(next); err != nil {
		t.Fatalf("Save: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read saved state: %v", err)
	}
	var legacy legacyStateShape
	if err := json.Unmarshal(data, &legacy); err != nil {
		t.Fatalf("legacy decode: %v", err)
	}

	if !reflect.DeepEqual(legacy.Findings, next.Findings) {
		t.Errorf("legacy Findings = %+v, want %+v", legacy.Findings, next.Findings)
	}
	if !reflect.DeepEqual(legacy.EOSL, next.EOSL) {
		t.Errorf("legacy EOSL = %+v, want %+v", legacy.EOSL, next.EOSL)
	}
	if !reflect.DeepEqual(legacy.Images, next.Images) {
		t.Errorf("legacy Images = %+v, want %+v", legacy.Images, next.Images)
	}
}
