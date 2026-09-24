package state

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/analyze"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

// Tests for end-of-life package findings (Report.EOLPackages), which state
// tracks in State.EOLPackages apart from ordinary findings.

// dayN is the n-th cycle's time, day1 being cycle 1.
func dayN(n int) time.Time { return day1.AddDate(0, 0, n-1) }

func eolFinding(image, pkg, vulnID string) scanner.Finding {
	return finding(image, pkg, vulnID, scanner.StatusEndOfLife)
}

func scanOf(image string, finds ...scanner.Finding) scanner.ImageScan {
	return scanner.ImageScan{Image: image, Findings: finds}
}

func eolKinds(d Diff) []string {
	var out []string
	for _, c := range d.NewEOLPackages {
		out = append(out, c.Image+" "+c.Package+" "+string(c.Kind))
	}
	return out
}

func changeKinds(d Diff) []string {
	var out []string
	for _, c := range d.Changes {
		out = append(out, c.Image+" "+c.Package+" "+string(c.Kind))
	}
	return out
}

func wantKinds(t *testing.T, what string, got []string, want ...string) {
	t.Helper()
	if len(got) == 0 && len(want) == 0 {
		return
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("%s = %v, want %v", what, got, want)
	}
}

func TestComputeEOL_UnknownPackageAppearsEOLOnly(t *testing.T) {
	d, st := Compute(empty(), report(day1, scanOf("web:1", eolFinding("web:1", "qt", "CVE-1"))))
	wantKinds(t, "eol changes", eolKinds(d), "web:1 qt eol_new")
	wantKinds(t, "changes", changeKinds(d))
	e, ok := st.EOLPackages["web:1\tqt"]
	if !ok || !e.FirstSeen.Equal(day1) || !reflect.DeepEqual(e.VulnIDs, []string{"CVE-1"}) {
		t.Errorf("EOL record = %+v (ok %v), want first seen day1 with CVE-1", e, ok)
	}
	if _, ok := st.Findings["web:1\tqt"]; ok {
		t.Error("an end-of-life-only package must not create an ordinary entry")
	}
	if !d.HasChanges() || d.OpenEOLPackages != 1 || !d.AnyOpen {
		t.Errorf("HasChanges %v OpenEOLPackages %d AnyOpen %v, want true/1/true", d.HasChanges(), d.OpenEOLPackages, d.AnyOpen)
	}
}

// The transition table, cycle after cycle: a package mixing statuses moves
// into end-of-life, gains and escalates end-of-life CVEs, gets a fix on its
// ordinary side, leaves end-of-life, and is detected again.
func TestComputeEOL_MultiCycleTransitions(t *testing.T) {
	const img = "web:1"
	kev := map[string]analyze.Enrichment{"CVE-3": {KEV: true}}

	// Cycle 1: curl has an affected and a fix_deferred CVE (one Watch group).
	d, st := Compute(empty(), triaged(dayN(1), nil, scanOf(img,
		finding(img, "curl", "CVE-1", scanner.StatusAffected),
		finding(img, "curl", "CVE-2", scanner.StatusFixDeferred),
	)))
	wantKinds(t, "c1 changes", changeKinds(d), "web:1 curl new")
	if e := st.Findings["web:1\tcurl"]; !reflect.DeepEqual(e.VulnIDs, []string{"CVE-1", "CVE-2"}) {
		t.Fatalf("c1 entry = %+v", e)
	}

	// Cycle 2: CVE-2 moves to end-of-life. The ordinary entry shrinks
	// silently; the end-of-life side announces eol_new.
	d, st = Compute(st, triaged(dayN(2), nil, scanOf(img,
		finding(img, "curl", "CVE-1", scanner.StatusAffected),
		eolFinding(img, "curl", "CVE-2"),
	)))
	wantKinds(t, "c2 changes", changeKinds(d))
	wantKinds(t, "c2 eol", eolKinds(d), "web:1 curl eol_new")
	if len(d.Resolved) != 0 || len(d.ResolvedEOLPackages) != 0 {
		t.Errorf("c2 resolved = %+v / %+v, want none", d.Resolved, d.ResolvedEOLPackages)
	}
	if e := st.Findings["web:1\tcurl"]; !reflect.DeepEqual(e.VulnIDs, []string{"CVE-1"}) || !e.FirstSeen.Equal(dayN(1)) {
		t.Errorf("c2 ordinary entry = %+v, want CVE-1 only, first seen cycle 1", e)
	}
	if e := st.EOLPackages["web:1\tcurl"]; !e.FirstSeen.Equal(dayN(2)) {
		t.Errorf("c2 EOL first seen = %v, want cycle 2 (not the ordinary entry's)", e.FirstSeen)
	}

	// Cycle 3: another end-of-life CVE → eol_new_cves.
	d, st = Compute(st, triaged(dayN(3), nil, scanOf(img,
		finding(img, "curl", "CVE-1", scanner.StatusAffected),
		eolFinding(img, "curl", "CVE-2"),
		eolFinding(img, "curl", "CVE-3"),
	)))
	wantKinds(t, "c3 changes", changeKinds(d))
	wantKinds(t, "c3 eol", eolKinds(d), "web:1 curl eol_new_cves")
	if got := d.NewEOLPackages[0].NewIDs; !reflect.DeepEqual(got, []string{"CVE-3"}) {
		t.Errorf("c3 NewIDs = %v, want [CVE-3]", got)
	}

	// Cycle 4: CVE-3 enters KEV → eol_escalated; the ordinary side is quiet.
	d, st = Compute(st, triaged(dayN(4), kev, scanOf(img,
		finding(img, "curl", "CVE-1", scanner.StatusAffected),
		eolFinding(img, "curl", "CVE-2"),
		eolFinding(img, "curl", "CVE-3"),
	)))
	wantKinds(t, "c4 changes", changeKinds(d))
	wantKinds(t, "c4 eol", eolKinds(d), "web:1 curl eol_escalated")
	if got := st.EOLPackages["web:1\tcurl"].Priority; got != "act_now" {
		t.Errorf("c4 EOL priority = %q, want act_now", got)
	}

	// Cycle 5: the ordinary CVE-1 gets a fix → now_fixable on the ordinary
	// side, nothing on the end-of-life side.
	c5 := scanOf(img,
		finding(img, "curl", "CVE-1", scanner.StatusFixed),
		eolFinding(img, "curl", "CVE-2"),
		eolFinding(img, "curl", "CVE-3"),
	)
	d, st = Compute(st, triaged(dayN(5), kev, c5))
	wantKinds(t, "c5 changes", changeKinds(d), "web:1 curl now_fixable")
	wantKinds(t, "c5 eol", eolKinds(d))

	// Cycle 6: the package disappears (image updated) → both sides resolve.
	d, st = Compute(st, triaged(dayN(6), kev, scanOf(img)))
	if !reflect.DeepEqual(d.Resolved, []Resolved{{Image: img, Package: "curl"}}) {
		t.Errorf("c6 Resolved = %+v", d.Resolved)
	}
	if !reflect.DeepEqual(d.ResolvedEOLPackages, []ResolvedEOL{{Image: img, Package: "curl"}}) {
		t.Errorf("c6 ResolvedEOLPackages = %+v", d.ResolvedEOLPackages)
	}
	if len(st.EOLPackages) != 0 || len(st.Findings) != 0 {
		t.Errorf("c6 state = %+v / %+v, want empty", st.Findings, st.EOLPackages)
	}

	// Cycle 7: detected end-of-life again → eol_new with a fresh first seen.
	d, st = Compute(st, triaged(dayN(7), kev, scanOf(img, eolFinding(img, "curl", "CVE-2"))))
	wantKinds(t, "c7 eol", eolKinds(d), "web:1 curl eol_new")
	if got := st.EOLPackages["web:1\tcurl"].FirstSeen; !got.Equal(dayN(7)) {
		t.Errorf("c7 EOL first seen = %v, want cycle 7", got)
	}
}

// An ordinary-only package whose every CVE moves to end-of-life is not
// reported resolved: the end-of-life change announces it.
func TestComputeEOL_AllCVEsMoveToEOLIsNotResolved(t *testing.T) {
	_, st := Compute(empty(), report(day1, scanOf("web:1", finding("web:1", "qt", "CVE-1", scanner.StatusAffected))))
	d, st := Compute(st, report(day2, scanOf("web:1", eolFinding("web:1", "qt", "CVE-1"))))
	if len(d.Resolved) != 0 {
		t.Errorf("Resolved = %+v, want none", d.Resolved)
	}
	wantKinds(t, "eol", eolKinds(d), "web:1 qt eol_new")
	if _, ok := st.Findings["web:1\tqt"]; ok {
		t.Error("the ordinary entry must be dropped once nothing ordinary remains")
	}
}

func TestComputeEOL_LowToWatchIsSilent(t *testing.T) {
	scan := scanOf("web:1", eolFinding("web:1", "qt", "CVE-1"))
	_, st := Compute(empty(), triaged(day1, nil, scan))
	d, st := Compute(st, triaged(day2, map[string]analyze.Enrichment{"CVE-1": {EPSS: 0.05, EPSSKnown: true}}, scan))
	if d.HasChanges() {
		t.Errorf("low→watch must not be announced: %+v", d.NewEOLPackages)
	}
	if got := st.EOLPackages["web:1\tqt"].Priority; got != "watch" {
		t.Errorf("stored priority = %q, want watch", got)
	}
}

// EOL→fixed (no other change): now_fixable on the ordinary side, the
// end-of-life record cleared with StillOpen, first seen taken from it.
func TestComputeEOL_EOLToFixedIsNowFixable(t *testing.T) {
	_, st := Compute(empty(), report(day1, scanOf("web:1", eolFinding("web:1", "qt", "CVE-1"))))
	d, st := Compute(st, report(day2, scanOf("web:1", finding("web:1", "qt", "CVE-1", scanner.StatusFixed))))
	wantKinds(t, "changes", changeKinds(d), "web:1 qt now_fixable")
	if !reflect.DeepEqual(d.ResolvedEOLPackages, []ResolvedEOL{{Image: "web:1", Package: "qt", StillOpen: true}}) {
		t.Errorf("ResolvedEOLPackages = %+v", d.ResolvedEOLPackages)
	}
	if got := st.Findings["web:1\tqt"].FirstSeen; !got.Equal(day1) {
		t.Errorf("FirstSeen = %v, want the end-of-life record's %v", got, day1)
	}
	if len(st.EOLPackages) != 0 {
		t.Errorf("EOL record must be cleared: %+v", st.EOLPackages)
	}
}

// EOL→affected with the same ID: no ordinary change, only the end-of-life
// clearance.
func TestComputeEOL_EOLToAffectedIsQuiet(t *testing.T) {
	_, st := Compute(empty(), report(day1, scanOf("web:1", eolFinding("web:1", "qt", "CVE-1"))))
	d, _ := Compute(st, report(day2, scanOf("web:1", finding("web:1", "qt", "CVE-1", scanner.StatusFixDeferred))))
	wantKinds(t, "changes", changeKinds(d))
	if !reflect.DeepEqual(d.ResolvedEOLPackages, []ResolvedEOL{{Image: "web:1", Package: "qt", StillOpen: true}}) {
		t.Errorf("ResolvedEOLPackages = %+v", d.ResolvedEOLPackages)
	}
}

// The "no other change" premise of the table: an EOL→fixed move that
// coincides with a KEV listing is escalated, and one that adds an ID is
// new_cves.
func TestComputeEOL_EOLToFixedWithOtherChanges(t *testing.T) {
	scan1 := scanOf("web:1", eolFinding("web:1", "qt", "CVE-1"))
	_, st := Compute(empty(), triaged(day1, nil, scan1))
	d, _ := Compute(st, triaged(day2, map[string]analyze.Enrichment{"CVE-1": {KEV: true}}, scanOf("web:1", finding("web:1", "qt", "CVE-1", scanner.StatusFixed))))
	wantKinds(t, "with KEV", changeKinds(d), "web:1 qt escalated")

	d, _ = Compute(st, triaged(day2, nil, scanOf("web:1",
		finding("web:1", "qt", "CVE-1", scanner.StatusFixed),
		finding("web:1", "qt", "CVE-9", scanner.StatusFixed),
	)))
	wantKinds(t, "with new ID", changeKinds(d), "web:1 qt new_cves")
	if got := d.Changes[0].NewIDs; !reflect.DeepEqual(got, []string{"CVE-9"}) {
		t.Errorf("NewIDs = %v, want [CVE-9] (CVE-1 was already known end-of-life)", got)
	}
}

// Rule for a known ordinary entry: a package mixing an ordinary CVE-A and an
// end-of-life CVE-B; B later gets a fix. The ordinary side is now_fixable,
// not new_cves, and the end-of-life side clears with StillOpen.
func TestComputeEOL_MixedThenFixIsNowFixable(t *testing.T) {
	cycle1 := scanOf("web:1",
		finding("web:1", "qt", "CVE-A", scanner.StatusAffected),
		eolFinding("web:1", "qt", "CVE-B"),
	)
	cycle2 := scanOf("web:1",
		finding("web:1", "qt", "CVE-A", scanner.StatusAffected),
		finding("web:1", "qt", "CVE-B", scanner.StatusFixed),
	)
	_, st := Compute(empty(), triaged(day1, nil, cycle1))
	d, next := Compute(st, triaged(day2, nil, cycle2))
	wantKinds(t, "changes", changeKinds(d), "web:1 qt now_fixable")
	if len(d.Changes) == 1 && len(d.Changes[0].NewIDs) != 0 {
		t.Errorf("NewIDs = %v, want none", d.Changes[0].NewIDs)
	}
	if !reflect.DeepEqual(d.ResolvedEOLPackages, []ResolvedEOL{{Image: "web:1", Package: "qt", StillOpen: true}}) {
		t.Errorf("ResolvedEOLPackages = %+v", d.ResolvedEOLPackages)
	}
	if got := next.Findings["web:1\tqt"].FirstSeen; !got.Equal(day1) {
		t.Errorf("FirstSeen = %v, want %v", got, day1)
	}

	// Same flow with B already act_now as end-of-life: the fix arriving
	// together with B's KEV listing is not an escalation, since the key's
	// baseline includes the end-of-life priority.
	kev := map[string]analyze.Enrichment{"CVE-B": {KEV: true}}
	_, st = Compute(empty(), triaged(day1, kev, cycle1))
	d, _ = Compute(st, triaged(day2, kev, cycle2))
	wantKinds(t, "changes (B act_now before)", changeKinds(d), "web:1 qt now_fixable")
}

// A package with a fixed and an end-of-life group: now_fixable stays on the
// ordinary side even when the end-of-life side is unchanged.
func TestComputeEOL_FixedAndEOLSamePackage(t *testing.T) {
	_, st := Compute(empty(), report(day1, scanOf("web:1",
		finding("web:1", "qt", "CVE-A", scanner.StatusAffected),
		eolFinding("web:1", "qt", "CVE-B"),
	)))
	d, next := Compute(st, report(day2, scanOf("web:1",
		finding("web:1", "qt", "CVE-A", scanner.StatusFixed),
		eolFinding("web:1", "qt", "CVE-B"),
	)))
	wantKinds(t, "changes", changeKinds(d), "web:1 qt now_fixable")
	wantKinds(t, "eol", eolKinds(d))
	for _, g := range d.Changes[0].Groups {
		if analyze.IsEOL(g) {
			t.Errorf("an ordinary change must not carry end-of-life groups: %+v", g)
		}
	}
	if _, ok := next.EOLPackages["web:1\tqt"]; !ok {
		t.Error("the end-of-life record must persist")
	}
}

// Upgrade from a state written before folded statuses were reported: a known
// package gaining a fix_deferred CVE is new_cves, the same ID already seen in
// another status is no change, and a package known only through fix_deferred
// is new.
func TestComputeEOL_UpgradeFirstCycleFoldedStatuses(t *testing.T) {
	prev := empty()
	prev.Findings["web:1\tcurl"] = Entry{FirstSeen: day1, VulnIDs: []string{"CVE-1"}}
	prev.Findings["web:1\tgit"] = Entry{FirstSeen: day1, VulnIDs: []string{"CVE-7"}}
	d, _ := Compute(prev, report(day2,
		scanOf("web:1",
			finding("web:1", "curl", "CVE-1", scanner.StatusAffected),
			finding("web:1", "curl", "CVE-2", scanner.StatusFixDeferred),
			finding("web:1", "git", "CVE-7", scanner.StatusAffected),
			finding("web:1", "git", "CVE-7", scanner.StatusFixDeferred),
			finding("web:1", "less", "CVE-9", scanner.StatusFixDeferred),
		),
	))
	wantKinds(t, "changes", changeKinds(d), "web:1 curl new_cves", "web:1 less new")
}

// State written before end-of-life packages existed: the first cycle records
// and announces every end-of-life package once, and a state with none is
// saved without the new key.
func TestComputeEOL_OldStateFirstCycle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	legacy := `{"version":1,"findings":{"web:1\topenssl":{"first_seen":"2026-06-24T09:00:00Z","fixable":true,"vuln_ids":["CVE-1"]}},"eosl":{}}`
	if err := os.WriteFile(path, []byte(legacy), 0o644); err != nil {
		t.Fatal(err)
	}
	store := FileStore{Path: path}
	prev, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if prev.EOLPackages == nil {
		t.Fatal("Load must initialize EOLPackages")
	}

	withEOL := report(day2, scanOf("web:1",
		finding("web:1", "openssl", "CVE-1", scanner.StatusFixed),
		eolFinding("web:1", "qt", "CVE-5"),
	))
	d, next := Compute(prev, withEOL)
	wantKinds(t, "changes", changeKinds(d))
	wantKinds(t, "eol", eolKinds(d), "web:1 qt eol_new")
	if err := store.Save(next); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), `"eol_packages"`) {
		t.Errorf("saved state must carry eol_packages:\n%s", data)
	}

	_, next = Compute(prev, report(day2, scanOf("web:1", finding("web:1", "openssl", "CVE-1", scanner.StatusFixed))))
	if err := store.Save(next); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(path)
	if strings.Contains(string(data), "eol_packages") {
		t.Errorf("a state without end-of-life packages must not gain the key:\n%s", data)
	}
}

func TestHasFindingsFor_SeesEOLRecords(t *testing.T) {
	st := empty()
	st.EOLPackages["web:1\tqt"] = EOLEntry{FirstSeen: day1, VulnIDs: []string{"CVE-1"}}
	if !st.HasFindingsFor("web:1") {
		t.Error("an end-of-life record must count as a finding on record")
	}
	if st.HasFindingsFor("api:1") {
		t.Error("unrelated reference must not match")
	}
	st = empty()
	st.EOSL["web:1"] = day1
	if st.HasFindingsFor("web:1") {
		t.Error("a base-OS record alone must not count")
	}
}

// Aging: 13 days is not stale, 14 is; the end-of-life record's own first
// seen is used even when the package's ordinary entry is older.
func TestComputeEOL_AgingBoundaries(t *testing.T) {
	for _, days := range []int{13, 14} {
		now := day1.AddDate(0, 0, days)
		prev := empty()
		prev.EOLPackages["web:1\tqt"] = EOLEntry{FirstSeen: day1, Priority: "low", VulnIDs: []string{"CVE-1"}}
		d, _ := Compute(prev, triaged(now, nil, scanOf("web:1", eolFinding("web:1", "qt", "CVE-1"))))
		if got := d.OldestUrgentDays(now); got != days {
			t.Errorf("%d days: OldestUrgentDays = %d", days, got)
		}
		if got := d.OldestOpenDays(now); got != days {
			t.Errorf("%d days: OldestOpenDays = %d", days, got)
		}
	}

	// The ordinary entry is 100 days old but low; the package became
	// end-of-life 3 days ago.
	now := day1.AddDate(0, 0, 100)
	prev := empty()
	prev.Findings["web:1\tqt"] = Entry{FirstSeen: day1, Priority: "low", VulnIDs: []string{"CVE-1"}}
	prev.EOLPackages["web:1\tqt"] = EOLEntry{FirstSeen: now.AddDate(0, 0, -3), Priority: "low", VulnIDs: []string{"CVE-2"}}
	d, _ := Compute(prev, triaged(now, nil, scanOf("web:1",
		finding("web:1", "qt", "CVE-1", scanner.StatusAffected),
		eolFinding("web:1", "qt", "CVE-2"),
	)))
	if got := d.OldestUrgentDays(now); got != 3 {
		t.Errorf("OldestUrgentDays = %d, want 3 (the end-of-life record's age)", got)
	}
	if got := d.OldestOpenDays(now); got != 100 {
		t.Errorf("OldestOpenDays = %d, want 100 (the ordinary entry)", got)
	}
}

// Records folded into a base-OS line age through the base-OS record, except
// act_now ones, which are shown on their own.
func TestComputeEOL_FoldedAging(t *testing.T) {
	now := dayN(30)
	prev := empty()
	prev.EOSL["legacy:1"] = dayN(20)
	prev.EOLPackages["legacy:1\tqt"] = EOLEntry{FirstSeen: dayN(1), Priority: "low", VulnIDs: []string{"CVE-1"}}
	prev.EOLPackages["legacy:1\tzlib"] = EOLEntry{FirstSeen: dayN(5), Priority: "act_now", VulnIDs: []string{"CVE-2"}}
	r := triaged(now, map[string]analyze.Enrichment{"CVE-2": {KEV: true}}, scanner.ImageScan{Image: "legacy:1", OSEOSL: true, Findings: []scanner.Finding{
		eolFinding("legacy:1", "qt", "CVE-1"),
		eolFinding("legacy:1", "zlib", "CVE-2"),
	}})
	d, _ := Compute(prev, r)
	if got := d.OldestUrgentDays(now); got != 25 {
		t.Errorf("OldestUrgentDays = %d, want 25 (the act_now record; the folded low one does not count)", got)
	}
	if d.OpenEOLPackages != 0 || !reflect.DeepEqual(d.OpenEOSL, []string{"legacy:1"}) {
		t.Errorf("OpenEOLPackages = %d, OpenEOSL = %v, want 0 and [legacy:1]", d.OpenEOLPackages, d.OpenEOSL)
	}
	if d.OpenActNow != 1 {
		t.Errorf("OpenActNow = %d, want 1 (folded act_now still counts)", d.OpenActNow)
	}
}

// Each key is counted once across the priority buckets: act_now on either
// side wins, otherwise the ordinary side's priority; an end-of-life-only
// watch/low counts only in the end-of-life segment.
func TestComputeEOL_PriorityBucketsCountEachKeyOnce(t *testing.T) {
	enrich := map[string]analyze.Enrichment{
		"CVE-KEV":   {KEV: true},
		"CVE-WATCH": {EPSS: 0.05, EPSSKnown: true},
	}
	r := triaged(day1, enrich, scanOf("web:1",
		// normal watch + EOL act_now
		finding("web:1", "a", "CVE-WATCH", scanner.StatusAffected),
		eolFinding("web:1", "a", "CVE-KEV"),
		// normal low + EOL act_now
		finding("web:1", "b", "CVE-LOW1", scanner.StatusAffected),
		eolFinding("web:1", "b", "CVE-KEV"),
		// normal low + EOL watch
		finding("web:1", "c", "CVE-LOW2", scanner.StatusAffected),
		eolFinding("web:1", "c", "CVE-WATCH"),
		// EOL-only watch and low
		eolFinding("web:1", "d", "CVE-WATCH"),
		eolFinding("web:1", "e", "CVE-LOW3"),
	))
	d, _ := Compute(empty(), r)
	if d.OpenActNow != 2 || d.OpenWatch != 0 || d.OpenLow != 1 {
		t.Errorf("act_now/watch/low = %d/%d/%d, want 2/0/1", d.OpenActNow, d.OpenWatch, d.OpenLow)
	}
	if d.OpenEOLPackages != 5 {
		t.Errorf("OpenEOLPackages = %d, want 5", d.OpenEOLPackages)
	}
}

// A full scan failure holds both maps and the base-OS record, announces no
// resolution, and AnyOpen reports the held records.
func TestComputeEOL_FullFailureHoldsEverything(t *testing.T) {
	_, st := Compute(empty(), report(day1, scanner.ImageScan{Image: "web:1", OSEOSL: true, Findings: []scanner.Finding{
		eolFinding("web:1", "qt", "CVE-1"),
	}}))
	d, next := Compute(st, report(day2, scanner.ImageScan{Image: "web:1", Err: errString("pull failed")}))
	if d.HasChanges() {
		t.Errorf("a failed scan must not report changes: %+v", d)
	}
	if _, ok := next.EOLPackages["web:1\tqt"]; !ok {
		t.Error("EOL record must be held")
	}
	if !d.AnyOpen || !reflect.DeepEqual(d.OpenEOSL, []string{"web:1"}) {
		t.Errorf("AnyOpen = %v OpenEOSL = %v, want true and the held base OS", d.AnyOpen, d.OpenEOSL)
	}
	if d.OldestOpen.IsZero() {
		t.Error("held records must still age")
	}
}

// A failed reference is held; a clean reference is not: nothing resolves for
// the failed one, and AnyOpen stays true.
func TestComputeEOL_FailedRefPlusCleanRef(t *testing.T) {
	_, st := Compute(empty(), report(day1, scanOf("web:1", finding("web:1", "openssl", "CVE-1", scanner.StatusFixed))))
	d, next := Compute(st, report(day2,
		scanner.ImageScan{Image: "web:1", Err: errString("pull failed")},
		scanOf("api:1"),
	))
	if len(d.Resolved) != 0 || !d.AnyOpen || len(next.Findings) != 1 {
		t.Errorf("Resolved %+v AnyOpen %v findings %+v, want held", d.Resolved, d.AnyOpen, next.Findings)
	}
	d, _ = Compute(next, report(dayN(3), scanOf("web:1"), scanOf("api:1")))
	if d.AnyOpen {
		t.Error("AnyOpen must be false once nothing is held")
	}
}

// Failure holding wins over the move-to-end-of-life rule, over three cycles,
// for both a sibling scan failure and an unconfirmed scan.
func TestComputeEOL_PartialFailureHoldingWinsOverMove(t *testing.T) {
	type cycleScans func(finds ...scanner.Finding) []scanner.ImageScan
	variants := map[string]struct {
		c1, c2 cycleScans
	}{
		"sibling failure": {
			c1: func(finds ...scanner.Finding) []scanner.ImageScan {
				return []scanner.ImageScan{resolvedScan("web:1", contentA, finds...), resolvedScan("web:1", contentB)}
			},
			c2: func(finds ...scanner.Finding) []scanner.ImageScan {
				return []scanner.ImageScan{failedResolvedScan("web:1", contentA, errString("pull failed")), resolvedScan("web:1", contentB, finds...)}
			},
		},
		"unconfirmed": {
			c1: func(finds ...scanner.Finding) []scanner.ImageScan {
				return []scanner.ImageScan{remotePinnedScan("web:1", contentA, finds...)}
			},
			c2: func(finds ...scanner.Finding) []scanner.ImageScan {
				return []scanner.ImageScan{remoteUnconfirmedScan("web:1", finds...)}
			},
		},
	}
	for name, v := range variants {
		t.Run(name, func(t *testing.T) {
			normal := finding("web:1", "qt", "CVE-A", scanner.StatusFixed)
			eol := eolFinding("web:1", "qt", "CVE-B")

			// Cycle 1: entity A has an ordinary fixable CVE.
			_, st1 := Compute(empty(), report(dayN(1), v.c1(normal)...))

			// Cycle 2: A cannot be confirmed; what is visible shows qt as
			// end-of-life. Hold the ordinary entry, record and announce the
			// end-of-life one, resolve nothing.
			d2, st2 := Compute(st1, report(dayN(2), v.c2(eol)...))
			if len(d2.Resolved) != 0 || len(d2.ResolvedEOLPackages) != 0 {
				t.Errorf("c2 resolved = %+v / %+v", d2.Resolved, d2.ResolvedEOLPackages)
			}
			wantKinds(t, "c2 eol", eolKinds(d2), "web:1 qt eol_new")
			if e, ok := st2.Findings["web:1\tqt"]; !ok || !reflect.DeepEqual(e.VulnIDs, []string{"CVE-A"}) {
				t.Errorf("c2 ordinary entry = %+v (ok %v), want held", e, ok)
			}
			if _, ok := st2.EOLPackages["web:1\tqt"]; !ok {
				t.Error("c2 EOL record missing")
			}

			// Cycle 3a: both re-confirmed, A's CVE still there → quiet.
			d3a, st3a := Compute(st2, report(dayN(3), v.c1(normal, eol)...))
			if d3a.HasChanges() {
				t.Errorf("c3a changes = %+v / %+v", d3a.Changes, d3a.NewEOLPackages)
			}
			if _, ok := st3a.Findings["web:1\tqt"]; !ok {
				t.Error("c3a ordinary entry must continue")
			}

			// Cycle 3b: re-confirmed, A's CVE gone → dropped by the move rule,
			// no Resolved (qt is end-of-life).
			d3b, st3b := Compute(st2, report(dayN(3), v.c1(eol)...))
			if len(d3b.Resolved) != 0 || len(d3b.Changes) != 0 {
				t.Errorf("c3b resolved/changes = %+v / %+v", d3b.Resolved, d3b.Changes)
			}
			if _, ok := st3b.Findings["web:1\tqt"]; ok {
				t.Error("c3b ordinary entry must be dropped")
			}
			if _, ok := st3b.EOLPackages["web:1\tqt"]; !ok {
				t.Error("c3b EOL record must continue")
			}
		})
	}
}

// Unconfirmed holding of an end-of-life record, then re-confirmation that it
// is gone (resolved) or still there (first seen carried over), with the
// base-OS set and the end-of-life count agreeing throughout.
func TestComputeEOL_UnconfirmedHoldThenReconfirm(t *testing.T) {
	c1 := remotePinnedScan("web:1", contentA, eolFinding("web:1", "qt", "CVE-1"))
	c1.OSEOSL = true
	api := remotePinnedScan("api:1", contentB, eolFinding("api:1", "libx", "CVE-2"))
	_, st1 := Compute(empty(), report(dayN(1), c1, api))

	d2, st2 := Compute(st1, report(dayN(2), remoteUnconfirmedScan("web:1"), api))
	if d2.HasChanges() {
		t.Errorf("c2 must be quiet: %+v", d2)
	}
	if !reflect.DeepEqual(d2.OpenEOSL, []string{"web:1"}) || d2.OpenEOLPackages != 1 {
		t.Errorf("c2 OpenEOSL %v OpenEOLPackages %d, want [web:1] and 1 (web:1's record folded, held)", d2.OpenEOSL, d2.OpenEOLPackages)
	}
	if _, ok := st2.EOLPackages["web:1\tqt"]; !ok {
		t.Fatal("c2 must hold the EOL record")
	}

	gone := remotePinnedScan("web:1", contentA)
	d3, _ := Compute(st2, report(dayN(3), gone, api))
	if !reflect.DeepEqual(d3.ResolvedEOLPackages, []ResolvedEOL{{Image: "web:1", Package: "qt"}}) {
		t.Errorf("c3 ResolvedEOLPackages = %+v", d3.ResolvedEOLPackages)
	}

	_, st3 := Compute(st2, report(dayN(3), c1, api))
	if got := st3.EOLPackages["web:1\tqt"].FirstSeen; !got.Equal(dayN(1)) {
		t.Errorf("c3 FirstSeen = %v, want carried over %v", got, dayN(1))
	}
}

// Partial failure with an end-of-life record still visible from the
// succeeding entity merges IDs and keeps the higher priority.
func TestComputeEOL_PartialFailureMergesEOL(t *testing.T) {
	kev := map[string]analyze.Enrichment{"CVE-1": {KEV: true}}
	_, st := Compute(empty(), triaged(day1, kev,
		resolvedScan("web:1", contentA, eolFinding("web:1", "qt", "CVE-1")),
		resolvedScan("web:1", contentB, eolFinding("web:1", "qt", "CVE-2")),
	))
	d, next := Compute(st, triaged(day2, kev,
		failedResolvedScan("web:1", contentA, errString("pull failed")),
		resolvedScan("web:1", contentB, eolFinding("web:1", "qt", "CVE-2")),
	))
	if d.HasChanges() {
		t.Errorf("changes = %+v", d)
	}
	e := next.EOLPackages["web:1\tqt"]
	if !reflect.DeepEqual(e.VulnIDs, []string{"CVE-1", "CVE-2"}) || e.Priority != "act_now" || !e.FirstSeen.Equal(day1) {
		t.Errorf("merged record = %+v", e)
	}
}

// Ordinary and end-of-life findings of one package clearing together
// produce both a Resolved and a ResolvedEOL.
func TestComputeEOL_SimultaneousResolution(t *testing.T) {
	_, st := Compute(empty(), report(day1, scanOf("web:1",
		finding("web:1", "qt", "CVE-A", scanner.StatusFixed),
		eolFinding("web:1", "qt", "CVE-B"),
	)))
	d, _ := Compute(st, report(day2, scanOf("web:1")))
	if !reflect.DeepEqual(d.Resolved, []Resolved{{Image: "web:1", Package: "qt"}}) ||
		!reflect.DeepEqual(d.ResolvedEOLPackages, []ResolvedEOL{{Image: "web:1", Package: "qt"}}) {
		t.Errorf("Resolved = %+v, ResolvedEOLPackages = %+v", d.Resolved, d.ResolvedEOLPackages)
	}
}

// Degraded intel and a missing baseline suppress eol_escalated, as for
// ordinary escalations.
func TestComputeEOL_EscalationSuppressed(t *testing.T) {
	scan := scanOf("web:1", scanner.Finding{Image: "web:1", Class: scanner.ClassOS, Package: "qt", InstalledVer: "1", Status: scanner.StatusEndOfLife, Severity: scanner.SeverityCritical, VulnID: "CVE-1"})
	_, st := Compute(empty(), triaged(day1, nil, scan)) // CRITICAL, no signal → watch
	deg := analyze.Build([]scanner.ImageScan{scan}, nil, analyze.Triage{Enabled: true, ActNowEPSS: 0.10, WatchEPSS: 0.01}, day2)
	if d, _ := Compute(st, deg); d.HasChanges() {
		t.Errorf("degraded intel must not escalate: %+v", d.NewEOLPackages)
	}
	_, pre := Compute(empty(), report(day1, scan)) // triage off: no stored priority
	if d, _ := Compute(pre, triaged(day2, map[string]analyze.Enrichment{"CVE-1": {KEV: true}}, scan)); d.HasChanges() {
		t.Errorf("an empty baseline must not escalate: %+v", d.NewEOLPackages)
	}
}
