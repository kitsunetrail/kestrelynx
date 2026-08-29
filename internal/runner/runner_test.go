package runner

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/analyze"
	"github.com/kitsunetrail/kestrelynx/internal/config"
	"github.com/kitsunetrail/kestrelynx/internal/intel"
	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/notify"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
	"github.com/kitsunetrail/kestrelynx/internal/state"
)

// refs builds bare container observations (unresolved, ContentID-less
// RunningImage, no name/workload) for tests that don't exercise identity
// resolution or container-level detail.
func refs(names ...string) []inventory.Container {
	out := make([]inventory.Container, len(names))
	for i, n := range names {
		out[i] = inventory.Container{Image: inventory.RunningImage{Ref: n}}
	}
	return out
}

type fakeLister struct {
	containers []inventory.Container
	err        error
}

func (f fakeLister) RunningContainers(context.Context) ([]inventory.Container, error) {
	return f.containers, f.err
}

// fakeScanner is a pointer receiver so calls can be recorded across
// invocations (the ContentID de-duplication tests assert on call count).
type fakeScanner struct {
	byImage map[string]scanner.ImageScan // keyed by ScanTarget.Ref
	calls   []scanner.ScanTarget
}

func (f *fakeScanner) Scan(_ context.Context, target scanner.ScanTarget) scanner.ImageScan {
	f.calls = append(f.calls, target)
	if s, ok := f.byImage[target.Ref]; ok {
		return s
	}
	return scanner.ImageScan{Image: target.Ref}
}

type fakeNotifier struct {
	called bool
	msg    notify.Message
	err    error
}

func (f *fakeNotifier) Send(_ context.Context, m notify.Message) error {
	f.called = true
	f.msg = m
	return f.err
}

type fakeStore struct {
	st        state.State
	saved     *state.State
	loadErr   error
	saveErr   error
	saveCalls int
}

func (f *fakeStore) Load() (state.State, error) { return f.st, f.loadErr }
func (f *fakeStore) Save(st state.State) error {
	f.saveCalls++
	f.saved = &st
	return f.saveErr
}

var clock = func() time.Time { return time.Date(2026, 6, 24, 9, 0, 0, 0, time.UTC) }

func TestRunOnce_NotifiesWhenIssuesFound(t *testing.T) {
	notif := &fakeNotifier{}
	r := Runner{
		Lister: fakeLister{containers: refs("vuln:1")},
		Scanner: &fakeScanner{byImage: map[string]scanner.ImageScan{
			"vuln:1": {Image: "vuln:1", Findings: []scanner.Finding{
				{Image: "vuln:1", Class: scanner.ClassOS, Package: "libc", InstalledVer: "1", FixedVer: "2", Status: scanner.StatusFixed, Severity: scanner.SeverityCritical, VulnID: "CVE-1"},
			}},
		}},
		Notifier: notif,
		Now:      clock,
	}
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if !notif.called {
		t.Fatal("notifier not called despite findings")
	}
	if notif.msg.Report.ImagesTotal != 1 {
		t.Errorf("ImagesTotal = %d, want 1", notif.msg.Report.ImagesTotal)
	}
	if notif.msg.Diff != nil {
		t.Error("full mode (no Store) should send a nil Diff")
	}
}

func TestRunOnce_SkipsNotificationWhenCleanByDefault(t *testing.T) {
	notif := &fakeNotifier{}
	r := Runner{
		Lister:   fakeLister{containers: refs("clean:1")},
		Scanner:  &fakeScanner{},
		Notifier: notif,
		Now:      clock,
	}
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if notif.called {
		t.Error("notifier called for clean report with NotifyOnClean=false")
	}
}

func TestRunOnce_NotifiesWhenCleanIfConfigured(t *testing.T) {
	notif := &fakeNotifier{}
	r := Runner{
		Lister:        fakeLister{containers: refs("clean:1")},
		Scanner:       &fakeScanner{},
		Notifier:      notif,
		NotifyOnClean: true,
		Now:           clock,
	}
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if !notif.called {
		t.Error("notifier not called for clean report with NotifyOnClean=true")
	}
}

func TestRunOnce_ListErrorAborts(t *testing.T) {
	notif := &fakeNotifier{}
	r := Runner{
		Lister:   fakeLister{err: errors.New("docker down")},
		Scanner:  &fakeScanner{},
		Notifier: notif,
		Now:      clock,
	}
	if err := r.RunOnce(context.Background()); err == nil {
		t.Fatal("expected error when listing fails")
	}
	if notif.called {
		t.Error("notifier should not be called when listing fails")
	}
}

func TestRunOnce_ScanErrorStillNotifies(t *testing.T) {
	notif := &fakeNotifier{}
	r := Runner{
		Lister: fakeLister{containers: refs("broken:1")},
		Scanner: &fakeScanner{byImage: map[string]scanner.ImageScan{
			"broken:1": {Image: "broken:1", Err: errors.New("pull failed")},
		}},
		Notifier: notif,
		Now:      clock,
	}
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if !notif.called {
		t.Fatal("scan failures should still trigger a notification")
	}
	if len(notif.msg.Report.ScanErrors) != 1 {
		t.Errorf("ScanErrors = %d, want 1", len(notif.msg.Report.ScanErrors))
	}
}

// --- ContentID de-duplication ---

func TestScanAll_ContentIDDedup_ScansOnceReplicatesToAllRefs(t *testing.T) {
	cid := "sha256:" + strings.Repeat("a", 64)
	sc := &fakeScanner{byImage: map[string]scanner.ImageScan{
		"app:v1": {
			Image:     "app:v1",
			ContentID: cid,
			Findings: []scanner.Finding{
				{Image: "app:v1", Class: scanner.ClassOS, Package: "libc", VulnID: "CVE-1", Severity: scanner.SeverityCritical, Status: scanner.StatusFixed},
			},
			RegistryDigests: []string{"app@sha256:" + strings.Repeat("d", 64)},
		},
	}}
	r := Runner{Scanner: sc, Now: clock}
	images := []inventory.RunningImage{
		{Ref: "app:v1", ContentID: cid},
		{Ref: "app:v2", ContentID: cid},
	}

	scans := r.scanAll(context.Background(), images)

	if len(sc.calls) != 1 {
		t.Fatalf("Scan called %d times, want 1 (same ContentID scanned once)", len(sc.calls))
	}
	if sc.calls[0].ContentID != cid {
		t.Errorf("scan target ContentID = %q, want %q", sc.calls[0].ContentID, cid)
	}
	if len(scans) != 2 {
		t.Fatalf("scans = %d, want 2 (one per alias ref)", len(scans))
	}

	byRef := map[string]scanner.ImageScan{}
	for _, s := range scans {
		byRef[s.Image] = s
	}
	v1, ok1 := byRef["app:v1"]
	v2, ok2 := byRef["app:v2"]
	if !ok1 || !ok2 {
		t.Fatalf("report should contain both aliases, got %+v", scans)
	}
	if len(v1.Findings) != 1 || v1.Findings[0].Image != "app:v1" {
		t.Errorf("v1 finding = %+v, want Image=app:v1", v1.Findings)
	}
	if len(v2.Findings) != 1 || v2.Findings[0].Image != "app:v2" {
		t.Errorf("v2 finding = %+v, want Image=app:v2", v2.Findings)
	}

	// Mutating one alias's findings slice must never affect the other: they
	// must not share a backing array (deep-copy safety).
	v1.Findings[0].Package = "mutated"
	if v2.Findings[0].Package == "mutated" {
		t.Fatal("findings slices are shared between aliases; must be deep-copied")
	}

	// Same for RegistryDigests: it's a shared, sorted attribute on the
	// cached scan result, so each alias must get its own backing array too.
	if len(v1.RegistryDigests) != 1 || len(v2.RegistryDigests) != 1 {
		t.Fatalf("RegistryDigests not carried to aliases: v1=%v v2=%v", v1.RegistryDigests, v2.RegistryDigests)
	}
	v1.RegistryDigests[0] = "mutated"
	if v2.RegistryDigests[0] == "mutated" {
		t.Fatal("RegistryDigests slices are shared between aliases; must be deep-copied")
	}
}

func TestScanAll_UnresolvedContentID_ScannedIndividually(t *testing.T) {
	sc := &fakeScanner{byImage: map[string]scanner.ImageScan{
		"a:1": {Image: "a:1"},
		"b:1": {Image: "b:1"},
	}}
	r := Runner{Scanner: sc, Now: clock}
	images := []inventory.RunningImage{{Ref: "a:1"}, {Ref: "b:1"}}

	scans := r.scanAll(context.Background(), images)

	if len(sc.calls) != 2 {
		t.Fatalf("Scan called %d times, want 2 (unresolved entries never join dedup)", len(sc.calls))
	}
	if len(scans) != 2 {
		t.Fatalf("scans = %d, want 2", len(scans))
	}
}

func TestRunOnce_ContentIDDedup_ReportCoversBothAliases(t *testing.T) {
	notif := &fakeNotifier{}
	cid := "sha256:" + strings.Repeat("a", 64)
	sc := &fakeScanner{byImage: map[string]scanner.ImageScan{
		"app:v1": {
			Image:     "app:v1",
			ContentID: cid,
			Findings: []scanner.Finding{
				{Image: "app:v1", Class: scanner.ClassOS, Package: "libc", InstalledVer: "1", FixedVer: "2", Status: scanner.StatusFixed, Severity: scanner.SeverityCritical, VulnID: "CVE-1"},
			},
		},
	}}
	r := Runner{
		Lister: fakeLister{containers: []inventory.Container{
			{Image: inventory.RunningImage{Ref: "app:v1", ContentID: cid}},
			{Image: inventory.RunningImage{Ref: "app:v2", ContentID: cid}},
		}},
		Scanner:  sc,
		Notifier: notif,
		Now:      clock,
	}
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if len(sc.calls) != 1 {
		t.Fatalf("Scan called %d times, want 1", len(sc.calls))
	}
	if notif.msg.Report.ImagesTotal != 2 {
		t.Errorf("ImagesTotal = %d, want 2 (both refs counted)", notif.msg.Report.ImagesTotal)
	}
	seen := map[string]bool{}
	for _, img := range notif.msg.Report.Actionable {
		seen[img.Image] = true
	}
	if !seen["app:v1"] || !seen["app:v2"] {
		t.Errorf("report should list both aliases, got %+v", notif.msg.Report.Actionable)
	}
}

// --- diff mode ---

func vulnScan() *fakeScanner {
	return &fakeScanner{byImage: map[string]scanner.ImageScan{
		"vuln:1": {Image: "vuln:1", Findings: []scanner.Finding{
			{Image: "vuln:1", Class: scanner.ClassOS, Package: "libc", InstalledVer: "1", FixedVer: "2", Status: scanner.StatusFixed, Severity: scanner.SeverityCritical, VulnID: "CVE-1"},
		}},
	}}
}

func TestRunOnce_DiffMode_FirstRunReportsNewAndSaves(t *testing.T) {
	notif := &fakeNotifier{}
	store := &fakeStore{}
	r := Runner{
		Lister:        fakeLister{containers: refs("vuln:1")},
		Scanner:       vulnScan(),
		Notifier:      notif,
		Store:         store,
		FullReportDay: NoFullReport,
		Now:           clock,
	}
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if notif.msg.Diff == nil {
		t.Fatal("diff mode should send a Diff")
	}
	if len(notif.msg.Diff.Changes) != 1 || notif.msg.Diff.Changes[0].Kind != state.KindNew {
		t.Errorf("Changes = %+v, want one KindNew", notif.msg.Diff.Changes)
	}
	if store.saved == nil {
		t.Fatal("state not saved after successful send")
	}
	if len(store.saved.Findings) != 1 {
		t.Errorf("saved findings = %d, want 1", len(store.saved.Findings))
	}
}

func TestRunOnce_DiffMode_UnchangedSendsHeartbeat(t *testing.T) {
	notif := &fakeNotifier{}
	store := &fakeStore{}
	r := Runner{
		Lister:        fakeLister{containers: refs("vuln:1")},
		Scanner:       vulnScan(),
		Notifier:      notif,
		Store:         store,
		FullReportDay: NoFullReport,
		Now:           clock,
	}
	// First run establishes state; feed it back for the second run.
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatalf("first RunOnce: %v", err)
	}
	store.st = *store.saved
	notif.called = false
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatalf("second RunOnce: %v", err)
	}
	if !notif.called {
		t.Fatal("unchanged open findings should still send a heartbeat")
	}
	if notif.msg.Diff.HasChanges() {
		t.Errorf("second run should have no changes, got %+v", notif.msg.Diff)
	}
}

func TestRunOnce_DiffMode_SendFailureSkipsSave(t *testing.T) {
	notif := &fakeNotifier{err: errors.New("slack down")}
	store := &fakeStore{}
	r := Runner{
		Lister:        fakeLister{containers: refs("vuln:1")},
		Scanner:       vulnScan(),
		Notifier:      notif,
		Store:         store,
		FullReportDay: NoFullReport,
		Now:           clock,
	}
	if err := r.RunOnce(context.Background()); err == nil {
		t.Fatal("expected send error")
	}
	if store.saveCalls != 0 {
		t.Error("state must not be saved when the send fails (changes would be lost)")
	}
}

func TestRunOnce_DiffMode_CleanAndUnchangedSkipsButSaves(t *testing.T) {
	notif := &fakeNotifier{}
	store := &fakeStore{}
	r := Runner{
		Lister:        fakeLister{containers: refs("clean:1")},
		Scanner:       &fakeScanner{},
		Notifier:      notif,
		Store:         store,
		FullReportDay: NoFullReport,
		Now:           clock,
	}
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if notif.called {
		t.Error("clean and unchanged should not notify by default")
	}
	if store.saveCalls != 1 {
		t.Error("state should still be saved on skipped notification")
	}
}

func TestRunOnce_DiffMode_ResolvedNotifiesEvenWhenClean(t *testing.T) {
	notif := &fakeNotifier{}
	store := &fakeStore{st: state.State{
		Version:  1,
		Findings: map[string]state.Entry{"vuln:1\tlibc": {FirstSeen: clock().AddDate(0, 0, -3), Fixable: true, VulnIDs: []string{"CVE-1"}}},
		EOSL:     map[string]time.Time{},
	}}
	r := Runner{
		Lister:        fakeLister{containers: refs("vuln:1")},
		Scanner:       &fakeScanner{}, // scan now comes back clean
		Notifier:      notif,
		Store:         store,
		FullReportDay: NoFullReport,
		Now:           clock,
	}
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if !notif.called {
		t.Fatal("a resolved finding is a change and should notify")
	}
	if len(notif.msg.Diff.Resolved) != 1 {
		t.Errorf("Resolved = %+v, want 1 entry", notif.msg.Diff.Resolved)
	}
}

func TestRunOnce_DiffMode_FullReportDay(t *testing.T) {
	notif := &fakeNotifier{}
	store := &fakeStore{}
	r := Runner{
		Lister:        fakeLister{containers: refs("vuln:1")},
		Scanner:       vulnScan(),
		Notifier:      notif,
		Store:         store,
		FullReportDay: clock().Weekday(),
		Now:           clock,
	}
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if !notif.msg.FullReport {
		t.Error("FullReport should be set on the configured weekday")
	}
}

// --- identity model: Replaced persistence across a failed send ---

// TestRunOnce_DiffMode_SendFailure_ReplacedPersistsToNextCycle guards the
// claim that a failed delivery cannot lose an image-replacement event: state
// is only saved after a successful send (sendDiff), so if cycle 2's send
// fails, state still reflects cycle 1's content. Cycle 3 (delivery succeeds)
// must therefore report the replacement again rather than silently dropping
// it because state had already "moved past" it.
//
// The lister and scanner must agree on which content is running each cycle
// (inventory.RunningImage.ContentID feeds scanner.ScanTarget.ContentID, which
// the real scanner.Trivy.Scan echoes back as ExpectedContentID,
// internal/scanner/exec.go:reconcileTarget) — a lister reporting no
// ContentID while the fake scanner claims a resolved identity is an
// unrealistic combination that no real pipeline would produce.
func TestRunOnce_DiffMode_SendFailure_ReplacedPersistsToNextCycle(t *testing.T) {
	cidA := "sha256:" + strings.Repeat("a", 64)
	cidB := "sha256:" + strings.Repeat("b", 64)

	imagesWith := func(cid string) []inventory.Container {
		return []inventory.Container{{Image: inventory.RunningImage{Ref: "app:1", ContentID: cid}}}
	}
	scanWith := func(cid string) *fakeScanner {
		return &fakeScanner{byImage: map[string]scanner.ImageScan{
			"app:1": {Image: "app:1", ExpectedContentID: cid, IdentityResolved: true},
		}}
	}
	wantReplaced := func(t *testing.T, got []state.ImageReplacement) {
		t.Helper()
		if len(got) != 1 {
			t.Fatalf("Replaced = %+v, want 1 entry", got)
		}
		rep := got[0]
		if rep.Ref != "app:1" || len(rep.PrevContentIDs) != 1 || rep.PrevContentIDs[0] != cidA || len(rep.ContentIDs) != 1 || rep.ContentIDs[0] != cidB {
			t.Errorf("Replaced entry = %+v, want Ref=app:1 PrevContentIDs=[%s] ContentIDs=[%s]", rep, cidA, cidB)
		}
	}

	store := &fakeStore{}
	r := Runner{
		Lister:        fakeLister{containers: imagesWith(cidA)},
		Scanner:       scanWith(cidA),
		Notifier:      &fakeNotifier{},
		Store:         store,
		FullReportDay: NoFullReport,
		Now:           clock,
	}
	// Cycle 1: establishes ContentID A as the running content.
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatalf("cycle 1: %v", err)
	}
	store.st = *store.saved

	// Cycle 2: content changes to B, but delivery fails — state must not
	// advance, so the replacement is not yet recorded as seen. The diff is
	// still computed before the (failed) send attempt, so its actual
	// Replaced content is verified here too, not just its presence later.
	failNotif := &fakeNotifier{err: errors.New("slack down")}
	r.Lister = fakeLister{containers: imagesWith(cidB)}
	r.Scanner = scanWith(cidB)
	r.Notifier = failNotif
	if err := r.RunOnce(context.Background()); err == nil {
		t.Fatal("cycle 2: expected send error")
	}
	if store.saveCalls != 1 {
		t.Fatalf("cycle 2: state must not be saved after a failed send, saveCalls = %d", store.saveCalls)
	}
	wantReplaced(t, failNotif.msg.Diff.Replaced)

	// Cycle 3: same content B again, delivery now succeeds. State still
	// reflects cycle 1's ContentID A (cycle 2's save was skipped), so the
	// replacement must be reported again rather than lost.
	notif3 := &fakeNotifier{}
	r.Notifier = notif3
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatalf("cycle 3: %v", err)
	}
	wantReplaced(t, notif3.msg.Diff.Replaced)
}

func TestNextDaily(t *testing.T) {
	now := time.Date(2026, 6, 24, 10, 0, 0, 0, time.UTC)
	// 09:00 already passed today → tomorrow 09:00
	got := nextDaily(now, 9, 0)
	want := time.Date(2026, 6, 25, 9, 0, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Errorf("nextDaily past = %v, want %v", got, want)
	}
	// 18:00 still ahead today → today 18:00
	got = nextDaily(now, 18, 0)
	want = time.Date(2026, 6, 24, 18, 0, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Errorf("nextDaily future = %v, want %v", got, want)
	}
}

func TestUntilNext_IntervalMode(t *testing.T) {
	// empty daily_at → 24h interval
	d := untilNext(config.ScheduleConfig{}, clock())
	if d != 24*time.Hour {
		t.Errorf("interval mode = %v, want 24h", d)
	}
}

// --- triage wiring ---

type fakeIntel struct {
	askedIDs      []string
	enrich        map[string]intel.Enrichment
	fresh         intel.Freshness
	err           error
	discussionIDs []string // ids passed to Discussions (nil = never called)
	discussions   map[string]intel.Discussion
}

func (f *fakeIntel) Lookup(_ context.Context, ids []string) (map[string]intel.Enrichment, intel.Freshness, error) {
	f.askedIDs = ids
	return f.enrich, f.fresh, f.err
}

func (f *fakeIntel) Discussions(_ context.Context, ids []string) map[string]intel.Discussion {
	f.discussionIDs = ids
	return f.discussions
}

func TestRunOnce_TriageWiring(t *testing.T) {
	notif := &fakeNotifier{}
	src := &fakeIntel{
		enrich: map[string]intel.Enrichment{"CVE-1": {KEV: true, EPSS: 0.9, EPSSKnown: true}},
		fresh:  intel.Freshness{KEVOK: true, EPSSOK: true},
	}
	r := Runner{
		Lister:     fakeLister{containers: refs("vuln:1")},
		Scanner:    vulnScan(),
		Notifier:   notif,
		Intel:      src,
		ActNowEPSS: 0.10,
		WatchEPSS:  0.01,
		Now:        clock,
	}
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if len(src.askedIDs) != 1 || src.askedIDs[0] != "CVE-1" {
		t.Errorf("intel asked for %v, want the scan's CVE IDs", src.askedIDs)
	}
	rep := notif.msg.Report
	if !rep.Triage {
		t.Fatal("report should be triaged when Intel is wired")
	}
	if got := analyze.GroupCount(rep.ByPriority().ActNow); got != 1 {
		t.Errorf("act_now groups = %d, want 1 (KEV finding)", got)
	}
}

func TestRunOnce_TriageIntelFailureStillNotifies(t *testing.T) {
	notif := &fakeNotifier{}
	src := &fakeIntel{err: errors.New("feeds down"), fresh: intel.Freshness{}}
	r := Runner{
		Lister:     fakeLister{containers: refs("vuln:1")},
		Scanner:    vulnScan(),
		Notifier:   notif,
		Intel:      src,
		ActNowEPSS: 0.10,
		WatchEPSS:  0.01,
		Now:        clock,
	}
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce must not fail on intel errors: %v", err)
	}
	if !notif.called {
		t.Fatal("notification must go out despite intel failure")
	}
	if !notif.msg.Report.Intel.Degraded() {
		t.Error("report should carry the degraded intel status")
	}
}

func TestRunOnce_NoIntelMeansNoTriage(t *testing.T) {
	notif := &fakeNotifier{}
	r := Runner{
		Lister:   fakeLister{containers: refs("vuln:1")},
		Scanner:  vulnScan(),
		Notifier: notif,
		Now:      clock,
	}
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if notif.msg.Report.Triage {
		t.Error("report must not be triaged when Intel is nil")
	}
}

func TestRunOnce_DiscussionLinksOnlyForActNowIDs(t *testing.T) {
	notif := &fakeNotifier{}
	src := &fakeIntel{
		enrich: map[string]intel.Enrichment{
			"CVE-1": {KEV: true},                    // act_now signal
			"CVE-2": {EPSS: 0.002, EPSSKnown: true}, // low: must not be queried
		},
		fresh: intel.Freshness{KEVOK: true, EPSSOK: true},
		discussions: map[string]intel.Discussion{
			"CVE-1": {Title: "t", URL: "https://news.ycombinator.com/item?id=1", Points: 166},
		},
	}
	scanTwo := &fakeScanner{byImage: map[string]scanner.ImageScan{
		"vuln:1": {Image: "vuln:1", Findings: []scanner.Finding{
			{Image: "vuln:1", Class: scanner.ClassOS, Package: "libc", InstalledVer: "1", FixedVer: "2", Status: scanner.StatusFixed, Severity: scanner.SeverityCritical, VulnID: "CVE-1"},
			{Image: "vuln:1", Class: scanner.ClassOS, Package: "zlib", InstalledVer: "1", FixedVer: "2", Status: scanner.StatusFixed, Severity: scanner.SeverityHigh, VulnID: "CVE-2"},
		}},
	}}
	r := Runner{
		Lister:          fakeLister{containers: refs("vuln:1")},
		Scanner:         scanTwo,
		Notifier:        notif,
		Intel:           src,
		ActNowEPSS:      0.10,
		WatchEPSS:       0.01,
		DiscussionLinks: true,
		Now:             clock,
	}
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if len(src.discussionIDs) != 1 || src.discussionIDs[0] != "CVE-1" {
		t.Errorf("Discussions queried with %v, want only the act-now CVE", src.discussionIDs)
	}
	// The link must reach the rendered report.
	pv := notif.msg.Report.ByPriority()
	top := pv.ActNow[0].Packages[0].TopVuln()
	if len(top.Refs) != 1 || top.Refs[0].Kind != "discussion" || top.Refs[0].URL != "https://news.ycombinator.com/item?id=1" {
		t.Errorf("act-now vuln refs = %+v, want the HN discussion", top.Refs)
	}
}

func TestRunOnce_DiscussionLinksOffQueriesNothing(t *testing.T) {
	notif := &fakeNotifier{}
	src := &fakeIntel{
		enrich: map[string]intel.Enrichment{"CVE-1": {KEV: true}},
		fresh:  intel.Freshness{KEVOK: true, EPSSOK: true},
	}
	r := Runner{
		Lister:          fakeLister{containers: refs("vuln:1")},
		Scanner:         vulnScan(),
		Notifier:        notif,
		Intel:           src,
		ActNowEPSS:      0.10,
		WatchEPSS:       0.01,
		DiscussionLinks: false,
		Now:             clock,
	}
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if src.discussionIDs != nil {
		t.Errorf("Discussions must not be called when disabled, got %v", src.discussionIDs)
	}
}

func TestRunOnce_DegradedIntelSkipsDiscussions(t *testing.T) {
	notif := &fakeNotifier{}
	src := &fakeIntel{err: errors.New("down"), fresh: intel.Freshness{}}
	r := Runner{
		Lister:          fakeLister{containers: refs("vuln:1")},
		Scanner:         vulnScan(),
		Notifier:        notif,
		Intel:           src,
		ActNowEPSS:      0.10,
		WatchEPSS:       0.01,
		DiscussionLinks: true,
		Now:             clock,
	}
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if src.discussionIDs != nil {
		t.Errorf("degraded intel must not trigger discussion queries, got %v", src.discussionIDs)
	}
}
