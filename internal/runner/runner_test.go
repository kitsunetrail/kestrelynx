package runner

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/kitsunetrail/stackwatch/internal/analyze"
	"github.com/kitsunetrail/stackwatch/internal/config"
	"github.com/kitsunetrail/stackwatch/internal/intel"
	"github.com/kitsunetrail/stackwatch/internal/notify"
	"github.com/kitsunetrail/stackwatch/internal/scanner"
	"github.com/kitsunetrail/stackwatch/internal/state"
)

type fakeLister struct {
	images []string
	err    error
}

func (f fakeLister) RunningImages(context.Context) ([]string, error) { return f.images, f.err }

type fakeScanner struct {
	byImage map[string]scanner.ImageScan
}

func (f fakeScanner) Scan(_ context.Context, image string) scanner.ImageScan {
	if s, ok := f.byImage[image]; ok {
		return s
	}
	return scanner.ImageScan{Image: image}
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
		Lister: fakeLister{images: []string{"vuln:1"}},
		Scanner: fakeScanner{byImage: map[string]scanner.ImageScan{
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
		Lister:   fakeLister{images: []string{"clean:1"}},
		Scanner:  fakeScanner{},
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
		Lister:        fakeLister{images: []string{"clean:1"}},
		Scanner:       fakeScanner{},
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
		Scanner:  fakeScanner{},
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
		Lister: fakeLister{images: []string{"broken:1"}},
		Scanner: fakeScanner{byImage: map[string]scanner.ImageScan{
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

// --- diff mode ---

func vulnScan() fakeScanner {
	return fakeScanner{byImage: map[string]scanner.ImageScan{
		"vuln:1": {Image: "vuln:1", Findings: []scanner.Finding{
			{Image: "vuln:1", Class: scanner.ClassOS, Package: "libc", InstalledVer: "1", FixedVer: "2", Status: scanner.StatusFixed, Severity: scanner.SeverityCritical, VulnID: "CVE-1"},
		}},
	}}
}

func TestRunOnce_DiffMode_FirstRunReportsNewAndSaves(t *testing.T) {
	notif := &fakeNotifier{}
	store := &fakeStore{}
	r := Runner{
		Lister:        fakeLister{images: []string{"vuln:1"}},
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
		Lister:        fakeLister{images: []string{"vuln:1"}},
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
		Lister:        fakeLister{images: []string{"vuln:1"}},
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
		Lister:        fakeLister{images: []string{"clean:1"}},
		Scanner:       fakeScanner{},
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
		Lister:        fakeLister{images: []string{"vuln:1"}},
		Scanner:       fakeScanner{}, // scan now comes back clean
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
		Lister:        fakeLister{images: []string{"vuln:1"}},
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
		Lister:     fakeLister{images: []string{"vuln:1"}},
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
		Lister:     fakeLister{images: []string{"vuln:1"}},
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
		Lister:   fakeLister{images: []string{"vuln:1"}},
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
	scanTwo := fakeScanner{byImage: map[string]scanner.ImageScan{
		"vuln:1": {Image: "vuln:1", Findings: []scanner.Finding{
			{Image: "vuln:1", Class: scanner.ClassOS, Package: "libc", InstalledVer: "1", FixedVer: "2", Status: scanner.StatusFixed, Severity: scanner.SeverityCritical, VulnID: "CVE-1"},
			{Image: "vuln:1", Class: scanner.ClassOS, Package: "zlib", InstalledVer: "1", FixedVer: "2", Status: scanner.StatusFixed, Severity: scanner.SeverityHigh, VulnID: "CVE-2"},
		}},
	}}
	r := Runner{
		Lister:          fakeLister{images: []string{"vuln:1"}},
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
		Lister:          fakeLister{images: []string{"vuln:1"}},
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
		Lister:          fakeLister{images: []string{"vuln:1"}},
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
