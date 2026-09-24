package runner

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/notify"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
	"github.com/kitsunetrail/kestrelynx/internal/state"
)

// An unconfirmed reference whose only history is an end-of-life package
// record is holding something, so the quiet cycle must still notify.
func TestRunOnce_DiffMode_HoldingUnconfirmedEOLOnlyForcesNotification(t *testing.T) {
	notif := &fakeNotifier{}
	seen := clock().AddDate(0, 0, -3)
	store := &fakeStore{st: state.State{
		Version:     1,
		Findings:    map[string]state.Entry{},
		EOSL:        map[string]time.Time{},
		EOLPackages: map[string]state.EOLEntry{"web:1\tqt": {FirstSeen: seen, VulnIDs: []string{"CVE-1"}}},
	}}
	r := Runner{
		Lister: fakeLister{containers: refs("web:1")},
		Scanner: &fakeScanner{byImage: map[string]scanner.ImageScan{
			"web:1": {Image: "web:1", Pinned: false, Source: scanner.SourceRemote},
		}},
		Notifier:      notif,
		Store:         store,
		FullReportDay: NoFullReport,
		Now:           clock,
	}
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if !notif.called || !notif.msg.Holding {
		t.Fatalf("called = %v, Holding = %v: a held end-of-life record must force a holding notification", notif.called, notif.msg.Holding)
	}
	out := notify.FormatSlackDiffText(notif.msg.Report, *notif.msg.Diff, notif.msg.FullReport, notif.msg.Holding)
	if strings.Contains(out, "all clear") || !strings.Contains(out, "holding previous findings") {
		t.Errorf("expected the holding line:\n%s", out)
	}
	if store.saved == nil {
		t.Fatal("state not saved")
	}
	if e, ok := store.saved.EOLPackages["web:1\tqt"]; !ok || !e.FirstSeen.Equal(seen) {
		t.Errorf("held EOL record = %+v (ok %v), want carried over", e, ok)
	}
}

// The message carries the end-of-life first-seen lookup of the next state,
// for the thread's age lines.
func TestRunOnce_DiffMode_PassesEOLFirstSeen(t *testing.T) {
	notif := &fakeNotifier{}
	store := &fakeStore{}
	r := Runner{
		Lister: fakeLister{containers: refs("web:1")},
		Scanner: &fakeScanner{byImage: map[string]scanner.ImageScan{
			"web:1": {Image: "web:1", Findings: []scanner.Finding{
				{Image: "web:1", Class: scanner.ClassOS, Package: "qt", InstalledVer: "5.15", Status: scanner.StatusEndOfLife, Severity: scanner.SeverityHigh, VulnID: "CVE-1"},
			}},
		}},
		Notifier:      notif,
		Store:         store,
		FullReportDay: NoFullReport,
		Now:           clock,
	}
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if notif.msg.EOLFirstSeen == nil {
		t.Fatal("Message.EOLFirstSeen must be set")
	}
	if got, ok := notif.msg.EOLFirstSeen("web:1", "qt"); !ok || !got.Equal(clock()) {
		t.Errorf("EOLFirstSeen = %v, %v; want %v", got, ok, clock())
	}
	if _, ok := notif.msg.FirstSeen("web:1", "qt"); ok {
		t.Error("an end-of-life-only package has no ordinary first-seen record")
	}
}
