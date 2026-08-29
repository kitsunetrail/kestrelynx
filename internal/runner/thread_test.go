package runner

import (
	"context"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/notify"
	"github.com/kitsunetrail/kestrelynx/internal/state"
)

// threadNotifier is a fakeNotifier that also reports a posted thread ref, the
// way SlackAPINotifier does after a successful thread post.
type threadNotifier struct {
	fakeNotifier
	ref state.ReportRef // reported via m.Result when non-zero
}

func (f *threadNotifier) Send(ctx context.Context, m notify.Message) error {
	if err := f.fakeNotifier.Send(ctx, m); err != nil {
		return err
	}
	if f.ref.TS != "" && m.Result != nil {
		m.Result.Ref = f.ref
	}
	return nil
}

func diffRunner(notif Notifier, store StateStore) Runner {
	return Runner{
		Lister:        fakeLister{containers: refs("vuln:1")},
		Scanner:       vulnScan(),
		Notifier:      notif,
		Store:         store,
		FullReportDay: NoFullReport,
		Now:           clock,
	}
}

func TestRunOnce_DiffMode_ThreadRequestedAndRefSaved(t *testing.T) {
	ref := state.ReportRef{Channel: "C1", TS: "1000.1", Permalink: "https://x.slack.com/archives/C1/p10001"}
	notif := &threadNotifier{ref: ref}
	store := &fakeStore{}
	if err := diffRunner(notif, store).RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	m := notif.msg
	if !m.Thread {
		t.Error("changes present: message must request the thread report")
	}
	if m.LastReport != nil {
		t.Errorf("first run must carry no last-report ref, got %+v", m.LastReport)
	}
	if m.FirstSeen == nil {
		t.Fatal("message must carry a FirstSeen lookup")
	}
	if seen, ok := m.FirstSeen("vuln:1", "libc"); !ok || !seen.Equal(clock()) {
		t.Errorf("FirstSeen(vuln:1, libc) = %v, %v; want %v, true", seen, ok, clock())
	}
	if store.saved == nil || store.saved.LastFullReport == nil {
		t.Fatal("posted thread ref not saved")
	}
	if *store.saved.LastFullReport != ref {
		t.Errorf("saved ref = %+v, want %+v", *store.saved.LastFullReport, ref)
	}
}

func TestRunOnce_DiffMode_QuietDayCarriesRef(t *testing.T) {
	ref := state.ReportRef{Channel: "C1", TS: "1000.1", Permalink: "https://x.slack.com/archives/C1/p10001"}
	notif := &threadNotifier{ref: ref}
	store := &fakeStore{}
	r := diffRunner(notif, store)
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatalf("first RunOnce: %v", err)
	}

	// Second run: same findings, no changes. The notifier posts no thread
	// this time; the stored ref must survive and be offered as LastReport.
	store.st = *store.saved
	notif.ref = state.ReportRef{}
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatalf("second RunOnce: %v", err)
	}
	if notif.msg.Thread {
		t.Error("no changes: message must not request the thread report")
	}
	if !notif.msg.LastReport.ValidFor("C1") {
		t.Errorf("message must carry the stored ref, got %+v", notif.msg.LastReport)
	}
	if store.saved.LastFullReport == nil || *store.saved.LastFullReport != ref {
		t.Errorf("quiet day must carry the ref over, got %+v", store.saved.LastFullReport)
	}
}

func TestRunOnce_DiffMode_SkippedNotificationPreservesRef(t *testing.T) {
	ref := state.ReportRef{Channel: "C1", TS: "1000.1", Permalink: "https://x.slack.com/archives/C1/p10001"}
	notif := &fakeNotifier{}
	store := &fakeStore{st: state.State{Version: 1, LastFullReport: &ref}}
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
		t.Fatal("clean and unchanged should skip the notification")
	}
	if store.saved.LastFullReport == nil || *store.saved.LastFullReport != ref {
		t.Errorf("skipped cycle must preserve the ref, got %+v", store.saved.LastFullReport)
	}
}

func TestRunOnce_DiffMode_FullReportDayRequestsThread(t *testing.T) {
	notif := &threadNotifier{}
	store := &fakeStore{}
	r := diffRunner(notif, store)
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatalf("first RunOnce: %v", err)
	}
	store.st = *store.saved

	// clock() is a Wednesday; make it the weekly full-report day.
	r.FullReportDay = clock().Weekday()
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatalf("second RunOnce: %v", err)
	}
	if !notif.msg.Thread {
		t.Error("weekly full-report day must request the thread report even without changes")
	}
}
