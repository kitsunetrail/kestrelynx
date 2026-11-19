package runner

import (
	"context"
	"errors"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

// refreshingScanner is a fakeScanner that can refresh its database, and
// records how many scans had run when it was asked to.
type refreshingScanner struct {
	fakeScanner
	err         error
	refreshes   int
	scansBefore int
}

func (f *refreshingScanner) RefreshDB(context.Context) (scanner.DBRefresh, error) {
	f.refreshes++
	f.scansBefore = len(f.calls)
	if f.err != nil {
		return scanner.DBRefresh{}, f.err
	}
	return scanner.DBRefresh{Fetched: true, UpdatedAt: clock()}, nil
}

func TestRunOnce_RefreshesTheDatabaseBeforeScanning(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"fetched", nil},
		// A failed refresh is not the end of the cycle: the scans run on the
		// database in the cache.
		{"failed", errors.New("registry unreachable")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sc := &refreshingScanner{err: tc.err}
			notif := &fakeNotifier{}
			r := Runner{
				Lister:        fakeLister{containers: refs("a:1", "b:1")},
				Scanner:       sc,
				Notifier:      notif,
				NotifyOnClean: true,
				Now:           clock,
			}
			for cycle := 1; cycle <= 2; cycle++ {
				if err := r.RunOnce(context.Background()); err != nil {
					t.Fatalf("RunOnce: %v", err)
				}
				if sc.refreshes != cycle {
					t.Fatalf("cycle %d: %d refreshes, want one per cycle", cycle, sc.refreshes)
				}
				if want := (cycle - 1) * 2; sc.scansBefore != want {
					t.Fatalf("cycle %d: the refresh came after %d scans, want %d", cycle, sc.scansBefore, want)
				}
				if len(sc.calls) != cycle*2 {
					t.Fatalf("cycle %d: %d scans, want %d", cycle, len(sc.calls), cycle*2)
				}
			}
		})
	}
}

// A scanner that cannot refresh (the fakes of the other tests) is scanned
// with as before.
func TestRunOnce_ScannerWithoutRefresh(t *testing.T) {
	sc := &fakeScanner{}
	r := Runner{Lister: fakeLister{containers: refs("a:1")}, Scanner: sc, Notifier: &fakeNotifier{}, Now: clock}
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if len(sc.calls) != 1 {
		t.Fatalf("%d scans, want 1", len(sc.calls))
	}
}
