// Tests for the generalized failed/unconfirmed accounting that feeds
// ImageObservation.{ScanFailed,PartialFailure,Unconfirmed}: a scan that
// errored is "failed"; a scan that succeeded but couldn't be pinned against
// a registry is "unconfirmed" — the two are disjoint by construction (Err's
// presence decides which, if either), so ScanFailed and PartialFailure must
// never both be true for the same reference.
package analyze

import (
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

// failedScan is one entity whose Trivy scan itself errored.
func failedScan(ref string) scanner.ImageScan {
	return scanner.ImageScan{Image: ref, Err: errString("scan failed")}
}

// unconfirmedScan is one entity whose scan succeeded but was never pinned
// against what was requested, fetched from a registry (Source == remote) —
// the shape a Kubernetes adapter's fallback scan produces.
func unconfirmedScan(ref string) scanner.ImageScan {
	return scanner.ImageScan{Image: ref, Pinned: false, Source: scanner.SourceRemote}
}

// confirmedScan is one entity whose scan succeeded and was pinned.
func confirmedScan(ref string) scanner.ImageScan {
	return scanner.ImageScan{Image: ref, Pinned: true, Source: scanner.SourceRemote}
}

// remoteFailedScan is one entity whose remote scan errored. Err decides its
// classification: it is failed, never unconfirmed, even though it is also
// unpinned and Source == remote.
func remoteFailedScan(ref string) scanner.ImageScan {
	return scanner.ImageScan{Image: ref, Err: errString("scan failed"), Pinned: false, Source: scanner.SourceRemote}
}

// localUnpinnedScan is Docker's shape for a reference-fallback scan: it
// never pins (no registry round-trip exists to confirm against), but
// Source == local, so it must never count as Unconfirmed — that accounting
// exists specifically for a registry that could quietly be serving
// something else, not for Docker's own image store.
func localUnpinnedScan(ref string) scanner.ImageScan {
	return scanner.ImageScan{Image: ref, Pinned: false, Source: scanner.SourceLocal}
}

func TestBuildInventory_FailedUnconfirmedPredicates(t *testing.T) {
	cases := []struct {
		name                                                string
		scans                                               []scanner.ImageScan
		wantScanFailed, wantPartialFailure, wantUnconfirmed bool
	}{
		{
			name:  "all confirmed",
			scans: []scanner.ImageScan{confirmedScan("web:1"), confirmedScan("web:1")},
		},
		{
			name:               "all failed",
			scans:              []scanner.ImageScan{failedScan("web:1"), failedScan("web:1")},
			wantScanFailed:     true,
			wantPartialFailure: false,
		},
		{
			name:               "some failed, rest confirmed",
			scans:              []scanner.ImageScan{failedScan("web:1"), confirmedScan("web:1"), confirmedScan("web:1")},
			wantScanFailed:     false,
			wantPartialFailure: true,
		},
		{
			name:               "some unconfirmed, rest confirmed",
			scans:              []scanner.ImageScan{unconfirmedScan("web:1"), confirmedScan("web:1")},
			wantPartialFailure: true,
			wantUnconfirmed:    true,
		},
		{
			name:               "all unconfirmed (no confirmed sibling)",
			scans:              []scanner.ImageScan{unconfirmedScan("web:1"), unconfirmedScan("web:1")},
			wantPartialFailure: true,
			wantUnconfirmed:    true,
		},
		{
			name:               "failed and unconfirmed together",
			scans:              []scanner.ImageScan{failedScan("web:1"), unconfirmedScan("web:1"), confirmedScan("web:1")},
			wantPartialFailure: true,
			wantUnconfirmed:    true,
		},
		{
			// failed == total: this must stay ScanFailed, not PartialFailure,
			// even though every failed entity is also (trivially) not
			// contributing a pinned result — failed and unconfirmed are
			// classified by Err's presence first, disjointly.
			name:           "failed == total with no unconfirmed entities",
			scans:          []scanner.ImageScan{failedScan("web:1"), failedScan("web:1"), failedScan("web:1")},
			wantScanFailed: true,
		},
		{
			// Docker's own shape: unpinned but Source == local must never
			// register as Unconfirmed, and with no Err anywhere this
			// reference is simply clean.
			name:  "local unpinned scan is confirmed, not unconfirmed",
			scans: []scanner.ImageScan{localUnpinnedScan("web:1"), confirmedScan("web:1")},
		},
		{
			// A remote scan that errored is failed only: it must not be
			// double-counted as unconfirmed just because it is also unpinned
			// with Source == remote. All entities failing keeps this
			// ScanFailed, with Unconfirmed false.
			name:           "all remote-failed counts as failed only",
			scans:          []scanner.ImageScan{remoteFailedScan("web:1"), remoteFailedScan("web:1")},
			wantScanFailed: true,
		},
		{
			// Same disjointness with a confirmed sibling: the remote failure
			// makes the reference a partial failure, not an unconfirmed one.
			name:               "remote failed plus confirmed is partial failure, not unconfirmed",
			scans:              []scanner.ImageScan{remoteFailedScan("web:1"), confirmedScan("web:1")},
			wantPartialFailure: true,
		},
		{
			// Failed and unconfirmed together with no confirmed entity:
			// failed < total keeps ScanFailed false, and the unconfirmed
			// entity keeps the reference in the partial-failure path.
			name:               "remote failed plus unconfirmed with no confirmed sibling",
			scans:              []scanner.ImageScan{remoteFailedScan("web:1"), unconfirmedScan("web:1")},
			wantPartialFailure: true,
			wantUnconfirmed:    true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := Build(c.scans, nil, Triage{}, fixedTime)
			o := imgObs(t, r.Images, "web:1")
			if o.ScanFailed != c.wantScanFailed {
				t.Errorf("ScanFailed = %v, want %v", o.ScanFailed, c.wantScanFailed)
			}
			if o.PartialFailure != c.wantPartialFailure {
				t.Errorf("PartialFailure = %v, want %v", o.PartialFailure, c.wantPartialFailure)
			}
			if o.Unconfirmed != c.wantUnconfirmed {
				t.Errorf("Unconfirmed = %v, want %v", o.Unconfirmed, c.wantUnconfirmed)
			}
			if o.ScanFailed && o.PartialFailure {
				t.Error("ScanFailed and PartialFailure must never both be true")
			}
		})
	}
}

// TestBuildInventory_UnconfirmedRefsProjection checks Report.UnconfirmedRefs:
// sorted, one entry per reference with at least one Unconfirmed entity, and
// nil when nothing is unconfirmed (the Docker case).
func TestBuildInventory_UnconfirmedRefsProjection(t *testing.T) {
	r := Build([]scanner.ImageScan{
		unconfirmedScan("zeta:1"),
		confirmedScan("alpha:1"),
		unconfirmedScan("alpha:1"),
	}, nil, Triage{}, fixedTime)

	if got := r.UnconfirmedRefs; len(got) != 2 || got[0] != "alpha:1" || got[1] != "zeta:1" {
		t.Errorf("UnconfirmedRefs = %v, want sorted [alpha:1 zeta:1]", got)
	}

	clean := Build([]scanner.ImageScan{confirmedScan("web:1")}, nil, Triage{}, fixedTime)
	if clean.UnconfirmedRefs != nil {
		t.Errorf("UnconfirmedRefs = %v, want nil when nothing is unconfirmed", clean.UnconfirmedRefs)
	}

	// total == 0 boundary: no scans at all produces no observations and no
	// unconfirmed refs — the predicates never fire on an empty cycle.
	empty := Build(nil, nil, Triage{}, fixedTime)
	if len(empty.Images) != 0 {
		t.Errorf("Images = %v, want empty for an empty scan set", empty.Images)
	}
	if empty.UnconfirmedRefs != nil {
		t.Errorf("UnconfirmedRefs = %v, want nil for an empty scan set", empty.UnconfirmedRefs)
	}
}
