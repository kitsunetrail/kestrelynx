// End-of-life rendering: base-OS end-of-life images and packages whose CVEs
// the vendor reports as out of support for the installed release. Both lead
// every view. A package of an image whose base OS is end-of-life is folded
// into that image's base-OS line (replacing the base image replaces the
// package too), except in Act now, which always shows act_now work.
package notify

import (
	"sort"

	"github.com/kitsunetrail/kestrelynx/internal/analyze"
	"github.com/kitsunetrail/kestrelynx/internal/state"
)

// eolFold is the one-line summary of the end-of-life changes of an image
// whose base OS is already end-of-life.
type eolFold struct {
	ref         string
	newPackages int // eol_new
	withNewCVEs int // eol_new_cves
}

// eolChangeView is how the diff lays out d.NewEOLPackages.
type eolChangeView struct {
	rows  []state.EOLChange // shown individually
	folds []eolFold         // one line per folded image, sorted by ref
	// newEOSLNote counts, per image whose base OS became end-of-life this
	// cycle, the non-act_now packages newly end-of-life, which the new
	// base-OS line mentions instead.
	newEOSLNote map[string]int
}

// count is the number the diff section heading shows: individual rows plus
// the changes summarized on fold lines (not those noted on a new base-OS
// line).
func (v eolChangeView) count() int {
	n := len(v.rows)
	for _, f := range v.folds {
		n += f.newPackages + f.withNewCVEs
	}
	return n
}

// splitEOLChanges decides, from state, which end-of-life changes the diff
// shows individually. The base-OS set is d.OpenEOSL (held records
// included), so the fold agrees with the heartbeat's base-OS count. An
// act_now change is always its own row; so is every change of an image
// whose base OS is supported.
func splitEOLChanges(d state.Diff) eolChangeView {
	folded := map[string]bool{}
	for _, img := range d.OpenEOSL {
		folded[img] = true
	}
	newEOSL := map[string]bool{}
	for _, img := range d.NewEOSL {
		newEOSL[img] = true
	}
	v := eolChangeView{newEOSLNote: map[string]int{}}
	byRef := map[string]*eolFold{}
	for _, c := range d.NewEOLPackages {
		if !folded[c.Image] || analyze.MaxPriority(c.Groups) == analyze.PriorityActNow {
			v.rows = append(v.rows, c)
			continue
		}
		if newEOSL[c.Image] && c.Kind == state.EOLKindNew {
			v.newEOSLNote[c.Image]++
			continue
		}
		f := byRef[c.Image]
		if f == nil {
			f = &eolFold{ref: c.Image}
			byRef[c.Image] = f
		}
		if c.Kind == state.EOLKindNew {
			f.newPackages++
		} else {
			f.withNewCVEs++
		}
	}
	for _, f := range byRef {
		v.folds = append(v.folds, *f)
	}
	sort.Slice(v.folds, func(i, j int) bool { return v.folds[i].ref < v.folds[j].ref })
	return v
}

// eolAsChange expresses an end-of-life change in the ordinary Change shape so
// the suffix and webhook-reason helpers shared with ordinary changes apply
// unchanged: eol_new_cves lists its new ids, eol_escalated reads
// "escalated to ACT NOW".
func eolAsChange(c state.EOLChange) state.Change {
	kind := state.KindNew
	switch c.Kind {
	case state.EOLKindNewCVEs:
		kind = state.KindNewCVEs
	case state.EOLKindEscalated:
		kind = state.KindEscalated
	}
	return state.Change{Image: c.Image, Package: c.Package, Kind: kind, NewCVEs: len(c.NewIDs), NewIDs: c.NewIDs, Groups: c.Groups}
}
