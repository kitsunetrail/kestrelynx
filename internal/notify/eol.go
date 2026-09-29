// End-of-life rendering: base-OS end-of-life images and packages whose CVEs
// the vendor reports as out of support for the installed release. Both lead
// every view. A package of an image whose base OS is end-of-life is folded
// into that image's base-OS line (replacing the base image replaces the
// package too), except in Act now, which always shows act_now work.
package notify

import (
	"fmt"
	"sort"
	"strings"

	"github.com/kitsunetrail/kestrelynx/internal/analyze"
	"github.com/kitsunetrail/kestrelynx/internal/state"
)

// foldedEOLNote annotates a base-OS end-of-life line with the number of
// end-of-life packages it stands for.
func foldedEOLNote(n int, msg messages) string {
	if n == 0 {
		return ""
	}
	return fmt.Sprintf(msg.FoldedEOLNote, n)
}

// eosLine is one base-OS end-of-life line of a report-derived view.
func eosLine(r analyze.Report, img string, byRef map[string]analyze.ImageObservation, msg messages) string {
	return fmt.Sprintf(msg.EOSLLine, refLabel(img, byRef, msg), foldedEOLNote(r.FoldedEOLCount(img), msg))
}

// writeEOSLSection renders the base-OS end-of-life section of the full view.
func writeEOSLSection(b *strings.Builder, r analyze.Report, byRef map[string]analyze.ImageObservation, msg messages) {
	if len(r.EOSLImages) == 0 {
		return
	}
	b.WriteString(msg.EOSLHeading)
	for _, img := range r.EOSLImages {
		b.WriteString(eosLine(r, img, byRef, msg))
	}
}

// writeEOLPackages renders the end-of-life package section of the full view:
// every end-of-life group not folded into a base-OS line, whatever its
// priority. With triage on, an act_now group only points at Act now, which
// shows it in full; the others carry their short evidence like Watch rows.
// With triage off it is laid out like the status sections.
func writeEOLPackages(b *strings.Builder, r analyze.Report, byRef map[string]analyze.ImageObservation, msg messages) {
	imgs := r.EOLPackageAlerts()
	n := analyze.GroupCount(imgs)
	if n == 0 {
		return
	}
	fmt.Fprintf(b, msg.EOLPackageHeading, n, msg.EOLSectionReason)
	for _, img := range imgs {
		if r.Triage {
			fmt.Fprintf(b, msg.ImageBullet, imageLabel(img, byRef, msg))
		} else {
			fmt.Fprintf(b, msg.ImageCritHighLine, imageEmoji(img), imageLabel(img, byRef, msg), img.CriticalCount(), img.TotalCount()-img.CriticalCount())
		}
		for _, g := range img.Packages {
			writePackage(b, g, false, eolRowSuffix(r, g, msg), msg)
		}
	}
}

// eolRowSuffix is the suffix of an end-of-life package row in the full view.
func eolRowSuffix(r analyze.Report, g analyze.PackageGroup, msg messages) string {
	if !r.Triage {
		return ""
	}
	if g.Priority == analyze.PriorityActNow {
		return msg.EOLSeeActNow
	}
	if ev := shortEvidence(r, g.TopVuln(), msg); ev != "" {
		return " — " + ev
	}
	return ""
}

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

// writeEOLChanges renders the diff's end-of-life package changes. Rows are
// laid out like the 🆕 section of the same mode; an act_now row carries its
// evidence line (there is no Act now section in the diff to point at).
func writeEOLChanges(b *strings.Builder, r analyze.Report, v eolChangeView, byRef map[string]analyze.ImageObservation, msg messages) {
	n := v.count()
	if n == 0 {
		return
	}
	fmt.Fprintf(b, msg.EOLPackagesChangedHeading, n, msg.EOLSectionReason)
	rows := v.rows
	if r.Triage {
		rows = append([]state.EOLChange(nil), v.rows...)
		sort.SliceStable(rows, func(i, j int) bool {
			pi, pj := analyze.MaxPriority(rows[i].Groups), analyze.MaxPriority(rows[j].Groups)
			if pi.Rank() != pj.Rank() {
				return pi.Rank() > pj.Rank()
			}
			if rows[i].Image != rows[j].Image {
				return rows[i].Image < rows[j].Image
			}
			return rows[i].Package < rows[j].Package
		})
	}
	lastImage := ""
	for _, c := range rows {
		if c.Image != lastImage {
			marker := groupsEmoji(c.Groups)
			if r.Triage {
				marker = priorityEmoji(analyze.MaxPriority(c.Groups))
			}
			fmt.Fprintf(b, "%s %s\n", marker, refLabel(c.Image, byRef, msg))
			lastImage = c.Image
		}
		asChange := eolAsChange(c)
		for _, g := range c.Groups {
			writePackage(b, g, false, changeSuffix(r, asChange, g, msg), msg)
			if g.Priority == analyze.PriorityActNow {
				writeEvidence(b, r, g, msg)
			}
		}
	}
	for _, f := range v.folds {
		var parts []string
		if f.newPackages > 0 {
			parts = append(parts, fmt.Sprintf(msg.EOLFoldNewPackages, f.newPackages))
		}
		if f.withNewCVEs > 0 {
			parts = append(parts, fmt.Sprintf(msg.EOLFoldWithNewCVEs, f.withNewCVEs))
		}
		fmt.Fprintf(b, msg.EOLFoldLine, refLabel(f.ref, byRef, msg), strings.Join(parts, ", "))
	}
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
