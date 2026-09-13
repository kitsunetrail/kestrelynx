package main

import (
	"fmt"
	"sort"
	"time"
)

// scopeSet turns a case's declared gt_b_scope list into a lookup set.
// Anything not in it stays undetermined regardless of what the log shows.
func scopeSet(names []string) map[string]bool {
	out := make(map[string]bool, len(names))
	for _, n := range names {
		out[n] = true
	}
	return out
}

// gtbTruth is what a ground-truth record establishes about the packages in
// a case's declared scope: which are proven used within the window, which
// are proven unused, and why any of the rest could not be decided.
type gtbTruth struct {
	Used              map[string]bool
	Covered           map[string]bool
	UndeterminedWhy   map[string]string
	IncompletenessLog []string
}

func newGTBTruth() gtbTruth {
	return gtbTruth{Used: map[string]bool{}, Covered: map[string]bool{}, UndeterminedWhy: map[string]string{}}
}

// usageInterval is one reconstructed (pid, starttime, path) interval: the
// span between a start event (exec/dlopen) and its matching end event
// (exit/dlclose), clamped to the observation window at either end when the
// interval extends past it.
type usageInterval struct {
	start   time.Time
	end     time.Time
	endOpen bool // no end event was recorded; the interval runs to window end
}

type intervalKey struct {
	pid       int
	starttime int64
	path      string
}

// buildGTBTruth derives per-package used/not-used/undetermined from a
// GroundTruthB record, restricted to the case's declared scope and to the
// observation window [windowStart, windowEnd).
//
// Three rules decide it, and they are deliberately asymmetric — proving use
// takes one positive, proving non-use takes a complete log:
//
//  1. An ok=true "open" inside the window proves use on its own. A
//     dependency library the dynamic loader resolved is exactly this case:
//     it has no interval of its own and must never be demoted for that.
//  2. An "open" outside the window still proves use when it can be tied to
//     a start event of the same process generation whose interval reaches
//     into the window — the library was loaded before the window opened and
//     was still loaded inside it. An open that cannot be tied to any such
//     interval proves nothing either way.
//  3. "Not used in the window" is concluded only when all three of the
//     design's conditions hold: no start interval for the package
//     intersects the window, no in-window open names one of its files, and
//     the case's logging method actually covers the package. The third is
//     what gt_b_scope declares — but a log that contradicts its own
//     completeness (an open with no parent generation, an end event with no
//     start, a path the independent ownership resolution does not map)
//     withdraws that guarantee, and the package goes back to undetermined
//     rather than silently becoming a true negative.
func buildGTBTruth(gtb *GroundTruthB, scope map[string]bool, windowStart, windowEnd time.Time) gtbTruth {
	out := newGTBTruth()
	if gtb == nil {
		for pkg := range scope {
			out.UndeterminedWhy[pkg] = "no ground-truth record was supplied"
		}
		return out
	}

	switch gtb.Kind {
	case "limited":
		// A post-window resident-process spot check can only ever confirm
		// use, never absence (a process that used something earlier in the
		// window may already be gone by the time the check runs).
		for _, rp := range gtb.ResidentPackages {
			if !rp.Used || !scope[rp.Package] {
				continue
			}
			out.Covered[rp.Package] = true
			out.Used[rp.Package] = true
		}
		for pkg := range scope {
			if !out.Covered[pkg] {
				out.UndeterminedWhy[pkg] = "a post-window resident-process check cannot establish non-use"
			}
		}

	case "usage_log":
		buildFromUsageLog(gtb, scope, windowStart, windowEnd, &out)
	}

	sort.Strings(out.IncompletenessLog)
	return out
}

func buildFromUsageLog(gtb *GroundTruthB, scope map[string]bool, windowStart, windowEnd time.Time, out *gtbTruth) {
	pathPkg := map[string]string{}
	for _, pp := range gtb.PathPackages {
		pathPkg[pp.Path] = pp.Package
	}

	// Intervals, keyed by (pid, starttime, path) — one process generation's
	// own run of one executable or one dlopen of one library.
	starts := map[intervalKey][]time.Time{}
	ends := map[intervalKey][]time.Time{}
	// Every start event of a process generation, regardless of path: an
	// "open" belongs to whichever of its own generation's intervals was
	// running at the time.
	genStarts := map[genEventKey][]intervalKey{}

	unmapped := map[string]bool{}
	for _, ev := range gtb.UsageLog {
		switch ev.Event {
		case "exec", "dlopen", "open", "dlclose", "exit":
		default:
			continue // "meta"/"stage" bookkeeping lines are not usage events
		}
		if _, known := pathPkg[ev.Path]; !known && ev.Path != "" {
			unmapped[ev.Path] = true
		}
		if !ev.OK {
			continue // a failed exec/open/dlopen is never usage
		}
		k := intervalKey{ev.PID, ev.Starttime, ev.Path}
		switch ev.Event {
		case "exec", "dlopen":
			starts[k] = append(starts[k], ev.Timestamp)
			gk := genEventKey{ev.PID, ev.Starttime}
			genStarts[gk] = append(genStarts[gk], k)
		case "exit", "dlclose":
			ends[k] = append(ends[k], ev.Timestamp)
		}
	}

	for path := range unmapped {
		out.IncompletenessLog = append(out.IncompletenessLog,
			fmt.Sprintf("usage log names %q, which the independent ownership resolution does not map to a package", path))
	}

	intervals := map[intervalKey][]usageInterval{}
	incompletePaths := map[string]string{}
	for k, ss := range starts {
		sort.Slice(ss, func(i, j int) bool { return ss[i].Before(ss[j]) })
		es := append([]time.Time(nil), ends[k]...)
		sort.Slice(es, func(i, j int) bool { return es[i].Before(es[j]) })
		for i, s := range ss {
			iv := usageInterval{start: s, end: windowEnd, endOpen: true}
			if i < len(es) {
				iv.end, iv.endOpen = es[i], false
			}
			intervals[k] = append(intervals[k], iv)
		}
		if len(es) > len(ss) {
			incompletePaths[k.path] = fmt.Sprintf("more end events than start events for pid %d (%q): the log is missing a start", k.pid, k.path)
		}
	}
	for k := range ends {
		if len(starts[k]) == 0 {
			incompletePaths[k.path] = fmt.Sprintf("an end event for pid %d (%q) has no matching start event", k.pid, k.path)
		}
	}

	usedPositive := map[string]bool{}
	markUsed := func(path string) {
		if pkg, ok := pathPkg[path]; ok {
			usedPositive[pkg] = true
		}
	}

	// Rule 1 and 2: opens.
	for _, ev := range gtb.UsageLog {
		if ev.Event != "open" || !ev.OK {
			continue
		}
		if inWindow(ev.Timestamp, windowStart, windowEnd) {
			markUsed(ev.Path)
			continue
		}
		// Outside the window: only a parent interval of the same process
		// generation that reaches into the window can carry it in.
		//
		// The library's own dlopen/dlclose interval is consulted first and,
		// when one exists, it is the only answer. A dlclose before the
		// window says the library was unloaded then, and falling back to
		// the enclosing exec interval — which runs on for as long as the
		// process does — would turn that explicit unload into "still loaded
		// throughout the window". The exec interval is the last resort, for
		// a library the loader resolved at startup and nothing ever
		// unloaded.
		attached, decided := false, false
		for _, iv := range intervals[intervalKey{ev.PID, ev.Starttime, ev.Path}] {
			if ev.Timestamp.Before(iv.start) || ev.Timestamp.After(iv.end) {
				continue
			}
			decided = true
			if intersectsWindow(ev.Timestamp, iv.end, windowStart, windowEnd) {
				markUsed(ev.Path)
				attached = true
				break
			}
		}
		if !decided {
			for _, k := range genStarts[genEventKey{ev.PID, ev.Starttime}] {
				if k.path == ev.Path {
					continue // already considered above
				}
				for _, iv := range intervals[k] {
					if !ev.Timestamp.Before(iv.start) && !ev.Timestamp.After(iv.end) && intersectsWindow(ev.Timestamp, iv.end, windowStart, windowEnd) {
						markUsed(ev.Path)
						attached = true
						break
					}
				}
				if attached {
					break
				}
			}
		}
		if !attached && !decided {
			if _, known := pathPkg[ev.Path]; known {
				incompletePaths[ev.Path] = fmt.Sprintf("an out-of-window open of %q belongs to no recorded interval of pid %d, so it can neither prove nor rule out in-window use", ev.Path, ev.PID)
			}
		}
	}

	// Intervals intersecting the window.
	for k, ivs := range intervals {
		for _, iv := range ivs {
			if intersectsWindow(iv.start, iv.end, windowStart, windowEnd) {
				markUsed(k.path)
			}
		}
	}

	incompletePkgs := map[string]string{}
	for path, why := range incompletePaths {
		if pkg, ok := pathPkg[path]; ok {
			incompletePkgs[pkg] = why
		}
	}
	// A path the ownership resolution does not map could belong to any
	// package, so it withdraws the completeness guarantee from all of them.
	globallyIncomplete := ""
	if len(unmapped) > 0 {
		globallyIncomplete = "the usage log names paths the independent ownership resolution does not map to a package, so no package's non-use can be certified"
	}

	for pkg := range scope {
		switch {
		case usedPositive[pkg]:
			out.Covered[pkg] = true
			out.Used[pkg] = true
		case globallyIncomplete != "":
			out.UndeterminedWhy[pkg] = globallyIncomplete
		case incompletePkgs[pkg] != "":
			out.UndeterminedWhy[pkg] = incompletePkgs[pkg]
			out.IncompletenessLog = append(out.IncompletenessLog, pkg+": "+incompletePkgs[pkg])
		default:
			out.Covered[pkg] = true
			out.Used[pkg] = false
		}
	}
	if globallyIncomplete != "" {
		out.IncompletenessLog = append(out.IncompletenessLog, globallyIncomplete)
	}
}

// genEventKey is one process generation in a usage log.
type genEventKey struct {
	pid       int
	starttime int64
}

func inWindow(t, start, end time.Time) bool {
	return !t.Before(start) && t.Before(end)
}

// intersectsWindow reports whether the half-open interval [start, end)
// overlaps [windowStart, windowEnd). An interval that began before the
// window is treated as starting at the window's start, and one with no
// recorded end has already been given windowEnd as its end.
func intersectsWindow(start, end, windowStart, windowEnd time.Time) bool {
	if start.Before(windowStart) {
		start = windowStart
	}
	return start.Before(windowEnd) && end.After(windowStart) && !start.After(end)
}
