package notify

import (
	"path"
	"strings"

	"github.com/kitsunetrail/kestrelynx/internal/analyze"
	"github.com/kitsunetrail/kestrelynx/internal/remediation"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

// waitVerdict is what a card's action line says about a newer version of the
// image its findings come from.
type waitVerdict int

const (
	// waitPlain: the base has no newer tag in its series; nothing more is
	// known.
	waitPlain waitVerdict = iota
	// waitResolved: a checked tag of a newer series resolves every fixed
	// finding of the card.
	waitResolved
	// waitPartial: it resolves some of them and the others remain.
	waitPartial
	// waitRemains: they remain in every checked tag of a newer series.
	waitRemains
	// waitNoNewerSeries: the complete listing has no newer series either.
	waitNoNewerSeries
)

// baseWait says that a package finding lives in an image the fix plan found
// no fix for in the image tag's own series, and what it found in a newer
// series: either the base image a Dockerfile builds from or a pinned image
// that runs as it is.
type baseWait struct {
	Image bool   // the running image's own tag rather than a Dockerfile's base
	Name  string // the repository name without registry and path
	Tag   string
	// OwnNoNewer says the tag's own series has no newer tag; otherwise its
	// newer tag did not resolve the findings.
	OwnNoNewer bool
	Verdict    waitVerdict
	To         string // the tag of a newer series that resolves something
	Change     remediation.SeriesChange
	WithNew    bool // that tag introduces findings
	// Resolved and Total count the card's fixed findings it resolves.
	Resolved, Total int
	// Checked are the tags of newer series checked that resolve none of
	// them, joined by "\x00".
	Checked string
}

// baseWaitKey identifies one finding target of one running entity.
type baseWaitKey struct {
	image  string // the running image's reference
	entity string // the running entity's key as the plan records it
	vuln   string
	coord  remediation.PackageCoord
}

// waitSource is what the plan says about the image one target comes from,
// the same for all its targets.
type waitSource struct {
	image      bool
	name, tag  string
	ownNoNewer bool
	// legacy allows the plain line, the one a Dockerfile item without a
	// newer series result shows.
	legacy  bool
	status  remediation.NewerSeriesStatus // "" without a newer series result
	to      string
	change  remediation.SeriesChange
	withNew bool
	checked string
}

// baseWaitEntry is what the plan says about one key: its source, the
// target's outcome in the tag shown, and, for a Dockerfile's base, the base
// layers the target was reported in.
type baseWaitEntry struct {
	src     waitSource
	outcome remediation.Outcome
	layers  map[string]bool
}

// baseWaitIndex finds, for a package group of a scanned image, the action
// line this cycle's plan gives it. The nil index matches nothing.
type baseWaitIndex struct {
	bases  map[baseWaitKey][]*baseWaitEntry // Dockerfile base images
	images map[baseWaitKey][]*baseWaitEntry // pinned running images
}

func (x *baseWaitIndex) add(m map[baseWaitKey][]*baseWaitEntry, k baseWaitKey, e *baseWaitEntry) {
	for _, have := range m[k] {
		if have.src == e.src && have.outcome == e.outcome {
			for l := range e.layers {
				have.layers[l] = true
			}
			return
		}
	}
	m[k] = append(m[k], e)
}

// newerSource is the source of a check of newer series, or false when it
// gives no line: an unfinished check, or no newer series after the own
// series had a newer tag that did not help. outcome gives a target's
// outcome in the tag shown.
func newerSource(ns *remediation.NewerSeries, own remediation.Reason, cands []remediation.NewerSeriesCandidate) (src waitSource, outcome func(remediation.Target) remediation.Outcome, ok bool) {
	src = waitSource{ownNoNewer: own == remediation.ReasonNoNewerTag, status: ns.Status}
	remains := func(remediation.Target) remediation.Outcome { return remediation.OutcomeRemaining }
	switch {
	case ns.Status == remediation.NewerSeriesNone:
		return src, remains, src.ownNoNewer
	case ns.Shown == "":
		return src, nil, false
	}
	var shown *remediation.NewerSeriesCandidate
	for i := range cands {
		if cands[i].Tag == ns.Shown {
			shown = &cands[i]
		}
	}
	if shown == nil || shown.Comparison == nil {
		return src, nil, false
	}
	src.to, src.change = shown.Tag, shown.Change
	// Whether the tag shown introduces findings is the item's to say: a
	// running image of a Dockerfile item may introduce none where another
	// does.
	for _, c := range ns.Candidates {
		if c.Tag == ns.Shown {
			src.withNew = c.Status == remediation.NewerSeriesResolvesWithNew
		}
	}
	vs := shown.Comparison.Verdicts
	return src, func(t remediation.Target) remediation.Outcome {
		for _, v := range vs {
			if v.VulnID == t.VulnID && v.Package == t.Package {
				return v.Outcome
			}
		}
		return ""
	}, true
}

// newBaseWaitIndex indexes the targets the plan has a line for: those of the
// running images of Dockerfile items whose base's series gave no fix, and
// those of pinned running images whose own series gave none, by running
// entity. A Dockerfile item without a newer series result keeps the plain
// line when it and the entity are no_candidate with reason no_newer_tag. It
// returns nil when there is no plan or nothing to index.
func newBaseWaitIndex(info *PlanInfo) *baseWaitIndex {
	if info == nil || info.Plan == nil {
		return nil
	}
	x := &baseWaitIndex{bases: map[baseWaitKey][]*baseWaitEntry{}, images: map[baseWaitKey][]*baseWaitEntry{}}
	confirmed := func(s remediation.ImageState) bool {
		return s.Ref != "" && s.Entity != "" && s.Entity != remediation.Unconfirmed
	}
	for _, it := range info.Plan.DockerfileItems {
		legacy := it.Category == remediation.CategoryNoCandidate && it.Reason == remediation.ReasonNoNewerTag
		for _, e := range it.Entities {
			if e.Category != remediation.CategoryNoCandidate || e.CurrentBase == nil || !confirmed(e.Running) {
				continue
			}
			name, tag := baseNameTag(*e.CurrentBase)
			if name == "" || tag == "" {
				continue
			}
			src := waitSource{name: name, tag: tag, ownNoNewer: e.Reason == remediation.ReasonNoNewerTag}
			src.legacy = legacy && src.ownNoNewer
			outcome := func(remediation.Target) remediation.Outcome { return "" }
			perTarget := func(t remediation.Target) waitSource { return src }
			switch {
			case it.NewerSeries == nil || e.NewerSeries == nil:
			case shownNone(it.NewerSeries):
				// The item shows no tag: none resolves a target in every
				// running image, or one could not be judged. A target still
				// remains in the tags this image's own comparisons show it
				// remaining in; one they do not, or that none compared, keeps
				// the line it had.
				legacySrc := src
				remains := waitSource{name: name, tag: tag, ownNoNewer: src.ownNoNewer, legacy: src.legacy, status: remediation.NewerSeriesNotResolving}
				perTarget = func(t remediation.Target) waitSource {
					tags, ok := remainingTags(e.NewerSeries.Candidates, t)
					if !ok {
						return legacySrc
					}
					s := remains
					s.checked = tags
					return s
				}
				outcome = func(t remediation.Target) remediation.Outcome {
					if _, ok := remainingTags(e.NewerSeries.Candidates, t); ok {
						return remediation.OutcomeRemaining
					}
					return ""
				}
			default:
				if ns, out, ok := newerSource(it.NewerSeries, e.Reason, e.NewerSeries.Candidates); ok {
					ns.name, ns.tag, ns.legacy = name, tag, src.legacy
					src, outcome = ns, out
				}
			}
			for _, t := range e.Targets {
				src := perTarget(t)
				if src.status == "" && !src.legacy {
					continue
				}
				ent := &baseWaitEntry{src: src, outcome: outcome(t), layers: map[string]bool{}}
				for _, l := range t.Layers {
					ent.layers[l] = true
				}
				x.add(x.bases, baseWaitKey{image: e.Running.Ref, entity: e.Running.Entity, vuln: t.VulnID, coord: t.Package}, ent)
			}
		}
	}
	for _, it := range info.Plan.Items {
		if it.NewerSeries == nil || !confirmed(it.Current) {
			continue
		}
		name, tag := baseNameTag(it.Current)
		if name == "" || tag == "" {
			continue
		}
		key := func(t remediation.Target) baseWaitKey {
			return baseWaitKey{image: it.Current.Ref, entity: it.Current.Entity, vuln: t.VulnID, coord: t.Package}
		}
		if shownNone(it.NewerSeries) {
			// As for a Dockerfile's base: a target remains in the tags whose
			// comparisons show it remaining; any other gets no line.
			for _, t := range it.Targets {
				tags, ok := remainingTags(it.NewerSeries.Candidates, t)
				if !ok {
					continue
				}
				src := waitSource{image: true, name: name, tag: tag, ownNoNewer: it.Reason == remediation.ReasonNoNewerTag, status: remediation.NewerSeriesNotResolving, checked: tags}
				x.add(x.images, key(t), &baseWaitEntry{src: src, outcome: remediation.OutcomeRemaining})
			}
			continue
		}
		src, outcome, ok := newerSource(it.NewerSeries, it.Reason, it.NewerSeries.Candidates)
		if !ok {
			continue
		}
		src.image, src.name, src.tag = true, name, tag
		for _, t := range it.Targets {
			x.add(x.images, key(t), &baseWaitEntry{src: src, outcome: outcome(t)})
		}
	}
	if len(x.bases) == 0 && len(x.images) == 0 {
		return nil
	}
	return x
}

// shownNone reports whether a check shows no tag on its own: none resolves a
// target, or one could not be judged.
func shownNone(ns *remediation.NewerSeries) bool {
	return ns.Status == remediation.NewerSeriesNotResolving || ns.Status == remediation.NewerSeriesNotChecked
}

// remainingTags joins the tags of the candidates whose comparison was made,
// every one of which shows target t remaining; ok is false when one does
// not, or none was compared. A candidate the check could not judge as a
// whole still counts by its comparison: a target it shows remaining is known
// to remain there, whatever another target's outcome.
func remainingTags(cands []remediation.NewerSeriesCandidate, t remediation.Target) (tags string, ok bool) {
	var out []string
	for _, c := range cands {
		if c.Comparison == nil || !c.Comparison.Comparable {
			continue
		}
		found := false
		for _, v := range c.Comparison.Verdicts {
			if v.VulnID == t.VulnID && v.Package == t.Package {
				found = v.Outcome == remediation.OutcomeRemaining
			}
		}
		if !found {
			return "", false
		}
		out = append(out, c.Tag)
	}
	return strings.Join(out, "\x00"), len(out) > 0
}

// baseNameTag is the short name and the tag of an image state: the last
// path element of its repository, so a registry host never shows.
func baseNameTag(s remediation.ImageState) (name, tag string) {
	ref := remediation.ParseImageRef(s.Ref)
	tag = s.Tag
	if tag == "" {
		tag = ref.Tag
	}
	if ref.Repository == "" {
		return "", ""
	}
	return path.Base(strings.TrimSuffix(ref.Repository, "/")), tag
}

// lookup returns the action line of group g of the scanned entity img. A
// line from a Dockerfile's base and one from the image's own tag that differ
// give none. It matches only when all of these hold, so that in doubt the
// card stays as it is:
//   - the entity is confirmed and is the one the plan judged (same reference
//     and entity key);
//   - the group has at least one fixed finding, and every fixed finding of it
//     is a target of exactly one source of the kind, the same for all;
//   - for a Dockerfile's base, every layer the group's findings were
//     attributed to is a base layer those targets were reported in, so a copy
//     of the package in a later layer, or one with no layer attribution,
//     never qualifies.
func (x *baseWaitIndex) lookup(img analyze.ImageFindings, g analyze.PackageGroup) (baseWait, bool) {
	if x == nil || img.Image == "" || !img.Subject.Resolved {
		return baseWait{}, false
	}
	entity := remediation.EntityKeyString(img.Subject.Key)
	if entity == remediation.Unconfirmed {
		return baseWait{}, false
	}
	base, okBase := x.match(x.bases, img, entity, g, true)
	own, okOwn := x.match(x.images, img, entity, g, false)
	switch {
	case okBase && okOwn:
		if base != own {
			return baseWait{}, false
		}
		return base, true
	case okBase:
		return base, true
	}
	return own, okOwn
}

func (x *baseWaitIndex) match(m map[baseWaitKey][]*baseWaitEntry, img analyze.ImageFindings, entity string, g analyze.PackageGroup, layered bool) (baseWait, bool) {
	if layered && len(g.LayerDiffIDs) == 0 {
		return baseWait{}, false
	}
	coord := remediation.PackageCoord{Ecosystem: g.Ecosystem, Class: g.Class, Name: g.Package}
	var src waitSource
	layers := map[string]bool{}
	var outcomes []remediation.Outcome
	mixed, allLegacy := false, true
	for _, v := range g.Vulns {
		if v.Status != scanner.StatusFixed {
			continue
		}
		es := m[baseWaitKey{image: img.Image, entity: entity, vuln: v.ID, coord: coord}]
		if len(es) != 1 {
			return baseWait{}, false
		}
		mixed = mixed || (len(outcomes) > 0 && es[0].src != src)
		allLegacy = allLegacy && es[0].src.legacy
		src = es[0].src
		for l := range es[0].layers {
			layers[l] = true
		}
		outcomes = append(outcomes, es[0].outcome)
	}
	if len(outcomes) == 0 {
		return baseWait{}, false
	}
	if mixed {
		// The card's findings are not all known the same way: only the
		// plain line, when every one of them has it, is still true.
		if !allLegacy {
			return baseWait{}, false
		}
		src = waitSource{name: src.name, tag: src.tag, ownNoNewer: true, legacy: true}
	}
	if layered {
		for _, l := range g.LayerDiffIDs {
			if l == "" || !layers[l] {
				return baseWait{}, false
			}
		}
	}
	return src.line(outcomes)
}

// line is the wait a card shows from the outcomes of its fixed findings, or
// false when it shows none.
func (s waitSource) line(outcomes []remediation.Outcome) (baseWait, bool) {
	w := baseWait{Image: s.image, Name: s.name, Tag: s.tag, OwnNoNewer: s.ownNoNewer, Total: len(outcomes)}
	plain := func() (baseWait, bool) {
		if !s.legacy {
			return baseWait{}, false
		}
		return baseWait{Name: s.name, Tag: s.tag, OwnNoNewer: true, Verdict: waitPlain}, true
	}
	switch s.status {
	case "":
		return plain()
	case remediation.NewerSeriesNone:
		w.Verdict = waitNoNewerSeries
		return w, true
	case remediation.NewerSeriesNotResolving:
		w.Verdict, w.Checked = waitRemains, s.checked
		return w, true
	}
	remaining := 0
	for _, o := range outcomes {
		switch o {
		case remediation.OutcomeResolved:
			w.Resolved++
		case remediation.OutcomeRemaining:
			remaining++
		default:
			// A finding the comparison could not judge: nothing is claimed.
			return plain()
		}
	}
	switch {
	case w.Resolved == 0:
		w.Verdict, w.Checked = waitRemains, s.to
	case remaining == 0:
		w.Verdict = waitResolved
	default:
		w.Verdict = waitPartial
	}
	if w.Resolved > 0 {
		w.To, w.Change, w.WithNew = s.to, s.change, s.withNew
	}
	return w, true
}
