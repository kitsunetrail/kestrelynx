package remediation

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/inventory"
)

// NewerSeriesStatus is the outcome of checking newer series of a pinned tag,
// for one candidate tag or for what the item shows.
type NewerSeriesStatus string

const (
	// NewerSeriesResolves: every target is resolved and nothing is
	// introduced.
	NewerSeriesResolves NewerSeriesStatus = "resolves"
	// NewerSeriesResolvesPartially: some targets are resolved, the others
	// are not, and nothing is introduced.
	NewerSeriesResolvesPartially NewerSeriesStatus = "resolves_partially"
	// NewerSeriesResolvesWithNew: some targets are resolved and findings, or
	// KEV-listed findings, are introduced.
	NewerSeriesResolvesWithNew NewerSeriesStatus = "resolves_with_new"
	// NewerSeriesNotResolving: no target is resolved.
	NewerSeriesNotResolving NewerSeriesStatus = "not_resolving"
	// NewerSeriesNotChecked: the check could not be made or judged; Reason
	// says why.
	NewerSeriesNotChecked NewerSeriesStatus = "not_checked"
	// NewerSeriesNone: the complete tag listing holds no tag of a newer
	// series of the same form.
	NewerSeriesNone NewerSeriesStatus = "no_newer_series"
)

// resolving reports whether s resolves at least one target.
func (s NewerSeriesStatus) resolving() bool {
	return s == NewerSeriesResolves || s == NewerSeriesResolvesPartially || s == NewerSeriesResolvesWithNew
}

// NewerSeries is what checking newer series of a pinned tag found: the
// candidates in the order they were checked, and the one the item shows.
type NewerSeries struct {
	Status NewerSeriesStatus `json:"status"`
	// Shown is the tag of the candidate the status comes from; empty when
	// no candidate resolves anything.
	Shown      string                 `json:"shown,omitempty"`
	Candidates []NewerSeriesCandidate `json:"candidates,omitempty"`
	Reason     Reason                 `json:"reason,omitempty"`
	Detail     string                 `json:"detail,omitempty"`
}

// SeriesChange is how far a newer series tag moves from the current tag.
type SeriesChange string

const (
	SeriesChangeMinor SeriesChange = "minor"
	SeriesChangeMajor SeriesChange = "major"
)

// NewerSeriesCandidate is one checked tag of a newer series.
type NewerSeriesCandidate struct {
	Tag    string            `json:"tag"`
	Change SeriesChange      `json:"change"`
	Status NewerSeriesStatus `json:"status"`
	// Candidate is the content the tag resolved to; nil when it was not
	// resolved.
	Candidate *ImageState `json:"candidate,omitempty"`
	// BaselineScan and CandidateScan are IDs into Plan.Scans.
	BaselineScan  string              `json:"baseline_scan,omitempty"`
	CandidateScan string              `json:"candidate_scan,omitempty"`
	Comparison    *VerificationResult `json:"comparison,omitempty"`
	Counts        *NewerSeriesCounts  `json:"counts,omitempty"`
	Reason        Reason              `json:"reason,omitempty"`
	Detail        string              `json:"detail,omitempty"`

	kev []string // the introduced KEV-listed vulnerabilities
}

// NewerSeriesCounts tallies a candidate's comparison over the targets.
type NewerSeriesCounts struct {
	Targets       int `json:"targets"`
	Resolved      int `json:"resolved"`
	Remaining     int `json:"remaining"`
	Unknown       int `json:"unknown"`
	Undetected    int `json:"undetected"`
	Introduced    int `json:"introduced"`
	IntroducedKEV int `json:"introduced_kev"`
}

// NewerSeriesOptions keep time and registry requests for the work that
// follows the check.
type NewerSeriesOptions struct {
	// ReserveTime is how long before the deadline of the context the check
	// stops; zero keeps no time.
	ReserveTime time.Duration
	// ReserveRequests is how many registry requests of the cycle's budget
	// the check leaves; zero keeps none.
	ReserveRequests int
	// IntelFor, when set, gives the intel the check's comparisons use in
	// place of Config.Intel, bound to the check's own context, so a lookup
	// that has to fetch data stops at the check's deadline too.
	IntelFor func(ctx context.Context) IntelFunc
}

// NewerSeriesSummary is what a check of newer series did.
type NewerSeriesSummary struct {
	Items            int // items and Dockerfile items checked
	Resolving        int // of them, those with a candidate that resolves a target
	NotChecked       int
	CandidateScans   int
	BaselineRescans  int
	TagPages         int
	RegistryRequests int
}

// newerTag is a tag of a newer series chosen as a candidate.
type newerTag struct {
	tag    string
	change SeriesChange
}

// CheckNewerSeries continues the pass of the last Plan call over plan, which
// is that call's plan with any later changes, and records on the pinned
// items whose own series gave no candidate that resolves their targets
// whether a tag of a newer series does. It shares the pass's caches and
// limits, writes nothing to an item but its NewerSeries, and stops early to
// keep what opts says for the work after it. Without a Plan call it does
// nothing.
func (p *Planner) CheckNewerSeries(ctx context.Context, plan *Plan, opts NewerSeriesOptions) NewerSeriesSummary {
	r := p.last
	if r == nil {
		return NewerSeriesSummary{}
	}
	stage := ctx
	if dl, ok := ctx.Deadline(); ok && opts.ReserveTime > 0 {
		var cancel context.CancelFunc
		stage, cancel = context.WithDeadline(ctx, dl.Add(-opts.ReserveTime))
		defer cancel()
	}
	r.ctx, r.outer = stage, ctx
	if opts.IntelFor != nil {
		r.stageIntel = opts.IntelFor(stage)
	}
	r.plan = *plan
	before := r.plan.Usage
	startUsed := p.cfg.Budget.Used()
	p.cfg.Budget.Reserve(opts.ReserveRequests)
	defer p.cfg.Budget.Reserve(0)

	inputs := map[string]ImageInput{}
	for _, in := range r.inputs {
		ref := in.Scan.Subject.Ref
		if ref == "" {
			ref = in.Scan.Image
		}
		k := ref + "|" + entityString(in.Scan.Subject.Key)
		if _, ok := inputs[k]; !ok {
			inputs[k] = in
		}
	}
	type unit struct {
		prio Priority
		item int // index into Items, or -1
		df   int // index into DockerfileItems, or -1
	}
	var units []unit
	for i, it := range r.plan.Items {
		if _, ok := inputs[it.Key]; ok && newerSeriesEligible(it) {
			units = append(units, unit{it.Priority, i, -1})
		}
	}
	for i, it := range r.plan.DockerfileItems {
		if newerSeriesEligibleDockerfile(it) {
			// The item's priority counts the findings of the whole image;
			// what a newer base can resolve are the base's targets.
			var targets []Target
			for _, e := range it.Entities {
				targets = append(targets, e.Targets...)
			}
			units = append(units, unit{maxTargetPriority(targets), -1, i})
		}
	}
	sort.SliceStable(units, func(i, j int) bool { return units[i].prio.Rank() > units[j].prio.Rank() })

	var sum NewerSeriesSummary
	for _, u := range units {
		var ns *NewerSeries
		if u.item >= 0 {
			it := &r.plan.Items[u.item]
			ns = r.newerSeriesItem(it, inputs[it.Key])
			it.NewerSeries = ns
		} else {
			it := &r.plan.DockerfileItems[u.df]
			r.newerSeriesDockerfile(it)
			ns = it.NewerSeries
		}
		sum.Items++
		switch {
		case ns.Status.resolving():
			sum.Resolving++
		case ns.Status == NewerSeriesNotChecked:
			sum.NotChecked++
		}
	}
	used := p.cfg.Budget.Used() - startUsed
	r.plan.Usage.RegistryRequests += used
	sum.CandidateScans = r.plan.Usage.CandidateScans - before.CandidateScans
	sum.BaselineRescans = r.plan.Usage.BaselineRescans - before.BaselineRescans
	sum.TagPages = r.plan.Usage.TagPages - before.TagPages
	sum.RegistryRequests = used
	*plan = r.plan
	return sum
}

// newerSeriesReasons are the outcomes of a pinned item's own series that
// leave its targets unresolved.
var newerSeriesReasons = map[Reason]bool{
	ReasonNoNewerTag:         true,
	ReasonSameContent:        true,
	ReasonCandidateNotFixing: true,
}

func newerSeriesEligible(it Item) bool {
	return it.Kind == TagPinned && it.Category == CategoryNoCandidate && newerSeriesReasons[it.Reason] && len(it.Targets) > 0
}

// newerSeriesEligibleDockerfile decides from the running images rather than
// the item: their reasons may differ from one another, which makes the item
// manual although each of them is left unresolved by the series.
func newerSeriesEligibleDockerfile(it DockerfileItem) bool {
	if it.BaseKind != TagPinned || len(it.Entities) == 0 {
		return false
	}
	for _, e := range it.Entities {
		if e.Category != CategoryNoCandidate || !newerSeriesReasons[e.Reason] || e.CurrentBase == nil || len(e.Targets) == 0 {
			return false
		}
	}
	return true
}

// stopped returns the outcome that ends the check when the pass is halted
// or its context is done.
func (r *run) stopped() *planOutcome {
	if r.halted == nil {
		if err := r.ctx.Err(); err != nil {
			r.halted = &halt{r.deadlineReason(), err.Error()}
		}
	}
	if r.halted != nil {
		return &planOutcome{CategoryDeferred, r.halted.reason, r.halted.detail}
	}
	return nil
}

func notChecked(out *planOutcome) *NewerSeries {
	return &NewerSeries{Status: NewerSeriesNotChecked, Reason: out.reason, Detail: out.detail}
}

// newerTags chooses the candidate tags of newer series of ref from the
// repository's whole listing: the newest tag of the same major with a newer
// minor, then the newest tag of a newer major. A tag counts when it is a
// pinned tag with the prefix and suffix of the current one and is not a
// prerelease. ns is set when there is nothing to check.
func (r *run) newerTags(ref ImageRef) (tags []newerTag, ns *NewerSeries) {
	list, out := r.fullTagList(ref.Repository)
	if out != nil {
		return nil, notChecked(out)
	}
	cur := ref.Version
	var minor, major *TagVersion
	var minorTag, majorTag string
	for _, tag := range list {
		if IsPrerelease(tag) {
			continue
		}
		v, ok := ParseTagVersion(tag)
		if !ok || v.Prefix != cur.Prefix || v.Suffix != cur.Suffix {
			continue
		}
		switch {
		case v.Major == cur.Major && v.Minor > cur.Minor:
			if minor == nil || versionLess(*minor, v) {
				vv := v
				minor, minorTag = &vv, tag
			}
		case v.Major > cur.Major:
			if major == nil || versionLess(*major, v) {
				vv := v
				major, majorTag = &vv, tag
			}
		}
	}
	if minor != nil {
		tags = append(tags, newerTag{minorTag, SeriesChangeMinor})
	}
	if major != nil {
		tags = append(tags, newerTag{majorTag, SeriesChangeMajor})
	}
	if len(tags) == 0 {
		return nil, &NewerSeries{Status: NewerSeriesNone, Detail: "the complete tag listing has no tag of a newer series of the same form"}
	}
	return tags, nil
}

func versionLess(a, b TagVersion) bool {
	if a.Major != b.Major {
		return a.Major < b.Major
	}
	if a.Minor != b.Minor {
		return a.Minor < b.Minor
	}
	return a.Patch < b.Patch
}

// checkNext reports whether a candidate with status s leaves reason to check
// the next one: it resolves part of the targets or none, so the next may do
// more. A candidate that resolves them all needs no other, and one that could
// not be checked stops the item, so that a later candidate never looks as if
// the earlier had been skipped.
func checkNext(s NewerSeriesStatus) bool {
	return s == NewerSeriesResolvesPartially || s == NewerSeriesResolvesWithNew || s == NewerSeriesNotResolving
}

// newerSeriesItem checks newer series of a running image's pinned tag.
func (r *run) newerSeriesItem(it *Item, in ImageInput) *NewerSeries {
	if out := r.stopped(); out != nil {
		return notChecked(out)
	}
	ref := ParseImageRef(it.Current.Ref)
	tags, ns := r.newerTags(ref)
	if ns != nil {
		return ns
	}
	ns = &NewerSeries{}
	platform := inventory.Platform{OS: in.Scan.Platform.OS, Architecture: in.Scan.Platform.Architecture}
	for _, t := range tags {
		c := r.newerImageCandidate(in, ref, t, platform, it.Targets)
		ns.Candidates = append(ns.Candidates, c)
		if !checkNext(c.Status) {
			break
		}
	}
	settleNewerSeries(ns)
	return ns
}

func (r *run) newerImageCandidate(in ImageInput, ref ImageRef, t newerTag, platform inventory.Platform, targets []Target) NewerSeriesCandidate {
	c := NewerSeriesCandidate{Tag: t.tag, Change: t.change}
	fail := func(status NewerSeriesStatus, reason Reason, detail string) NewerSeriesCandidate {
		c.Status, c.Reason, c.Detail = status, reason, detail
		return c
	}
	if out := r.stopped(); out != nil {
		return fail(NewerSeriesNotChecked, out.reason, out.detail)
	}
	res, out := r.resolveTag(ref.Repository, t.tag, platform)
	if out != nil {
		return fail(NewerSeriesNotChecked, out.reason, out.detail)
	}
	c.Candidate = &ImageState{
		Ref:            ref.Repository + ":" + t.tag,
		Tag:            t.tag,
		ConfigDigest:   res.ConfigDigest,
		ManifestDigest: res.ManifestDigest,
		TopDigest:      res.TopDigest,
		Platform:       platform.OS + "/" + platform.Architecture,
	}
	same, known, matched := sameContent(in.Scan.Subject.Key, res)
	switch {
	case !known:
		return fail(NewerSeriesNotChecked, ReasonEntityUnverified, "the running entity cannot be compared with registry content")
	case same:
		c.Comparison, c.Counts = unchangedComparison(targets)
		return fail(NewerSeriesNotResolving, ReasonSameContent, "the tag resolves to the content already running (the running digest equals its "+matched+" digest)")
	}
	cmp := r.compareImage(in, ref.Repository, t.tag, platform, res, targets)
	c.BaselineScan, c.CandidateScan = cmp.baseScan, cmp.candScan
	if cmp.out != nil {
		return fail(NewerSeriesNotChecked, cmp.out.reason, cmp.out.detail)
	}
	// Judging the comparison may have looked up what it introduces; a
	// result reached after the stage's deadline is not kept.
	if out := r.stopped(); out != nil {
		return fail(NewerSeriesNotChecked, out.reason, out.detail)
	}
	c.Comparison, c.kev = cmp.vr, cmp.dec.IntroducedKEV
	c.Status, c.Reason = classifyNewer(*cmp.vr, *cmp.dec)
	c.Counts = decisionCounts(*cmp.dec)
	return c
}

// classifyNewer reads a candidate's outcome from its verdicts on the targets
// rather than from the kind of decision, which puts introduced findings
// before anything resolved: here what is resolved and what is introduced are
// told apart. Any target that could not be judged, or that the comparison
// did not show, leaves it unchecked.
func classifyNewer(vr VerificationResult, d Decision) (NewerSeriesStatus, Reason) {
	switch {
	case !vr.Comparable:
		return NewerSeriesNotChecked, vr.Reason
	case d.Unknown > 0:
		return NewerSeriesNotChecked, ReasonAnalysisIncomplete
	case d.Undetected > 0:
		return NewerSeriesNotChecked, ReasonTargetsNotDetected
	case d.Resolved == 0:
		return NewerSeriesNotResolving, ""
	case d.Introduced > 0 || len(d.IntroducedKEV) > 0:
		return NewerSeriesResolvesWithNew, ""
	case d.Resolved < d.Targets:
		return NewerSeriesResolvesPartially, ""
	}
	return NewerSeriesResolves, ""
}

// unchangedComparison is the outcome of a candidate whose content is the
// one already in use: every target remains, with no scan behind it.
func unchangedComparison(targets []Target) (*VerificationResult, *NewerSeriesCounts) {
	vr := &VerificationResult{Comparable: true, Scope: "the candidate is the content already in use; nothing was scanned"}
	for _, t := range targets {
		vr.Verdicts = append(vr.Verdicts, VulnVerdict{VulnID: t.VulnID, Package: t.Package, Outcome: OutcomeRemaining})
	}
	return vr, &NewerSeriesCounts{Targets: len(targets), Remaining: len(targets)}
}

func decisionCounts(d Decision) *NewerSeriesCounts {
	return &NewerSeriesCounts{
		Targets: d.Targets, Resolved: d.Resolved, Remaining: d.Remaining, Unknown: d.Unknown,
		Undetected: d.Undetected, Introduced: d.Introduced, IntroducedKEV: len(d.IntroducedKEV),
	}
}

// settleNewerSeries chooses what ns shows from its checked candidates: one
// that resolves every target first, then the one that resolves the most
// (without introduced findings when two resolve as many, and the earlier
// when that is equal too). Candidates that could not be checked are never
// chosen, so a candidate checked before the check stopped still shows.
func settleNewerSeries(ns *NewerSeries) {
	ns.Shown, ns.Reason, ns.Detail = "", "", ""
	var best *NewerSeriesCandidate
	checked, notResolving := 0, 0
	for i := range ns.Candidates {
		c := &ns.Candidates[i]
		switch {
		case c.Status == NewerSeriesNotChecked:
			continue
		case c.Status == NewerSeriesNotResolving:
			notResolving++
		case best == nil || betterNewer(*c, *best):
			best = c
		}
		checked++
	}
	switch {
	case best != nil:
		ns.Status, ns.Shown = best.Status, best.Tag
	case checked > 0 && checked == notResolving:
		ns.Status = NewerSeriesNotResolving
	default:
		ns.Status = NewerSeriesNotChecked
		for _, c := range ns.Candidates {
			if c.Status == NewerSeriesNotChecked {
				ns.Reason, ns.Detail = c.Reason, c.Detail
				break
			}
		}
	}
}

// betterNewer reports whether candidate a shows before b, both resolving.
func betterNewer(a, b NewerSeriesCandidate) bool {
	if (a.Status == NewerSeriesResolves) != (b.Status == NewerSeriesResolves) {
		return a.Status == NewerSeriesResolves
	}
	ar, br := resolvedOf(a), resolvedOf(b)
	if ar != br {
		return ar > br
	}
	return a.Status != NewerSeriesResolvesWithNew && b.Status == NewerSeriesResolvesWithNew
}

func resolvedOf(c NewerSeriesCandidate) int {
	if c.Counts == nil {
		return 0
	}
	return c.Counts.Resolved
}

// newerSeriesDockerfile checks newer series of a Dockerfile's pinned base for
// every running image of the item: a candidate tag counts for the item only
// as the outcome of all of them, each image's own part is kept on its
// entity.
func (r *run) newerSeriesDockerfile(it *DockerfileItem) {
	set := func(ns *NewerSeries) {
		it.NewerSeries = ns
		for i := range it.Entities {
			cp := *ns
			it.Entities[i].NewerSeries = &cp
		}
	}
	if out := r.stopped(); out != nil {
		set(notChecked(out))
		return
	}
	ref := ParseImageRef(it.BaseRef)
	tags, ns := r.newerTags(ref)
	if ns != nil {
		set(ns)
		return
	}
	item := &NewerSeries{}
	ents := make([]*NewerSeries, len(it.Entities))
	for i := range ents {
		ents[i] = &NewerSeries{}
	}
	for _, t := range tags {
		parts := make([]NewerSeriesCandidate, len(it.Entities))
		for i := range it.Entities {
			parts[i] = r.newerBaseCandidate(it.Entities[i], ref, t)
			ents[i].Candidates = append(ents[i].Candidates, parts[i])
		}
		c := aggregateNewerBase(t, it.Entities, parts)
		item.Candidates = append(item.Candidates, c)
		if !checkNext(c.Status) {
			break
		}
	}
	settleNewerSeries(item)
	it.NewerSeries = item
	for i := range it.Entities {
		settleNewerSeries(ents[i])
		it.Entities[i].NewerSeries = ents[i]
	}
}

func (r *run) newerBaseCandidate(e DockerfileEntity, ref ImageRef, t newerTag) NewerSeriesCandidate {
	c := NewerSeriesCandidate{Tag: t.tag, Change: t.change}
	fail := func(status NewerSeriesStatus, reason Reason, detail string) NewerSeriesCandidate {
		c.Status, c.Reason, c.Detail = status, reason, detail
		return c
	}
	if out := r.stopped(); out != nil {
		return fail(NewerSeriesNotChecked, out.reason, out.detail)
	}
	platform, ok := parsePlatform(e.CurrentBase.Platform)
	if !ok {
		return fail(NewerSeriesNotChecked, ReasonPlatformUnknown, "the platform of the current base is not known")
	}
	// The current base was resolved by the series check; this is its cached
	// resolution.
	curRes, out := r.resolveTag(ref.Repository, ref.Tag, platform)
	if out != nil {
		return fail(NewerSeriesNotChecked, out.reason, out.detail)
	}
	cmp := r.compareBase(ref, t.tag, platform, curRes, e.Targets)
	c.Candidate = cmp.cand
	c.BaselineScan, c.CandidateScan = cmp.baseScan, cmp.candScan
	if cmp.out != nil {
		if cmp.out.reason == ReasonSameContent {
			c.Comparison, c.Counts = unchangedComparison(e.Targets)
			return fail(NewerSeriesNotResolving, cmp.out.reason, cmp.out.detail)
		}
		return fail(NewerSeriesNotChecked, cmp.out.reason, cmp.out.detail)
	}
	// Judging the comparison may have looked up what it introduces; a
	// result reached after the stage's deadline is not kept.
	if out := r.stopped(); out != nil {
		return fail(NewerSeriesNotChecked, out.reason, out.detail)
	}
	c.Comparison, c.kev = cmp.vr, cmp.dec.IntroducedKEV
	c.Status, c.Reason = classifyNewer(*cmp.vr, *cmp.dec)
	c.Counts = decisionCounts(*cmp.dec)
	return c
}

// aggregateNewerBase is the item's outcome for one candidate tag over its
// running images. It needs every image's part checked, and the tag to have
// pointed at the same content for all of them: the same top-level digest,
// and the same platform manifest for images of one platform. A target is
// resolved when every image that has it resolves it.
func aggregateNewerBase(t newerTag, ents []DockerfileEntity, parts []NewerSeriesCandidate) NewerSeriesCandidate {
	c := NewerSeriesCandidate{Tag: t.tag, Change: t.change}
	for _, p := range parts {
		if p.Status == NewerSeriesNotChecked {
			c.Status, c.Reason, c.Detail = NewerSeriesNotChecked, p.Reason, p.Detail
			return c
		}
	}
	manifests := map[string]string{}
	var first *ImageState
	for _, p := range parts {
		if p.Candidate == nil {
			continue
		}
		if first == nil {
			first = p.Candidate
		}
		m, seen := manifests[p.Candidate.Platform]
		if p.Candidate.TopDigest != first.TopDigest || (seen && m != p.Candidate.ManifestDigest) {
			c.Status, c.Reason = NewerSeriesNotChecked, ReasonCandidateChanged
			c.Detail = fmt.Sprintf("tag %s pointed at different content for the running images (%s and %s)", t.tag, first.TopDigest, p.Candidate.TopDigest)
			return c
		}
		manifests[p.Candidate.Platform] = p.Candidate.ManifestDigest
	}
	if first != nil {
		c.Candidate = &ImageState{Ref: first.Ref, Tag: first.Tag, TopDigest: first.TopDigest}
	}

	tmp := make([]DockerfileEntity, len(ents))
	kev := map[string]bool{}
	for i, p := range parts {
		tmp[i] = DockerfileEntity{Targets: ents[i].Targets, Comparison: p.Comparison}
		for _, id := range p.kev {
			kev[id] = true
		}
	}
	dc := dockerfileCounts(tmp)
	counts := &NewerSeriesCounts{
		Targets: dc.Targets, Resolved: dc.Resolved, Remaining: dc.Remaining,
		Undetected: dc.Targets - dc.Resolved - dc.Remaining, Introduced: dc.Introduced, IntroducedKEV: len(kev),
	}
	c.Counts = counts
	switch {
	case counts.Undetected > 0:
		c.Status, c.Reason = NewerSeriesNotChecked, ReasonTargetsNotDetected
	case counts.Resolved == 0:
		c.Status = NewerSeriesNotResolving
	case counts.Introduced > 0 || counts.IntroducedKEV > 0:
		c.Status = NewerSeriesResolvesWithNew
	case counts.Resolved < counts.Targets:
		c.Status = NewerSeriesResolvesPartially
	default:
		c.Status = NewerSeriesResolves
	}
	return c
}
