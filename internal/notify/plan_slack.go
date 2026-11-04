// The fix plan in Slack: a message of its own, sent after the vulnerability
// message in the same channel. It is laid out like the vulnerability message —
// sections with a bold image line, "label: value" lines and dividers — and
// is sent only when what it shows has changed, and on the weekly day.
package notify

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/remediation"
)

// Caps on the lists a line of the plan message names by item.
const (
	planListed   = 10 // package changes of one line
	planLeftOuts = 10 // packages a file lists with a reason
)

// planTag names the kind of proposal a line of an entry stands for, for the
// summary line of a plan without pull requests.
type planTag int

const (
	tagCandidate planTag = iota
	tagRepull
	tagRebuild
	tagDecide
	tagNotComparable
	tagFailed
	tagDeferred
	tagNewerSeries
)

// planEntry is what one file (or one image to pull again) adds under the
// images it concerns.
type planEntry struct {
	images   []string // running images, in plan order
	services []string // the services, when no running image is known for them
	lines    []string
	tags     map[planTag]bool
}

// plain adds a line that stands for no kind of proposal by itself.
func (e *planEntry) plain(line string) { e.lines = append(e.lines, line) }

func (e *planEntry) line(tag planTag, line string) {
	e.lines = append(e.lines, line)
	if e.tags == nil {
		e.tags = map[planTag]bool{}
	}
	e.tags[tag] = true
}

// planGroup is the section of one set of images: their bold lines, then the
// lines of the entries that concern exactly that set.
type planGroup struct {
	headings []string
	lines    []string
}

// planView is the content of the plan message before it is laid out.
type planView struct {
	summary     string
	unavailable string // the note of a plan that was not produced
	groups      []planGroup
	notes       []string
	// detail is every name, version and reason the message is made from,
	// whole: the lines of a message cut long lists short.
	detail []string
}

// empty reports whether the view has nothing to say.
func (v planView) empty() bool {
	return v.unavailable == "" && len(v.groups) == 0 && len(v.notes) == 0
}

type planOpts struct {
	// normalize shows a pull request opened in this cycle as an open one, so
	// the same pull request reads the same in the next cycle. The fingerprint
	// is made this way.
	normalize bool
	// openOnly leaves out the pull requests that were merged or closed, for
	// the weekly list of what is still waiting for a person.
	openOnly bool
}

type planBuilder struct {
	plan      remediation.Plan
	msg       messages
	opts      planOpts
	byService map[string][]string // workload key -> running image references
	langItems map[string]remediation.LanguageItem
	entries   []planEntry
	detail    []string
}

func buildPlanView(p *PlanInfo, msg messages, o planOpts) planView {
	var v planView
	if p == nil {
		return v
	}
	if p.Plan == nil {
		if p.Unavailable == PlanDatabasesNotPrepared {
			v.unavailable = trimNL(msg.PlanUnavailableDB)
		} else {
			v.unavailable = trimNL(msg.PlanUnavailableOther)
		}
		return v
	}
	b := &planBuilder{plan: *p.Plan, msg: msg, opts: o, byService: map[string][]string{}, langItems: map[string]remediation.LanguageItem{}}
	for _, it := range b.plan.Items {
		for _, s := range it.Services {
			k := s.WorkloadKey()
			if k == "" {
				continue
			}
			b.byService[k] = appendOnce(b.byService[k], it.Current.Ref)
		}
	}
	for _, li := range b.plan.LanguageItems {
		b.langItems[li.Key] = li
	}
	b.build()

	groups := map[string]int{}
	for _, e := range b.entries {
		if len(e.lines) == 0 {
			continue
		}
		key := "img\x00" + strings.Join(e.images, "\x00")
		if len(e.images) == 0 {
			key = "svc\x00" + strings.Join(e.services, "\x00")
		}
		i, ok := groups[key]
		if !ok {
			g := planGroup{}
			if len(e.images) > 0 {
				for _, ref := range e.images {
					g.headings = append(g.headings, boldLine(msg.LblImage+": ", refMrkdwn(ref)))
				}
			} else {
				names := make([]string, len(e.services))
				for j, s := range e.services {
					names[j] = litMrkdwn(s)
				}
				g.headings = []string{boldLine(msg.PlanLblService+": ", strings.Join(names, msg.PlanListSep))}
			}
			v.groups = append(v.groups, g)
			i = len(v.groups) - 1
			groups[key] = i
		}
		v.groups[i].lines = append(v.groups[i].lines, e.lines...)
	}
	v.summary = b.summary()
	v.detail = b.detail
	if line := pullRequestProblemLine(b.plan, msg); line != "" {
		v.notes = append(v.notes, line)
	}
	if p.NotSaved {
		v.notes = append(v.notes, trimNL(msg.PlanNotSaved))
	}
	return v
}

func appendOnce(list []string, s string) []string {
	for _, have := range list {
		if have == s {
			return list
		}
	}
	return append(list, s)
}

// hasPullRequest reports whether any unit has a pull request: the stage may
// report units that have none (they need a person, or wait).
func (b *planBuilder) hasPullRequest() bool {
	for _, u := range b.plan.PullRequests {
		if u.Number > 0 {
			return true
		}
	}
	return false
}

// summary is the line under the heading: the pull requests by status when
// there are any, else the proposals by kind.
func (b *planBuilder) summary() string {
	msg := b.msg
	if b.hasPullRequest() {
		n := map[remediation.PRUnitStatus]int{}
		for _, u := range b.plan.PullRequests {
			s := u.Status
			if b.opts.openOnly && (s == remediation.PRStatusMerged || s == remediation.PRStatusSuppressed) {
				continue
			}
			if b.opts.normalize && s == remediation.PRStatusCreated {
				s = remediation.PRStatusOpen
			}
			n[s]++
		}
		var segs []string
		for _, c := range []struct {
			format string
			n      int
		}{
			{msg.PlanPRSegCreated, n[remediation.PRStatusCreated]},
			{msg.PlanPRSegOpen, n[remediation.PRStatusOpen]},
			{msg.PlanPRSegMerged, n[remediation.PRStatusMerged]},
			{msg.PlanPRSegClosed, n[remediation.PRStatusSuppressed]},
			{msg.PlanPRSegManual, n[remediation.PRStatusManual]},
			{msg.PlanPRSegDeferred, n[remediation.PRStatusDeferred]},
			{msg.PlanPRSegBlocked, n[remediation.PRStatusFailed] + n[remediation.PRStatusWriteBlocked]},
		} {
			if c.n > 0 {
				segs = append(segs, fmt.Sprintf(c.format, c.n))
			}
		}
		if len(segs) > 0 {
			return fmt.Sprintf(msg.PlanPRCounts, strings.Join(segs, " · "))
		}
	}
	counts := map[planTag]int{}
	for _, e := range b.entries {
		for t := range e.tags {
			counts[t]++
		}
	}
	var segs []string
	for _, c := range []struct {
		format string
		tag    planTag
	}{
		{msg.PlanSegCandidate, tagCandidate},
		{msg.PlanSegRepull, tagRepull},
		{msg.PlanSegRebuild, tagRebuild},
		{msg.PlanSegDecide, tagDecide},
		{msg.PlanSegNotComparable, tagNotComparable},
		{msg.PlanSegFailed, tagFailed},
		{msg.PlanSegDeferred, tagDeferred},
		{msg.PlanSegNewerSeries, tagNewerSeries},
	} {
		if counts[c.tag] > 0 {
			segs = append(segs, fmt.Sprintf(c.format, counts[c.tag]))
		}
	}
	if len(segs) == 0 {
		return ""
	}
	return fmt.Sprintf(msg.PlanCounts, strings.Join(segs, " · "))
}

// build collects the entries: the pull requests first, then the proposals
// that have no pull request.
func (b *planBuilder) build() {
	plan := b.plan
	for _, u := range plan.PullRequests {
		if b.opts.openOnly && (u.Status == remediation.PRStatusMerged || u.Status == remediation.PRStatusSuppressed) {
			continue
		}
		switch u.Kind {
		case "dockerfile":
			b.add(b.dockerfileUnit(u))
		case "language":
			b.add(b.languageUnit(u))
		default:
			b.add(b.composeUnit(u))
		}
	}
	for _, it := range plan.Items {
		if b.composeUnitOf(it) {
			continue
		}
		b.add(b.composeItem(it))
	}
	for _, di := range plan.DockerfileItems {
		if dockerfileUnitOf(di, plan.PullRequests) != nil {
			continue
		}
		b.add(b.dockerfileItem(di))
	}
	for _, li := range plan.LanguageItems {
		if languageUnitOf(li, plan.PullRequests) != nil {
			continue
		}
		b.add(b.languageItem(li))
	}
}

func (b *planBuilder) add(e planEntry) { b.entries = append(b.entries, e) }

// isContainerKey reports whether a workload key is container/<name>, the key of
// a container started outside Compose.
func isContainerKey(key string) bool {
	return strings.HasPrefix(key, "container/") && strings.Count(key, "/") == 1
}

// imagesOf resolves workloads (compose/<project>/<service>, container/<name>,
// or the Kubernetes key) to the running images of their services; without any,
// the service names are returned: the Compose service, the container name, or
// the whole Kubernetes key.
func (b *planBuilder) imagesOf(e *planEntry, workloads []string) {
	var services []string
	for _, w := range workloads {
		for _, ref := range b.byService[w] {
			e.images = appendOnce(e.images, ref)
		}
		name := w
		switch {
		case strings.HasPrefix(w, "compose/"):
			name = workloadService(w)
		case isContainerKey(w):
			name = strings.TrimPrefix(w, "container/")
		}
		services = appendOnce(services, name)
	}
	if len(e.images) == 0 {
		sort.Strings(services)
		e.services = services
	}
}

func (b *planBuilder) fileValue(repo, p string) string {
	if repo == "" {
		return litMrkdwn(p)
	}
	return fmt.Sprintf(b.msg.PlanFileValue, litMrkdwn(repo), litMrkdwn(p))
}

func (b *planBuilder) reason(code remediation.Reason) string {
	b.detail = append(b.detail, "reason\x00"+string(code))
	return planReasonText(b.msg.Lang, string(code))
}

// joined lists items, cut to planListed with the count of the rest.
func (b *planBuilder) joined(items []string) string {
	b.detail = append(b.detail, "list\x00"+strings.Join(items, "\x00"))
	shown := items
	if len(shown) > planListed {
		shown = shown[:planListed]
	}
	out := strings.Join(shown, b.msg.PlanListSep)
	if n := len(items) - len(shown); n > 0 {
		out += fmt.Sprintf(b.msg.PlanMore, n)
	}
	return out
}

func (b *planBuilder) change(name, from, to string) string {
	return fmt.Sprintf(b.msg.PlanChange, litMrkdwn(name), litMrkdwn(from), litMrkdwn(to))
}

// planChainShown is how many direct dependencies a line names before it counts
// the rest.
const planChainShown = 3

// changeThrough is change for a package that a chain update brought to its
// version through the direct dependencies in through; move gives the versions
// one of them went from and to.
func (b *planBuilder) changeThrough(name, from, to string, through []string, move func(string) (string, string, bool)) string {
	if len(through) == 0 {
		return b.change(name, from, to)
	}
	var tops []string
	for _, t := range through {
		if f, to, ok := move(t); ok && f != to {
			tops = append(tops, b.change(t, f, to))
		} else {
			tops = append(tops, litMrkdwn(t))
		}
	}
	return fmt.Sprintf(b.msg.PlanChangeWith, litMrkdwn(name), litMrkdwn(from), litMrkdwn(to), b.cut(tops))
}

// cut joins the items of a list, the first planChainShown of them and the
// count of the rest.
func (b *planBuilder) cut(items []string) string {
	b.detail = append(b.detail, "cut\x00"+strings.Join(items, "\x00"))
	shown := items
	if len(shown) > planChainShown {
		shown = shown[:planChainShown]
	}
	out := strings.Join(shown, b.msg.PlanListSep)
	if n := len(items) - len(shown); n > 0 {
		out += fmt.Sprintf(b.msg.PlanMore, n)
	}
	return out
}

// chainTops names the direct dependencies of a chain update for a line about a
// package it did not take to its version: each with the version it has, or the
// versions it went from and to when it moved.
func (b *planBuilder) chainTops(c *remediation.ChainUpdate) string {
	var tops []string
	if len(c.Tops) > 0 {
		for _, t := range c.Tops {
			if t.To != "" && t.To != t.From {
				tops = append(tops, b.change(t.Name, t.From, t.To))
			} else {
				tops = append(tops, litMrkdwn(t.Name)+" "+litMrkdwn(t.From))
			}
		}
	} else {
		seen := map[string]bool{}
		for _, k := range c.Blocked {
			if id := k.Parent + "@" + k.ParentVersion; !seen[id] {
				seen[id] = true
				tops = append(tops, litMrkdwn(k.Parent)+" "+litMrkdwn(k.ParentVersion))
			}
		}
	}
	if len(tops) == 0 {
		return ""
	}
	return b.cut(tops)
}

// chainHolders names the dependents that hold the package back, each with its
// version, from the requirements the chain update found; "" when it recorded
// none for the package.
func (b *planBuilder) chainHolders(x pkgLine) string {
	type holder struct{ parent, version string }
	seen := map[holder]bool{}
	var parts []string
	for _, k := range x.chain.Blocked {
		h := holder{k.Parent, k.ParentVersion}
		if !remediation.SameDependencyName(x.manager, k.Package, x.name) || seen[h] {
			continue
		}
		seen[h] = true
		parts = append(parts, litMrkdwn(k.Parent)+" "+litMrkdwn(k.ParentVersion))
	}
	if len(parts) == 0 {
		return ""
	}
	return b.cut(parts)
}

// hintLines are the lines under a package's chain line that say, for newer
// releases of the dependents holding it back, whether they let the project
// use a fixed version of it.
func (b *planBuilder) hintLines(x pkgLine) []string {
	if x.chain == nil {
		return nil
	}
	return b.releaseLines(x, x.chain.Hints, x.chain.Outcome == remediation.ChainNotFixed)
}

// releaseLines are the lines of hints about the dependents of a package;
// notFixed says an update re-resolved within the project's ranges and did not
// reach the fix.
func (b *planBuilder) releaseLines(x pkgLine, hints []remediation.ChainHint, notFixed bool) []string {
	manifest := "package.json"
	switch x.manager {
	case remediation.ManagerUv:
		manifest = "pyproject.toml"
	case remediation.ManagerPip:
		manifest = "requirements.txt"
	}
	pkg := litMrkdwn(x.name)
	var out []string
	add := func(line string) { out = append(out, fmt.Sprintf(b.msg.PlanHintBullet, line)) }
	for _, h := range hints {
		if !remediation.SameDependencyName(x.manager, h.Package, x.name) {
			continue
		}
		parent := litMrkdwn(h.Parent)
		if r := h.InSpec; r != nil && h.Direct {
			verdict := b.hintVerdict(pkg, r)
			// The update re-resolved within the project's ranges and still did
			// not reach the fix: a release there allowing it does not mean it
			// can be had, which the line says.
			if r.Fixes && !r.Dropped && notFixed {
				verdict = fmt.Sprintf(b.msg.PlanHintFixesNotRaised, pkg)
			}
			add(fmt.Sprintf(b.msg.PlanHintRelease, parent, litMrkdwn(r.Version), fmt.Sprintf(b.msg.PlanHintInSpec, manifest), verdict))
		}
		if r := h.Latest; r != nil {
			add(fmt.Sprintf(b.msg.PlanHintRelease, parent, litMrkdwn(r.Version), b.msg.PlanHintLatest, b.hintVerdict(pkg, r)))
			if !h.Direct && len(h.Via) > 0 && (r.Fixes || r.Dropped) {
				via := make([]string, len(h.Via))
				for i, v := range h.Via {
					via[i] = litMrkdwn(v)
				}
				add(fmt.Sprintf(b.msg.PlanHintVia, b.cut(via), parent))
			}
		}
	}
	return out
}

// hintVerdict is what one release of a dependent lets the project do with the
// package.
func (b *planBuilder) hintVerdict(pkg string, r *remediation.ChainHintRelease) string {
	switch {
	case r.Dropped:
		return fmt.Sprintf(b.msg.PlanHintDropped, pkg)
	case r.Fixes:
		return fmt.Sprintf(b.msg.PlanHintFixes, pkg)
	}
	return fmt.Sprintf(b.msg.PlanHintNoFix, pkg)
}

// heldLine is the line about a package the packages that depend on it hold
// back, as an update found them without moving them, "" when it found none.
func (b *planBuilder) heldLine(x pkgLine) string {
	if x.hint == nil || x.target == "" || x.reason != remediation.ReasonDependentsHoldBack {
		return ""
	}
	type holder struct{ parent, version string }
	seen := map[holder]bool{}
	var parts []string
	for _, h := range x.hint.HeldBy {
		k := holder{h.Parent, h.ParentVersion}
		if seen[k] {
			continue
		}
		seen[k] = true
		parts = append(parts, litMrkdwn(h.Parent)+" "+litMrkdwn(h.ParentVersion))
	}
	if len(parts) == 0 {
		return ""
	}
	return fmt.Sprintf(b.msg.PlanChainHeldBack, litMrkdwn(x.name), litMrkdwn(x.from), litMrkdwn(x.target), b.cut(parts))
}

// otherMajorLine is the line about a package whose fixes are all of another
// major version, with what brings the old one in for Go, "" without a hint
// naming the fix.
func (b *planBuilder) otherMajorLine(x pkgLine) string {
	switch x.reason {
	case remediation.ReasonFixInOtherMajor, remediation.ReasonMavenFixInOtherMajor, remediation.ReasonMavenReleaseNotFound:
	default:
		return ""
	}
	if x.hint == nil || x.hint.Fix == nil {
		return ""
	}
	name, from, fix := litMrkdwn(x.name), litMrkdwn(x.from), litMrkdwn(x.hint.Fix.Version)
	if x.hint.Direct {
		return fmt.Sprintf(b.msg.PlanOtherMajorDirect, name, from, fix)
	}
	var parts []string
	for _, h := range x.hint.HeldBy {
		parts = append(parts, litMrkdwn(h.Parent)+" "+litMrkdwn(h.ParentVersion))
	}
	if len(parts) > 0 {
		return fmt.Sprintf(b.msg.PlanOtherMajorHeld, name, from, fix, b.cut(parts))
	}
	return fmt.Sprintf(b.msg.PlanOtherMajor, name, from, fix)
}

// decidedLine is the line about a Maven or Gradle package whose version a pom
// outside the project decides, "" without such a hint.
func (b *planBuilder) decidedLine(x pkgLine) string {
	if x.hint == nil || x.hint.DecidedBy == nil || x.target == "" {
		return ""
	}
	d := x.hint.DecidedBy
	format := b.msg.PlanDecidedByParent
	switch d.Kind {
	case remediation.DeciderBOM:
		format = b.msg.PlanDecidedByBOM
	case remediation.DeciderSpringBoot:
		format = b.msg.PlanDecidedBySpringBoot
	}
	return fmt.Sprintf(format, litMrkdwn(x.name), litMrkdwn(x.from), litMrkdwn(x.target), litMrkdwn(d.Name), litMrkdwn(d.Version))
}

// usedByLine is the line about a Maven or Gradle package an update left
// below its target because packages it depends on bring it in (in a Gradle
// configuration), or a Gradle configuration declares it itself; "" without
// such a hint.
func (b *planBuilder) usedByLine(x pkgLine) string {
	h := x.hint
	if h == nil || x.target == "" || x.reason != remediation.ReasonTargetNotUpdated || h.DecidedBy != nil || h.GoLine != nil || h.Fix != nil ||
		(x.manager != remediation.ManagerMaven && x.manager != remediation.ManagerGradle) {
		return ""
	}
	name, from, target := litMrkdwn(x.name), litMrkdwn(x.from), litMrkdwn(x.target)
	if len(h.HeldBy) == 0 {
		if h.Direct && h.Configuration != "" {
			return fmt.Sprintf(b.msg.PlanDeclaredIn, name, from, target, litMrkdwn(h.Configuration))
		}
		return ""
	}
	var parts []string
	for _, k := range h.HeldBy {
		parts = append(parts, litMrkdwn(k.Parent)+" "+litMrkdwn(k.ParentVersion))
	}
	brought := x.from
	if r := h.HeldBy[0].Range; r != "" {
		brought = r
	}
	if h.Configuration != "" {
		return fmt.Sprintf(b.msg.PlanUsedByIn, name, from, target, b.cut(parts), litMrkdwn(brought), litMrkdwn(h.Configuration))
	}
	return fmt.Sprintf(b.msg.PlanUsedBy, name, from, target, b.cut(parts), litMrkdwn(brought))
}

// deciderLines are the lines under a decidedLine or a usedByLine: what the
// newest release of the deciding pom (or of each dependent) in its minor
// version, and its newest release, set the package to.
func (b *planBuilder) deciderLines(x pkgLine) []string {
	d := x.hint.DecidedBy
	whoOf := func(h remediation.ChainHint) string {
		if d != nil && d.Kind == remediation.DeciderSpringBoot {
			return "Spring Boot"
		}
		return litMrkdwn(h.Parent)
	}
	verdict := func(r *remediation.ChainHintRelease) string {
		switch {
		case r.Dropped:
			return fmt.Sprintf(b.msg.PlanHintNotSet, litMrkdwn(x.name))
		case r.Fixes:
			return b.msg.PlanHintSetsFix
		}
		return b.msg.PlanHintSetsNoFix
	}
	var out []string
	for _, h := range x.hint.Releases {
		who := whoOf(h)
		for _, rel := range []struct {
			r     *remediation.ChainHintRelease
			which string
		}{{h.InSpec, b.msg.PlanHintSameMinor}, {h.Latest, b.msg.PlanHintLatest}} {
			if rel.r != nil {
				out = append(out, fmt.Sprintf(b.msg.PlanHintBullet, fmt.Sprintf(b.msg.PlanHintRelease, who, litMrkdwn(rel.r.Version), rel.which, verdict(rel.r))))
			}
		}
	}
	return out
}

// goLineLine is the line about a Go package an update did not take to its
// fixed version for the Go it needs, with the module version whose go.mod
// asks for it, "" without such a hint.
func (b *planBuilder) goLineLine(x pkgLine) string {
	if x.hint == nil || x.hint.GoLine == nil || x.target == "" {
		return ""
	}
	g := x.hint.GoLine
	to := x.target
	if g.To != "" {
		to = g.To
	}
	name, from, target := litMrkdwn(x.name), litMrkdwn(x.from), litMrkdwn(to)
	line, mod, ver := litMrkdwn(g.Go), litMrkdwn(g.Module), litMrkdwn(g.Version)
	switch {
	case x.reason == remediation.ReasonGoRuntimeUnavailable:
		return fmt.Sprintf(b.msg.PlanGoRuntimeMissing, name, from, target, line, mod, ver)
	case x.reason != remediation.ReasonGoLineRaised:
		return ""
	case g.BuiltWith == "":
		return fmt.Sprintf(b.msg.PlanGoLineRaisedUnknown, name, from, target, line, mod, ver)
	}
	return fmt.Sprintf(b.msg.PlanGoLineRaised, name, from, target, line, mod, ver, litMrkdwn(g.BuiltWith))
}

// chainLine is the line about a package a chain update was meant for and did
// not take to its version, "" when the update's record does not say enough.
func (b *planBuilder) chainLine(x pkgLine) string {
	if x.chain == nil || x.target == "" {
		return ""
	}
	tops := b.chainTops(x.chain)
	if tops == "" {
		return ""
	}
	name, from, target := litMrkdwn(x.name), litMrkdwn(x.from), litMrkdwn(x.target)
	switch x.reason {
	case remediation.ReasonDependentsNotFixed:
		if holders := b.chainHolders(x); holders != "" {
			return fmt.Sprintf(b.msg.PlanChainHeldBack, name, from, target, holders)
		}
		return fmt.Sprintf(b.msg.PlanChainNotFixedTops, name, from, target, tops)
	case remediation.ReasonDependentsRejected:
		return fmt.Sprintf(b.msg.PlanChainRejected, name, from, target, tops, b.reason(x.chain.Reason))
	case remediation.ReasonDependentsUnsupported, remediation.ReasonDependentsLimit:
		return fmt.Sprintf(b.msg.PlanChainHeld, name, from, target, tops, b.reason(x.chain.Reason))
	}
	return ""
}

// prLine is the pull request line of a unit that has a pull request.
func (b *planBuilder) prLine(u remediation.PRUnit) string {
	link := mrkdwnLink(u.URL, fmt.Sprintf("#%d", u.Number))
	status := ""
	switch u.Status {
	case remediation.PRStatusCreated:
		status = b.msg.PlanPRStatusCreated
		if b.opts.normalize {
			status = b.msg.PlanPRStatusOpen
		}
	case remediation.PRStatusOpen:
		status = b.msg.PlanPRStatusOpen
	case remediation.PRStatusMerged:
		status = b.msg.PlanPRStatusMerged
	case remediation.PRStatusSuppressed:
		status = b.msg.PlanPRStatusClosed
	}
	if status == "" {
		return kv(b.msg.PlanLblPR, link)
	}
	return kv(b.msg.PlanLblPR, fmt.Sprintf(b.msg.PlanPRValue, link, status))
}

// unitLines adds the lines every pull request unit has: the pull request or,
// without one, the candidate and why there is none.
func (b *planBuilder) unitLines(e *planEntry, u remediation.PRUnit, update string) {
	if u.Number > 0 {
		e.line(tagCandidate, b.prLine(u))
		if update != "" {
			e.line(tagCandidate, kv(b.msg.PlanLblUpdate, update))
		}
		return
	}
	// A unit without a pull request counts as what keeps it from having one.
	tag := tagCandidate
	switch u.Status {
	case remediation.PRStatusManual:
		tag = tagDecide
	case remediation.PRStatusFailed, remediation.PRStatusWriteBlocked:
		tag = tagFailed
	case remediation.PRStatusDeferred:
		tag = tagDeferred
	}
	if update != "" {
		e.line(tag, kv(b.msg.PlanLblCandidate, update))
	}
	why := b.reason(u.Reason)
	if u.Reason == "" {
		why = litMrkdwn(string(u.Status))
	}
	switch u.Status {
	case remediation.PRStatusManual:
		e.line(tagDecide, kv(b.msg.PlanLblDecide, why))
	case remediation.PRStatusFailed, remediation.PRStatusWriteBlocked:
		e.line(tagFailed, kv(b.msg.PlanLblFailed, why))
	case remediation.PRStatusDeferred:
		e.line(tagDeferred, kv(b.msg.PlanLblDeferred, why))
	}
}

// outcome is the label and tag of an item without a proposal that a person
// should know about: a decision to make, a comparison that could not be made,
// a failure, or work put off. ok is false for the other categories.
func (b *planBuilder) outcome(c remediation.Category) (label string, tag planTag, ok bool) {
	switch c {
	case remediation.CategoryManual:
		return b.msg.PlanLblDecide, tagDecide, true
	case remediation.CategoryNotComparable:
		return b.msg.PlanLblNotComparable, tagNotComparable, true
	case remediation.CategoryFailed:
		return b.msg.PlanLblFailed, tagFailed, true
	case remediation.CategoryDeferred:
		return b.msg.PlanLblDeferred, tagDeferred, true
	}
	return "", 0, false
}

// --- Compose images ---

// composeUnitOf reports whether a pull request unit stands for the update the
// item proposes.
func (b *planBuilder) composeUnitOf(it remediation.Item) bool {
	if it.Category != remediation.CategoryPRCandidate || it.Candidate == nil {
		return false
	}
	for _, u := range b.plan.PullRequests {
		if (u.Kind == "" || u.Kind == "kubernetes" || u.Kind == "kustomize" || u.Kind == "helm_values") && u.Current == it.Current.Ref && u.CandidateTag == it.Candidate.Tag {
			return true
		}
	}
	return false
}

func (b *planBuilder) composeUnit(u remediation.PRUnit) planEntry {
	e := planEntry{images: []string{u.Current}}
	e.plain(kv(b.msg.PlanLblFile, b.fileValue(u.Repo, u.Path)))
	image, old := splitImageRef(u.Current)
	b.unitLines(&e, u, b.change(image, old, u.CandidateTag))
	if u.Kind == "kubernetes" || u.Kind == "kustomize" || u.Kind == "helm_values" {
		if line := b.managedBy(remediation.ManagementOf(b.plan, u.Workloads)); line != "" {
			e.plain(line)
		}
	}
	return e
}

// resolves says how many of the targeted findings an item's candidate
// resolves, and what else is worth saying about them: the findings the
// running image's scan did not show, and the KEV-listed ones among the
// resolved.
func (b *planBuilder) resolves(it remediation.Item) (main string, extra []string) {
	msg := b.msg
	if n, partial := partialOf(it); partial {
		main = fmt.Sprintf(msg.PlanResolvesPartial, resolvedCount(it), n)
	} else {
		main = fmt.Sprintf(msg.PlanResolves, resolvedCount(it))
	}
	if d := it.Decision; d != nil && d.Undetected > 0 {
		extra = append(extra, fmt.Sprintf(msg.PlanUndetectedClause, d.Undetected))
	}
	if k := resolvedKEVTargets(it); k > 0 {
		extra = append(extra, fmt.Sprintf(msg.PlanKEVClause, k))
	}
	return main, extra
}

func (b *planBuilder) wrap(parts ...string) string {
	return fmt.Sprintf(b.msg.PlanClauseWrap, strings.Join(parts, b.msg.PlanClauseJoin))
}

func (b *planBuilder) composeItem(it remediation.Item) planEntry {
	e := b.composeItemLines(it)
	if len(e.lines) > 0 {
		if line := b.managedBy(it.Management); line != "" {
			e.plain(line)
		}
	}
	return e
}

func (b *planBuilder) composeItemLines(it remediation.Item) planEntry {
	e := planEntry{images: []string{it.Current.Ref}}
	switch it.Category {
	case remediation.CategoryPullAgain:
		main, extra := b.resolves(it)
		value := main
		if len(extra) > 0 {
			value += b.wrap(extra...)
		}
		e.line(tagRepull, kv(b.msg.PlanLblRepull, value))
		for _, a := range it.Pull {
			e.plain(kv(b.msg.PlanLblPullPolicy, b.pullAdvice(a)))
		}
	case remediation.CategoryPRCandidate:
		if it.Candidate != nil {
			image, old := splitImageRef(it.Current.Ref)
			main, extra := b.resolves(it)
			e.line(tagCandidate, kv(b.msg.PlanLblCandidate, b.change(image, old, it.Candidate.Tag)+b.wrap(append([]string{main}, extra...)...)))
		}
	case remediation.CategoryManual:
		if it.Candidate != nil && it.Candidate.Tag != "" && it.Kind == remediation.TagPinned {
			image, old := splitImageRef(it.Current.Ref)
			e.plain(kv(b.msg.PlanLblCandidate, b.change(image, old, it.Candidate.Tag)))
		}
		e.line(tagDecide, kv(b.msg.PlanLblDecide, b.reason(it.Reason)))
	default:
		if label, tag, ok := b.outcome(it.Category); ok {
			e.line(tag, kv(label, b.reason(it.Reason)))
		}
	}
	image, old := splitImageRef(it.Current.Ref)
	if tag, line, ok := b.newerSeriesLine(it.NewerSeries, func(to string) string { return b.change(image, old, to) }, false); ok {
		e.line(tag, line)
	}
	return e
}

// newerSeriesLine is the line of a check of newer series that found a tag
// resolving something: a line of its own, apart from the update candidates
// since no pull request is made for it, or a decision when the tag
// introduces findings. ok is false for every other outcome of the check,
// which is not shown here. update renders the change to a tag; base marks a
// comparison of base images.
func (b *planBuilder) newerSeriesLine(ns *remediation.NewerSeries, update func(to string) string, base bool) (tag planTag, line string, ok bool) {
	if ns == nil || ns.Shown == "" {
		return 0, "", false
	}
	var c *remediation.NewerSeriesCandidate
	for i := range ns.Candidates {
		if ns.Candidates[i].Tag == ns.Shown {
			c = &ns.Candidates[i]
		}
	}
	if c == nil || c.Counts == nil {
		return 0, "", false
	}
	msg := b.msg
	clauses := []string{msg.PlanNewerMinor}
	if c.Change == remediation.SeriesChangeMajor {
		clauses[0] = msg.PlanNewerMajor
	}
	n := c.Counts
	switch ns.Status {
	case remediation.NewerSeriesResolves, remediation.NewerSeriesResolvesPartially:
		if n.Resolved < n.Targets {
			clauses = append(clauses, fmt.Sprintf(msg.PlanResolvesPartial, n.Resolved, n.Targets))
		} else {
			clauses = append(clauses, fmt.Sprintf(msg.PlanResolves, n.Resolved))
		}
		if base {
			clauses = append(clauses, msg.PlanNewerBaseCompared)
		}
		clauses = append(clauses, msg.PlanNewerUnverified)
		return tagNewerSeries, kv(msg.PlanLblNewerSeries, update(c.Tag)+b.wrap(clauses...)), true
	case remediation.NewerSeriesResolvesWithNew:
		if base {
			clauses = append(clauses, msg.PlanNewerBaseCompared)
		}
		clauses = append(clauses, msg.PlanNewerUnverified)
		return tagDecide, kv(msg.PlanLblDecide, fmt.Sprintf(msg.PlanNewerWithNew, update(c.Tag), n.Resolved, n.Introduced)+b.wrap(clauses...)), true
	}
	return 0, "", false
}

// pullAdvice is the value of a pull policy line: the policy, what it means for
// taking the new content of the floating tag, and the workloads it covers.
func (b *planBuilder) pullAdvice(a remediation.PullAdvice) string {
	var guidance string
	switch a.Guidance {
	case remediation.GuidanceRestart:
		guidance = b.msg.PlanPullRestart
	case remediation.GuidanceChangeTag:
		guidance = b.msg.PlanPullChangeTag
	case remediation.GuidanceImportToNode:
		guidance = b.msg.PlanPullImportToNode
	default:
		guidance = litMrkdwn(string(a.Guidance))
	}
	names := make([]string, len(a.Workloads))
	for i, w := range a.Workloads {
		names[i] = litMrkdwn(w)
	}
	return fmt.Sprintf(b.msg.PlanPullValue, litMrkdwn(a.Policy), guidance, b.joined(names))
}

// managedBy is the line that names the tools managing the workloads of an
// item, from the chains that have a layer above the Kubernetes resource
// itself; "" when none has. The chains are read from markers the tools leave
// on the objects, which the label says.
func (b *planBuilder) managedBy(ms []remediation.WorkloadChains) string {
	type shown struct{ workload, chain string }
	var all []shown
	for _, m := range ms {
		var chains []string
		for _, c := range m.Chains {
			if len(c) < 2 {
				continue
			}
			var layers []string
			for _, o := range c {
				layers = append(layers, b.ownerText(o))
			}
			chains = append(chains, strings.Join(layers, " → "))
		}
		if len(chains) > 0 {
			all = append(all, shown{m.Workload, strings.Join(chains, "; ")})
		}
	}
	if len(all) == 0 {
		return ""
	}
	values := make([]string, len(all))
	for i, x := range all {
		values[i] = x.chain
		if len(ms) > 1 {
			// Several workloads run the image: say which one each chain is of.
			values[i] = fmt.Sprintf(b.msg.PlanManagedValue, litMrkdwn(x.workload), x.chain)
		}
	}
	return kv(b.msg.PlanLblManagedBy, b.joined(values))
}

// ownerText names one layer of a management chain.
func (b *planBuilder) ownerText(o remediation.ChainOwner) string {
	name, scope := litMrkdwn(o.Name), litMrkdwn(o.Scope)
	switch {
	case o.Kind == remediation.OwnerHelm:
		return fmt.Sprintf(b.msg.PlanOwnerHelm, name, scope)
	case o.Kind == remediation.OwnerArgoCD:
		return fmt.Sprintf(b.msg.PlanOwnerArgoCD, name)
	case o.Kind == remediation.OwnerFlux && o.ResourceID == remediation.ResourceIDFluxHelmRelease:
		return fmt.Sprintf(b.msg.PlanOwnerFluxHelm, name, scope)
	case o.Kind == remediation.OwnerFlux:
		return fmt.Sprintf(b.msg.PlanOwnerFluxKust, name, scope)
	case o.Scope != "":
		return litMrkdwn(string(o.Resource) + " " + o.Scope + "/" + o.Name)
	}
	return litMrkdwn(string(o.Resource) + " " + o.Name)
}

// --- Dockerfile base images ---

func (b *planBuilder) dockerfileUnit(u remediation.PRUnit) planEntry {
	e := planEntry{}
	b.imagesOf(&e, u.Workloads)
	e.plain(kv(b.msg.PlanLblFile, b.fileValue(u.Repo, u.Path)))
	image, old := splitImageRef(u.Current)
	update := fmt.Sprintf(b.msg.PlanBaseImageValue, litMrkdwn(image), litMrkdwn(old), litMrkdwn(u.CandidateTag))
	b.unitLines(&e, u, update)
	if line := b.managedBy(remediation.ManagementOf(b.plan, u.Workloads)); line != "" {
		e.plain(line)
	}
	return e
}

func (b *planBuilder) dockerfileItem(it remediation.DockerfileItem) planEntry {
	e := planEntry{}
	b.imagesOf(&e, it.Workloads)
	file := kv(b.msg.PlanLblFile, b.fileValue(it.Source.Repository, it.Source.Path))
	candidate := func() string {
		image, old := splitImageRef(it.BaseRef)
		return fmt.Sprintf(b.msg.PlanBaseImageValue, litMrkdwn(image), litMrkdwn(old), litMrkdwn(it.Candidate.Tag))
	}
	switch {
	case it.Category == remediation.CategoryPRCandidate && it.Candidate != nil:
		var parts []string
		if it.Counts.Resolved < it.Counts.Targets {
			parts = append(parts, fmt.Sprintf(b.msg.PlanResolvesPartial, it.Counts.Resolved, it.Counts.Targets))
		} else {
			parts = append(parts, fmt.Sprintf(b.msg.PlanResolves, it.Counts.Resolved))
		}
		if k := dockerfileKEVResolved(it); k > 0 {
			parts = append(parts, fmt.Sprintf(b.msg.PlanKEVClause, k))
		}
		e.plain(file)
		e.line(tagCandidate, kv(b.msg.PlanLblCandidate, candidate()+b.wrap(parts...)))
	case it.Category == remediation.CategoryManual:
		e.plain(file)
		if it.Candidate != nil && it.Candidate.Tag != "" {
			e.plain(kv(b.msg.PlanLblCandidate, candidate()))
		}
		e.line(tagDecide, kv(b.msg.PlanLblDecide, b.reason(it.Reason)))
	case it.Reason == remediation.ReasonBaseUpdateNotDeployed && it.AwaitingDeploy != nil:
		m := it.AwaitingDeploy
		image, _ := splitImageRef(it.BaseRef)
		_, from := splitImageRef(m.From)
		link := fmt.Sprintf("#%d", m.Number)
		if m.URL != "" {
			link = mrkdwnLink(m.URL, link)
		}
		e.plain(file)
		e.line(tagRebuild, kv(b.msg.PlanLblRebuild, fmt.Sprintf(b.msg.PlanBaseNotDeployed, link, litMrkdwn(image), litMrkdwn(from), litMrkdwn(m.To))))
	case it.Category == remediation.CategoryNotComparable && it.Reason == remediation.ReasonBaseLayersMismatch && it.BaseRef != "":
		e.plain(file)
		e.line(tagNotComparable, kv(b.msg.PlanLblNotComparable, fmt.Sprintf(b.msg.PlanBaseLayersMismatch, litMrkdwn(it.BaseRef))))
	case it.Category == remediation.CategoryNotComparable && it.Reason == remediation.ReasonFloatingBaseUnconfirmed:
		e.plain(file)
		guide := b.msg.PlanDockerfileRebuild
		switch {
		case it.Source.Origin == remediation.DockerfileFromMapping:
			guide = b.msg.PlanDockerfileRebuildMapping
		case it.Source.Origin == remediation.DockerfileFromBoth && slices.ContainsFunc(it.Workloads, isContainerKey):
			guide = b.msg.PlanDockerfileRebuildMixed
		}
		e.line(tagRebuild, kv(b.msg.PlanLblRebuild, guide))
		for _, rr := range it.RebuildRuntimes {
			if total := len(rr.Disappearing) + len(rr.Remaining); total > 0 {
				e.plain(fmt.Sprintf(b.msg.PlanRebuildRuntime, litMrkdwn(it.BaseRef), litMrkdwn(rr.Package), litMrkdwn(rr.BaseVersion),
					litMrkdwn(rr.Installed), len(rr.Disappearing), total))
			}
		}
	default:
		if label, tag, ok := b.outcome(it.Category); ok {
			e.plain(file)
			e.line(tag, kv(label, b.reason(it.Reason)))
		}
	}
	image, old := splitImageRef(it.BaseRef)
	newer := func(to string) string {
		return fmt.Sprintf(b.msg.PlanBaseImageValue, litMrkdwn(image), litMrkdwn(old), litMrkdwn(to))
	}
	if tag, line, ok := b.newerSeriesLine(it.NewerSeries, newer, true); ok {
		if len(e.lines) == 0 {
			e.plain(file)
		}
		e.line(tag, line)
	}
	return e
}

// --- language packages ---

// languageFile is the lockfile of a unit as the plan names it.
func languageFile(li remediation.LanguageItem) string {
	return path.Join(li.Source.Directory, li.Manager.LockfileName())
}

func (b *planBuilder) languageUnit(u remediation.PRUnit) planEntry {
	e := planEntry{}
	b.imagesOf(&e, u.Workloads)
	e.plain(kv(b.msg.PlanLblFile, b.fileValue(u.Repo, u.Path)))
	update := ""
	if l := u.Language; l != nil {
		var changes []string
		moves := map[string]remediation.LangChainMove{}
		for _, m := range l.Chain {
			moves[m.Name] = m
		}
		for _, p := range l.Packages {
			changes = append(changes, b.changeThrough(p.Name, p.From, p.To, p.Through, func(n string) (string, string, bool) {
				m, ok := moves[n]
				return m.From, m.To, ok
			}))
		}
		update = b.joined(changes)
	}
	b.unitLines(&e, u, update)
	if l := u.Language; l != nil {
		var majors []string
		for _, p := range l.Packages {
			if p.Major {
				majors = append(majors, b.majorPackage(p.Name, p.From, p.To))
			}
		}
		for _, ed := range l.ManifestEdits {
			if ed.Major {
				majors = append(majors, fmt.Sprintf(b.msg.PlanMajorEdit, litMrkdwn(ed.Name), litMrkdwn(ed.From), litMrkdwn(ed.To), litMrkdwn(ed.File)))
			}
		}
		if len(majors) > 0 {
			e.plain(kv(b.msg.PlanLblMajor, b.joined(majors)))
		}
	}
	// The pull request's own view has the packages it leaves out; an item tied
	// to a pull request made in an earlier cycle holds no marks of its own.
	var left []leftOut
	if l := u.Language; l != nil {
		li := b.langItems[u.ItemKey]
		for _, x := range l.Remaining {
			left = append(left, leftOut{x.Name, x.From, x.Target, x.Reason, nil, x.MavenBOM, li.Manager, remainingHint(li, x)})
		}
	}
	var planned []pkgLine
	if li, ok := b.langItems[u.ItemKey]; ok {
		if len(left) == 0 {
			left = leftOutOf(li)
		}
		planned = b.plannedManual(li, false)
	}
	b.leftOutLines(&e, left, planned, b.lockName(u.Path, u.ItemKey))
	return e
}

// bomRaise is the note of a package left alone because its BOM's minor version
// does not reach the fix: the later release of the BOM that does, set through
// its property when the project sets the BOM's version with one.
func (b *planBuilder) bomRaise(x pkgLine) string {
	r := x.bom
	if r == nil || x.reason != remediation.ReasonMavenBOMSeriesUnreached {
		return ""
	}
	what := r.BOM
	if r.Property != "" {
		what = r.Property
	}
	return fmt.Sprintf(b.msg.PlanBOMRaise, litMrkdwn(what), litMrkdwn(r.To))
}

func (b *planBuilder) majorPackage(name, from, to string) string {
	c := b.change(name, from, to)
	if strings.HasPrefix(from, "0.") {
		return fmt.Sprintf(b.msg.PlanMajorZero, c)
	}
	return c
}

// lockName is the name of the lockfile of a unit: the file the pull request
// changes, or else the one its manager keeps.
func (b *planBuilder) lockName(p, itemKey string) string {
	if p != "" {
		return path.Base(p)
	}
	if li, ok := b.langItems[itemKey]; ok {
		return li.Manager.LockfileName()
	}
	return ""
}

type leftOut struct {
	name, from, target string
	reason             remediation.Reason
	chain              *remediation.ChainUpdate
	bom                *remediation.MavenBOMRaise
	manager            remediation.DependencyManager
	hint               *remediation.FixHint
}

// remainingHint is the hint of a package a pull request leaves out, from the
// item's package of that name left out for the same reason: the record of the
// pull request does not hold hints.
func remainingHint(li remediation.LanguageItem, x remediation.PRLanguageRemaining) *remediation.FixHint {
	for _, p := range li.Packages {
		if p.LeftOut && p.Name == x.Name && p.Ecosystem == x.Ecosystem && p.Reason == x.Reason && p.Installed == x.From {
			return p.Hint()
		}
	}
	return nil
}

func leftOutOf(li remediation.LanguageItem) []leftOut {
	var out []leftOut
	var chain *remediation.ChainUpdate
	if li.Update != nil {
		chain = li.Update.Chain
	}
	for _, p := range li.Packages {
		if p.LeftOut {
			out = append(out, leftOut{p.Name, p.Installed, p.SelectionLowerBound, p.Reason, chain, p.MavenBOM, li.Manager, p.Hint()})
		}
	}
	return out
}

// pkgLine is a package a file lists with the reason it needs a person.
type pkgLine struct {
	name, from, target string
	reason             remediation.Reason
	chain              *remediation.ChainUpdate // what the chain update did, when it was tried
	unchanged          bool                     // the update left the lockfile as it was
	leftOut            bool                     // the package was left out of an update of the others
	// lockVersions are the versions the files list when they list the package
	// at another version than the image has.
	lockVersions []string
	inFile       bool // the files have the package, at another version
	// bom is a later minor version of the package's BOM that reaches its
	// target, for a person to raise the BOM to.
	bom *remediation.MavenBOMRaise
	// manager is the item's, which names the manifest the hints speak of.
	manager remediation.DependencyManager
	// partOf are the packages of a global node_modules a package in one is
	// part of, the package itself left out.
	partOf []string
	// hint is what holds the package back, as the update found it.
	hint *remediation.FixHint
}

// leftOutLines lists the packages left out of an update, then the packages
// the plan left to a person before any update (planned), under one label.
func (b *planBuilder) leftOutLines(e *planEntry, left []leftOut, planned []pkgLine, file string) {
	items := make([]pkgLine, 0, len(left)+len(planned))
	for _, x := range left {
		items = append(items, pkgLine{name: x.name, from: x.from, target: x.target, reason: x.reason, leftOut: true, chain: x.chain, bom: x.bom, manager: x.manager, hint: x.hint})
	}
	items = append(items, planned...)
	b.packageLines(e, tagDecide, b.msg.PlanLblDecide, file, items)
}

// plannedManual are the packages of an item that the plan left to a person
// before any update ran, as lines: they are named whatever else the item
// proposes, so that a pull request of the other packages does not hide them.
// The packages an update left out are not among them, nor those that only
// share an update set another package of which could not be updated, nor,
// with ownReason, the packages the item's own reason covers.
func (b *planBuilder) plannedManual(li remediation.LanguageItem, ownReason bool) []pkgLine {
	var out []pkgLine
	for _, p := range li.Packages {
		if p.Action != remediation.ActionManual || p.LeftOut || p.Reason == remediation.ReasonUpdateSetNotApplied || (ownReason && ofItemReason(li, p)) {
			continue
		}
		out = append(out, b.pkgLineOf(li, p))
	}
	return out
}

// packageLines lists packages with their reasons, ten at most: a package with
// a target version gets a line of its own; the packages that have no target
// are listed under one line for their reason. Everything is recorded for the
// fingerprint, the cut part too.
func (b *planBuilder) packageLines(e *planEntry, tag planTag, label, file string, items []pkgLine) {
	for _, x := range items {
		d := strings.Join([]string{"package", x.name, x.from, x.target, string(x.reason), fmt.Sprint(x.unchanged), fmt.Sprint(x.leftOut), fmt.Sprint(x.inFile), strings.Join(x.lockVersions, ","), b.bomRaise(x)}, "\x00")
		if len(x.partOf) > 0 {
			d += "\x00" + strings.Join(x.partOf, ",")
		}
		b.detail = append(b.detail, d)
	}
	shown := items
	if len(shown) > planLeftOuts {
		shown = shown[:planLeftOuts]
	}
	type bareGroup struct {
		header  string
		bullets []string
	}
	var groups []*bareGroup
	byKey := map[string]*bareGroup{}
	for _, x := range shown {
		if line := b.otherMajorLine(x); line != "" {
			e.line(tag, kv(label, line))
			for _, h := range b.releaseLines(x, x.hint.Releases, false) {
				e.line(tag, h)
			}
			continue
		}
		if x.target == "" {
			key, header := string(x.reason), b.reason(x.reason)
			bullet := fmt.Sprintf(b.msg.PlanBullet, litMrkdwn(x.name), litMrkdwn(x.from))
			if x.reason == remediation.ReasonGlobalNodeModules {
				header = fmt.Sprintf(b.msg.PlanGlobalModules, litMrkdwn(file))
				if len(x.partOf) > 0 {
					owners := make([]string, len(x.partOf))
					for i, o := range x.partOf {
						owners[i] = litMrkdwn(o)
					}
					bullet = fmt.Sprintf(b.msg.PlanBulletPartOf, litMrkdwn(x.name), litMrkdwn(x.from), strings.Join(owners, b.msg.PlanListSep))
				}
			}
			if x.reason == remediation.ReasonNotFoundInSource {
				if !x.inFile {
					header = fmt.Sprintf(b.msg.PlanNotInFile, litMrkdwn(file))
				} else {
					key += "\x00version"
					header = fmt.Sprintf(b.msg.PlanWrongVersion, litMrkdwn(file))
					versions := make([]string, len(x.lockVersions))
					for i, v := range x.lockVersions {
						versions[i] = litMrkdwn(v)
					}
					if len(versions) == 0 {
						versions = []string{"-"}
					}
					bullet = fmt.Sprintf(b.msg.PlanBulletVersions, litMrkdwn(x.name), litMrkdwn(x.from), litMrkdwn(file), strings.Join(versions, b.msg.PlanListSep))
				}
			}
			g, ok := byKey[key]
			if !ok {
				g = &bareGroup{header: header}
				byKey[key] = g
				groups = append(groups, g)
			}
			g.bullets = append(g.bullets, bullet)
			continue
		}
		name, from, target := litMrkdwn(x.name), litMrkdwn(x.from), litMrkdwn(x.target)
		var line string
		var hints []string
		switch {
		case b.chainLine(x) != "":
			line = b.chainLine(x)
			hints = b.hintLines(x)
		case b.heldLine(x) != "":
			line = b.heldLine(x)
			hints = b.releaseLines(x, x.hint.Releases, false)
		case b.goLineLine(x) != "":
			line = b.goLineLine(x)
		case b.decidedLine(x) != "":
			line = b.decidedLine(x)
			hints = b.deciderLines(x)
		case b.usedByLine(x) != "":
			line = b.usedByLine(x)
			hints = b.deciderLines(x)
		case x.reason == remediation.ReasonTargetNotUpdated:
			line = fmt.Sprintf(b.msg.PlanNotUpdated, name, from, target)
		case x.leftOut:
			line = fmt.Sprintf(b.msg.PlanLeftOut, name, from, target, b.reason(x.reason)) + b.bomRaise(x)
		default:
			note := ""
			if x.unchanged {
				note = b.msg.PlanLockfileUnchanged
			}
			line = fmt.Sprintf(b.msg.PlanPackageReason, name, from, target, b.reason(x.reason), note+b.bomRaise(x))
		}
		e.line(tag, kv(label, line))
		for _, h := range hints {
			e.line(tag, h)
		}
	}
	for _, g := range groups {
		e.line(tag, kv(label, g.header))
		for _, bullet := range g.bullets {
			e.line(tag, bullet)
		}
	}
	if n := len(items) - len(shown); n > 0 {
		e.line(tag, kv(label, strings.TrimSpace(fmt.Sprintf(b.msg.PlanMore, n))))
	}
}

func (b *planBuilder) languageItem(li remediation.LanguageItem) planEntry {
	e := planEntry{}
	b.imagesOf(&e, li.Workloads)
	file := kv(b.msg.PlanLblFile, b.fileValue(li.Source.Repository, languageFile(li)))
	switch li.Category {
	case remediation.CategoryDependencyUpdateCandidate:
		var changes []string
		kev := 0
		for _, p := range li.Packages {
			if p.Action == remediation.ActionUpdate {
				changes = append(changes, b.change(p.Name, p.Installed, p.SelectionLowerBound))
				kev += p.KEVCount()
			}
		}
		if len(changes) == 0 {
			return e
		}
		value := b.joined(changes)
		if kev > 0 {
			value += b.wrap(fmt.Sprintf(b.msg.PlanKEVClause, kev))
		}
		e.plain(file)
		e.line(tagCandidate, kv(b.msg.PlanLblCandidate, value))
		b.plannedLines(&e, li)
	case remediation.CategoryRebuildExpected:
		var pkgs []remediation.LanguagePackage
		for _, p := range li.Packages {
			if p.Action == remediation.ActionRebuildExpected {
				pkgs = append(pkgs, p)
				b.detail = append(b.detail, strings.Join([]string{"rebuild", p.Name, p.Installed, p.SelectionLowerBound}, "\x00"))
			}
		}
		if len(pkgs) == 0 {
			return e
		}
		e.plain(file)
		for i, p := range pkgs {
			if i == planListed {
				e.line(tagRebuild, kv(b.msg.PlanLblRebuild, strings.TrimSpace(fmt.Sprintf(b.msg.PlanMore, len(pkgs)-planListed))))
				break
			}
			e.line(tagRebuild, kv(b.msg.PlanLblRebuild, fmt.Sprintf(b.msg.PlanRebuildValue,
				litMrkdwn(p.Name), litMrkdwn(p.Installed), litMrkdwn(p.SelectionLowerBound))))
		}
		b.plannedLines(&e, li)
	case remediation.CategoryPRCandidate:
		var changes []string
		move := func(string) (string, string, bool) { return "", "", false }
		if li.Update != nil && li.Update.Chain != nil {
			tops := li.Update.Chain.Tops
			move = func(n string) (string, string, bool) {
				for _, t := range tops {
					if t.Name == n {
						return t.From, t.To, true
					}
				}
				return "", "", false
			}
		}
		for _, p := range li.Packages {
			if p.Action == remediation.ActionUpdate {
				changes = append(changes, b.changeThrough(p.Name, p.Installed, p.AdoptedVersion, p.Through, move))
			}
		}
		if len(changes) > 0 {
			e.plain(file)
			e.line(tagCandidate, kv(b.msg.PlanLblCandidate, b.joined(changes)))
		}
		b.leftOutLines(&e, leftOutOf(li), b.plannedManual(li, false), path.Base(languageFile(li)))
	case remediation.CategoryManual, remediation.CategoryNotComparable, remediation.CategoryFailed, remediation.CategoryDeferred:
		label, tag, _ := b.outcome(li.Category)
		why := b.reason(li.Reason)
		if x := li.RuntimeEOL; li.Reason == remediation.ReasonRuntimeEndOfLife && x != nil {
			if x.EOL == "" {
				why = fmt.Sprintf(b.msg.PlanRuntimeEOLNoDate, litMrkdwn(x.Name))
			} else {
				why = fmt.Sprintf(b.msg.PlanRuntimeEOL, litMrkdwn(x.Name), litMrkdwn(x.EOL))
			}
		}
		e.plain(file)
		// The packages the item's reason does not cover need a decision
		// whatever the item's state is: they are named after its own lines,
		// in the same list when those need a decision too.
		pkgs := packagesOfReason(li)
		planned := b.plannedManual(li, true)
		switch {
		case b.chainWaiting(&e, tag, label, li):
		case len(pkgs) > 0 && li.RuntimeEOL == nil:
			if tag == tagDecide {
				b.packageReasonLines(&e, tag, label, li, pkgs, planned)
				planned = nil
			} else {
				b.packageReasonLines(&e, tag, label, li, pkgs, nil)
			}
		default:
			e.line(tag, kv(label, why))
		}
		if len(planned) > 0 {
			b.packageLines(&e, tagDecide, b.msg.PlanLblDecide, path.Base(languageFile(li)), planned)
		}
	}
	return e
}

// plannedLines names, under the label of what needs a decision, the packages
// the plan left to a person in an item that proposes an update or a rebuild.
func (b *planBuilder) plannedLines(e *planEntry, li remediation.LanguageItem) {
	if planned := b.plannedManual(li, false); len(planned) > 0 {
		b.packageLines(e, tagDecide, b.msg.PlanLblDecide, path.Base(languageFile(li)), planned)
	}
}

// chainWaiting adds the lines of an item that waits for a version of the chain
// update to be old enough: one for each package the update was meant for. It
// reports whether it did.
func (b *planBuilder) chainWaiting(e *planEntry, tag planTag, label string, li remediation.LanguageItem) bool {
	if li.Reason != remediation.ReasonReleaseTooNew || li.RetryAfter == nil || li.Update == nil || li.Update.Chain == nil {
		return false
	}
	c := li.Update.Chain
	tops := b.chainTops(c)
	if tops == "" {
		return false
	}
	retry := li.RetryAfter.UTC().Format(time.RFC3339)
	seen := map[string]bool{}
	wrote := false
	for _, k := range c.Blocked {
		if seen[k.Package] {
			continue
		}
		seen[k.Package] = true
		for _, p := range li.Packages {
			if p.Action == remediation.ActionUpdate && (p.Name == k.Package || p.Normalized == k.Package) {
				b.detail = append(b.detail, strings.Join([]string{"chain wait", p.Name, p.Installed, p.SelectionLowerBound, retry}, "\x00"))
				e.line(tag, kv(label, fmt.Sprintf(b.msg.PlanChainWaiting, litMrkdwn(p.Name), litMrkdwn(p.Installed), litMrkdwn(p.SelectionLowerBound), tops, litMrkdwn(retry))))
				wrote = true
			}
		}
	}
	return wrote
}

// chainPackageReason reports whether a reason is one a package gets when the
// update of the packages that hold it back was meant for it.
func chainPackageReason(r remediation.Reason) bool {
	switch r {
	case remediation.ReasonDependentsNotFixed, remediation.ReasonDependentsRejected,
		remediation.ReasonDependentsUnsupported, remediation.ReasonDependentsLimit:
		return true
	}
	return false
}

// packagesOfReason are the packages of an item whose own reason is the item's
// reason: the item is manual because of them. The packages the update of the
// packages that hold them back was meant for are among them, whatever the
// item's reason is.
func packagesOfReason(li remediation.LanguageItem) []remediation.LanguagePackage {
	var out []remediation.LanguagePackage
	for _, p := range li.Packages {
		if ofItemReason(li, p) {
			out = append(out, p)
		}
	}
	return out
}

// ofItemReason reports whether p is one of the packages of packagesOfReason.
func ofItemReason(li remediation.LanguageItem, p remediation.LanguagePackage) bool {
	return li.Reason != "" && p.Action == remediation.ActionManual && (p.Reason == li.Reason || chainPackageReason(p.Reason))
}

// lockVersions are the versions the files list for a package that is listed
// at another version than the image has (the file has occurrences of it); none
// when the package is not in the files at all.
func lockVersions(p remediation.LanguagePackage) []string {
	var out []string
	for _, o := range p.Occurrences {
		if o.Version != "" {
			out = appendOnce(out, o.Version)
		}
	}
	return out
}

// globalOwners are the packages of a global node_modules a package in one is
// part of (npm for npm's own dependencies), the package itself left out.
func globalOwners(p remediation.LanguagePackage) []string {
	if p.Reason != remediation.ReasonGlobalNodeModules {
		return nil
	}
	var out []string
	for _, o := range p.Origins {
		if owner, ok := remediation.GlobalNodeModule(o.PkgPath); ok && owner != p.Name {
			out = appendOnce(out, owner)
		}
	}
	sort.Strings(out)
	return out
}

// lockfileLeftAlone matches the detail of an update that changed nothing.
var lockfileLeftAlone = regexp.MustCompile(`^the (?:update|rewrite) left .+ unchanged$`)

// packageReasonLines names the packages an item is manual for, with the
// reason, as the lines of the packages left out of an update are. The lockfile
// is said not to have changed only when the detail says the update left it
// unchanged. The lines of planned follow them.
func (b *planBuilder) packageReasonLines(e *planEntry, tag planTag, label string, li remediation.LanguageItem, pkgs []remediation.LanguagePackage, planned []pkgLine) {
	items := make([]pkgLine, 0, len(pkgs)+len(planned))
	for _, p := range pkgs {
		items = append(items, b.pkgLineOf(li, p))
	}
	items = append(items, planned...)
	b.packageLines(e, tag, label, path.Base(languageFile(li)), items)
}

// pkgLineOf is the line of a package of an item that needs a person.
func (b *planBuilder) pkgLineOf(li remediation.LanguageItem, p remediation.LanguagePackage) pkgLine {
	var chain *remediation.ChainUpdate
	if li.Update != nil {
		chain = li.Update.Chain
	}
	return pkgLine{name: p.Name, from: p.Installed, target: p.SelectionLowerBound, reason: p.Reason, chain: chain,
		unchanged:    lockfileLeftAlone.MatchString(p.Detail) || lockfileLeftAlone.MatchString(li.Detail),
		lockVersions: lockVersions(p), inFile: len(p.Occurrences) > 0, bom: p.MavenBOM, manager: li.Manager, partOf: globalOwners(p), hint: p.Hint()}
}

// --- the message ---

// SlackFingerprint identifies what the Slack fix plan message shows: the
// summary, the images, files, pull requests and proposals, and the notes. A
// pull request opened in this cycle counts as an open one, so it is announced
// once. It does not depend on the language. A plan with nothing to show has
// the empty fingerprint.
func (p *PlanInfo) SlackFingerprint() string {
	v := buildPlanView(p, enMessages, planOpts{normalize: true})
	if v.empty() {
		return ""
	}
	h := sha256.New()
	write := func(s string) { h.Write([]byte(s)); h.Write([]byte{0}) }
	write(v.summary)
	write(v.unavailable)
	for _, g := range v.groups {
		write("group")
		for _, s := range g.headings {
			write(s)
		}
		for _, s := range g.lines {
			write(s)
		}
	}
	for _, s := range v.notes {
		write(s)
	}
	for _, s := range v.detail {
		write(s)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// SlackDue reports whether the Slack fix plan message is sent: when what it
// shows has changed, and on the weekly day when it has anything to show.
func (p *PlanInfo) SlackDue() bool {
	if p == nil {
		return false
	}
	if p.SlackChanged {
		return true
	}
	return p.Weekly && !buildPlanView(p, enMessages, planOpts{openOnly: true}).empty()
}

// EmailDue reports whether the email fix plan is sent: when what it shows has
// changed for email, and on the weekly day when it has anything to show.
func (p *PlanInfo) EmailDue() bool {
	if p == nil {
		return false
	}
	if p.EmailChanged {
		return true
	}
	return p.Weekly && !buildPlanView(p, enMessages, planOpts{openOnly: true}).empty()
}

// BuildPlanMessages renders the fix plan message of m, or nothing when it is
// not due.
func BuildPlanMessages(m Message, lang Language) []SlackMessage {
	return buildPlanMessages(m, messagesFor(lang), defaultRenderLimits)
}

func buildPlanMessages(m Message, msg messages, lim RenderLimits) []SlackMessage {
	p := m.Plan
	if !p.SlackDue() {
		return nil
	}
	lim = lim.normalized()
	// The list of a day with nothing new is what is still waiting for a
	// person; a changed plan is shown whole.
	v := buildPlanView(p, msg, planOpts{openOnly: !p.SlackChanged})
	if m.Report.GenericWebhookConfigured && len(v.groups) > 0 {
		v.notes = append(v.notes, trimNL(msg.DetailsInWebhook))
	}

	head := []string{trimNL(msg.PlanHeading)}
	plain := v.summary
	switch {
	case v.unavailable != "":
		head = append(head, v.unavailable)
		plain = strings.Trim(v.unavailable, "_")
	case v.summary != "":
		head = append(head, v.summary)
	case len(v.groups) == 0 && len(v.notes) == 0:
		head = append(head, trimNL(msg.PlanNothing))
		plain = trimNL(msg.PlanNothing)
	}
	var l layout
	l.section(lim, head, false)
	for _, g := range v.groups {
		l.group()
		lines := append(append([]string(nil), g.headings...), g.lines...)
		l.emit(unit{blocks: sectionBlocks(lines, lim.MaxTextUnits), contTitle: g.headings[0]}, false)
	}
	if len(v.notes) > 0 {
		l.group()
		l.section(lim, v.notes, false)
	}

	date := (&chView{r: m.Report}).dateText()
	return splitUnits(l.units, splitSpec{
		lim: lim,
		lead: func(n, total int) string {
			return trimNL(msg.PlanHeading) + fmt.Sprintf(msg.ChannelContinued, n, total)
		},
		cont: msg.ThreadContinued,
		fallback: func(info msgInfo) string {
			if info.n > 1 {
				return fmt.Sprintf(msg.PlanFallbackCont, date, info.n, info.total)
			}
			return fmt.Sprintf(msg.PlanFallback, date, plain)
		},
	})
}
