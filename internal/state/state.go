// Package state persists per-finding first-seen timestamps between scan cycles
// and computes the cycle-over-cycle diff that drives diff-mode notifications
// (docs/NOTIFICATION_SPEC.md §7). Repeating an identical report every day trains
// the reader to ignore it; the diff surfaces what changed and ages what didn't.
package state

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/analyze"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

// version guards the on-disk format. A mismatch is treated as no prior state
// (everything re-reported as new) rather than an error.
const version = 1

// Entry is the persisted memory of one finding (one package within one image,
// across all Trivy statuses).
//
// Priority was added for Phase 1+ (docs/TRIAGE_SPEC.md §5.3) without a version
// bump: state written before the upgrade simply decodes with an empty
// Priority, which suppresses escalation detection for one cycle instead of
// re-announcing every known finding as new.
//
// ContentID was added for the Phase 2 identity model without a version
// bump, for the same reason: it is the single verified entity confirmed
// running under the entry's reference as of this cycle. It is left empty
// whenever that isn't a safe claim to make this cycle — the reference is
// Ambiguous (more than one distinct entity) or partially failed to scan (a
// sibling entity's success this cycle makes the stored identity stale) —
// rather than showing a possibly-stale identity as if it were current. A
// *full* scan failure is the
// existing untouched-carryover case (see Compute): the entry, ContentID
// included, is left exactly as it was, since no other entity's success this
// cycle could have made it misleading.
type Entry struct {
	FirstSeen time.Time `json:"first_seen"`
	Fixable   bool      `json:"fixable"` // any of the package's CVEs has a fix
	Priority  string    `json:"priority,omitempty"`
	VulnIDs   []string  `json:"vuln_ids"`
	ContentID string    `json:"content_id,omitempty"`
}

// ImageMeta is the persisted identity record for one reference. ContentIDs/
// Ambiguous are Docker-observed data (analyze.ImageObservation.ContentIDs
// survives a Trivy scan failure unchanged, chunk1), so Compute refreshes
// them every cycle regardless of scan outcome. LastSeen alone follows a
// stricter rule: only updated on a cycle where every entity under the
// reference scanned successfully; otherwise the last confirmed value carries
// over.
type ImageMeta struct {
	ContentIDs      []string  `json:"content_ids,omitempty"`
	RegistryDigests []string  `json:"registry_digests,omitempty"`
	Ambiguous       bool      `json:"ambiguous,omitempty"`
	LastSeen        time.Time `json:"last_seen"`
}

// State is everything remembered between scan cycles.
//
// LastFullReport was added for the Slack thread report without a version
// bump: older state decodes with a nil ref, which simply forces one fresh
// full-report post.
//
// Images was added for the Phase 2 identity model without a version bump:
// older state decodes with a nil map, and the first cycle on the new binary
// simply records the current identity information as a fresh baseline.
type State struct {
	Version        int                  `json:"version"`
	Findings       map[string]Entry     `json:"findings"`         // keyed by image \t package
	EOSL           map[string]time.Time `json:"eosl"`             // image -> first seen as EOL
	Images         map[string]ImageMeta `json:"images,omitempty"` // keyed by reference
	LastFullReport *ReportRef           `json:"last_full_report,omitempty"`
}

// ReportRef locates the Slack message whose thread carries the most recent
// full open-findings report. Channel records the configured destination at
// post time: if notifications later move elsewhere, the permalink points at a
// thread the new channel's readers may not see, so the ref is treated as
// absent and the next cycle posts a fresh full report.
type ReportRef struct {
	Channel   string `json:"channel_id"`
	TS        string `json:"ts"`
	Permalink string `json:"permalink"`
}

// ValidFor reports whether the ref can serve as the "last full report" link
// for the given destination channel. Safe to call on a nil ref.
func (r *ReportRef) ValidFor(channel string) bool {
	return r != nil && r.TS != "" && r.Permalink != "" && r.Channel == channel
}

// empty returns a fresh, usable state.
func empty() State {
	return State{
		Version:  version,
		Findings: map[string]Entry{},
		EOSL:     map[string]time.Time{},
		Images:   map[string]ImageMeta{},
	}
}

// key identifies a finding. Tab is not a valid character in image references or
// package names, so the compound key is unambiguous.
func key(image, pkg string) string { return image + "\t" + pkg }

func keyImage(k string) string {
	if i := strings.IndexByte(k, '\t'); i >= 0 {
		return k[:i]
	}
	return k
}

func keyPackage(k string) string {
	if i := strings.IndexByte(k, '\t'); i >= 0 {
		return k[i+1:]
	}
	return ""
}

// FirstSeen returns when the finding (image, pkg) was first observed. ok is
// false for findings this state has never recorded.
func (s State) FirstSeen(image, pkg string) (time.Time, bool) {
	e, ok := s.Findings[key(image, pkg)]
	return e.FirstSeen, ok
}

// FileStore persists State as a single JSON file, written atomically.
type FileStore struct {
	Path string
}

// Load reads the state file. A missing file or a version mismatch yields empty
// state and no error (first run / format change); only unreadable or corrupt
// data is an error, so the caller can decide to fall back rather than
// re-notify everything silently.
func (s FileStore) Load() (State, error) {
	data, err := os.ReadFile(s.Path)
	if os.IsNotExist(err) {
		return empty(), nil
	}
	if err != nil {
		return empty(), fmt.Errorf("read state %s: %w", s.Path, err)
	}
	var st State
	if err := json.Unmarshal(data, &st); err != nil {
		return empty(), fmt.Errorf("parse state %s: %w", s.Path, err)
	}
	if st.Version != version {
		return empty(), nil
	}
	if st.Findings == nil {
		st.Findings = map[string]Entry{}
	}
	if st.EOSL == nil {
		st.EOSL = map[string]time.Time{}
	}
	if st.Images == nil {
		st.Images = map[string]ImageMeta{}
	}
	return st, nil
}

// Save writes the state atomically (temp file + rename) so a crash mid-write
// never leaves a truncated file behind.
func (s FileStore) Save(st State) error {
	if err := os.MkdirAll(filepath.Dir(s.Path), 0o755); err != nil {
		return fmt.Errorf("create state dir: %w", err)
	}
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}
	tmp := s.Path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return fmt.Errorf("write state: %w", err)
	}
	if err := os.Rename(tmp, s.Path); err != nil {
		return fmt.Errorf("replace state: %w", err)
	}
	return nil
}

// ChangeKind classifies why a finding appears in the "new" section.
type ChangeKind string

const (
	KindNew        ChangeKind = "new"         // package not seen before
	KindEscalated  ChangeKind = "escalated"   // known package's priority rose (e.g. a CVE entered KEV)
	KindNewCVEs    ChangeKind = "new_cves"    // known package gained CVEs
	KindNowFixable ChangeKind = "now_fixable" // known package's fix became available
)

// Change is one finding that is new or changed since the previous scan. Groups
// carries the package's current per-status groups (usually one; a package can
// have both fixed and unfixed CVEs).
type Change struct {
	Image   string
	Package string
	Kind    ChangeKind
	NewCVEs int // for KindNewCVEs: how many CVE IDs are new
	Groups  []analyze.PackageGroup
}

// Resolved is a finding present in the previous scan but gone now: fixed,
// image updated, or the container no longer running.
type Resolved struct {
	Image   string
	Package string
}

// ImageReplacement is one reference whose running content changed between
// scans. It fires only when both the previous and current verified
// ContentID sets are non-empty and differ as sets — never on first
// observation (an empty-to-non-empty transition is the identity model
// recording data for the first time, not a replacement). Detection does not
// depend on scan success: ContentIDs is
// Docker-observed and survives a Trivy scan failure unchanged (see
// replacedImages), so a genuine replacement is still reported even if the new
// content's own scan failed.
type ImageReplacement struct {
	Ref            string
	PrevContentIDs []string
	ContentIDs     []string
}

// Diff is what changed between the previous scan and the current report, plus
// the ambient "still open" summary used for the heartbeat line.
type Diff struct {
	NewEOSL      []string
	ResolvedEOSL []string
	Changes      []Change
	Resolved     []Resolved
	Replaced     []ImageReplacement

	OpenCritical int
	OpenHigh     int
	OpenImages   int
	OldestOpen   time.Time // zero when nothing is open

	// Triage breakdown (zero when triage is off). Counts are package groups,
	// the unit shown to the user. OldestUrgent ages only act_now/watch (and
	// EOSL) findings: an old "low" is the triage working as designed, not debt.
	OpenActNow   int
	OpenWatch    int
	OpenLow      int
	OldestUrgent time.Time
}

// HasChanges reports whether anything is new or resolved since the last scan.
func (d Diff) HasChanges() bool {
	return len(d.Changes) > 0 || len(d.Resolved) > 0 || len(d.NewEOSL) > 0 || len(d.ResolvedEOSL) > 0 || len(d.Replaced) > 0
}

// OldestOpenDays is the age in whole days of the oldest open finding at now,
// 0 when nothing is open or everything was first seen today.
func (d Diff) OldestOpenDays(now time.Time) int { return wholeDays(d.OldestOpen, now) }

// OldestUrgentDays is the age in whole days of the oldest open act_now/watch
// (or EOSL) finding at now.
func (d Diff) OldestUrgentDays(now time.Time) int { return wholeDays(d.OldestUrgent, now) }

func wholeDays(t, now time.Time) int {
	if t.IsZero() {
		return 0
	}
	days := int(now.Sub(t).Hours() / 24)
	if days < 0 {
		return 0
	}
	return days
}

// current is the merged view of one finding across the report's sections.
type current struct {
	groups  []analyze.PackageGroup
	ids     map[string]bool
	fixable bool
}

// Compute diffs the report against the previous state and returns the diff and
// the next state to persist. Findings of images whose scan failed this cycle
// are carried over untouched — a transient pull failure must not report every
// known finding as resolved and re-announce it tomorrow.
//
// Report.Images (the identity inventory) is the sole source for two things:
// updating State.Images, and classifying each reference as fully failed
// (every entity failed to scan; existing behavior, carry findings over
// untouched and suppress Resolved), partially failed (some but not all
// entities failed; carry over the findings only the failed entity
// contributed, and conservatively merge the findings both contributed, so a
// sibling entity's temporary scan failure can never look like "fixed" or
// "gone" and then reappear as new/escalated once it recovers), or fully
// resolved (ordinary diffing, unaffected).
func Compute(prev State, r analyze.Report) (Diff, State) {
	next := empty()
	now := r.GeneratedAt

	// refContentID holds, for each reference, the single verified ContentID
	// safe to publish as "the" entity running there this cycle: every entity
	// under the reference had a Docker-observed ContentID this cycle
	// (IdentityResolved — independent of scan success), there is exactly one
	// distinct value among them (not Ambiguous), and the reference did not
	// (partially) fail to scan. Every other case — Ambiguous, a mix of
	// resolved and reference-fallback entities, or a (partial) scan failure —
	// is deliberately left absent.
	refContentID := map[string]string{}
	fullyFailedRef := map[string]bool{}
	partiallyFailedRef := map[string]bool{}
	for _, o := range r.Images {
		if o.ScanFailed {
			fullyFailedRef[o.Ref] = true
		}
		if o.PartialFailure {
			partiallyFailedRef[o.Ref] = true
		}
		if o.IdentityResolved && !o.Ambiguous && !o.ScanFailed && !o.PartialFailure && len(o.ContentIDs) == 1 {
			refContentID[o.Ref] = o.ContentIDs[0]
		}
	}
	next.Images = nextImages(prev.Images, r.Images, now)
	d := Diff{Replaced: replacedImages(prev.Images, r.Images)}

	cur := map[string]*current{}
	order := []string{} // report order: sections are already priority-sorted
	for _, section := range [][]analyze.ImageFindings{r.Actionable, r.Watch, r.WontFix} {
		for _, img := range section {
			for _, g := range img.Packages {
				k := key(img.Image, g.Package)
				c := cur[k]
				if c == nil {
					c = &current{ids: map[string]bool{}}
					cur[k] = c
					order = append(order, k)
				}
				c.groups = append(c.groups, g)
				for _, id := range g.VulnIDs() {
					c.ids[id] = true
				}
				if g.Status == scanner.StatusFixed {
					c.fixable = true
				}
			}
		}
	}

	for _, k := range order {
		ref := keyImage(k)
		c := cur[k]
		ids := make([]string, 0, len(c.ids))
		for id := range c.ids {
			ids = append(ids, id)
		}
		sort.Strings(ids)

		prevE, known := prev.Findings[k]
		firstSeen := now
		if known {
			firstSeen = prevE.FirstSeen
		}
		prio := analyze.MaxPriority(c.groups)

		// Conservative merge: a partially-failed reference's cur view only
		// reflects the entities that scanned successfully this cycle, so what
		// gets persisted must not regress below what a sibling entity
		// contributed last time it succeeded: VulnIDs is the union of prev and
		// cur, Fixable is prev||cur, and Priority is whichever is higher.
		storeIDs, storeFixable, storePrio := ids, c.fixable, prio
		if partiallyFailedRef[ref] && known {
			storeIDs = mergeSorted(ids, prevE.VulnIDs)
			storeFixable = storeFixable || prevE.Fixable
			if prevPrio := analyze.Priority(prevE.Priority); prevPrio.Rank() > storePrio.Rank() {
				storePrio = prevPrio
			}
		}
		next.Findings[k] = Entry{
			FirstSeen: firstSeen, Fixable: storeFixable, Priority: string(storePrio),
			VulnIDs: storeIDs, ContentID: refContentID[ref],
		}

		change := Change{Image: ref, Package: keyPackage(k), Groups: c.groups}
		switch {
		case !known:
			change.Kind = KindNew
		// Escalation outranks the other kinds: "this got urgent" is the news,
		// whatever caused it. An empty stored priority (state written before
		// the triage upgrade, or triage previously off) never escalates —
		// there is no baseline to have risen from. Degraded intel suppresses
		// escalations too: severity-only fallback inflates every priority, and
		// announcing that en masse would turn a feed outage into a false alarm
		// storm (the header warning carries the news instead).
		case !r.Intel.Degraded() && prevE.Priority != "" && prio.Rank() > analyze.Priority(prevE.Priority).Rank():
			change.Kind = KindEscalated
		case countNew(ids, prevE.VulnIDs) > 0:
			change.Kind = KindNewCVEs
			change.NewCVEs = countNew(ids, prevE.VulnIDs)
		case c.fixable && !prevE.Fixable:
			change.Kind = KindNowFixable
		default:
			continue // unchanged
		}
		d.Changes = append(d.Changes, change)
	}

	for k, e := range prev.Findings {
		if _, ok := cur[k]; ok {
			continue
		}
		ref := keyImage(k)
		switch {
		case fullyFailedRef[ref]:
			// Existing full-failure behavior: carry the entry over exactly as
			// it was, ContentID included — there is no sibling entity whose
			// success could make a stale ContentID misleading here.
			next.Findings[k] = e
			continue
		case partiallyFailedRef[ref]:
			// This finding belonged to the one entity that failed to scan
			// this cycle while a sibling under the same ref succeeded. Carry
			// it over unknown-but-not-resolved, and blank ContentID — unlike
			// the full-failure case, a sibling's success this cycle makes it
			// misleading to keep asserting an old identity as current.
			e.ContentID = ""
			next.Findings[k] = e
			continue
		}
		d.Resolved = append(d.Resolved, Resolved{Image: ref, Package: keyPackage(k)})
	}
	sort.Slice(d.Resolved, func(i, j int) bool {
		if d.Resolved[i].Image != d.Resolved[j].Image {
			return d.Resolved[i].Image < d.Resolved[j].Image
		}
		return d.Resolved[i].Package < d.Resolved[j].Package
	})

	for _, img := range r.EOSLImages {
		firstSeen, known := prev.EOSL[img]
		if !known {
			firstSeen = now
			d.NewEOSL = append(d.NewEOSL, img)
		}
		next.EOSL[img] = firstSeen
	}
	for img := range prev.EOSL {
		if _, ok := next.EOSL[img]; ok {
			continue
		}
		// Same conservative carryover as findings: a reference that lost its
		// only EOSL-reporting entity to a (partial) scan failure this cycle
		// must not look like the base image got un-EOL'd.
		if fullyFailedRef[img] || partiallyFailedRef[img] {
			next.EOSL[img] = prev.EOSL[img]
			continue
		}
		d.ResolvedEOSL = append(d.ResolvedEOSL, img)
	}
	sort.Strings(d.ResolvedEOSL)

	d.OpenImages = r.AffectedImageCount()
	for _, e := range next.Findings {
		if d.OldestOpen.IsZero() || e.FirstSeen.Before(d.OldestOpen) {
			d.OldestOpen = e.FirstSeen
		}
		switch analyze.Priority(e.Priority) {
		case analyze.PriorityActNow:
			d.OpenActNow++
		case analyze.PriorityWatch:
			d.OpenWatch++
		case analyze.PriorityLow:
			d.OpenLow++
		}
		if urgent(e.Priority) && (d.OldestUrgent.IsZero() || e.FirstSeen.Before(d.OldestUrgent)) {
			d.OldestUrgent = e.FirstSeen
		}
	}
	for _, t := range next.EOSL {
		if d.OldestOpen.IsZero() || t.Before(d.OldestOpen) {
			d.OldestOpen = t
		}
		if d.OldestUrgent.IsZero() || t.Before(d.OldestUrgent) {
			d.OldestUrgent = t
		}
	}
	for _, section := range [][]analyze.ImageFindings{r.Actionable, r.Watch, r.WontFix} {
		for _, img := range section {
			d.OpenCritical += img.CriticalCount()
			d.OpenHigh += img.TotalCount() - img.CriticalCount()
		}
	}
	return d, next
}

// nextImages builds State.Images for the next cycle from this cycle's
// identity inventory. ContentIDs/Ambiguous are Docker-observed data
// (analyze.ImageObservation.ContentIDs survives a Trivy scan failure
// unchanged, chunk1) and so are refreshed every cycle regardless of scan
// outcome. RegistryDigests only ever comes from a successful, resolved scan's
// Trivy Metadata (analyze.Build already only populates it from those), so a
// cycle with no such scan for a reference correctly records none rather than
// keeping a possibly-stale digest from a different entity. LastSeen alone
// follows a stricter rule: updated only when every entity under the
// reference scanned successfully this cycle; otherwise the last confirmed
// value carries over.
func nextImages(prevImages map[string]ImageMeta, obs []analyze.ImageObservation, now time.Time) map[string]ImageMeta {
	next := map[string]ImageMeta{}
	for _, o := range obs {
		meta := ImageMeta{ContentIDs: o.ContentIDs, RegistryDigests: o.RegistryDigests, Ambiguous: o.Ambiguous}
		if !o.ScanFailed && !o.PartialFailure {
			meta.LastSeen = now
		} else if prevMeta, ok := prevImages[o.Ref]; ok {
			meta.LastSeen = prevMeta.LastSeen
		}
		next[o.Ref] = meta
	}
	return next
}

// replacedImages detects image-replacement events: a reference whose
// verified ContentID set is non-empty both last cycle and this cycle, and
// differs between the two. ContentIDs is Docker-observed and independent of
// scan success (see nextImages), so this comparison is not gated on
// ScanFailed/PartialFailure — the set is accurate either way.
func replacedImages(prevImages map[string]ImageMeta, obs []analyze.ImageObservation) []ImageReplacement {
	var out []ImageReplacement
	for _, o := range obs {
		prevMeta, known := prevImages[o.Ref]
		if !known || len(prevMeta.ContentIDs) == 0 || len(o.ContentIDs) == 0 {
			continue // migration-initial (or never-resolved) on either side: never fires
		}
		if !equalStrings(prevMeta.ContentIDs, o.ContentIDs) {
			out = append(out, ImageReplacement{Ref: o.Ref, PrevContentIDs: prevMeta.ContentIDs, ContentIDs: o.ContentIDs})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Ref < out[j].Ref })
	return out
}

// equalStrings reports whether two already-sorted string slices hold the same
// set of values.
func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// mergeSorted returns the sorted union of two ID sets.
func mergeSorted(a, b []string) []string {
	seen := make(map[string]bool, len(a)+len(b))
	out := make([]string, 0, len(a)+len(b))
	for _, id := range a {
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	for _, id := range b {
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

// urgent reports whether a stored priority counts toward the heartbeat's
// staleness escalation.
func urgent(p string) bool {
	pr := analyze.Priority(p)
	return pr == analyze.PriorityActNow || pr == analyze.PriorityWatch
}

// countNew counts ids not present in prev (both sorted or not; prev is small).
func countNew(ids, prev []string) int {
	seen := map[string]bool{}
	for _, id := range prev {
		seen[id] = true
	}
	n := 0
	for _, id := range ids {
		if !seen[id] {
			n++
		}
	}
	return n
}
