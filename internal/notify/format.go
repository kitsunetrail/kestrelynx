// Package notify formats an analyze.Report and delivers it to Slack and/or a
// generic webhook. Formatting (pure) is kept separate from delivery (HTTP) so
// the message content is unit-testable without a network.
package notify

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/analyze"
	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
	"github.com/kitsunetrail/kestrelynx/internal/state"
)

const timeLayout = "2006-01-02 15:04"

// collapsePreview caps how many package names are listed when the lower-risk
// fixes are collapsed into a single summary line.
const collapsePreview = 5

// staleDays is the age at which the "still open" heartbeat escalates: after
// this many days an unresolved finding stops being news and starts being debt.
const staleDays = 14

// writeHeader renders the product header line shared by full and diff-mode
// Slack messages. A named environment gets inserted once, right after the
// product name; the unnamed default environment renders exactly the text
// that predates the environment model, so a single-host deployment that
// never set environment.name sees byte-identical output. Renderers with no
// header line of their own (e.g. the thread report) do not call this and are
// unaffected.
func writeHeader(b *strings.Builder, r analyze.Report) {
	if r.Environment.Name != "" {
		fmt.Fprintf(b, "🛡️ *KestreLynx* [%s] — scan results for %s\n", r.Environment.Name, r.GeneratedAt.Format(timeLayout))
		return
	}
	fmt.Fprintf(b, "🛡️ *KestreLynx* — scan results for %s\n", r.GeneratedAt.Format(timeLayout))
}

// FormatSlackText renders a report as a Slack message body (mrkdwn). It leads
// with a one-line priority summary, then shows the findings that need a human
// decision — EOL base images, CRITICALs, and major-version bumps — in full,
// while collapsing the bulk of low-risk fixes into a per-image one-liner. The
// full, unabridged data is always available via the generic webhook payload.
// A report with no issues yields a short "all clear" message — but even then,
// an unresolved (reference-fallback) image must still be called out: "clean"
// from a scan that never confirmed which entity it scanned is not the same
// claim as "confirmed clean", and the short-circuit below must not silently
// swallow that distinction.
func FormatSlackText(r analyze.Report) string {
	var b strings.Builder
	writeHeader(&b, r)
	fmt.Fprintf(&b, "%d images scanned, %d affected\n", r.ImagesTotal, r.AffectedImageCount())

	if !r.HasIssues() {
		b.WriteString("\n✅ All clear (no HIGH/CRITICAL vulnerabilities found)\n")
		writeUnresolvedRefs(&b, r)
		return b.String()
	}

	writeFullBody(&b, r)
	return b.String()
}

// writeFullBody renders the complete open-findings view (headline, EOSL,
// sections, scan failures). Shared by full mode and the diff-mode weekly
// full report. With triage on, the view is organized by priority instead of
// fix status (docs/TRIAGE_SPEC.md §6).
func writeFullBody(b *strings.Builder, r analyze.Report) {
	if r.Triage {
		writeTriageBody(b, r)
		return
	}
	writeHeadline(b, summarize(r))
	byRef := imagesByRef(r)

	if len(r.EOSLImages) > 0 {
		b.WriteString("\n*⛔ Base OS end-of-life (top priority)*\n")
		for _, img := range r.EOSLImages {
			fmt.Fprintf(b, "• %s — base OS is EOL (no more security updates coming)\n", refLabel(img, byRef))
		}
	}

	collapsed := writeActionable(b, r.Actionable, byRef)
	writeSection(b, "ℹ️ No fix yet (affected / waiting on upstream)", r.Watch, false, byRef)
	writeSection(b, "🔕 Upstream won't fix (will_not_fix)", r.WontFix, false, byRef)
	writeScanErrors(b, r.ScanErrors, byRef)
	writeUnresolvedRefs(b, r)

	if collapsed > 0 {
		fmt.Fprintf(b, "\n_%d lower-risk fix(es) summarized — full list in the generic webhook payload._\n", collapsed)
	}
}

// FormatSlackDiffText renders the diff-mode Slack message: what is new or
// resolved since the previous scan, then a one-line "open now" summary with the
// age of the oldest unresolved finding (docs/NOTIFICATION_SPEC.md §7). Repeating
// the same list daily trains the reader to ignore it; age does the reminding
// instead. When fullReport is true (weekly digest day) the one-liner is replaced
// by the complete open-findings view.
func FormatSlackDiffText(r analyze.Report, d state.Diff, fullReport bool) string {
	var b strings.Builder
	writeHeader(&b, r)
	fmt.Fprintf(&b, "%d images scanned, %d affected\n", r.ImagesTotal, r.AffectedImageCount())

	byRef := imagesByRef(r)

	// Replaced is handled ahead of the "No changes" check: it is itself a
	// change (state.Diff.HasChanges() includes it), so it must never be
	// silently absorbed into a heartbeat that only looks at findings. A clean
	// image's replacement is news too.
	writeReplaced(&b, d.Replaced)

	if !d.HasChanges() && !fullReport {
		b.WriteString("\nNo changes since last scan.\n")
		writeScanErrors(&b, r.ScanErrors, byRef)
		writeAnyOpenNow(&b, r, d)
		// A clean, unresolved (reference-fallback) image must not go
		// unmentioned just because it has no changes/findings to report —
		// silence here would read as "confirmed clean".
		writeUnresolvedRefs(&b, r)
		return b.String()
	}

	if len(d.NewEOSL) > 0 {
		b.WriteString("\n*⛔ New: base OS end-of-life (top priority)*\n")
		for _, img := range d.NewEOSL {
			fmt.Fprintf(&b, "• %s — base OS is EOL (no more security updates coming)\n", refLabel(img, byRef))
		}
	}

	if r.Triage {
		writeIntelWarning(&b, r)
		writeTriageChanges(&b, r, d.Changes)
	} else {
		writeChanges(&b, d.Changes, byRef)
	}
	writeResolved(&b, d, byRef)

	if fullReport {
		b.WriteString("\n*📋 Weekly full report — everything currently open*\n")
		// writeFullBody (via writeTriageBody or its own tail) carries its own
		// writeUnresolvedRefs call, so it is not repeated here.
		writeFullBody(&b, r)
	} else {
		writeScanErrors(&b, r.ScanErrors, byRef)
		writeAnyOpenNow(&b, r, d)
		writeUnresolvedRefs(&b, r)
	}
	return b.String()
}

// writeReplaced renders the images whose verified running content changed
// since the previous scan: one line per image, previous content digest(s)
// vs current.
// Fires independently of findings — even a clean image's replacement is news
// the diff exists to carry.
func writeReplaced(b *strings.Builder, replaced []state.ImageReplacement) {
	if len(replaced) == 0 {
		return
	}
	fmt.Fprintf(b, "\n*🔄 Image content changed (%d)*\n", len(replaced))
	for _, rep := range replaced {
		fmt.Fprintf(b, "• %s: image updated (%s → %s)\n", rep.Ref, joinShortDigests(rep.PrevContentIDs), joinShortDigests(rep.ContentIDs))
	}
}

// joinShortDigests renders a ContentID set as short, comma-joined digests for
// display. The sets themselves (state.ImageReplacement's Prev/ContentIDs) are
// already sorted upstream, so this only shortens each value — it never
// reorders.
func joinShortDigests(ids []string) string {
	short := make([]string, len(ids))
	for i, id := range ids {
		short[i] = shortDigest(id)
	}
	return strings.Join(short, ", ")
}

// shortDigest is the display form of a content digest across the notify
// layer: the "sha256:" prefix stripped, then the leading 12 hex characters
// — a single rule shared by the Replaced lines and the ambiguous-reference
// heading annotation below.
func shortDigest(contentID string) string {
	hex := strings.TrimPrefix(contentID, "sha256:")
	if len(hex) > 12 {
		return hex[:12]
	}
	return hex
}

// imagesByRef indexes the report's identity inventory by reference, serving
// two different kinds of lookup that must not be confused:
//   - Per-entity renderers with an analyze.ImageFindings in hand (imageLabel,
//     imagePayloads) use it only for the reference's aggregate Ambiguous
//     status and RegistryDigests — never for IdentityResolved, since that
//     aggregate would misreport a resolved entity as unresolved whenever a
//     sibling under the same reference fell back to scanning by reference.
//     Per-entity resolution is ImageFindings.ContentID's own job.
//   - Reference-only renderers with nothing but a bare ref string (refLabel:
//     diff/EOSL/scan-error lines that are reference-keyed by design) have no
//     per-entity ContentID to fall back on, so the reference's aggregate
//     IdentityResolved — "did every entity under this ref resolve this
//     cycle" — is the coarsest signal available and the correct one to use
//     there.
//
// Ambiguous is also computed report-wide here rather than re-derived from the
// status sections, which — split across Actionable/Watch/WontFix — could miss
// a sibling entity landing in a different bucket.
func imagesByRef(r analyze.Report) map[string]analyze.ImageObservation {
	out := make(map[string]analyze.ImageObservation, len(r.Images))
	for _, o := range r.Images {
		out[o.Ref] = o
	}
	return out
}

// identityUnconfirmedText is the single wording for "this identity could not
// be pinned this cycle", shared by every rendering context so a future
// wording change cannot silently drift between them: the entity-level
// heading annotation (imageLabel), the reference-level line annotation
// (refLabel), and the cross-cutting summary list (writeUnresolvedRefs).
const identityUnconfirmedText = "identity unconfirmed: scanned by reference"

// imageLabel is the display name for one ImageFindings entry, annotated per
// the identity model: unresolved (ContentID empty — a reference-fallback
// scan) gets an explicit warning that the entity actually running there was
// never confirmed; resolved-but-ambiguous (more than one distinct entity
// currently running under the same reference) gets the short content digest
// appended so the per-entity sections can be told apart. The ordinary
// single-entity case (the vast majority) renders exactly as before.
func imageLabel(img analyze.ImageFindings, byRef map[string]analyze.ImageObservation) string {
	switch {
	case img.ContentID == "":
		return img.Image + " — " + identityUnconfirmedText
	case byRef[img.Image].Ambiguous:
		return img.Image + " (" + shortDigest(img.ContentID) + ")"
	default:
		return img.Image
	}
}

// refLabel is the reference-level counterpart of imageLabel, for renderers
// that only ever have a bare reference string — not an analyze.ImageFindings
// entry with its own ContentID — because they sit downstream of the
// reference-keyed diff history or the per-reference EOSL/scan-error lists
// (state.Change.Image, state.Resolved.Image, analyze.ScanError.Image, an EOSL
// image name: diff history stays reference-keyed on purpose, so per-entity
// ContentID is not available to restore here). It appends the same warning
// whenever the reference's identity inventory (analyze.Report.Images, looked
// up by ref) says at least one entity running under it was unresolved this
// cycle. Unlike imageLabel it never appends a short digest for an Ambiguous
// reference: a diff/EOSL/error line is already a union across every entity
// running under the reference, so there is no single content id to show. A
// reference absent from byRef — not scanned this cycle, e.g. a Resolved/gone
// image — is left unannotated: no data is not the same claim as
// "unconfirmed".
func refLabel(ref string, byRef map[string]analyze.ImageObservation) string {
	if obs, ok := byRef[ref]; ok && !obs.IdentityResolved {
		return ref + " — " + identityUnconfirmedText
	}
	return ref
}

// unresolvedRefsLine renders the cross-cutting summary of every reference
// with at least one unresolved entity this cycle: a reference-fallback scan
// of a *clean* image must not go unmentioned just because it produced no
// findings, no EOSL warning, and no scan error — silence there would read as
// "confirmed clean" when it is really "scanned by reference, unconfirmed".
// "" when every reference resolved this cycle. Sorted for stable output.
// Shared by writeUnresolvedRefs (the Slack messages) and the thread report,
// so the two never drift apart.
func unresolvedRefsLine(r analyze.Report) string {
	var refs []string
	for _, o := range r.Images {
		if !o.IdentityResolved {
			refs = append(refs, o.Ref)
		}
	}
	if len(refs) == 0 {
		return ""
	}
	sort.Strings(refs)
	return fmt.Sprintf("⚠️ %s — %s\n", identityUnconfirmedText, strings.Join(refs, ", "))
}

// writeUnresolvedRefs appends unresolvedRefsLine to a Slack message body, if
// non-empty. Fires independently of findings/EOSL/scan errors. Doubling up
// with a heading-level annotation (imageLabel/refLabel) elsewhere in the same
// message is expected and fine — both draw from identityUnconfirmedText, so
// the wording never drifts between the two.
func writeUnresolvedRefs(b *strings.Builder, r analyze.Report) {
	if line := unresolvedRefsLine(r); line != "" {
		b.WriteString("\n" + line)
	}
}

// writeAnyOpenNow picks the heartbeat style for the report's mode.
func writeAnyOpenNow(b *strings.Builder, r analyze.Report, d state.Diff) {
	if r.Triage {
		writeTriageOpenNow(b, r, d)
		return
	}
	writeOpenNow(b, r, d)
}

// writeChanges renders the new/changed findings grouped per image, in report
// priority order, each package line in full detail.
func writeChanges(b *strings.Builder, changes []state.Change, byRef map[string]analyze.ImageObservation) {
	if len(changes) == 0 {
		return
	}
	fmt.Fprintf(b, "\n*🆕 New since last scan (%d)*\n", len(changes))
	lastImage := ""
	for _, c := range changes {
		if c.Image != lastImage {
			fmt.Fprintf(b, "%s %s\n", changesEmoji(c), refLabel(c.Image, byRef))
			lastImage = c.Image
		}
		for _, g := range c.Groups {
			writePackage(b, g, g.Status == scanner.StatusFixed, changeSuffix(c))
		}
	}
}

// changeSuffix annotates why a known package reappears in the new section.
func changeSuffix(c state.Change) string {
	switch c.Kind {
	case state.KindNewCVEs:
		return fmt.Sprintf(" — %d new CVE(s)", c.NewCVEs)
	case state.KindNowFixable:
		return " — fix now available"
	default:
		return ""
	}
}

func changesEmoji(c state.Change) string {
	for _, g := range c.Groups {
		if g.Critical > 0 {
			return "🔴"
		}
	}
	return "🟠"
}

// writeResolved renders findings that disappeared since the previous scan, one
// line per image. Seeing yesterday's fix confirmed is the reward loop of diff
// mode, so it is never collapsed away.
func writeResolved(b *strings.Builder, d state.Diff, byRef map[string]analyze.ImageObservation) {
	if len(d.Resolved) == 0 && len(d.ResolvedEOSL) == 0 {
		return
	}
	fmt.Fprintf(b, "\n*✅ Resolved since last scan (%d)*\n", len(d.Resolved)+len(d.ResolvedEOSL))
	for _, img := range d.ResolvedEOSL {
		fmt.Fprintf(b, "• %s — base OS no longer EOL\n", refLabel(img, byRef))
	}
	byImage := map[string][]string{}
	var imgOrder []string
	for _, res := range d.Resolved {
		if _, ok := byImage[res.Image]; !ok {
			imgOrder = append(imgOrder, res.Image)
		}
		byImage[res.Image] = append(byImage[res.Image], res.Package)
	}
	for _, img := range imgOrder {
		fmt.Fprintf(b, "• %s: %s\n", refLabel(img, byRef), strings.Join(byImage[img], ", "))
	}
}

// writeOpenNow renders the one-line ambient summary that keeps unresolved
// findings from being forgotten between changes.
func writeOpenNow(b *strings.Builder, r analyze.Report, d state.Diff) {
	if !r.HasFindings() {
		b.WriteString("\n🎉 Open now: none — all clear\n")
		return
	}
	fmt.Fprintf(b, "\n📌 Open now: CRITICAL %d / HIGH %d across %d image(s)", d.OpenCritical, d.OpenHigh, d.OpenImages)
	if days := d.OldestOpenDays(r.GeneratedAt); days > 0 {
		if days >= staleDays {
			fmt.Fprintf(b, " — ⏰ oldest unresolved %d day(s)", days)
		} else {
			fmt.Fprintf(b, " — oldest unresolved %d day(s)", days)
		}
	}
	b.WriteString("\n_Details in the generic webhook payload, or in the weekly full report._\n")
}

func writeScanErrors(b *strings.Builder, errs []analyze.ScanError, byRef map[string]analyze.ImageObservation) {
	if len(errs) == 0 {
		return
	}
	b.WriteString("\n*⚠️ Scan failures*\n")
	for _, e := range errs {
		fmt.Fprintf(b, "• %s — %s\n", refLabel(e.Image, byRef), e.Err)
	}
}

// priority holds the headline counts shown at the top of the message.
type priority struct {
	eol, critical, care, safe int
}

// summarize tallies the headline: EOL base images, total CRITICAL CVEs across
// all sections, fixable packages that need care (major bump), and fixable
// packages low-risk enough to be collapsed.
func summarize(r analyze.Report) priority {
	p := priority{eol: len(r.EOSLImages)}
	for _, section := range [][]analyze.ImageFindings{r.Actionable, r.Watch, r.WontFix} {
		for _, img := range section {
			p.critical += img.CriticalCount()
		}
	}
	for _, img := range r.Actionable {
		for _, g := range img.Packages {
			switch {
			case needsAttention(g):
				if g.Risk == analyze.RiskCaution {
					p.care++
				}
			default:
				p.safe++
			}
		}
	}
	return p
}

func writeHeadline(b *strings.Builder, p priority) {
	var seg []string
	if p.eol > 0 {
		seg = append(seg, fmt.Sprintf("⛔ %d EOL base", p.eol))
	}
	if p.critical > 0 {
		seg = append(seg, fmt.Sprintf("🔴 %d CRITICAL", p.critical))
	}
	if p.care > 0 {
		seg = append(seg, fmt.Sprintf("🟠 %d need care", p.care))
	}
	if p.safe > 0 {
		seg = append(seg, fmt.Sprintf("🟢 %d safe", p.safe))
	}
	if len(seg) > 0 {
		fmt.Fprintf(b, "*Priority:* %s\n", strings.Join(seg, " · "))
	}
}

// needsAttention reports whether a fixable package warrants a human decision and
// should be shown in full: it carries a CRITICAL, or its fix is a major-version
// bump (possible breaking change).
func needsAttention(g analyze.PackageGroup) bool {
	return g.Critical > 0 || g.Risk == analyze.RiskCaution
}

// writeActionable renders the fixable section, showing packages that need
// attention in full and collapsing the rest into one summary line per image.
// Returns the total number of packages collapsed.
func writeActionable(b *strings.Builder, imgs []analyze.ImageFindings, byRef map[string]analyze.ImageObservation) int {
	if len(imgs) == 0 {
		return 0
	}
	b.WriteString("\n*✅ Actionable now (fixed)*\n")
	collapsed := 0
	for _, img := range imgs {
		fmt.Fprintf(b, "%s %s  CRITICAL %d / HIGH %d\n", imageEmoji(img), imageLabel(img, byRef), img.CriticalCount(), img.TotalCount()-img.CriticalCount())
		var rest []analyze.PackageGroup
		for _, g := range img.Packages {
			if needsAttention(g) {
				writePackage(b, g, true, "")
			} else {
				rest = append(rest, g)
			}
		}
		if len(rest) > 0 {
			collapsed += len(rest)
			writeCollapsed(b, rest)
		}
	}
	return collapsed
}

// writeSection renders an image section with every package shown in full. Used
// for the watch / won't-fix sections, which are not actionable now and are
// typically short.
func writeSection(b *strings.Builder, title string, imgs []analyze.ImageFindings, fixed bool, byRef map[string]analyze.ImageObservation) {
	if len(imgs) == 0 {
		return
	}
	fmt.Fprintf(b, "\n*%s*\n", title)
	for _, img := range imgs {
		fmt.Fprintf(b, "%s %s  CRITICAL %d / HIGH %d\n", imageEmoji(img), imageLabel(img, byRef), img.CriticalCount(), img.TotalCount()-img.CriticalCount())
		for _, g := range img.Packages {
			writePackage(b, g, fixed, "")
		}
	}
}

func writePackage(b *strings.Builder, g analyze.PackageGroup, fixed bool, suffix string) {
	b.WriteString("   • ")
	if fixed {
		fmt.Fprintf(b, "%s %s → %s", g.Package, g.InstalledVer, g.FixedVer)
	} else {
		fmt.Fprintf(b, "%s %s (no fix available)", g.Package, g.InstalledVer)
	}
	fmt.Fprintf(b, " (CRITICAL %d / HIGH %d)", g.Critical, g.High)
	if label := riskLabel(g.Risk); label != "" {
		fmt.Fprintf(b, "  %s", label)
	}
	if g.Class == "lang" {
		b.WriteString(" [lang]")
	}
	b.WriteString(suffix)
	b.WriteString("\n")
}

// writeCollapsed renders one summary line for the lower-risk fixes hidden from
// the detailed view, listing up to collapsePreview package names.
func writeCollapsed(b *strings.Builder, rest []analyze.PackageGroup) {
	var crit, high int
	names := make([]string, 0, len(rest))
	for _, g := range rest {
		crit += g.Critical
		high += g.High
		names = append(names, g.Package)
	}
	sev := fmt.Sprintf("HIGH %d", high)
	if crit > 0 {
		sev = fmt.Sprintf("CRITICAL %d / HIGH %d", crit, high)
	}
	shown, extra := names, 0
	if len(names) > collapsePreview {
		shown, extra = names[:collapsePreview], len(names)-collapsePreview
	}
	fmt.Fprintf(b, "   • +%d lower-risk fixes (%s): %s", len(rest), sev, strings.Join(shown, ", "))
	if extra > 0 {
		fmt.Fprintf(b, " (+%d more)", extra)
	}
	b.WriteString("\n")
}

func imageEmoji(img analyze.ImageFindings) string {
	if img.CriticalCount() > 0 {
		return "🔴"
	}
	return "🟠"
}

func riskLabel(r analyze.Risk) string {
	switch r {
	case analyze.RiskDistroUpdate:
		return "🟢 upgrade: distro security patch"
	case analyze.RiskSafe:
		return "🟢 upgrade: low-risk"
	case analyze.RiskCaution:
		return "🟠 upgrade: major version bump — needs care"
	case analyze.RiskUnknown:
		return "⚪ upgrade: risk unknown"
	default:
		return ""
	}
}

// --- generic webhook payload ---

type webhookPayload struct {
	GeneratedAt string              `json:"generated_at"`
	Environment *environmentPayload `json:"environment,omitempty"`
	Summary     summary             `json:"summary"`
	EOSLImages  []string            `json:"eosl_images"`
	Actionable  []imagePayload      `json:"actionable"`
	Watch       []imagePayload      `json:"watch"`
	WontFix     []imagePayload      `json:"wont_fix"`
	ScanErrors  []errorPayload      `json:"scan_errors"`
	Diff        *diffPayload        `json:"diff,omitempty"`
}

// environmentPayload mirrors inventory.Environment. Kind is always present —
// BuildWebhookPayload always populates the pointer, since even the unnamed
// default environment has a Kind — while Name is omitted for the unnamed
// default rather than sent as "".
type environmentPayload struct {
	Kind string `json:"kind"`
	Name string `json:"name,omitempty"`
}

// diffPayload mirrors state.Diff for webhook consumers. The full sections above
// are always present; the diff is additive so receivers can build their own
// "what changed" view without keeping state.
type diffPayload struct {
	New           []changePayload   `json:"new"`
	Resolved      []resolvedPayload `json:"resolved"`
	Replaced      []replacedPayload `json:"replaced"`
	NewEOSL       []string          `json:"new_eosl"`
	ResolvedEOSL  []string          `json:"resolved_eosl"`
	OldestOpenDay int               `json:"oldest_open_days"`
}

// replacedPayload mirrors state.ImageReplacement: a reference whose verified
// running content changed since the previous scan. The ID sets are already
// sorted upstream.
type replacedPayload struct {
	Ref            string   `json:"ref"`
	PrevContentIDs []string `json:"prev_content_ids"`
	ContentIDs     []string `json:"content_ids"`
}

type changePayload struct {
	Image    string `json:"image"`
	Package  string `json:"package"`
	Kind     string `json:"kind"` // new | escalated | new_cves | now_fixable
	NewCVEs  int    `json:"new_cve_count,omitempty"`
	Critical int    `json:"critical"`
	High     int    `json:"high"`
	Priority string `json:"priority,omitempty"` // triage: act_now | watch | low
	Reason   string `json:"reason,omitempty"`   // escalated: evidence for the new verdict
}

type resolvedPayload struct {
	Image   string `json:"image"`
	Package string `json:"package"`
}

type summary struct {
	ImagesTotal    int            `json:"images_total"`
	ImagesAffected int            `json:"images_affected"`
	PriorityCounts map[string]int `json:"priority_counts,omitempty"` // triage: act_now / watch / low
	Intel          *intelPayload  `json:"intel,omitempty"`           // triage: data freshness
}

// intelPayload tells webhook consumers how much to trust the priorities in
// this payload.
type intelPayload struct {
	Degraded  bool `json:"degraded"`
	KEVOK     bool `json:"kev_ok"`
	EPSSOK    bool `json:"epss_ok"`
	StaleDays int  `json:"stale_days"`
}

type imagePayload struct {
	Image          string           `json:"image"`
	SeverityCounts map[string]int   `json:"severity_counts"`
	Findings       []findingPayload `json:"findings"`

	// Containers is the entity-level observation backing this section entry
	// (analyze.ImageFindings.Containers): every running container matching
	// this (Image, ContentID) exactly. Unlike RegistryDigests below this is
	// per-entity, not a Ref-level union — a reference running two distinct
	// verified contents lists each content's own containers under its own
	// section entry, not a merged set.
	Containers []containerPayload `json:"containers"`

	// Identity fields. ContentID mirrors analyze.ImageFindings.ContentID:
	// non-empty only when this entity's identity was resolved (single
	// confirmed entity — the ordinary case, or one entry of an Ambiguous
	// reference). IdentityResolved and ScanTargetKind are both entity-level,
	// derived from that same ContentID (non-empty => resolved / "content_id";
	// empty => unresolved / "reference") — never the reference's aggregate
	// IdentityResolved (analyze.Report.Images), so a resolved entity is never
	// reported as unresolved just because a sibling under the same reference
	// fell back to scanning by reference. RegistryDigests alone is the
	// reference's identity inventory, looked up by Image (ImageFindings
	// carries no per-entity RegistryDigests of its own).
	ContentID        string   `json:"content_id,omitempty"`
	RegistryDigests  []string `json:"registry_digests"`
	IdentityResolved bool     `json:"identity_resolved"`
	ScanTargetKind   string   `json:"scan_target_kind"` // content_id | reference
}

// containerPayload mirrors inventory.Container: the container's own display
// name, plus whatever Workload association was found for it.
type containerPayload struct {
	Name     string          `json:"name"`
	Workload workloadPayload `json:"workload"`
}

// workloadPayload mirrors inventory.Workload. Kind is always written,
// including "unknown" — inventory.WorkloadUnknown is the Go empty string so
// a zero-valued Workload reads as unknown by construction, but the webhook
// contract spells it out explicitly so a receiver can tell "no association
// found" apart from "this payload version doesn't carry workloads at all".
// Group/Name are omitted when unknown, since neither is meaningful then.
type workloadPayload struct {
	Kind  string `json:"kind"`
	Group string `json:"group,omitempty"`
	Name  string `json:"name,omitempty"`
}

type findingPayload struct {
	Package        string         `json:"package"`
	Installed      string         `json:"installed"`
	Fixed          string         `json:"fixed"`
	Status         string         `json:"status"`
	SeverityCounts map[string]int `json:"severity_counts"`
	UpgradeRisk    string         `json:"upgrade_risk"`
	Priority       string         `json:"priority,omitempty"` // triage verdict for the package
	VulnIDs        []string       `json:"vuln_ids"`
	Vulns          []vulnPayload  `json:"vulns"` // per-CVE detail (superset of vuln_ids)
}

// vulnPayload is the per-CVE record: id and severity always; the triage fields
// carry the enrichment when triage is on. EPSS is null when no score is known.
type vulnPayload struct {
	ID         string       `json:"id"`
	Severity   string       `json:"severity"`
	URL        string       `json:"url,omitempty"`   // scanner's primary advisory
	Title      string       `json:"title,omitempty"` // short human-readable summary, if the scanner supplied one
	KEV        bool         `json:"kev"`
	Ransomware bool         `json:"ransomware,omitempty"`
	EPSS       *float64     `json:"epss"`
	Priority   string       `json:"priority,omitempty"`
	Refs       []refPayload `json:"refs,omitempty"` // vendor advisory, discussions
}

type refPayload struct {
	Kind  string `json:"kind"` // vendor | discussion
	Label string `json:"label"`
	URL   string `json:"url"`
}

type errorPayload struct {
	Image string `json:"image"`
	Error string `json:"error"`
}

// BuildWebhookPayload produces the structured JSON payload for the generic
// webhook. It is returned as a value so callers (and tests) can marshal it.
// The payload always carries the full current data (the webhook's role is the
// unabridged record); d adds the diff section when diff mode is on.
func BuildWebhookPayload(r analyze.Report, d *state.Diff) any {
	byRef := imagesByRef(r)
	p := webhookPayload{
		GeneratedAt: r.GeneratedAt.Format(time.RFC3339),
		Environment: &environmentPayload{
			Kind: string(r.Environment.Kind),
			Name: r.Environment.Name,
		},
		Summary: summary{
			ImagesTotal:    r.ImagesTotal,
			ImagesAffected: r.AffectedImageCount(),
		},
		EOSLImages: r.EOSLImages,
		Actionable: imagePayloads(r.Actionable, byRef),
		Watch:      imagePayloads(r.Watch, byRef),
		WontFix:    imagePayloads(r.WontFix, byRef),
		ScanErrors: errorPayloads(r.ScanErrors),
	}
	if r.Triage {
		pv := r.ByPriority()
		p.Summary.PriorityCounts = map[string]int{
			"act_now": analyze.GroupCount(pv.ActNow),
			"watch":   analyze.GroupCount(pv.Watch),
			"low":     analyze.GroupCount(pv.Low),
		}
		p.Summary.Intel = &intelPayload{
			Degraded:  r.Intel.Degraded(),
			KEVOK:     r.Intel.KEVOK,
			EPSSOK:    r.Intel.EPSSOK,
			StaleDays: r.Intel.StaleDays,
		}
	}
	if d != nil {
		p.Diff = buildDiffPayload(r, *d)
	}
	return p
}

func buildDiffPayload(r analyze.Report, d state.Diff) *diffPayload {
	dp := &diffPayload{
		New:           []changePayload{},
		Resolved:      []resolvedPayload{},
		Replaced:      []replacedPayload{},
		NewEOSL:       emptyIfNil(d.NewEOSL),
		ResolvedEOSL:  emptyIfNil(d.ResolvedEOSL),
		OldestOpenDay: d.OldestOpenDays(r.GeneratedAt),
	}
	for _, c := range d.Changes {
		var crit, high int
		for _, g := range c.Groups {
			crit += g.Critical
			high += g.High
		}
		cp := changePayload{
			Image:    c.Image,
			Package:  c.Package,
			Kind:     string(c.Kind),
			NewCVEs:  c.NewCVEs,
			Critical: crit,
			High:     high,
			Priority: string(analyze.MaxPriority(c.Groups)),
		}
		if c.Kind == state.KindEscalated {
			cp.Reason = changeEvidence(r, c)
		}
		dp.New = append(dp.New, cp)
	}
	for _, res := range d.Resolved {
		dp.Resolved = append(dp.Resolved, resolvedPayload{Image: res.Image, Package: res.Package})
	}
	for _, rep := range d.Replaced {
		dp.Replaced = append(dp.Replaced, replacedPayload{
			Ref:            rep.Ref,
			PrevContentIDs: emptyIfNil(rep.PrevContentIDs),
			ContentIDs:     emptyIfNil(rep.ContentIDs),
		})
	}
	return dp
}

func emptyIfNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func imagePayloads(imgs []analyze.ImageFindings, byRef map[string]analyze.ImageObservation) []imagePayload {
	out := make([]imagePayload, 0, len(imgs))
	for _, img := range imgs {
		findings := make([]findingPayload, 0, len(img.Packages))
		for _, g := range img.Packages {
			vulns := make([]vulnPayload, 0, len(g.Vulns))
			for _, v := range g.Vulns {
				vp := vulnPayload{
					ID:         v.ID,
					Severity:   string(v.Severity),
					URL:        v.URL,
					Title:      v.Title,
					KEV:        v.KEV,
					Ransomware: v.Ransomware,
					Priority:   string(v.Priority),
				}
				if v.EPSSKnown {
					epss := v.EPSS
					vp.EPSS = &epss
				}
				for _, ref := range v.Refs {
					vp.Refs = append(vp.Refs, refPayload(ref))
				}
				vulns = append(vulns, vp)
			}
			findings = append(findings, findingPayload{
				Package:        g.Package,
				Installed:      g.InstalledVer,
				Fixed:          g.FixedVer,
				Status:         string(g.Status),
				SeverityCounts: map[string]int{"CRITICAL": g.Critical, "HIGH": g.High},
				UpgradeRisk:    string(g.Risk),
				Priority:       string(g.Priority),
				VulnIDs:        g.VulnIDs(),
				Vulns:          vulns,
			})
		}
		// scan_target_kind and identity_resolved are both entity-level (this
		// ImageFindings' own ContentID), not the reference's aggregate
		// IdentityResolved: a mixed reference (one entity pinned by ContentID,
		// a sibling on reference-fallback) must not report a resolved entity
		// as identity_resolved=false just because a sibling wasn't.
		// RegistryDigests alone stays a Ref-level lookup (analyze.ImageFindings
		// carries no per-entity RegistryDigests of its own).
		resolved := img.ContentID != ""
		scanTargetKind := "reference"
		if resolved {
			scanTargetKind = "content_id"
		}
		out = append(out, imagePayload{
			Image:            img.Image,
			SeverityCounts:   map[string]int{"CRITICAL": img.CriticalCount(), "HIGH": img.TotalCount() - img.CriticalCount()},
			Findings:         findings,
			Containers:       containerPayloads(img.Containers),
			ContentID:        img.ContentID,
			RegistryDigests:  emptyIfNil(byRef[img.Image].RegistryDigests),
			IdentityResolved: resolved,
			ScanTargetKind:   scanTargetKind,
		})
	}
	return out
}

// containerPayloads converts an entity's observed containers to their
// webhook form. Empty/nil input yields an empty slice, not null — matching
// the other list fields in imagePayload (e.g. RegistryDigests via
// emptyIfNil).
func containerPayloads(cs []inventory.Container) []containerPayload {
	out := make([]containerPayload, 0, len(cs))
	for _, c := range cs {
		out = append(out, containerPayload{
			Name: c.Name,
			Workload: workloadPayload{
				Kind:  workloadKindPayload(c.Workload.Kind),
				Group: c.Workload.Group,
				Name:  c.Workload.Name,
			},
		})
	}
	return out
}

// workloadKindPayload maps inventory.WorkloadKind to its webhook string,
// writing out "unknown" explicitly for inventory.WorkloadUnknown (the Go
// zero value, "") rather than letting it serialize as an empty string.
func workloadKindPayload(k inventory.WorkloadKind) string {
	if k == inventory.WorkloadUnknown {
		return "unknown"
	}
	return string(k)
}

func errorPayloads(errs []analyze.ScanError) []errorPayload {
	out := make([]errorPayload, 0, len(errs))
	for _, e := range errs {
		out = append(out, errorPayload{Image: e.Image, Error: e.Err})
	}
	return out
}
