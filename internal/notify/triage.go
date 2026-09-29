// Triage-mode Slack rendering: the message is organized by priority — act
// now / watch / low — instead of by fix status.
// Every act-now item carries its evidence (KEV, EPSS) inline: the product's
// promise is "fix this one tonight, ignore the rest", and an unexplained order
// would be indistinguishable from the severity walls it replaces.
package notify

import (
	"fmt"
	"sort"
	"strings"

	"github.com/kitsunetrail/kestrelynx/internal/analyze"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
	"github.com/kitsunetrail/kestrelynx/internal/state"
)

// writeTriageBody renders the complete open-findings view in priority order.
// It is the triage-mode counterpart of writeFullBody. The Sensor/eBPF
// warning is written once, centrally, by the entry points that call into
// this (FormatSlackText, FormatSlackDiffText) — not repeated here.
func writeTriageBody(b *strings.Builder, r analyze.Report, msg messages) {
	pv := r.ByPriority()
	// ActNow is never filtered: a group eligible for muting is never
	// act_now by construction.
	pv.Watch = filterMuted(pv.Watch)
	pv.Low = filterMuted(pv.Low)
	byRef := imagesByRef(r)
	writeTriageHeadline(b, r, pv, msg)
	writeIntelWarning(b, r, msg)

	writeEOSLSection(b, r, byRef, msg)
	writeEOLPackages(b, r, byRef, msg)
	writeActNow(b, r, pv.ActNow, byRef, msg)
	writeWatch(b, r, pv.Watch, byRef, msg)
	writeLow(b, r, pv.Low, msg)
	writeMutedCount(b, r, msg)
	writeScanErrors(b, r.ScanErrors, byRef, msg)
	writeIntelStale(b, r, msg)
	writeRuntimeSummary(b, r, msg)
	writeUnresolvedRefs(b, r, msg)
}

// writeTriageHeadline is the one-line summary that replaces the severity
// headline: EOL bases and end-of-life packages (kept as their own segments so
// counts stay honest), then the three priority buckets. Zero segments are
// omitted. The end-of-life package segment counts fix status and act now
// counts exploitation priority, so an act_now end-of-life package is counted
// in both.
func writeTriageHeadline(b *strings.Builder, r analyze.Report, pv analyze.PriorityView, msg messages) {
	var seg []string
	if n := len(r.EOSLImages); n > 0 {
		seg = append(seg, fmt.Sprintf(msg.SegEOLBase, n))
	}
	if n := analyze.GroupCount(r.EOLPackageAlerts()); n > 0 {
		seg = append(seg, fmt.Sprintf(msg.SegEOLPackage, n))
	}
	if n := analyze.GroupCount(pv.ActNow); n > 0 {
		seg = append(seg, fmt.Sprintf(msg.SegActNow, n))
	}
	if n := analyze.GroupCount(pv.Watch); n > 0 {
		seg = append(seg, fmt.Sprintf(msg.SegWatch, n))
	}
	if n := analyze.GroupCount(pv.Low); n > 0 {
		seg = append(seg, fmt.Sprintf(msg.SegLow, n))
	}
	if len(seg) > 0 {
		fmt.Fprintf(b, msg.PriorityLine, strings.Join(seg, " · "))
	}
}

// writeIntelWarning surfaces missing intel right under the headline: the
// triage verdicts below are only as good as the data behind them.
func writeIntelWarning(b *strings.Builder, r analyze.Report, msg messages) {
	switch {
	case r.Intel.Degraded():
		b.WriteString(msg.IntelDegradedWarning)
	case !r.Intel.KEVOK:
		b.WriteString(msg.IntelKEVUnavailable)
	case !r.Intel.EPSSOK:
		b.WriteString(msg.IntelEPSSUnavailable)
	}
}

// writeIntelStale annotates a message built from cached feeds that could not
// be refreshed (a fail-open window: a stale cache is used rather than
// blocking or discarding triage).
func writeIntelStale(b *strings.Builder, r analyze.Report, msg messages) {
	if r.Intel.StaleDays > 0 && !r.Intel.Degraded() {
		fmt.Fprintf(b, msg.IntelStale, r.Intel.StaleDays)
	}
}

// writeActNow renders the act-now bucket in full: package line plus an
// evidence line per package.
func writeActNow(b *strings.Builder, r analyze.Report, imgs []analyze.ImageFindings, byRef map[string]analyze.ImageObservation, msg messages) {
	if len(imgs) == 0 {
		return
	}
	fmt.Fprintf(b, msg.ActNowHeading, analyze.GroupCount(imgs))
	for _, img := range imgs {
		fmt.Fprintf(b, msg.ImageBullet, imageLabel(img, byRef, msg))
		for _, g := range img.Packages {
			writePackage(b, g, g.Status == scanner.StatusFixed, "", msg)
			writeEvidence(b, r, g, msg)
			if runtimeInUse(g.Runtime) {
				fmt.Fprintf(b, "     %s\n", runtimeInUsePhrase(g.Runtime, msg))
			}
		}
	}
}

// writeWatch renders the watch bucket compactly: one package line with a short
// reason, no separate evidence line.
func writeWatch(b *strings.Builder, r analyze.Report, imgs []analyze.ImageFindings, byRef map[string]analyze.ImageObservation, msg messages) {
	if len(imgs) == 0 {
		return
	}
	fmt.Fprintf(b, msg.WatchHeading, analyze.GroupCount(imgs))
	for _, img := range imgs {
		fmt.Fprintf(b, msg.ImageBullet, imageLabel(img, byRef, msg))
		for _, g := range img.Packages {
			suffix := ""
			if ev := shortEvidence(r, g.TopVuln(), msg); ev != "" {
				suffix = " — " + ev
			}
			suffix += runtimeWatchSuffix(g.Runtime, msg)
			writePackage(b, g, g.Status == scanner.StatusFixed, suffix, msg)
		}
	}
}

// writeLow collapses the low bucket to a count: these are the findings the
// triage layer exists to keep out of the reader's way. The full list is
// always in the generic webhook payload, when one is configured — the
// weekly report shows this same count-only line, never more.
func writeLow(b *strings.Builder, r analyze.Report, imgs []analyze.ImageFindings, msg messages) {
	n := analyze.GroupCount(imgs)
	if n == 0 {
		return
	}
	fmt.Fprintf(b, msg.LowHeading, n, n, len(imgs))
	if inUse := countInUse(imgs); inUse > 0 {
		fmt.Fprintf(b, msg.TriageLowInUseCount, inUse)
	}
	b.WriteString("\n")
	// The generic webhook is the only destination with per-package detail
	// beyond this count, and only when one is actually configured — a
	// weekly full report shows this same count-only line, never more.
	if r.GenericWebhookConfigured {
		b.WriteString(msg.DetailsInWebhook)
	}
}

// writeEvidence renders the "why act now" line under a package: the strongest
// CVE with its KEV/EPSS facts, a hint when the fix status limits the response,
// and the count of further CVEs folded into the group.
func writeEvidence(b *strings.Builder, r analyze.Report, g analyze.PackageGroup, msg messages) {
	top := g.TopVuln()
	if top.ID == "" {
		return
	}
	fmt.Fprintf(b, "     ↳ %s", evidence(r, top, msg))
	if rest := len(g.Vulns) - 1; rest > 0 {
		fmt.Fprintf(b, msg.EvidenceMoreCVEs, rest)
	}
	switch g.Status {
	case scanner.StatusAffected:
		b.WriteString(msg.NoFixYetMitigation)
	case scanner.StatusWontFix:
		b.WriteString(msg.WontFixReplace)
	case scanner.StatusEndOfLife:
		b.WriteString(msg.EOLEvidenceMark)
	}
	b.WriteString("\n")
	writeRefs(b, top, msg)
}

// writeRefs renders the reference links under an act-now evidence line: the
// scanner's advisory, the vendor advisory from the KEV notes, and the HN
// discussion when one exists. Links only — verifiable facts, no summaries.
func writeRefs(b *strings.Builder, v analyze.VulnRef, msg messages) {
	var parts []string
	if v.URL != "" {
		parts = append(parts, fmt.Sprintf(msg.AdvisoryLink, v.URL, msg.AdvisoryLinkLabel))
	}
	for _, ref := range v.Refs {
		label := ref.Label
		switch ref.Kind {
		case "vendor":
			// analyze.Ref.Label and the webhook payload keep their own
			// English "vendor advisory" text (analyze/triage.go, format.go's
			// refPayload) — this substitution is Slack-display-only.
			label = msg.VendorAdvisoryLinkLabel
		case "discussion":
			label = "💬 " + label
		}
		parts = append(parts, fmt.Sprintf("<%s|%s>", ref.URL, label))
	}
	if len(parts) == 0 {
		return
	}
	fmt.Fprintf(b, msg.RefsLine, strings.Join(parts, " · "))
}

// vulnIDLink renders a vulnerability ID as a Slack link to its official
// record. Only CVE ids have an NVD page; ids from other schemes (GHSA-,
// DLA-, ...) are returned as plain text.
func vulnIDLink(id string) string {
	if strings.HasPrefix(id, "CVE-") {
		return fmt.Sprintf("<https://nvd.nist.gov/vuln/detail/%s|%s>", id, id)
	}
	return id
}

// evidence states the facts behind a verdict for Slack rendering: linked ID,
// severity, then exploitation intel. In degraded mode there is no intel to
// cite and the header warning already explains why.
func evidence(r analyze.Report, v analyze.VulnRef, msg messages) string {
	return evidenceLine(r, v, vulnIDLink(v.ID), msg)
}

// plainEvidence is the mrkdwn-free variant for the webhook payload, which is
// consumed outside Slack and must not carry <url|label> markup.
func plainEvidence(r analyze.Report, v analyze.VulnRef, msg messages) string {
	return evidenceLine(r, v, v.ID, msg)
}

func evidenceLine(r analyze.Report, v analyze.VulnRef, id string, msg messages) string {
	parts := []string{id + " " + string(v.Severity)}
	if r.Intel.Degraded() {
		parts = append(parts, msg.EvidenceSeverityOnly)
		return strings.Join(parts, " · ")
	}
	if v.KEV {
		parts = append(parts, msg.EvidenceKEV)
	}
	parts = append(parts, fmt.Sprintf(msg.EvidenceEPSSPrefix, epssString(v)))
	if v.Ransomware {
		parts = append(parts, msg.EvidenceRansomware)
	}
	return strings.Join(parts, " · ")
}

// shortEvidence is the compact reason used inline in the watch bucket.
func shortEvidence(r analyze.Report, v analyze.VulnRef, msg messages) string {
	if v.ID == "" || r.Intel.Degraded() {
		return ""
	}
	if v.KEV {
		return vulnIDLink(v.ID) + msg.ShortEvidenceKEV
	}
	return vulnIDLink(v.ID) + fmt.Sprintf(msg.ShortEvidenceEPSSPrefix, epssString(v))
}

// epssString formats a probability for reading in a chat message: whole
// percents once material, one decimal below that, and floor/ceiling labels
// rather than a misleading "0.0%" or an overclaiming "100%" (EPSS never
// asserts certainty; scores like 0.99999 are ">99%", not 100%).
func epssString(v analyze.VulnRef) string {
	if !v.EPSSKnown {
		return "n/a"
	}
	pct := v.EPSS * 100
	switch {
	case pct >= 99.5:
		return ">99%"
	case pct >= 1:
		return fmt.Sprintf("%.0f%%", pct)
	case pct >= 0.1:
		return fmt.Sprintf("%.1f%%", pct)
	default:
		return "<0.1%"
	}
}

// --- diff-mode triage rendering ---

// writeTriageChanges renders the new/changed findings sorted most-urgent
// first, with evidence lines for act-now items and the escalation callout that
// is diff mode's payoff: "this got urgent overnight" is exactly the news a
// daily digest exists to carry.
func writeTriageChanges(b *strings.Builder, r analyze.Report, changes []state.Change, msg messages) {
	if len(changes) == 0 {
		return
	}
	sorted := make([]state.Change, len(changes))
	copy(sorted, changes)
	// Sorted by the change's full priority (all groups, muted or not) —
	// priority is never touched by muting, so this order must not be
	// either.
	sort.SliceStable(sorted, func(i, j int) bool {
		pi, pj := analyze.MaxPriority(sorted[i].Groups), analyze.MaxPriority(sorted[j].Groups)
		if pi.Rank() != pj.Rank() {
			return pi.Rank() > pj.Rank()
		}
		if sorted[i].Image != sorted[j].Image {
			return sorted[i].Image < sorted[j].Image
		}
		return sorted[i].Package < sorted[j].Package
	})

	visible := visibleChanges(sorted)
	if len(visible) == 0 {
		return
	}
	byRef := imagesByRef(r)
	fmt.Fprintf(b, msg.NewSinceLastScanHeading, len(visible))
	lastImage := ""
	for _, vc := range visible {
		if vc.change.Image != lastImage {
			fmt.Fprintf(b, "%s %s\n", priorityEmoji(analyze.MaxPriority(vc.change.Groups)), refLabel(vc.change.Image, byRef, msg))
			lastImage = vc.change.Image
		}
		for _, g := range vc.groups {
			writePackage(b, g, g.Status == scanner.StatusFixed, changeSuffix(r, vc.change, g, msg)+runtimeChangeSuffix(g, msg), msg)
			if g.Priority == analyze.PriorityActNow {
				writeEvidence(b, r, g, msg)
				if runtimeInUse(g.Runtime) {
					fmt.Fprintf(b, "     %s\n", runtimeInUsePhrase(g.Runtime, msg))
				}
			}
		}
	}
}

// writeTriageOpenNow is the heartbeat line with the priority breakdown. Only
// urgent findings age it: an old "low" is the triage doing its job, not debt.
// holding is the same signal writeOpenNow honors: it must not assert "all
// clear" when the current cycle looks clean only because an unpinned scan is
// having a previous finding held rather than resolved.
func writeTriageOpenNow(b *strings.Builder, r analyze.Report, d state.Diff, holding bool, msg messages) {
	if !r.HasFindings() {
		writeNothingOpenNow(b, d, holding, msg)
		return
	}
	seg := openNowEOLSegments(d, true, msg)
	if d.OpenActNow > 0 {
		seg = append(seg, fmt.Sprintf(msg.OpenNowActNow, d.OpenActNow))
	}
	if d.OpenWatch > 0 {
		seg = append(seg, fmt.Sprintf(msg.SegWatch, d.OpenWatch))
	}
	if d.OpenLow > 0 {
		seg = append(seg, fmt.Sprintf(msg.SegLow, d.OpenLow))
	}
	fmt.Fprintf(b, msg.OpenNowPrefix, strings.Join(seg, " / "))
	// "act-now/watch", not "urgent": the age covers both buckets (an old low
	// is the triage doing its job), and calling a watch-only backlog "urgent"
	// misreads as act-now debt when the act-now count is zero.
	if days := d.OldestUrgentDays(r.GeneratedAt); days > 0 {
		if days >= staleDays {
			fmt.Fprintf(b, msg.OldestActNowWatchStale, days)
		} else {
			fmt.Fprintf(b, msg.OldestActNowWatch, days)
		}
	}
	b.WriteString("\n")
	if r.GenericWebhookConfigured {
		b.WriteString(msg.DetailsInWebhook)
	}
}

func priorityEmoji(p analyze.Priority) string {
	switch p {
	case analyze.PriorityActNow:
		return "🚨"
	case analyze.PriorityWatch:
		return "👀"
	default:
		return "🔕"
	}
}

func priorityLabel(p analyze.Priority, msg messages) string {
	switch p {
	case analyze.PriorityActNow:
		return msg.PriorityLabelActNow
	case analyze.PriorityWatch:
		return msg.PriorityLabelWatch
	default:
		return msg.PriorityLabelLow
	}
}

// changeEvidence is the webhook "reason" for an escalated change: the facts of
// the strongest CVE in the change's strongest group.
func changeEvidence(r analyze.Report, c state.Change, msg messages) string {
	var best analyze.PackageGroup
	for _, g := range c.Groups {
		if g.Priority.Rank() >= best.Priority.Rank() {
			best = g
		}
	}
	if best.TopVuln().ID == "" {
		return ""
	}
	return plainEvidence(r, best.TopVuln(), msg)
}
