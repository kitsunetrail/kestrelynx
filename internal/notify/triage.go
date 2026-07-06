// Triage-mode Slack rendering (Phase 1+, docs/TRIAGE_SPEC.md §6): the message
// is organized by priority — act now / watch / low — instead of by fix status.
// Every act-now item carries its evidence (KEV, EPSS) inline: the product's
// promise is "fix this one tonight, ignore the rest", and an unexplained order
// would be indistinguishable from the severity walls it replaces.
package notify

import (
	"fmt"
	"sort"
	"strings"

	"github.com/kitsunetrail/stackwatch/internal/analyze"
	"github.com/kitsunetrail/stackwatch/internal/scanner"
	"github.com/kitsunetrail/stackwatch/internal/state"
)

// writeTriageBody renders the complete open-findings view in priority order.
// It is the triage-mode counterpart of writeFullBody.
func writeTriageBody(b *strings.Builder, r analyze.Report) {
	pv := r.ByPriority()
	writeTriageHeadline(b, r, pv)
	writeIntelWarning(b, r)

	if len(r.EOSLImages) > 0 {
		b.WriteString("\n*⛔ Base OS end-of-life (top priority)*\n")
		for _, img := range r.EOSLImages {
			fmt.Fprintf(b, "• %s — base OS is EOL (no more security updates coming)\n", img)
		}
	}

	writeActNow(b, r, pv.ActNow)
	writeWatch(b, r, pv.Watch)
	writeLow(b, pv.Low)
	writeScanErrors(b, r.ScanErrors)
	writeIntelStale(b, r)
}

// writeTriageHeadline is the one-line summary that replaces the severity
// headline: EOL bases (kept as their own segment so counts stay honest), then
// the three priority buckets. Zero segments are omitted.
func writeTriageHeadline(b *strings.Builder, r analyze.Report, pv analyze.PriorityView) {
	var seg []string
	if n := len(r.EOSLImages); n > 0 {
		seg = append(seg, fmt.Sprintf("⛔ %d EOL base", n))
	}
	if n := analyze.GroupCount(pv.ActNow); n > 0 {
		seg = append(seg, fmt.Sprintf("🚨 %d act now", n))
	}
	if n := analyze.GroupCount(pv.Watch); n > 0 {
		seg = append(seg, fmt.Sprintf("👀 %d watch", n))
	}
	if n := analyze.GroupCount(pv.Low); n > 0 {
		seg = append(seg, fmt.Sprintf("🔕 %d low", n))
	}
	if len(seg) > 0 {
		fmt.Fprintf(b, "*Priority:* %s\n", strings.Join(seg, " · "))
	}
}

// writeIntelWarning surfaces missing intel right under the headline: the
// triage verdicts below are only as good as the data behind them.
func writeIntelWarning(b *strings.Builder, r analyze.Report) {
	switch {
	case r.Intel.Degraded():
		b.WriteString("⚠️ Vulnerability intel (KEV/EPSS) unavailable — severity-only triage, nothing demoted to low\n")
	case !r.Intel.KEVOK:
		b.WriteString("⚠️ CISA KEV data unavailable — act-now detection may be incomplete\n")
	case !r.Intel.EPSSOK:
		b.WriteString("⚠️ EPSS data unavailable — triage is using KEV and severity only\n")
	}
}

// writeIntelStale annotates a message built from cached feeds that could not
// be refreshed (fail-open window, docs/TRIAGE_SPEC.md §3).
func writeIntelStale(b *strings.Builder, r analyze.Report) {
	if r.Intel.StaleDays > 0 && !r.Intel.Degraded() {
		fmt.Fprintf(b, "\n_Intel data is %d day(s) old (feeds unreachable)._\n", r.Intel.StaleDays)
	}
}

// writeActNow renders the act-now bucket in full: package line plus an
// evidence line per package.
func writeActNow(b *strings.Builder, r analyze.Report, imgs []analyze.ImageFindings) {
	if len(imgs) == 0 {
		return
	}
	fmt.Fprintf(b, "\n*🚨 Act now (%d)*\n", analyze.GroupCount(imgs))
	for _, img := range imgs {
		fmt.Fprintf(b, "%s %s\n", imageEmoji(img), img.Image)
		for _, g := range img.Packages {
			writePackage(b, g, g.Status == scanner.StatusFixed, "")
			writeEvidence(b, r, g)
		}
	}
}

// writeWatch renders the watch bucket compactly: one package line with a short
// reason, no separate evidence line.
func writeWatch(b *strings.Builder, r analyze.Report, imgs []analyze.ImageFindings) {
	if len(imgs) == 0 {
		return
	}
	fmt.Fprintf(b, "\n*👀 Watch (%d)*\n", analyze.GroupCount(imgs))
	for _, img := range imgs {
		fmt.Fprintf(b, "%s %s\n", imageEmoji(img), img.Image)
		for _, g := range img.Packages {
			suffix := ""
			if ev := shortEvidence(r, g.TopVuln()); ev != "" {
				suffix = " — " + ev
			}
			writePackage(b, g, g.Status == scanner.StatusFixed, suffix)
		}
	}
}

// writeLow collapses the low bucket to a count: these are the findings the
// triage layer exists to keep out of the reader's way. The full list is always
// in the webhook payload and the weekly report.
func writeLow(b *strings.Builder, imgs []analyze.ImageFindings) {
	n := analyze.GroupCount(imgs)
	if n == 0 {
		return
	}
	fmt.Fprintf(b, "\n*🔕 Low priority (%d)* — %d finding(s) across %d image(s), no exploitation signal (not in KEV, EPSS below threshold).\n", n, n, len(imgs))
	b.WriteString("_Details in the generic webhook payload or the weekly full report._\n")
}

// writeEvidence renders the "why act now" line under a package: the strongest
// CVE with its KEV/EPSS facts, a hint when the fix status limits the response,
// and the count of further CVEs folded into the group.
func writeEvidence(b *strings.Builder, r analyze.Report, g analyze.PackageGroup) {
	top := g.TopVuln()
	if top.ID == "" {
		return
	}
	fmt.Fprintf(b, "     ↳ %s", evidence(r, top))
	if rest := len(g.Vulns) - 1; rest > 0 {
		fmt.Fprintf(b, " (+%d more CVE(s) in this package)", rest)
	}
	switch g.Status {
	case scanner.StatusAffected:
		b.WriteString(" — no fix yet, consider mitigation")
	case scanner.StatusWontFix:
		b.WriteString(" — upstream won't fix, consider replacing")
	}
	b.WriteString("\n")
	writeRefs(b, top)
}

// writeRefs renders the reference links under an act-now evidence line: the
// scanner's advisory, the vendor advisory from the KEV notes, and the HN
// discussion when one exists. Links only — verifiable facts, no summaries
// (docs/TRIAGE_SPEC.md §8).
func writeRefs(b *strings.Builder, v analyze.VulnRef) {
	var parts []string
	if v.URL != "" {
		parts = append(parts, fmt.Sprintf("<%s|advisory>", v.URL))
	}
	for _, ref := range v.Refs {
		label := ref.Label
		if ref.Kind == "discussion" {
			label = "💬 " + label
		}
		parts = append(parts, fmt.Sprintf("<%s|%s>", ref.URL, label))
	}
	if len(parts) == 0 {
		return
	}
	fmt.Fprintf(b, "       📎 %s\n", strings.Join(parts, " · "))
}

// evidence states the facts behind a verdict: ID, severity, then exploitation
// intel. In degraded mode there is no intel to cite and the header warning
// already explains why.
func evidence(r analyze.Report, v analyze.VulnRef) string {
	parts := []string{v.ID + " " + string(v.Severity)}
	if r.Intel.Degraded() {
		parts = append(parts, "severity only (intel unavailable)")
		return strings.Join(parts, " · ")
	}
	if v.KEV {
		parts = append(parts, "CISA KEV (exploited in the wild)")
	}
	parts = append(parts, "EPSS "+epssString(v))
	if v.Ransomware {
		parts = append(parts, "🧨 ransomware campaign")
	}
	return strings.Join(parts, " · ")
}

// shortEvidence is the compact reason used inline in the watch bucket.
func shortEvidence(r analyze.Report, v analyze.VulnRef) string {
	if v.ID == "" || r.Intel.Degraded() {
		return ""
	}
	if v.KEV {
		return v.ID + " · CISA KEV"
	}
	return v.ID + " · EPSS " + epssString(v)
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
func writeTriageChanges(b *strings.Builder, r analyze.Report, changes []state.Change) {
	if len(changes) == 0 {
		return
	}
	sorted := make([]state.Change, len(changes))
	copy(sorted, changes)
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

	fmt.Fprintf(b, "\n*🆕 New since last scan (%d)*\n", len(sorted))
	lastImage := ""
	for _, c := range sorted {
		if c.Image != lastImage {
			fmt.Fprintf(b, "%s %s\n", priorityEmoji(analyze.MaxPriority(c.Groups)), c.Image)
			lastImage = c.Image
		}
		for _, g := range c.Groups {
			writePackage(b, g, g.Status == scanner.StatusFixed, triageChangeSuffix(c))
			if g.Priority == analyze.PriorityActNow {
				writeEvidence(b, r, g)
			}
		}
	}
}

// triageChangeSuffix annotates why a known package reappears.
func triageChangeSuffix(c state.Change) string {
	switch c.Kind {
	case state.KindEscalated:
		return " — ⬆️ escalated to " + priorityLabel(analyze.MaxPriority(c.Groups))
	case state.KindNewCVEs:
		return fmt.Sprintf(" — %d new CVE(s)", c.NewCVEs)
	case state.KindNowFixable:
		return " — fix now available"
	default:
		return ""
	}
}

// writeTriageOpenNow is the heartbeat line with the priority breakdown. Only
// urgent findings age it: an old "low" is the triage doing its job, not debt.
func writeTriageOpenNow(b *strings.Builder, r analyze.Report, d state.Diff) {
	if !r.HasFindings() {
		b.WriteString("\n🎉 Open now: none — all clear\n")
		return
	}
	var seg []string
	if n := len(r.EOSLImages); n > 0 {
		seg = append(seg, fmt.Sprintf("⛔ %d EOL base", n))
	}
	if d.OpenActNow > 0 {
		seg = append(seg, fmt.Sprintf("🚨 %d act-now", d.OpenActNow))
	}
	if d.OpenWatch > 0 {
		seg = append(seg, fmt.Sprintf("👀 %d watch", d.OpenWatch))
	}
	if d.OpenLow > 0 {
		seg = append(seg, fmt.Sprintf("🔕 %d low", d.OpenLow))
	}
	fmt.Fprintf(b, "\n📌 Open now: %s", strings.Join(seg, " / "))
	if days := d.OldestUrgentDays(r.GeneratedAt); days > 0 {
		if days >= staleDays {
			fmt.Fprintf(b, " — 🔴 oldest urgent unresolved %d day(s)", days)
		} else {
			fmt.Fprintf(b, " — oldest urgent unresolved %d day(s)", days)
		}
	}
	b.WriteString("\n_Details in the generic webhook payload, or in the weekly full report._\n")
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

func priorityLabel(p analyze.Priority) string {
	switch p {
	case analyze.PriorityActNow:
		return "ACT NOW"
	case analyze.PriorityWatch:
		return "WATCH"
	default:
		return "LOW"
	}
}

// changeEvidence is the webhook "reason" for an escalated change: the facts of
// the strongest CVE in the change's strongest group.
func changeEvidence(r analyze.Report, c state.Change) string {
	var best analyze.PackageGroup
	for _, g := range c.Groups {
		if g.Priority.Rank() >= best.Priority.Rank() {
			best = g
		}
	}
	if best.TopVuln().ID == "" {
		return ""
	}
	return evidence(r, best.TopVuln())
}
