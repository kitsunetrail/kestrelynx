// Triage-mode Slack rendering: the message is organized by priority — act
// now / watch / low — instead of by fix status.
// Every act-now item carries its evidence (KEV, EPSS) inline: the product's
// promise is "fix this one tonight, ignore the rest", and an unexplained order
// would be indistinguishable from the severity walls it replaces.
package notify

import (
	"fmt"
	"strings"

	"github.com/kitsunetrail/kestrelynx/internal/analyze"
	"github.com/kitsunetrail/kestrelynx/internal/state"
)

// triageSegments are the segments of the triage priority line, zero counts
// omitted.
func triageSegments(r analyze.Report, pv analyze.PriorityView, msg messages) []string {
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
	return seg
}

// intelWarning is the warning text for missing intel ("" when none is
// missing), newline-terminated like every dictionary line.
func intelWarning(r analyze.Report, msg messages) string {
	switch {
	case r.Intel.Degraded():
		return msg.IntelDegradedWarning
	case !r.Intel.KEVOK:
		return msg.IntelKEVUnavailable
	case !r.Intel.EPSSOK:
		return msg.IntelEPSSUnavailable
	}
	return ""
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
