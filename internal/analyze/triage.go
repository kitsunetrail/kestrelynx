// Triage (Phase 1+, docs/TRIAGE_SPEC.md): combine severity with exploitation
// intel (CISA KEV, EPSS) into a per-CVE priority — act_now / watch / low — so
// the notification can say "fix this one tonight, ignore the rest" instead of
// listing twenty equal-looking CRITICALs.
package analyze

import (
	"sort"

	"github.com/kitsunetrail/stackwatch/internal/scanner"
)

// Priority is StackWatch's triage verdict for a vulnerability. It is kept
// separate from Severity (ADR-008): severity is the reported impact, priority
// is our judgement of urgency, and the evidence for it is always shown.
type Priority string

const (
	PriorityNone   Priority = ""        // triage disabled
	PriorityLow    Priority = "low"     // no exploitation signal: safe to batch
	PriorityWatch  Priority = "watch"   // keep in sight, no urgency
	PriorityActNow Priority = "act_now" // exploited or likely to be: tonight's work
)

// Rank orders priorities for max-aggregation and escalation checks.
func (p Priority) Rank() int {
	switch p {
	case PriorityActNow:
		return 3
	case PriorityWatch:
		return 2
	case PriorityLow:
		return 1
	default:
		return 0
	}
}

// Enrichment is the exploitation intel for one vulnerability ID. It mirrors
// intel.Enrichment; analyze deliberately does not import the intel package
// (the analysis rules depend on the data, not on how it is fetched).
type Enrichment struct {
	KEV        bool    // listed in the CISA KEV catalog (exploited in the wild)
	Ransomware bool    // KEV: known use in ransomware campaigns
	EPSS       float64 // exploitation probability [0,1]; valid only when EPSSKnown
	EPSSKnown  bool
	KEVNoteURL string // vendor advisory / CISA alert from the KEV notes
}

// Ref is a reference link attached to a vulnerability (Phase 1.5,
// docs/TRIAGE_SPEC.md §8): a verifiable URL, never a generated summary.
type Ref struct {
	Kind  string // "vendor" (KEV notes) | "discussion" (HN)
	Label string // short human label, e.g. "vendor advisory", "HN (166 pts)"
	URL   string
}

// IntelStatus reports how trustworthy the enrichment data is, mirroring
// intel.Freshness.
type IntelStatus struct {
	KEVOK     bool
	EPSSOK    bool
	StaleDays int
}

// Degraded reports that no intel is usable: triage falls back to severity-only
// rules that create no "low" bucket (ADR-011 — a data outage must fail toward
// noise, never toward silently downgrading a real threat).
func (s IntelStatus) Degraded() bool { return !s.KEVOK && !s.EPSSOK }

// Triage carries the enrichment data and thresholds into Build. The zero value
// disables triage entirely (Phase 1 behavior: no priorities assigned).
type Triage struct {
	Enabled    bool
	ActNowEPSS float64 // EPSS at or above this is act_now (default 0.10)
	WatchEPSS  float64 // EPSS at or above this is at least watch (default 0.01)
	Enrich     map[string]Enrichment
	Refs       map[string][]Ref // extra links per vulnerability ID (discussions)
	Intel      IntelStatus
}

// SignalsActNow reports whether the intel alone makes an ID act_now (KEV or
// EPSS at threshold). It is the shared predicate between priority assignment
// and the runner's "which CVEs deserve a discussion lookup" filter, so the two
// can never drift apart.
func (tr Triage) SignalsActNow(e Enrichment) bool {
	return e.KEV || (e.EPSSKnown && e.EPSS >= tr.ActNowEPSS)
}

// VulnRef is one vulnerability inside a PackageGroup, with its triage verdict
// and the evidence behind it.
type VulnRef struct {
	ID         string
	Severity   scanner.Severity
	URL        string // scanner's primary advisory link for this CVE
	Title      string // short human-readable summary, if the scanner supplied one
	KEV        bool
	Ransomware bool
	EPSS       float64
	EPSSKnown  bool
	Priority   Priority
	Refs       []Ref // vendor advisory (KEV notes), discussion links
}

// priorityOf applies the rule table from docs/TRIAGE_SPEC.md §4: exploitation
// reality first (KEV), then likelihood (EPSS), with severity as the fallback
// net for CVEs the intel is silent about. Status only ever demotes watch → low
// for will_not_fix; a KEV/high-EPSS finding is never demoted for lacking a fix
// (hiding an actively exploited vulnerability because it can't be patched yet
// would be a lie — it needs mitigation, not silence).
func (tr Triage) priorityOf(sev scanner.Severity, e Enrichment, status scanner.Status) Priority {
	if !tr.Enabled {
		return PriorityNone
	}
	if tr.Intel.Degraded() {
		// Severity-only fallback: no low bucket while we're flying blind.
		if sev == scanner.SeverityCritical {
			return PriorityActNow
		}
		return PriorityWatch
	}
	if tr.SignalsActNow(e) {
		return PriorityActNow
	}
	p := PriorityLow
	if (e.EPSSKnown && e.EPSS >= tr.WatchEPSS) || sev == scanner.SeverityCritical {
		p = PriorityWatch
	}
	if status == scanner.StatusWontFix && p == PriorityWatch {
		p = PriorityLow
	}
	return p
}

// buildRefs assembles a vulnerability's reference links: the vendor advisory
// from the KEV notes first (the "how to respond" link), then whatever extra
// links the runner collected (discussions).
func buildRefs(e Enrichment, extra []Ref) []Ref {
	var refs []Ref
	if e.KEVNoteURL != "" {
		refs = append(refs, Ref{Kind: "vendor", Label: "vendor advisory", URL: e.KEVNoteURL})
	}
	return append(refs, extra...)
}

// sortVulns orders a group's vulnerabilities by verdict strength: priority
// desc, then EPSS desc (unknown scores last), then ID for stability. The first
// element is the group's headline evidence (TopVuln).
func sortVulns(vulns []VulnRef) {
	sort.Slice(vulns, func(i, j int) bool {
		a, b := vulns[i], vulns[j]
		if a.Priority.Rank() != b.Priority.Rank() {
			return a.Priority.Rank() > b.Priority.Rank()
		}
		if a.EPSSKnown != b.EPSSKnown {
			return a.EPSSKnown
		}
		if a.EPSS != b.EPSS {
			return a.EPSS > b.EPSS
		}
		return a.ID < b.ID
	})
}

// MaxPriority is the strongest verdict across a set of package groups (used by
// state and notify, which see one finding as several per-status groups).
func MaxPriority(groups []PackageGroup) Priority {
	max := PriorityNone
	for _, g := range groups {
		if g.Priority.Rank() > max.Rank() {
			max = g.Priority
		}
	}
	return max
}

// PriorityView regroups a report's findings by triage priority for rendering:
// the same image may appear in several buckets with the relevant subset of its
// packages. Only meaningful when the report was built with triage enabled.
type PriorityView struct {
	ActNow []ImageFindings
	Watch  []ImageFindings
	Low    []ImageFindings
}

// GroupCount is the number of package groups (the unit shown to the user)
// across a bucket's images.
func GroupCount(imgs []ImageFindings) int {
	n := 0
	for _, img := range imgs {
		n += len(img.Packages)
	}
	return n
}

// ByPriority builds the priority view from the status-based sections. The
// status sections remain the report's canonical structure (ADR-010, webhook
// compatibility); this is the Slack rendering's axis.
func (r Report) ByPriority() PriorityView {
	buckets := map[Priority]map[string][]PackageGroup{}
	for _, section := range [][]ImageFindings{r.Actionable, r.Watch, r.WontFix} {
		for _, img := range section {
			for _, g := range img.Packages {
				m := buckets[g.Priority]
				if m == nil {
					m = map[string][]PackageGroup{}
					buckets[g.Priority] = m
				}
				m[img.Image] = append(m[img.Image], g)
			}
		}
	}
	return PriorityView{
		ActNow: bucketSection(buckets[PriorityActNow]),
		Watch:  bucketSection(buckets[PriorityWatch]),
		Low:    bucketSection(buckets[PriorityLow]),
	}
}

// bucketSection finalizes one priority bucket into sorted ImageFindings.
func bucketSection(images map[string][]PackageGroup) []ImageFindings {
	if len(images) == 0 {
		return nil
	}
	out := make([]ImageFindings, 0, len(images))
	for image, groups := range images {
		sortPackages(groups)
		out = append(out, ImageFindings{Image: image, Packages: groups})
	}
	sortImages(out)
	return out
}
