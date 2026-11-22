// Semantic layer of the Block Kit rendering: one package finding as a card of
// plain values (names, versions, ids, counts, facts), independent of how a
// view lays it out. The renderers in cardrender.go turn a card into blocks;
// nothing here knows about Slack markup beyond the CVE links and the
// untrusted-text escaping the existing helpers already provide.
package notify

import (
	"fmt"
	"strings"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/analyze"
	rtevidence "github.com/kitsunetrail/kestrelynx/internal/evidence"
	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
	"github.com/kitsunetrail/kestrelynx/internal/state"
)

// runtimeMode says how much of a card's runtime state is shown.
type runtimeMode int

const (
	// rtNone shows nothing.
	rtNone runtimeMode = iota
	// rtShort is the one-line "▶ in use (running)" form for an in-use package.
	rtShort
	// rtInUse is the full fact block, for an in-use package only.
	rtInUse
	// rtAll is the full fact block plus the not-in-use and unavailable states.
	rtAll
)

// cardCVE is one vulnerability of a package.
type cardCVE struct {
	ID         string
	Severity   string
	EPSS       string // epssString result
	KEV        bool
	Ransomware bool
	// IntelDegraded is true when triage is on and its KEV/EPSS data cannot
	// be used.
	IntelDegraded bool
	EPSSKnown     bool // false when EPSS is "n/a"
	// Intel is true when triage is on and its KEV/EPSS data is trustworthy,
	// i.e. when EPSS and KEV facts may be cited at all.
	Intel bool
	// URL is the scanner's advisory for the vulnerability, which its id links
	// to; "" when the scanner gave none.
	URL string
	// Title is the scanner's summary of the vulnerability; "" when it gave
	// none.
	Title string
	// Refs are the further links of the vulnerability.
	Refs []cardRef
}

// cardRef is one further link of a vulnerability: the vendor advisory from
// the KEV notes (Kind "vendor"). Label is the analyzer's own label, shown
// only for a kind the messages have no label for.
type cardRef struct {
	Kind  string
	Label string
	URL   string
}

// cardRuntime is a package's runtime-usage state as separate facts.
type cardRuntime struct {
	Usage         rtevidence.Usage // "" when runtime evidence was never attached
	ShortWord     string           // in use: "running" / "loaded" / "executed"
	Facts         inUseFacts       // in use: valid when FactsOK
	FactsOK       bool
	UnavailReason string // unavailable: the reason text
}

// cardAge is how long a finding has been open.
type cardAge struct {
	Known     bool
	Days      int // 0 means first seen today
	FirstSeen string
}

// pkgCard is one package finding as values. A view picks which of these to
// show; the card itself carries every value its builder was asked for.
type pkgCard struct {
	Name      string
	Ecosystem string // language packages only
	Installed string
	Fixed     string // fixed version(s); "" when there is none
	FixNote   string // what to do when there is no fix; "" when none applies
	Risk      analyze.Risk
	Critical  int
	High      int
	Medium    int
	Low       int
	Unknown   int

	Changes []string // diff views: what changed for this package

	// CVEs are the vulnerabilities of the package, strongest first, up to
	// cveListMax; CVEExtra counts the rest. A compact card names them on one
	// line and a detail card gives each a line of its own.
	CVEs     []cardCVE
	CVEExtra int

	RuntimeMode runtimeMode
	Runtime     cardRuntime

	Age cardAge

	SeeActNow bool // end-of-life act-now package: points at the Act now section

	// BaseWait is set when the finding lives in the base image of a
	// Dockerfile-built image, or in a pinned running image, whose tag's own
	// series the plan found no fix in; it says what a newer series showed.
	BaseWait *baseWait
	// Action is set when the plan says something else about how the card's
	// findings get fixed (see card_action.go). A card has BaseWait or Action,
	// never both.
	Action *cardAction
}

// cardOpts selects which values newPkgCard collects.
type cardOpts struct {
	// noCVEs leaves the vulnerabilities out: the card only points at the
	// section that shows the package in full.
	noCVEs  bool
	notes   bool // fix note under "none" (otherwise the end-of-life row text only)
	runtime runtimeMode
	change  *state.Change
	// age dates the finding; nil for a view that does not show the age.
	age func(image, pkg string) (time.Time, bool)
}

// cveListMax caps how many vulnerabilities a card names before falling back
// to a count (the full list is in the generic webhook payload, when one is
// configured). A package has no upper bound of its own, and a Slack message
// does.
const cveListMax = 20

// cardCVEOf collects the display values of one vulnerability of r.
func cardCVEOf(r analyze.Report, v analyze.VulnRef) cardCVE {
	c := cardCVE{
		ID:            v.ID,
		Severity:      string(v.Severity),
		EPSS:          epssString(v),
		EPSSKnown:     v.EPSSKnown,
		KEV:           v.KEV,
		Ransomware:    v.Ransomware,
		IntelDegraded: r.Triage && r.Intel.Degraded(),
		Intel:         r.Triage && !r.Intel.Degraded(),
		URL:           v.URL,
		Title:         v.Title,
	}
	for _, ref := range v.Refs {
		c.Refs = append(c.Refs, cardRef{Kind: ref.Kind, Label: ref.Label, URL: ref.URL})
	}
	return c
}

// riskValue is the display value of an upgrade risk, without a label.
func riskValue(r analyze.Risk, msg messages) string {
	switch r {
	case analyze.RiskDistroUpdate:
		return msg.RiskValueDistroUpdate
	case analyze.RiskSafe:
		return msg.RiskValueSafe
	case analyze.RiskCaution:
		return msg.RiskValueCaution
	case analyze.RiskUnknown:
		return msg.RiskValueUnknown
	default:
		return ""
	}
}

// cardRuntimeOf collects the runtime facts of rt.
func cardRuntimeOf(rt analyze.Runtime, msg messages) cardRuntime {
	c := cardRuntime{Usage: rt.Usage}
	switch rt.Usage {
	case rtevidence.UsageInUse:
		c.ShortWord = runtimeShortWord(rt.EvidenceKinds, msg)
		c.Facts, c.FactsOK = runtimeInUseFacts(rt, msg)
	case rtevidence.UsageUnavailable:
		c.UnavailReason = reasonText(rt.Reason, msg)
	}
	return c
}

// newPkgCard collects one package group's values for a view. image is the
// reference the group belongs to (the age lookup is keyed on it).
func newPkgCard(r analyze.Report, image string, g analyze.PackageGroup, o cardOpts, msg messages) pkgCard {
	c := pkgCard{
		Name:        g.Package,
		Installed:   g.InstalledVer,
		Risk:        g.Risk,
		Critical:    g.Critical,
		High:        g.High,
		Medium:      g.Medium,
		Low:         g.Low,
		Unknown:     g.Unknown,
		RuntimeMode: o.runtime,
	}
	if g.Class == "lang" {
		c.Ecosystem = langTag(g.Ecosystem)
	}
	switch {
	case g.Status == scanner.StatusFixed:
		c.Fixed = g.FixedVer
	case analyze.IsEOL(g):
		c.FixNote = msg.EOLPackageText
		if o.notes {
			c.FixNote = msg.FixNoteEOL
		}
		// No fix will come for a runtime's series, so only the series can move.
		if inventory.RuntimeVersionEnv(g.Ecosystem) != "" {
			c.FixNote = msg.EOLRuntimeText
			if o.notes {
				c.FixNote = msg.FixNoteEOLRuntime
			}
		}
	case o.notes && g.Status == scanner.StatusAffected:
		c.FixNote = msg.FixNoteMitigate
	case o.notes && g.Status == scanner.StatusWontFix:
		c.FixNote = msg.FixNoteWontFix
	}

	if !o.noCVEs {
		for _, v := range g.Vulns {
			switch {
			case v.ID == "":
			case len(c.CVEs) < cveListMax:
				c.CVEs = append(c.CVEs, cardCVEOf(r, v))
			default:
				c.CVEExtra++
			}
		}
	}

	if o.runtime != rtNone {
		c.Runtime = cardRuntimeOf(g.Runtime, msg)
	}
	if o.change != nil {
		c.Changes = changeParts(*o.change, g, msg)
	}
	if o.age != nil {
		if t, ok := o.age(image, g.Package); ok {
			c.Age = cardAge{Known: true, Days: openDays(t, r.GeneratedAt), FirstSeen: t.Format("2006-01-02")}
		}
	}
	return c
}

// changeParts are the pieces of a package's "Change" line, in display order:
// the new CVE ids when the change carries some for this group, then the
// kind's own label. A plain new finding has no change line.
func changeParts(c state.Change, g analyze.PackageGroup, msg messages) []string {
	var parts []string
	if ids := groupNewIDs(c, g); len(ids) > 0 {
		shown, extra := ids, 0
		if len(ids) > newIDsMax {
			shown, extra = ids[:newIDsMax], len(ids)-newIDsMax
		}
		urls := make(map[string]string, len(g.Vulns))
		for _, v := range g.Vulns {
			urls[v.ID] = v.URL
		}
		links := make([]string, len(shown))
		for i, id := range shown {
			links[i] = cveLink(id, urls[id])
		}
		s := fmt.Sprintf(msg.CardNewCVEs, strings.Join(links, ", "))
		if extra > 0 {
			s += fmt.Sprintf(msg.MoreCount, extra)
		}
		parts = append(parts, s)
	}
	switch c.Kind {
	case state.KindEscalated:
		parts = append(parts, fmt.Sprintf(msg.EscalatedTo, priorityLabel(analyze.MaxPriority(c.Groups), msg)))
	case state.KindNowFixable:
		parts = append(parts, msg.FixNowAvailable)
	case state.KindUnmuted:
		parts = append(parts, fmt.Sprintf(msg.Unmuted, unmutedReason(changeReasonGroups(c), msg)))
	}
	return parts
}

// stripLeadDash drops the " — " an inline suffix format starts with, for
// reuse of the same wording as a line of its own.
func stripLeadDash(s string) string { return strings.TrimPrefix(s, " — ") }
