// Card renderers: a pkgCard (cards.go) turned into the lines and blocks of
// one view. The lines are "label: value" pairs; every label comes from the
// messages dictionary, and the values keep the formats the plain-text
// renderers already use (versions, CVE links, EPSS, paths in inline code).
package notify

import (
	"fmt"
	"strings"

	"github.com/kitsunetrail/kestrelynx/internal/analyze"
	rtevidence "github.com/kitsunetrail/kestrelynx/internal/evidence"
	"github.com/kitsunetrail/kestrelynx/internal/remediation"
)

// renderer carries what every card needs to render: the dictionary and the
// size limits sections are packed against.
type renderer struct {
	msg messages
	lim RenderLimits
}

// kv is one "label: value" line.
func kv(label, value string) string { return label + ": " + value }

// titleLine is the card's bold name line, with the ecosystem of a language
// package in brackets after one space.
func (c pkgCard) titleLine() string {
	s := boldLine("◆ ", boldMrkdwn(c.Name))
	if c.Ecosystem != "" {
		s += " [" + escMrkdwn(c.Ecosystem) + "]"
	}
	return s
}

// fixedValue is the value of the fixed-in line: the fixed version(s), or
// "none" with what to do about it.
func (rd renderer) fixedValue(c pkgCard) string {
	if c.Fixed != "" {
		return escMrkdwn(c.Fixed)
	}
	v := rd.msg.LblFixedNone
	if c.FixNote != "" {
		v += " — " + c.FixNote
	}
	return v
}

func (rd renderer) countsValue(c pkgCard) string {
	return countsLine(rd.msg, analyze.SeverityCounts{Critical: c.Critical, High: c.High, Medium: c.Medium, Low: c.Low, Unknown: c.Unknown})
}

// baseWaitLine is the action line of a finding whose image tag's own series
// has no fix, with what a newer series showed, or "" when the card has none.
// It never says that no fix exists: only the tags named were checked.
func (rd renderer) baseWaitLine(c pkgCard) string {
	w := c.BaseWait
	if w == nil {
		return ""
	}
	msg := rd.msg
	name, tag := litMrkdwn(w.Name), litMrkdwn(w.Tag)
	if w.Verdict == waitPlain {
		return kv(msg.LblAction, fmt.Sprintf(msg.CardBaseWait, name, tag))
	}
	subject := msg.CardSubjectBase
	if w.Image {
		subject = msg.CardSubjectImage
	}
	own := msg.CardOwnNotFixed
	if w.OwnNoNewer {
		own = msg.CardOwnNoNewer
	}
	change := msg.CardChangeMinor
	if w.Change == remediation.SeriesChangeMajor {
		change = msg.CardChangeMajor
	}
	var checked []string
	for _, t := range strings.Split(w.Checked, "\x00") {
		if t != "" {
			checked = append(checked, litMrkdwn(t))
		}
	}
	var head string
	var clauses []string
	switch w.Verdict {
	case waitResolved:
		head = fmt.Sprintf(msg.CardNewerResolved, subject, name, tag, litMrkdwn(w.To))
		clauses = []string{change, own}
	case waitPartial:
		head = fmt.Sprintf(msg.CardNewerPartial, subject, name, tag, litMrkdwn(w.To))
		clauses = []string{fmt.Sprintf(msg.CardPartialClause, w.Resolved, w.Total), change, own}
	case waitRemains:
		tags := strings.Join(checked, msg.CardTagJoin)
		if w.OwnNoNewer {
			head = fmt.Sprintf(msg.CardNewerWait, subject, name, tag)
			clauses = []string{fmt.Sprintf(msg.CardCheckedNotFixed, tags)}
		} else {
			head = fmt.Sprintf(msg.CardNewerWaitUntagged, subject, name)
			clauses = []string{fmt.Sprintf(msg.CardOwnCheckedNotFixed, tags)}
		}
	case waitNoNewerSeries:
		head = fmt.Sprintf(msg.CardNewerWait, subject, name, tag)
		clauses = []string{msg.CardNoNewerSeries}
	default:
		return ""
	}
	if w.WithNew {
		clauses = append(clauses, msg.CardWithNew)
	}
	if !w.Image && w.Verdict != waitNoNewerSeries {
		clauses = append(clauses, msg.CardBaseCompared)
	}
	return kv(msg.LblAction, head+fmt.Sprintf(msg.CardClauseWrap, strings.Join(clauses, msg.CardClauseJoin)))
}

// actionLine is the action line of a card: the wait of baseWaitLine, or what
// the plan says else about how the card's findings get fixed; "" when the
// card has neither.
func (rd renderer) actionLine(c pkgCard) string {
	if l := rd.baseWaitLine(c); l != "" {
		return l
	}
	a := c.Action
	if a == nil {
		return ""
	}
	msg := rd.msg
	wrap := func(head string, clauses ...string) string {
		var kept []string
		for _, cl := range clauses {
			if cl != "" {
				kept = append(kept, cl)
			}
		}
		if len(kept) == 0 {
			return kv(msg.LblAction, head)
		}
		return kv(msg.LblAction, head+fmt.Sprintf(msg.CardClauseWrap, strings.Join(kept, msg.CardClauseJoin)))
	}
	name, tag, to := litMrkdwn(a.Name), litMrkdwn(a.Tag), litMrkdwn(a.To)
	file := msg.CardDependencyFiles
	if a.File != "" {
		file = litMrkdwn(a.File)
	}
	// A line about the base image of a Dockerfile names it as its subject
	// and says that the bases were compared, not the image built from them.
	subject, compared := msg.CardSubjectImage, ""
	if a.Base {
		subject, compared = msg.CardSubjectBase, msg.CardBaseCompared
	}
	partial := fmt.Sprintf(msg.CardPartialClause, a.Resolved, a.Total)
	// why is the reason of a line that only gives one; decision is the
	// clause of an update a person decides on, "" for any other.
	why := planReasonText(msg.Lang, string(a.Why))
	decision := ""
	if a.Why != "" {
		decision = fmt.Sprintf(msg.CardDecisionClause, why)
	}
	switch a.Kind {
	case actImageResolved:
		return wrap(fmt.Sprintf(msg.CardNewerResolved, subject, name, tag, to), rd.prClause(a.PR), decision, compared)
	case actImagePartial:
		return wrap(fmt.Sprintf(msg.CardNewerPartial, subject, name, tag, to), partial, rd.prClause(a.PR), decision, compared)
	case actImageRemains:
		return wrap(fmt.Sprintf(msg.CardNewerWait, subject, name, tag), fmt.Sprintf(msg.CardSameSeriesNotFixed, to), decision, compared)
	case actImageUnknown:
		return wrap(fmt.Sprintf(msg.CardNewerUnknown, subject, name, tag, to), compared)
	case actPullResolved:
		return wrap(fmt.Sprintf(msg.CardPullResolved, subject, name, tag), decision)
	case actPullPartial:
		return wrap(fmt.Sprintf(msg.CardPullPartial, subject, name, tag), partial, decision)
	case actPullRemains:
		return wrap(fmt.Sprintf(msg.CardContentWait, subject, name, tag), msg.CardPullNotFixed, decision)
	case actPullUnknown:
		return wrap(fmt.Sprintf(msg.CardPullUnknown, subject, name, tag))
	case actImageDecision:
		return wrap(fmt.Sprintf(msg.CardImageDecision, name), why)
	case actPullDecision:
		return wrap(fmt.Sprintf(msg.CardPullDecision, name, tag), why)
	case actContentSame:
		return wrap(fmt.Sprintf(msg.CardContentWait, subject, name, tag), msg.CardSameContentRunning)
	case actTagWaitNoNewer:
		return wrap(fmt.Sprintf(msg.CardNewerWait, subject, name, tag), msg.CardOwnNoNewer)
	case actTagWaitSameContent:
		return wrap(fmt.Sprintf(msg.CardNewerWait, subject, name, tag), msg.CardOwnSameContent)
	case actTagWaitNotFixed:
		return wrap(fmt.Sprintf(msg.CardNewerWaitUntagged, subject, name), msg.CardOwnNotFixed, compared)
	case actBaseDecision:
		return wrap(msg.CardBaseDecision, why)
	case actBaseUnchanged:
		return wrap(fmt.Sprintf(msg.CardContentWait, subject, name, tag), msg.CardBaseContentUnchanged)
	case actRebuildResolved:
		return wrap(msg.CardRebuildResolved, fmt.Sprintf(msg.CardRebuildFixedInBase, name, tag))
	case actRebuildPartial:
		return wrap(msg.CardRebuildPartial, partial, fmt.Sprintf(msg.CardRebuildComparedBase, name, tag))
	case actRebuildRemains:
		return wrap(fmt.Sprintf(msg.CardContentWait, subject, name, tag), msg.CardRebuildStillPresent)
	case actRebuildNotInBase:
		return wrap(msg.CardRebuildUnknown, msg.CardRebuildNotInBase)
	case actBaseMergedWait:
		return wrap(rd.prClause(a.PR))
	case actLangInPR:
		prs := rd.prNumbers(a.PR)
		switch a.PR.Kind {
		case prMergedRunning:
			return wrap(fmt.Sprintf(msg.CardLangPRMerged, prs, to))
		case prClosed:
			return wrap(fmt.Sprintf(msg.CardLangPRClosed, prs, to))
		case prReplaced:
			return wrap(fmt.Sprintf(msg.CardLangPRReplaced, prs, to, rd.prNumber(a.PR.Replaced)))
		}
		return wrap(fmt.Sprintf(msg.CardLangPR, prs, to))
	case actLangCandidate:
		return wrap(fmt.Sprintf(msg.CardLangCandidate, file, to), rd.prClause(a.PR))
	case actLangCandidateAtLeast:
		return wrap(fmt.Sprintf(msg.CardLangCandidateAtLeast, file, to), rd.prClause(a.PR))
	case actLangRebuild:
		return wrap(fmt.Sprintf(msg.CardLangRebuild, to))
	case actLangOutOfReach:
		return wrap(fmt.Sprintf(msg.CardLangOutOfReach, file), why)
	case actLangNotAutomatic:
		return wrap(fmt.Sprintf(msg.CardLangNotAutomatic, file), why)
	case actLangItemFailed:
		return wrap(fmt.Sprintf(msg.CardLangItemFailed, file), why)
	case actLangItemLater:
		return wrap(fmt.Sprintf(msg.CardLangItemLater, file), why)
	case actLangUnconfirmed:
		if a.Why == "" {
			return wrap(fmt.Sprintf(msg.CardLangUnconfirmed, file))
		}
		return wrap(fmt.Sprintf(msg.CardLangUnconfirmed, file), why)
	case actNotChecked:
		return wrap(fmt.Sprintf(msg.CardNotChecked, subject), why)
	case actCheckFailed:
		return wrap(fmt.Sprintf(msg.CardCheckFailed, subject), why)
	case actCheckLater:
		return wrap(fmt.Sprintf(msg.CardCheckLater, subject), why)
	case actGlobalSelf:
		return wrap(fmt.Sprintf(msg.CardGlobalSelf, litMrkdwn(a.Dir), litMrkdwn(a.Owner), file))
	case actGlobalBundled:
		if a.OwnerVersion == "" {
			return wrap(fmt.Sprintf(msg.CardGlobalBundled, litMrkdwn(a.Owner), litMrkdwn(a.Dir), file))
		}
		return wrap(fmt.Sprintf(msg.CardGlobalBundledVersion, litMrkdwn(a.Owner), litMrkdwn(a.OwnerVersion), litMrkdwn(a.Dir), file))
	}
	return ""
}

// prNumber names one pull request: its number, linked when its URL is known.
func (rd renderer) prNumber(r prRef) string {
	label := fmt.Sprintf("#%d", r.Number)
	if r.URL == "" {
		return label
	}
	return mrkdwnLink(r.URL, label)
}

// prNumbers names the pull requests of a clause.
func (rd renderer) prNumbers(p prClause) string {
	refs := make([]string, len(p.PRs))
	for i, r := range p.PRs {
		refs[i] = rd.prNumber(r)
	}
	return strings.Join(refs, rd.msg.CardClauseJoin)
}

// prClause puts the pull request part of an action line into words; "" when
// it says nothing.
func (rd renderer) prClause(p prClause) string {
	msg := rd.msg
	ref := rd.prNumber
	prs := rd.prNumbers(p)
	why := planReasonText(msg.Lang, string(p.Reason))
	if p.Reason == "" {
		why = litMrkdwn(p.Status)
	}
	switch p.Kind {
	case prExists:
		return fmt.Sprintf(msg.CardPR, prs)
	case prMergedRunning:
		return fmt.Sprintf(msg.CardPRMergedRunning, prs)
	case prMergedRebuild:
		return fmt.Sprintf(msg.CardPRMergedRebuild, prs)
	case prClosed:
		return fmt.Sprintf(msg.CardPRClosed, prs)
	case prReplaced:
		return fmt.Sprintf(msg.CardPRReplaced, prs, ref(p.Replaced))
	case prModified:
		return fmt.Sprintf(msg.CardPRModified, prs)
	case prNotCreated:
		return fmt.Sprintf(msg.CardPRNotCreated, why)
	case prWontCreate:
		return fmt.Sprintf(msg.CardPRWontCreate, why)
	case prUnconfirmed:
		return fmt.Sprintf(msg.CardPRUnconfirmed, why)
	}
	return ""
}

func (rd renderer) changeLine(c pkgCard) string {
	if len(c.Changes) == 0 {
		return ""
	}
	return kv(rd.msg.LblChange, strings.Join(c.Changes, " · "))
}

// cveLine names the vulnerabilities of the card on one line (a compact
// card), or "" when the card has none. Where the triage intel is trustworthy,
// a CVE with an EPSS score shows it and one without is named alone; a CVE in
// CISA KEV makes its package act now, which has the detail card and not this
// line. Without that intel (triage off, or its data unusable) each CVE shows
// its severity instead, which is then all there is to tell them apart. The
// ones past cveListMax are a count.
func (rd renderer) cveLine(c pkgCard) string {
	if len(c.CVEs) == 0 {
		return ""
	}
	parts := make([]string, len(c.CVEs))
	for i, t := range c.CVEs {
		parts[i] = cveLink(t.ID, t.URL)
		switch {
		case !t.Intel:
			if t.Severity != "" {
				parts[i] += " (" + escMrkdwn(t.Severity) + ")"
			}
		case t.EPSSKnown:
			parts[i] += " (" + fmt.Sprintf(rd.msg.EvidenceEPSSPrefix, escMrkdwn(t.EPSS)) + ")"
		}
	}
	line := kv(rd.msg.LblCVEs, strings.Join(parts, ", "))
	if c.CVEExtra > 0 {
		line += fmt.Sprintf(rd.msg.MoreCount, c.CVEExtra)
	}
	return line
}

// cveLines give each vulnerability of the card a line of its own (a detail
// card), under the label the compact line has: the id, the severity, the EPSS
// score and the exploitation facts where the intel behind them is
// trustworthy, the scanner's summary, and the vendor advisory. With the intel
// unusable the label line says once that only the severity is shown. The
// vulnerabilities past cveListMax are a count on a last line.
func (rd renderer) cveLines(c pkgCard) []string {
	if len(c.CVEs) == 0 {
		return nil
	}
	msg := rd.msg
	head := msg.LblCVEs + ":"
	if c.CVEs[0].IntelDegraded {
		head = kv(msg.LblCVEs, msg.EvidenceSeverityOnly)
	}
	lines := []string{head}
	for _, t := range c.CVEs {
		parts := []string{cveLink(t.ID, t.URL)}
		if t.Severity != "" {
			parts = append(parts, escMrkdwn(t.Severity))
		}
		if t.Intel {
			parts = append(parts, fmt.Sprintf(msg.EvidenceEPSSPrefix, escMrkdwn(t.EPSS)))
			if t.KEV {
				parts = append(parts, msg.EvidenceKEV)
			}
			if t.Ransomware {
				parts = append(parts, msg.EvidenceRansomware)
			}
		}
		// The summary is an external text on a line of its own CVE: it is
		// shown as the literal one line it is.
		if t.Title != "" {
			parts = append(parts, litMrkdwn(t.Title))
		}
		parts = append(parts, refLinksSafe(t.Refs, msg)...)
		lines = append(lines, "• "+strings.Join(parts, " · "))
	}
	if c.CVEExtra > 0 {
		lines = append(lines, "• "+fmt.Sprintf(msg.CardCVEsMore, c.CVEExtra))
	}
	return lines
}

// runtimeLines are the lines of a card's runtime section. Only an in-use
// package yields the evidence, exposure and privilege facts, all from the
// one representative container; the not-in-use and unavailable states are
// shown only by the views that ask for them (rtAll).
func (rd renderer) runtimeLines(c pkgCard) []string {
	rt := c.Runtime
	switch c.RuntimeMode {
	case rtNone:
		return nil
	case rtShort:
		if rt.Usage != rtevidence.UsageInUse {
			return nil
		}
		return []string{kv(rd.msg.LblRuntime, fmt.Sprintf(rd.msg.InUsePrefix, rt.ShortWord))}
	}
	switch rt.Usage {
	case rtevidence.UsageInUse:
		lines := []string{kv(rd.msg.LblRuntime, rd.msg.InUseFallbackArrow)}
		if !rt.FactsOK {
			return lines
		}
		f := rt.Facts
		lines = append(lines, kv(rd.msg.LblEvidence, f.EvidenceBare))
		last := lastSeenText(f.LastSeen, rd.msg)
		var parts []string
		label := ""
		switch {
		case f.Exposure != "":
			label = rd.msg.LblExposure
			parts = append(parts, f.Exposure)
			if f.HighPrivilege {
				parts = append(parts, rd.msg.HighPrivilegeNote)
			}
		case f.HighPrivilege:
			label = rd.msg.LblPrivilege
			parts = append(parts, rd.msg.HighPrivilegeNote)
		}
		switch {
		case label != "":
			if last != "" {
				parts = append(parts, last)
			}
			lines = append(lines, kv(label, strings.Join(parts, " · ")))
		case !f.LastSeen.IsZero():
			lines = append(lines, kv(rd.msg.LblLastSeen, f.LastSeen.Format("01-02 15:04")))
		}
		return lines
	case rtevidence.UsageNotObserved:
		if c.RuntimeMode == rtAll {
			return []string{kv(rd.msg.LblRuntime, rd.msg.ThreadNotObserved)}
		}
	case rtevidence.UsageUnavailable:
		if c.RuntimeMode == rtAll {
			return []string{kv(rd.msg.LblRuntime, fmt.Sprintf(rd.msg.ThreadRuntimeUnavailable, rt.UnavailReason))}
		}
	}
	return nil
}

// ageText is the card's elapsed-time context line, "" when unknown.
func (rd renderer) ageText(c pkgCard) string {
	if !c.Age.Known {
		return ""
	}
	if c.Age.Days > 0 {
		return fmt.Sprintf(rd.msg.CardAgeLine, c.Age.Days, c.Age.FirstSeen)
	}
	return rd.msg.CardAgeToday
}

// detailHeadLines are the first section of a detail or thread card: name,
// change, installed and fixed versions, upgrade risk and finding counts.
func (rd renderer) detailHeadLines(c pkgCard) []string {
	lines := []string{c.titleLine()}
	if l := rd.changeLine(c); l != "" {
		lines = append(lines, l)
	}
	lines = append(lines, kv(rd.msg.LblInstalled, escMrkdwn(c.Installed)), kv(rd.msg.LblFixed, rd.fixedValue(c)))
	if v := riskValue(c.Risk, rd.msg); v != "" {
		lines = append(lines, kv(rd.msg.LblUpgradeRisk, v))
	}
	lines = append(lines, kv(rd.msg.LblFindings, rd.countsValue(c)))
	if l := rd.actionLine(c); l != "" {
		lines = append(lines, l)
	}
	return lines
}

// detailCard is the channel's detail card: a head section, a section with
// the vulnerabilities and a runtime section, each present only when it has
// content.
func (rd renderer) detailCard(c pkgCard) []Block {
	blocks := sectionBlocks(rd.detailHeadLines(c), rd.lim.MaxTextUnits)
	blocks = append(blocks, sectionBlocks(rd.cveLines(c), rd.lim.MaxTextUnits)...)
	blocks = append(blocks, sectionBlocks(rd.runtimeLines(c), rd.lim.MaxTextUnits)...)
	return blocks
}

// threadCard is the thread's card: the detail card, then the age as
// context. A section with no values is not built. The view
// puts the divider in front.
func (rd renderer) threadCard(c pkgCard) []Block {
	blocks := rd.detailCard(c)
	if age := rd.ageText(c); age != "" {
		blocks = append(blocks, contextBlock(age))
	}
	return blocks
}

// contTitle heads the continuation of a card that had to be cut between its
// sections: the package name and its installed version.
// The name and version are shortened: the heading must stay small however
// long they are.
func (rd renderer) contTitle(c pkgCard) string {
	name := boldLine("◆ ", boldMrkdwnCapped(c.Name, contNameUnits))
	if c.Ecosystem != "" {
		name += " [" + capEscaped(escMrkdwn(c.Ecosystem), contNameUnits) + "]"
	}
	return name + rd.msg.ThreadContinued + "\n" + kv(rd.msg.LblInstalled, capEscaped(escMrkdwn(c.Installed), contNameUnits))
}

// contNameUnits caps a name or version repeated in a continuation heading.
const contNameUnits = 200

// capEscaped shortens already-escaped text to at most max UTF-16 units with
// an ellipsis, never inside an entity.
func capEscaped(s string, max int) string {
	if utf16Len(s) <= max {
		return s
	}
	var b strings.Builder
	n := 0
	for _, a := range runeAtoms(s) {
		if n+a.n > max-1 {
			break
		}
		b.WriteString(a.text)
		n += a.n
	}
	return b.String() + "…"
}

// imageHeadingCapped is imageHeading with the label shortened, for the
// heading a continuation message repeats.
func (rd renderer) imageHeadingCapped(label string) string {
	return boldLine(rd.msg.LblImage+": ", boldMrkdwnCapped(label, contNameUnits))
}

// compactLines are the lines of a card shown as one section: name, change,
// installed and fixed versions on one line (the upgrade risk in parentheses
// after the fixed version), counts, the vulnerabilities and the short runtime
// state.
func (rd renderer) compactLines(c pkgCard) []string {
	lines := []string{c.titleLine()}
	if l := rd.changeLine(c); l != "" {
		lines = append(lines, l)
	}
	fixed := rd.fixedValue(c)
	if v := riskValue(c.Risk, rd.msg); v != "" && c.Fixed != "" {
		fixed += " (" + v + ")"
	}
	lines = append(lines,
		kv(rd.msg.LblInstalled, escMrkdwn(c.Installed))+" · "+kv(rd.msg.LblFixed, fixed),
		kv(rd.msg.LblFindings, rd.countsValue(c)))
	if l := rd.actionLine(c); l != "" {
		lines = append(lines, l)
	}
	if l := rd.cveLine(c); l != "" {
		lines = append(lines, l)
	}
	if c.SeeActNow {
		lines = append(lines, kv(rd.msg.LblDetails, rd.msg.CardSeeActNow))
	}
	lines = append(lines, rd.runtimeLines(c)...)
	return lines
}

// imageHeading is the bold image line that opens an image's cards.
func (rd renderer) imageHeading(label string) string {
	return boldLine(rd.msg.LblImage+": ", boldMrkdwn(label))
}
