// Thread-report rendering: the channel
// message stays the diff ("what changed"), while its thread carries the state
// ("what is open right now"). The thread expands urgent and watch findings in
// full — per-CVE evidence, references, and how long each finding has been
// open — and collapses low priority to a count, so the report stays readable
// on the day someone finally sits down to fix things.
package notify

import (
	"fmt"
	"strings"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/analyze"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

// threadMsgLimit caps one thread message's mrkdwn text. Slack renders roughly
// 3000 characters per section without truncation; overflowing content is
// split into consecutive replies on the same thread instead.
const threadMsgLimit = 2900

// alsoIDsMax caps how many secondary CVE ids are listed per package before
// falling back to a count (the full list is in the generic webhook payload,
// when one is configured).
const alsoIDsMax = 8

// threadSection is one titled chunk of the report. Blocks are the preferred
// split unit (one image, one line): a message boundary never lands inside a
// block unless a single block alone exceeds the size limit.
type threadSection struct {
	title  string
	blocks []string
}

// Ages supplies the first-seen times behind the thread's "open N day(s)"
// lines. Ordinary package groups use Finding; end-of-life package groups use
// EOL, which dates from when the package became end-of-life. Either may be
// nil, which omits the age lines of the groups it would cover.
type Ages struct {
	Finding func(image, pkg string) (time.Time, bool)
	EOL     func(image, pkg string) (time.Time, bool)
}

// forGroup picks the lookup that dates g.
func (a Ages) forGroup(g analyze.PackageGroup) func(image, pkg string) (time.Time, bool) {
	if analyze.IsEOL(g) {
		return a.EOL
	}
	return a.Finding
}

// BuildThreadMessages renders the full open-findings report as one or more
// mrkdwn messages to post as replies under the summary message. It returns
// nil when nothing is open (spec edge case 4: skip the thread entirely).
// limit <= 0 uses the default per-message budget.
func BuildThreadMessages(r analyze.Report, ages Ages, limit int, lang ...Language) []string {
	return buildThreadMessages(r, ages, limit, messagesFor(resolveLanguage(lang)))
}

func buildThreadMessages(r analyze.Report, ages Ages, limit int, msg messages) []string {
	if !r.HasFindings() {
		return nil
	}
	if limit <= 0 {
		limit = threadMsgLimit
	}
	title := fmt.Sprintf(msg.ThreadTitle, r.GeneratedAt.Format(timeLayout))
	byRef := imagesByRef(r)

	var secs []threadSection
	if len(r.EOSLImages) > 0 {
		s := threadSection{title: fmt.Sprintf(msg.EOLBaseImagesHeading, len(r.EOSLImages))}
		for _, img := range r.EOSLImages {
			s.blocks = append(s.blocks, eosLine(r, img, byRef, msg))
		}
		secs = append(secs, s)
	}
	if imgs := r.EOLPackageAlerts(); len(imgs) > 0 {
		secs = append(secs, eolThreadSection(r, byRef, imgs, ages, msg))
	}
	if r.Triage {
		secs = append(secs, triageThreadSections(r, byRef, ages, msg)...)
	} else {
		secs = append(secs, statusThreadSections(r, byRef, ages, msg)...)
	}
	if n := mutedCount(r); n > 0 {
		secs = append(secs, threadSection{blocks: []string{"\n" + fmt.Sprintf(msg.MutedLine, n)}})
	}
	// Same cross-cutting "identity unconfirmed" summary as the Slack messages,
	// wired into the thread report too.
	if line := unresolvedRefsLine(r, msg); line != "" {
		secs = append(secs, threadSection{blocks: []string{"\n" + line}})
	}
	return packThread(title, secs, limit, msg)
}

// triageThreadSections is the priority-ordered body: urgent and watch in full
// detail, low as a count-only line.
func triageThreadSections(r analyze.Report, byRef map[string]analyze.ImageObservation, ages Ages, msg messages) []threadSection {
	pv := r.ByPriority()
	// ActNow is never filtered: a group eligible for muting is never
	// act_now by construction.
	pv.Watch = filterMuted(pv.Watch)
	pv.Low = filterMuted(pv.Low)
	var secs []threadSection
	if n := analyze.GroupCount(pv.ActNow); n > 0 {
		secs = append(secs, threadBucket(r, byRef, fmt.Sprintf(msg.ThreadActNowHeading, n), pv.ActNow, ages, msg))
	}
	if n := analyze.GroupCount(pv.Watch); n > 0 {
		secs = append(secs, threadBucket(r, byRef, fmt.Sprintf(msg.ThreadWatchHeading, n), pv.Watch, ages, msg))
	}
	if n := analyze.GroupCount(pv.Low); n > 0 {
		low := fmt.Sprintf(msg.ThreadLowHeading, n)
		// The generic webhook is the only destination with per-package
		// detail beyond this count, and only when one is actually
		// configured — a weekly full report shows this same count-only
		// line, never more.
		if r.GenericWebhookConfigured {
			low += msg.ThreadLowDetailsSuffix
		}
		low += "\n"
		if inUse := countInUse(pv.Low); inUse > 0 {
			low += fmt.Sprintf(msg.ThreadLowInUseCount, inUse)
		}
		secs = append(secs, threadSection{blocks: []string{low}})
	}
	return secs
}

// statusThreadSections is the triage-off fallback: the status-based sections
// with every package expanded (no low bucket exists to collapse).
func statusThreadSections(r analyze.Report, byRef map[string]analyze.ImageObservation, ages Ages, msg messages) []threadSection {
	section := func(title string, imgs []analyze.ImageFindings) threadSection {
		return threadBucket(r, byRef, "*"+title+"*", imgs, ages, msg)
	}
	var secs []threadSection
	if len(r.Actionable) > 0 {
		// Never filtered: only affected/will_not_fix findings are ever
		// eligible for muting.
		secs = append(secs, section(msg.ActionableTitle, r.Actionable))
	}
	if watch := filterMuted(r.Watch); len(watch) > 0 {
		secs = append(secs, section(msg.WatchSectionTitle, watch))
	}
	if wontFix := filterMuted(r.WontFix); len(wontFix) > 0 {
		secs = append(secs, section(msg.WontFixSectionTitle, wontFix))
	}
	return secs
}

// threadBucket renders one bucket, one block per image so message splits fall
// between images.
func threadBucket(r analyze.Report, byRef map[string]analyze.ImageObservation, title string, imgs []analyze.ImageFindings, ages Ages, msg messages) threadSection {
	s := threadSection{title: title}
	for _, img := range imgs {
		var b strings.Builder
		fmt.Fprintf(&b, "%s %s\n", threadImageMarker(r, img), imageLabel(img, byRef, msg))
		for _, g := range img.Packages {
			writePackage(&b, g, g.Status == scanner.StatusFixed, "", msg)
			writeThreadDetail(&b, r, img.Image, g, ages.forGroup(g), msg)
			writeRuntimeThreadLine(&b, g.Runtime, msg)
		}
		s.blocks = append(s.blocks, b.String())
	}
	return s
}

// eolThreadSection renders the end-of-life packages not folded into a
// base-OS line, one block per image. An act_now group is a one-line pointer:
// the ACT NOW section below carries its full detail.
func eolThreadSection(r analyze.Report, byRef map[string]analyze.ImageObservation, imgs []analyze.ImageFindings, ages Ages, msg messages) threadSection {
	s := threadSection{title: fmt.Sprintf(msg.EOLPackagesThreadHeading, analyze.GroupCount(imgs), msg.EOLSectionReason)}
	for _, img := range imgs {
		var b strings.Builder
		fmt.Fprintf(&b, "%s %s\n", threadImageMarker(r, img), imageLabel(img, byRef, msg))
		for _, g := range img.Packages {
			if g.Priority == analyze.PriorityActNow {
				writePackage(&b, g, false, msg.EOLSeeActNow, msg)
				continue
			}
			writePackage(&b, g, false, "", msg)
			writeThreadDetail(&b, r, img.Image, g, ages.forGroup(g), msg)
			writeRuntimeThreadLine(&b, g.Runtime, msg)
		}
		s.blocks = append(s.blocks, b.String())
	}
	return s
}

// threadImageMarker picks the per-image line marker: in triage mode the
// bucket header (ACT NOW/WATCH/LOW) already carries the priority signal, so a
// severity emoji per image would be redundant and just uses a plain bullet.
// The status-based fallback (triage off) has no such bucket signal, so it
// keeps the severity emoji.
func threadImageMarker(r analyze.Report, img analyze.ImageFindings) string {
	if r.Triage {
		return "•"
	}
	return imageEmoji(img)
}

// writeThreadDetail renders one package's thread detail: the headline CVE's
// evidence, its Trivy title (a one-line "what is this" the CVE ID alone
// doesn't convey), references, the remaining CVE ids, and the open age.
func writeThreadDetail(b *strings.Builder, r analyze.Report, image string, g analyze.PackageGroup, firstSeen func(image, pkg string) (time.Time, bool), msg messages) {
	if top := g.TopVuln(); top.ID != "" {
		// With triage off there is no intel to cite (and evidence() would
		// misreport that as an outage), so the line is just id + severity.
		line := vulnIDLink(top.ID) + " " + string(top.Severity)
		if r.Triage {
			line = evidence(r, top, msg)
		}
		fmt.Fprintf(b, "     ↳ %s", line)
		switch g.Status {
		case scanner.StatusAffected:
			b.WriteString(msg.NoFixYetMitigation)
		case scanner.StatusWontFix:
			b.WriteString(msg.WontFixReplace)
		case scanner.StatusEndOfLife:
			b.WriteString(msg.EOLEvidenceMark)
		}
		b.WriteString("\n")
		if top.Title != "" {
			fmt.Fprintf(b, "       %s\n", top.Title)
		}
		writeRefs(b, top, msg)
		writeAlsoIDs(b, g, msg)
	}
	if firstSeen == nil {
		return
	}
	if t, ok := firstSeen(image, g.Package); ok {
		if days := openDays(t, r.GeneratedAt); days > 0 {
			fmt.Fprintf(b, msg.ThreadImageAgeLine, days, t.Format("2006-01-02"))
		} else {
			b.WriteString(msg.ThreadFirstSeenToday)
		}
	}
}

// writeAlsoIDs lists the CVE ids folded behind the headline evidence.
func writeAlsoIDs(b *strings.Builder, g analyze.PackageGroup, msg messages) {
	if len(g.Vulns) <= 1 {
		return
	}
	ids := make([]string, 0, len(g.Vulns)-1)
	for _, v := range g.Vulns[1:] {
		ids = append(ids, vulnIDLink(v.ID))
	}
	extra := 0
	if len(ids) > alsoIDsMax {
		ids, extra = ids[:alsoIDsMax], len(ids)-alsoIDsMax
	}
	fmt.Fprintf(b, msg.ThreadAlsoIDs, strings.Join(ids, ", "))
	if extra > 0 {
		fmt.Fprintf(b, msg.MoreCount, extra)
	}
	b.WriteString("\n")
}

// openDays is the whole-day age of a finding at now (0 for today or a clock
// skew into the future).
func openDays(t, now time.Time) int {
	days := int(now.Sub(t).Hours() / 24)
	if days < 0 {
		return 0
	}
	return days
}

// packThread packs section blocks into messages of at most limit characters.
// Splits happen at block boundaries first (spec: priority unit, then item
// count); a section continued on a later message repeats its title with a
// "(cont.)" marker. A single block larger than the budget is split on line
// boundaries as a last resort.
func packThread(title string, secs []threadSection, limit int, msg messages) []string {
	blockBudget := limit - 400 // headroom for the title and a repeated section header
	if blockBudget < 1 {
		blockBudget = limit
	}

	var msgs []string
	cur := title + "\n"
	curSection := ""             // section whose header is already in cur
	started := map[string]bool{} // sections whose header appeared in any message

	for _, s := range secs {
		for _, blk := range s.blocks {
			for _, piece := range splitByLines(blk, blockBudget) {
				head := ""
				if s.title != "" && s.title != curSection {
					head = "\n" + sectionHeader(s.title, started[s.title], msg) + "\n"
				}
				if cur != "" && len(cur)+len(head)+len(piece) > limit {
					msgs = append(msgs, strings.Trim(cur, "\n"))
					cur, curSection = "", ""
					head = ""
					if s.title != "" {
						head = sectionHeader(s.title, started[s.title], msg) + "\n"
					}
				}
				cur += head + piece
				if s.title != "" {
					curSection = s.title
					started[s.title] = true
				}
			}
		}
	}
	if strings.TrimSpace(cur) != "" {
		msgs = append(msgs, strings.Trim(cur, "\n"))
	}
	return msgs
}

func sectionHeader(title string, cont bool, msg messages) string {
	if cont {
		return title + msg.ThreadContinued
	}
	return title
}

// splitByLines returns the block unchanged when it fits, otherwise cuts it
// into line-aligned pieces no larger than budget (a single oversized line is
// passed through rather than cut mid-word).
func splitByLines(blk string, budget int) []string {
	if len(blk) <= budget {
		return []string{blk}
	}
	var pieces []string
	cur := ""
	for _, line := range strings.SplitAfter(blk, "\n") {
		if line == "" {
			continue
		}
		if cur != "" && len(cur)+len(line) > budget {
			pieces = append(pieces, cur)
			cur = ""
		}
		cur += line
	}
	if cur != "" {
		pieces = append(pieces, cur)
	}
	return pieces
}
