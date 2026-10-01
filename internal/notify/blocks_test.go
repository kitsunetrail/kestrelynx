package notify

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/analyze"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
	"github.com/kitsunetrail/kestrelynx/internal/state"
)

// bigReport builds a triage report with n watch-priority OS packages in one
// image; title, when set, becomes every CVE's title.
func bigReport(n int, title string) analyze.Report {
	var finds []scanner.Finding
	enrich := map[string]analyze.Enrichment{}
	for i := 1; i <= n; i++ {
		id := fmt.Sprintf("CVE-2040-%04d", i)
		finds = append(finds, scanner.Finding{
			Image: "big:1", Class: scanner.ClassOS, Package: fmt.Sprintf("pkg%02d", i), InstalledVer: "1.0",
			Status: scanner.StatusAffected, Severity: scanner.SeverityHigh, VulnID: id, URL: "https://avd.example/" + id, Title: title,
		})
		enrich[id] = analyze.Enrichment{EPSS: 0.05, EPSSKnown: true}
	}
	scan := pinned(scanner.ImageScan{Image: "big:1", Findings: finds}, goldenContentWeb)
	return analyze.Build([]scanner.ImageScan{scan}, nil, triageRules(enrich), genTime)
}

func messageIndexOf(msgs []SlackMessage, needle string) int {
	for i, m := range msgs {
		for _, b := range m.Blocks {
			if strings.Contains(b.Text, needle) {
				return i
			}
		}
	}
	return -1
}

func TestBlockKitJSONShape(t *testing.T) {
	m := SlackMessage{Text: "t", Blocks: []Block{
		{Kind: BlockSection, Text: "a <b|c>"},
		{Kind: BlockDivider},
		{Kind: BlockContext, Text: "d"},
	}}
	got, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	var v map[string]any
	if err := json.Unmarshal(got, &v); err != nil {
		t.Fatal(err)
	}
	var want map[string]any
	if err := json.Unmarshal([]byte(`{"text":"t","blocks":[{"type":"section","text":{"type":"mrkdwn","text":"a <b|c>"}},{"type":"divider"},{"type":"context","elements":[{"type":"mrkdwn","text":"d"}]}]}`), &want); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(v, want) {
		t.Errorf("JSON:\n got %s", got)
	}
	if empty, _ := json.Marshal(SlackMessage{Text: "x"}); string(empty) != `{"text":"x","blocks":[]}` {
		t.Errorf("empty message JSON = %s", empty)
	}
}

// balancedFragment reports a problem with a fragment of mrkdwn text that
// must stand alone: an unclosed code span or link, or a cut entity.
func balancedFragment(p string) string {
	if strings.Count(p, "`")%2 != 0 {
		return "unbalanced backticks"
	}
	if strings.Count(p, "<") != strings.Count(p, ">") {
		return "unbalanced link brackets"
	}
	for i := 0; i < len(p); i++ {
		if p[i] == '&' && escapedEntity(p[i:]) == 0 {
			return "cut entity"
		}
	}
	return ""
}

func TestSplitLongLine_EveryFragmentIsBalanced(t *testing.T) {
	link := "<https://example.com/a/very/long/path|label>"
	code := "`/usr/lib/x86_64-linux-gnu/libssl.so.3`"
	cases := map[string]string{
		"mixed":      strings.Repeat("あ", 40) + link + strings.Repeat("い", 40) + code + strings.Repeat("う", 40),
		"entities":   strings.Repeat("a&amp;b&lt;c&gt;", 60),
		"hugeCode":   "x `" + strings.Repeat("c&amp;d", 120) + "` y",
		"hugeLink":   "see <https://example.com/" + strings.Repeat("p", 200) + "|" + strings.Repeat("l", 40) + "> end",
		"hugeBare":   "<https://example.com/" + strings.Repeat("q&amp;", 80) + ">",
		"cjkOnly":    strings.Repeat("字", 300),
		"spacedText": strings.Repeat("word ", 80),
	}
	for name, line := range cases {
		for _, max := range []int{40, 60, 100} {
			pieces := splitLongLine(line, max)
			for _, p := range pieces {
				if utf16Len(p) > max {
					t.Errorf("%s/%d: piece of %d units: %q", name, max, utf16Len(p), p)
				}
				if bad := balancedFragment(p); bad != "" {
					t.Errorf("%s/%d: %s in %q", name, max, bad, p)
				}
			}
		}
	}

	// The text survives: a code span is reopened per fragment, so only the
	// backticks differ; a link too large to stay whole becomes its URL text.
	inner := strings.Repeat("c&amp;d", 120)
	var got strings.Builder
	for _, p := range splitLongLine(cases["hugeCode"], 60) {
		got.WriteString(strings.ReplaceAll(p, "`", ""))
	}
	if !strings.Contains(strings.ReplaceAll(got.String(), " ", ""), inner) {
		t.Errorf("code text lost across fragments")
	}
	got.Reset()
	for _, p := range splitLongLine(cases["hugeLink"], 60) {
		got.WriteString(strings.ReplaceAll(p, " ", ""))
	}
	if !strings.Contains(got.String(), "https://example.com/"+strings.Repeat("p", 200)) {
		t.Errorf("link URL text lost: %q", got.String())
	}
}

func TestSplitLongLine_PrefersBreakingAtSpaces(t *testing.T) {
	pieces := splitLongLine(strings.Repeat("word ", 30), 22)
	for _, p := range pieces[:len(pieces)-1] {
		if !strings.HasSuffix(p, " ") {
			t.Errorf("piece %q was cut mid-word", p)
		}
	}
}

func TestUTF16Len(t *testing.T) {
	if got := utf16Len("a日🔥"); got != 4 { // 1 + 1 + 2
		t.Errorf("utf16Len = %d, want 4", got)
	}
	if got := truncateUnits("🔥🔥🔥", 5); utf16Len(got) > 5 || !strings.HasSuffix(got, "…") {
		t.Errorf("truncateUnits = %q", got)
	}
}

func TestThreadSplit_ManyPackagesKeepCardsWhole(t *testing.T) {
	r := bigReport(60, "")
	msgs := buildThreadBlockMessages(r, Ages{}, enMessages, defaultRenderLimits)
	if len(msgs) < 3 {
		t.Fatalf("60 packages should span several messages, got %d", len(msgs))
	}
	checkMessageConstraints(t, "thread 60", msgs, defaultRenderLimits)

	prev := -1
	for i := 1; i <= 60; i++ {
		name := fmt.Sprintf("pkg%02d", i)
		head := messageIndexOf(msgs, "*◆ "+name+"*")
		cve := messageIndexOf(msgs, fmt.Sprintf("CVE-2040-%04d|", i))
		if head < 0 {
			t.Fatalf("%s is missing", name)
		}
		if head != cve {
			t.Errorf("%s: head in message %d but its CVE line in %d: a card was cut", name, head+1, cve+1)
		}
		if head < prev {
			t.Errorf("%s: message %d comes before the previous package's %d", name, head+1, prev+1)
		}
		prev = head
		if n := strings.Count(allBlocksText(msgs), "*◆ "+name+"*"); n != 1 {
			t.Errorf("%s appears %d times", name, n)
		}
	}
	for i, m := range msgs[1:] {
		first := m.Blocks[0].Text
		if m.Blocks[0].Kind != BlockSection ||
			!strings.Contains(first, "*👀 WATCH (60) — not urgent, keep an eye on* _(cont.)_") ||
			!strings.Contains(first, "*Image: big:1* _(cont.)_") {
			t.Errorf("message %d does not open with the continuation heading: %q", i+2, first)
		}
		if !strings.HasSuffix(m.Text, "(cont.)"+fmt.Sprintf(" · big:1 (%d package(s))", strings.Count(allBlocksText([]SlackMessage{m}), "*◆ "))) {
			t.Errorf("message %d fallback text %q", i+2, m.Text)
		}
	}
	if !strings.HasPrefix(msgs[0].Blocks[0].Text, "📊 *Everything open now") {
		t.Errorf("first message does not open with the report title: %q", msgs[0].Blocks[0].Text)
	}
}

func TestChannelSplit_NumberedContinuationAndFooterOnFirst(t *testing.T) {
	r := bigReport(60, "")
	footer := ChannelFooter{Kind: FooterThreadNotice}
	msgs := buildChannelMessages(Message{Report: r}, footer, enMessages, defaultRenderLimits)
	if len(msgs) < 2 {
		t.Fatalf("60 packages should span several messages, got %d", len(msgs))
	}
	checkMessageConstraints(t, "channel 60", msgs, defaultRenderLimits)
	notice := footerText(footer, enMessages, defaultRenderLimits)
	for i, m := range msgs {
		hasNotice := strings.Contains(allBlocksText([]SlackMessage{m}), notice)
		if hasNotice != (i == 0) {
			t.Errorf("message %d: footer present = %v", i+1, hasNotice)
		}
		if i == 0 {
			continue
		}
		wantHead := fmt.Sprintf("🛡️ *KestreLynx* — scan results for 2026-06-24 09:00 _(cont. %d/%d)_", i+1, len(msgs))
		first := m.Blocks[0].Text
		if !strings.HasPrefix(first, wantHead) {
			t.Errorf("message %d opens with %q, want prefix %q", i+1, first, wantHead)
		}
		if !strings.Contains(first, "*👀 Watch (60) — not urgent, keep an eye on* _(cont.)_") || !strings.Contains(first, "*Image: big:1* _(cont.)_") {
			t.Errorf("message %d heading lacks the category/image continuation: %q", i+1, first)
		}
		if want := fmt.Sprintf("KestreLynx 2026-06-24 09:00 Everything currently open (cont. %d/%d)", i+1, len(msgs)); m.Text != want {
			t.Errorf("message %d fallback = %q, want %q", i+1, m.Text, want)
		}
	}
	for i := 1; i <= 60; i++ {
		if n := strings.Count(allBlocksText(msgs), fmt.Sprintf("*◆ pkg%02d*", i)); n != 1 {
			t.Errorf("pkg%02d appears %d times", i, n)
		}
	}
}

func TestSplit_NeverEndsInHeadingOrDivider(t *testing.T) {
	// Sweep the block budget so every boundary position is tried.
	r := bigReport(12, "short title")
	for maxBlocks := 8; maxBlocks <= 20; maxBlocks++ {
		lim := RenderLimits{MaxBlocks: maxBlocks, MaxTextUnits: 3000, MaxMessageUnits: 12000, MaxFallbackUnits: 4000}
		msgs := buildThreadBlockMessages(r, Ages{}, jaMessages, lim)
		checkMessageConstraints(t, fmt.Sprintf("blocks<=%d", maxBlocks), msgs, lim)
		for i, m := range msgs {
			last := m.Blocks[len(m.Blocks)-1]
			if last.Kind == BlockSection && strings.HasPrefix(last.Text, "*イメージ:") {
				t.Errorf("blocks<=%d message %d ends with an image heading", maxBlocks, i+1)
			}
		}
	}
}

func TestLongTitleIsSplitAcrossSectionsOfOneCard(t *testing.T) {
	title := strings.Repeat("長い説明文 ", 900) // ~5400 units
	r := bigReport(1, title)
	msgs := buildThreadBlockMessages(r, Ages{}, jaMessages, defaultRenderLimits)
	checkMessageConstraints(t, "long title", msgs, defaultRenderLimits)
	sections := 0
	runes := 0
	for _, m := range msgs {
		for _, b := range m.Blocks {
			if b.Kind == BlockSection && strings.ContainsRune(b.Text, '長') {
				sections++
				runes += strings.Count(b.Text, "長")
			}
		}
	}
	if sections < 2 {
		t.Fatalf("a 5400-unit title should span at least two sections, got %d", sections)
	}
	if runes != 900 {
		t.Errorf("the split title keeps %d of 900 repetitions", runes)
	}
}

func TestLongReferenceListKeepsLinksIntact(t *testing.T) {
	rd := renderer{msg: enMessages, lim: defaultRenderLimits}
	c := pkgCard{Name: "p", Installed: "1", Critical: 1, HasTop: true, TopMode: topFull,
		Top: cardCVE{ID: "CVE-2040-0001", Severity: "HIGH", EPSS: "1%", Intel: true}}
	for i := 0; i < 120; i++ {
		c.Refs = append(c.Refs, cardRef{Kind: "discussion", Label: strings.Repeat("l", 30), URL: fmt.Sprintf("https://example.com/%d", i)})
	}
	blocks := rd.detailCard(c)
	n := 0
	for _, b := range blocks {
		if utf16Len(b.Text) > rd.lim.MaxTextUnits {
			t.Errorf("section of %d units", utf16Len(b.Text))
		}
		if strings.Count(b.Text, "<") != strings.Count(b.Text, ">") {
			t.Errorf("a link is cut in %q", b.Text[:60])
		}
		n += strings.Count(b.Text, "https://example.com/")
	}
	if n != 120 {
		t.Errorf("%d of 120 references survive", n)
	}
}

func TestOversizedCardIsCutBetweenItsSectionsWithItsNameRepeated(t *testing.T) {
	title := strings.Repeat("x", 2900) + "\n" // forces more text than a small message budget
	r := bigReport(1, title+strings.Repeat("y", 2900))
	lim := RenderLimits{MaxBlocks: 50, MaxTextUnits: 3000, MaxMessageUnits: 3500, MaxFallbackUnits: 4000}
	msgs := buildThreadBlockMessages(r, Ages{}, enMessages, lim)
	if len(msgs) < 2 {
		t.Fatalf("a card larger than a message must be cut, got %d message(s)", len(msgs))
	}
	checkMessageConstraints(t, "oversized card", msgs, lim)
	for i, m := range msgs[1:] {
		if !strings.Contains(m.Blocks[0].Text, "*◆ pkg01* _(cont.)_") || !strings.Contains(m.Blocks[0].Text, "Installed: 1.0") {
			t.Errorf("continuation %d does not name the card: %q", i+2, m.Blocks[0].Text)
		}
	}
}

func TestChannelBuild_EmptyAndAllClear(t *testing.T) {
	r := analyze.Build([]scanner.ImageScan{pinned(scanner.ImageScan{Image: "clean:1"}, goldenContentWeb)}, nil, triageRules(nil), genTime)
	msgs := buildChannelMessages(Message{Report: r}, ChannelFooter{}, enMessages, defaultRenderLimits)
	checkMessageConstraints(t, "all clear", msgs, defaultRenderLimits)
	if !strings.Contains(allBlocksText(msgs), "All clear") {
		t.Errorf("all-clear message lacks the all-clear line:\n%s", dumpMessages(msgs))
	}
	if got := buildThreadBlockMessages(r, Ages{}, enMessages, defaultRenderLimits); got != nil {
		t.Errorf("thread for a report with nothing open = %v, want nil", got)
	}
}

func TestChannelFooterKinds(t *testing.T) {
	r := bigReport(1, "")
	for _, c := range []struct {
		name   string
		footer ChannelFooter
		want   string
	}{
		{"none", ChannelFooter{}, ""},
		{"thread", ChannelFooter{Kind: FooterThreadNotice}, "📊 Everything open now is in this message's thread ↓"},
		{"last report", ChannelFooter{Kind: FooterLastReport, Permalink: "https://x.slack.com/p1"}, "🔗 Everything open as of the last report → <https://x.slack.com/p1|thread>"},
	} {
		msgs := BuildChannelMessages(Message{Report: r}, c.footer, LanguageEN)
		last := msgs[0].Blocks[len(msgs[0].Blocks)-1]
		switch {
		case c.want == "" && last.Kind == BlockContext && strings.Contains(last.Text, "thread"):
			t.Errorf("%s: unexpected footer %q", c.name, last.Text)
		case c.want != "" && (last.Kind != BlockContext || last.Text != c.want):
			t.Errorf("%s: last block = %v %q, want context %q", c.name, last.Kind, last.Text, c.want)
		}
	}
}

// TestBlockKitOmitsRetiredWording checks, over every golden case, that the
// wording the new layout retires never reaches the output.
func TestBlockKitOmitsRetiredWording(t *testing.T) {
	retired := []string{
		"short-lived programs not fully observed",
		"短命なプログラムは完全には観測できていない",
		"📎", "↳", "upgrade: ", "アップグレード:",
	}
	for _, c := range allBlockCases(t) {
		text := allBlocksText(c.build(c.limits()))
		for _, w := range retired {
			if strings.Contains(text, w) {
				t.Errorf("%s: output contains retired wording %q", c.name, w)
			}
		}
	}
}

// TestBlockKitLeavesWebhookWordingAlone pins the English reason texts the
// generic webhook shares with the Slack renderer: the new labels are separate
// dictionary keys, so these must keep their historical text.
func TestBlockKitLeavesWebhookWordingAlone(t *testing.T) {
	if enMessages.EvidenceKEV != "CISA KEV (exploited in the wild)" || enMessages.EvidenceRansomware != "🧨 ransomware campaign" {
		t.Errorf("evidence wording shared with the webhook changed")
	}
	if enMessages.UnmutedNowInUse != "now in use" || enMessages.EvidenceSeverityOnly != "severity only (intel unavailable)" {
		t.Errorf("reason wording shared with the webhook changed")
	}
	r, changed, _, _ := goldenCycle(goldenModes()[0], false)
	data, err := json.Marshal(BuildWebhookPayload(r, &changed))
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Diff struct {
			New []struct{ Reason string }
		}
	}
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, n := range v.Diff.New {
		if strings.Contains(n.Reason, "CISA KEV (exploited in the wild)") {
			found = true
		}
	}
	if !found {
		t.Errorf("webhook escalation reasons lost their English evidence text")
	}
}

// --- escaping ---

func TestEscaping_ExternalValuesNeverReachSlackSyntax(t *testing.T) {
	enrich := map[string]analyze.Enrichment{
		"CVE-2041-0001": {KEV: true, EPSS: 0.5, EPSSKnown: true, KEVNoteURL: "https://v.example/a|b"},
	}
	scan := pinned(scanner.ImageScan{Image: "web<1>&co:1", Findings: []scanner.Finding{{
		Image: "web<1>&co:1", Class: scanner.ClassOS, Package: "a<b", InstalledVer: "1<2", Status: scanner.StatusAffected,
		Severity: scanner.SeverityCritical, VulnID: "CVE-2041-0001", URL: "https://avd.example/x y",
		Title: "<!channel> & <@U123> &lt;kept&gt;",
	}}}, goldenContentWeb)
	failed := scanner.ImageScan{Image: "bad<img>:1", Err: errString("pull failed: a & b <c>")}
	r := analyze.Build([]scanner.ImageScan{scan, failed}, nil, triageRules(enrich), genTime)
	r.Environment.Name = "prod<&>"

	var all []SlackMessage
	all = append(all, buildThreadBlockMessages(r, Ages{}, enMessages, defaultRenderLimits)...)
	all = append(all, buildChannelMessages(Message{Report: r}, ChannelFooter{Kind: FooterThreadNotice}, enMessages, defaultRenderLimits)...)
	text := allBlocksText(all)
	fallback := ""
	for _, m := range all {
		fallback += m.Text + "\n"
	}

	for _, want := range []string{
		"&lt;!channel&gt; &amp; &lt;@U123&gt; &amp;lt;kept&amp;gt;", // a Title is escaped once
		"*◆ a&lt;b*",                       // package name
		"Installed: 1&lt;2",                // version
		"web&lt;1&gt;&amp;co:1",            // image reference
		"pull failed: a &amp; b &lt;c&gt;", // scan error text
		"[prod&lt;&amp;&gt;]",              // environment name (fallback)
		"prod&lt;&amp;&gt;",                // environment name (header)
	} {
		if !strings.Contains(text+fallback, want) {
			t.Errorf("escaped text %q not found", want)
		}
	}
	for _, bad := range []string{"<!channel>", "<@U123>", "a<b", "prod<&>", "<c>"} {
		if strings.Contains(text, bad) || strings.Contains(fallback, bad) {
			t.Errorf("raw %q reaches Slack mrkdwn", bad)
		}
	}
	// A reference URL that cannot be a link target is plain text.
	if strings.Contains(text, "<https://v.example/a|b") || !strings.Contains(text, "(https://v.example/a|b)") {
		t.Errorf("a URL containing '|' must be shown as text, not as a link:\n%s", text)
	}
	if strings.Contains(text, "<https://avd.example/x y") {
		t.Errorf("a URL containing a space must not become a link")
	}
	// Every '<' left is the start of a link built from a validated URL.
	for _, line := range strings.Split(text, "\n") {
		for i := 0; i < len(line); i++ {
			if line[i] != '<' {
				continue
			}
			if !strings.HasPrefix(line[i:], "<https://") && !strings.HasPrefix(line[i:], "<http://") {
				t.Errorf("unexpected '<' in %q", line)
			}
		}
	}
}

func TestEscaping_GeneratedLiteralsAndLinks(t *testing.T) {
	if got := escMrkdwn("EPSS <0.1% >99% &"); got != "EPSS &lt;0.1% &gt;99% &amp;" {
		t.Errorf("escMrkdwn = %q", got)
	}
	if got := mrkdwnLink("https://example.com/?a=1&b=2", "x<y"); got != "<https://example.com/?a=1&amp;b=2|x&lt;y>" {
		t.Errorf("mrkdwnLink = %q", got)
	}
	for _, bad := range []string{"javascript:alert(1)", "https://a.example/x|y", "https://a.example/x>y", "https://a.example/ x", "ftp://a.example/x", ""} {
		if got := mrkdwnLink(bad, "label"); strings.HasPrefix(got, "<") {
			t.Errorf("mrkdwnLink(%q) = %q, want plain text", bad, got)
		}
	}
	if got := cardIDLink("GHSA-<x>"); got != "GHSA-&lt;x&gt;" {
		t.Errorf("cardIDLink = %q", got)
	}
	if got := cardIDLink("CVE-2026-1"); got != "<https://nvd.nist.gov/vuln/detail/CVE-2026-1|CVE-2026-1>" {
		t.Errorf("cardIDLink = %q", got)
	}
	// EPSS text with '<' is escaped where it is rendered.
	rd := renderer{msg: enMessages, lim: defaultRenderLimits}
	c := pkgCard{HasTop: true, TopMode: topShort, Top: cardCVE{ID: "CVE-2026-1", EPSS: "<0.1%", Intel: true}}
	if line := rd.topLine(c); !strings.Contains(line, "EPSS &lt;0.1%") {
		t.Errorf("topLine = %q", line)
	}
}

// --- context blocks ---

func TestContextBlocksRespectTheTextLimit(t *testing.T) {
	r := bigReport(3, "")
	for i := 0; i < 400; i++ {
		r.Images = append(r.Images, analyze.ImageObservation{Ref: fmt.Sprintf("registry.example/team/app-%03d:1.0", i)})
	}
	footer := ChannelFooter{Kind: FooterLastReport, Permalink: "https://example.slack.com/archives/C1/p1?" + strings.Repeat("a=1&", 1200) + "z=1"}
	msgs := buildChannelMessages(Message{Report: r}, footer, jaMessages, defaultRenderLimits)
	checkMessageConstraints(t, "400 unresolved refs", msgs, defaultRenderLimits)
	notes := 0
	for _, m := range msgs {
		for i, b := range m.Blocks {
			if b.Kind != BlockContext {
				continue
			}
			notes++
			if utf16Len(b.Text) > 3000 {
				t.Errorf("context of %d units", utf16Len(b.Text))
			}
			if i == 0 {
				t.Errorf("a context opens a message")
			}
			if bad := balancedFragment(b.Text); bad != "" {
				t.Errorf("context %s: %q", bad, b.Text[:40])
			}
		}
	}
	if notes < 3 {
		t.Errorf("long notes should span several contexts, got %d", notes)
	}
	all := strings.ReplaceAll(allBlocksText(msgs), "\n", "")
	for i := 0; i < 400; i++ {
		if !strings.Contains(all, fmt.Sprintf("app-%03d:1.0", i)) {
			t.Errorf("ref %d lost", i)
		}
	}
}

// --- oversized card ---

func TestOversizedCardKeepsContextAndFallbackPerFragment(t *testing.T) {
	r := bigReport(1, strings.Repeat("x", 2900)+"\n"+strings.Repeat("y", 2900))
	ages := Ages{Finding: func(image, pkg string) (time.Time, bool) { return genTime.AddDate(0, 0, -5), true }}
	lim := RenderLimits{MaxBlocks: 50, MaxTextUnits: 3000, MaxMessageUnits: 3500, MaxFallbackUnits: 4000}
	msgs := buildThreadBlockMessages(r, ages, enMessages, lim)
	if len(msgs) < 2 {
		t.Fatalf("expected the card to be cut, got %d message(s)", len(msgs))
	}
	checkMessageConstraints(t, "oversized card with age", msgs, lim)
	for i, m := range msgs {
		if strings.TrimSpace(m.Text) == "" || !strings.Contains(m.Text, "big:1") {
			t.Errorf("message %d fallback = %q, want it to name the image", i+1, m.Text)
		}
		for j, b := range m.Blocks {
			if b.Kind == BlockContext && (j == 0 || m.Blocks[j-1].Kind == BlockDivider) {
				t.Errorf("message %d: the age context is not attached to a section", i+1)
			}
		}
	}
	if !strings.Contains(allBlocksText(msgs), "⏱ open 5 day(s)") {
		t.Errorf("age context lost")
	}
	// The package is counted once, on the message holding its first fragment.
	n := 0
	for _, m := range msgs {
		n += strings.Count(m.Text, "(1 package(s))")
	}
	if n != 1 {
		t.Errorf("the package is counted in %d fallbacks, want 1", n)
	}
}

// --- splitting at category boundaries ---

func TestSplitRightBeforeSummarySectionsAddsNoStaleContinuation(t *testing.T) {
	r, changed, _, _ := goldenCycle(goldenModes()[0], false)
	sawLow := false
	for maxBlocks := 6; maxBlocks <= 40; maxBlocks++ {
		lim := RenderLimits{MaxBlocks: maxBlocks, MaxTextUnits: 3000, MaxMessageUnits: 12000, MaxFallbackUnits: 4000}
		for _, c := range []struct {
			name string
			msgs []SlackMessage
		}{
			{"full", buildChannelMessages(Message{Report: r}, ChannelFooter{Kind: FooterThreadNotice}, enMessages, lim)},
			{"weekly", buildChannelMessages(Message{Report: r, Diff: &changed, FullReport: true}, ChannelFooter{Kind: FooterThreadNotice}, enMessages, lim)},
			{"diff", buildChannelMessages(Message{Report: r, Diff: &changed}, ChannelFooter{Kind: FooterThreadNotice}, enMessages, lim)},
		} {
			checkMessageConstraints(t, fmt.Sprintf("%s blocks<=%d", c.name, maxBlocks), c.msgs, lim)
			for i, msg := range c.msgs {
				if strings.HasPrefix(msg.Blocks[len(msg.Blocks)-1].Text, "*📋") {
					t.Errorf("%s blocks<=%d message %d ends with the weekly heading", c.name, maxBlocks, i+1)
				}
				if i == 0 {
					continue
				}
				first := msg.Blocks[0].Text
				if !strings.Contains(first, "Image: ") || !strings.Contains(first, "(cont.)_") {
					continue
				}
				// A continued image heading must lead into a card.
				next := 1
				if msg.Blocks[next].Kind == BlockDivider {
					next++
				}
				if !strings.Contains(msg.Blocks[next].Text, "*◆ ") {
					t.Errorf("%s blocks<=%d message %d: continuation heading above %q", c.name, maxBlocks, i+1, msg.Blocks[next].Text)
				}
			}
			if strings.Contains(allBlocksText(c.msgs), "*🔕 Low priority") {
				sawLow = true
			}
		}
	}
	if !sawLow {
		t.Fatal("the sweep never reached the low-priority section")
	}
}

// --- end-of-life base images in the thread ---

func TestThreadEOSLUsesTheThreadLayout(t *testing.T) {
	r, _, _, _ := eolCycle(goldenModes()[0])
	msgs := buildThreadBlockMessages(r, Ages{}, enMessages, defaultRenderLimits)
	first := msgs[0].Blocks[0].Text
	want := "*⛔ EOL base images (2)*\n*Image: legacy:1*\nStatus: base OS is EOL (no more security updates coming)\nincludes 2 end-of-life package(s)"
	if !strings.Contains(first, want) {
		t.Errorf("category heading, image heading and description must share a section: %q", first)
	}
	want2 := "*Image: old:3*\nStatus: base OS is EOL (no more security updates coming)\nincludes 1 end-of-life package(s)"
	found := false
	for i, b := range msgs[0].Blocks {
		if b.Kind == BlockSection && b.Text == want2 {
			found = true
			if msgs[0].Blocks[i-1].Kind != BlockDivider {
				t.Errorf("no divider before the second image heading")
			}
		}
	}
	if !found {
		t.Errorf("second image section missing")
	}
	// Images and packages are counted over the whole message; the pointer
	// card of an act-now end-of-life package is not a package shown here.
	cards := strings.Count(allBlocksText(msgs[:1]), "*◆ ") - strings.Count(allBlocksText(msgs[:1]), "see Act now")
	wantFallback := fmt.Sprintf("Everything currently open — ⛔ EOL base · legacy:1 +2 more image(s) (%d package(s))", cards)
	if msgs[0].Text != wantFallback {
		t.Errorf("fallback = %q, want %q", msgs[0].Text, wantFallback)
	}
}

// --- many messages ---

func TestContinuationNumberingBeyondNinetyNine(t *testing.T) {
	r := bigReport(240, "")
	lim := RenderLimits{MaxBlocks: 6, MaxTextUnits: 3000, MaxMessageUnits: 600, MaxFallbackUnits: 4000}
	msgs := buildChannelMessages(Message{Report: r}, ChannelFooter{Kind: FooterThreadNotice}, enMessages, lim)
	if len(msgs) < 101 {
		t.Fatalf("need more than 100 messages, got %d", len(msgs))
	}
	checkMessageConstraints(t, "many messages", msgs, lim)
	last := msgs[len(msgs)-1]
	want := fmt.Sprintf("_(cont. %d/%d)_", len(msgs), len(msgs))
	if !strings.Contains(last.Blocks[0].Text, want) {
		t.Errorf("last message heading %q lacks %s", last.Blocks[0].Text, want)
	}
}

// --- display ---

func TestEcosystemTagAndFallbackRole(t *testing.T) {
	r, _, _, _ := goldenCycle(goldenModes()[1], false)
	msgs := buildChannelMessages(Message{Report: r}, ChannelFooter{}, enMessages, defaultRenderLimits)
	if strings.Contains(allBlocksText(msgs), "  [") {
		t.Errorf("two spaces before an ecosystem tag")
	}
	if !strings.Contains(allBlocksText(msgs), "*◆ setuptools* [python-pkg]") {
		t.Errorf("ecosystem tag missing")
	}
	if !strings.HasPrefix(msgs[0].Text, "KestreLynx 2026-06-24 09:00 Everything currently open — ") || strings.Contains(msgs[0].Text, "open. ") {
		t.Errorf("fallback = %q", msgs[0].Text)
	}
}

func TestFallbackPackageCountCoversTheWholeMessage(t *testing.T) {
	r, _, _, next := goldenCycle(goldenModes()[0], false)
	msgs := buildThreadBlockMessages(r, Ages{Finding: next.FirstSeen}, enMessages, defaultRenderLimits)
	cards := strings.Count(allBlocksText(msgs[:1]), "*◆ ")
	if want := fmt.Sprintf("(%d package(s))", cards); !strings.HasSuffix(msgs[0].Text, want) {
		t.Errorf("fallback %q does not end with %s", msgs[0].Text, want)
	}
}

// --- escaping through the collapsed line, note spill, footer degradation, newlines ---

func TestEscaping_TriageOffCollapsedNamesAndWeekly(t *testing.T) {
	var finds []scanner.Finding
	for i, name := range []string{"<!channel>", "a&b", "ok"} {
		finds = append(finds, scanner.Finding{Image: "web:1", Class: scanner.ClassOS, Package: name, InstalledVer: "1", FixedVer: "2",
			Status: scanner.StatusFixed, Severity: scanner.SeverityHigh, VulnID: fmt.Sprintf("CVE-2042-%04d", i)})
	}
	scan := pinned(scanner.ImageScan{Image: "web:1", Findings: finds}, goldenContentWeb)
	r := analyze.Build([]scanner.ImageScan{scan}, nil, analyze.Triage{}, genTime)
	_, prev := state.Compute(state.State{}, analyze.Build(nil, nil, analyze.Triage{}, genTime.AddDate(0, 0, -1)))
	d, _ := state.Compute(prev, r)
	for name, m := range map[string]Message{
		"full":   {Report: r},
		"weekly": {Report: r, Diff: &d, FullReport: true},
	} {
		text := allBlocksText(buildChannelMessages(m, ChannelFooter{}, enMessages, defaultRenderLimits))
		if !strings.Contains(text, "&lt;!channel&gt;") || !strings.Contains(text, "a&amp;b") {
			t.Errorf("%s: collapsed names not escaped:\n%s", name, text)
		}
		if strings.Contains(text, "<!channel>") {
			t.Errorf("%s: raw <!channel> reaches mrkdwn", name)
		}
	}
}

func TestThreadLongNoteSpillsWithAHeading(t *testing.T) {
	r := bigReport(3, "")
	for i := 0; i < 400; i++ {
		r.Images = append(r.Images, analyze.ImageObservation{Ref: fmt.Sprintf("registry.example/team/app-%03d:1.0", i)})
	}
	msgs := buildThreadBlockMessages(r, Ages{}, jaMessages, defaultRenderLimits)
	checkMessageConstraints(t, "thread 400 refs", msgs, defaultRenderLimits)
	all := strings.ReplaceAll(allBlocksText(msgs), "\n", "")
	for i := 0; i < 400; i++ {
		if !strings.Contains(all, fmt.Sprintf("app-%03d:1.0", i)) {
			t.Fatalf("ref %d lost", i)
		}
	}
	// With small limits the note must spill across messages, each headed.
	lim := RenderLimits{MaxBlocks: 50, MaxTextUnits: 3000, MaxMessageUnits: 2500, MaxFallbackUnits: 4000}
	msgs = buildThreadBlockMessages(r, Ages{}, jaMessages, lim)
	checkMessageConstraints(t, "thread 400 refs small", msgs, lim)
	head := unresolvedNoteHead(jaMessages)
	spilled := 0
	for _, m := range msgs[1:] {
		if m.Blocks[0].Kind != BlockSection {
			t.Errorf("a message opens with a context")
		}
		if strings.Contains(m.Blocks[0].Text, head+jaMessages.ThreadContinued) {
			spilled++
		}
	}
	if spilled == 0 {
		t.Errorf("no continuation of the note carries its heading %q", head)
	}
}

func TestHugeValidPermalinkDegradesTheFooter(t *testing.T) {
	r := bigReport(3, "")
	link := "https://example.slack.com/archives/C1/p1?" + strings.Repeat("a=1&", 40000) + "z=1"
	if !validLinkURL(link) {
		t.Fatal("the permalink should be syntactically valid")
	}
	for _, lim := range []RenderLimits{defaultRenderLimits, {MaxBlocks: 8, MaxTextUnits: 3000, MaxMessageUnits: 2000, MaxFallbackUnits: 4000}} {
		msgs := buildChannelMessages(Message{Report: r}, ChannelFooter{Kind: FooterLastReport, Permalink: link}, enMessages, lim)
		checkMessageConstraints(t, "huge permalink", msgs, lim)
		last := msgs[0].Blocks[len(msgs[0].Blocks)-1]
		if last.Kind == BlockContext && strings.Contains(last.Text, "a=1&") {
			t.Errorf("the huge link was kept in the footer")
		}
	}
	msgs := buildChannelMessages(Message{Report: r}, ChannelFooter{Kind: FooterLastReport, Permalink: link}, enMessages, defaultRenderLimits)
	if last := msgs[0].Blocks[len(msgs[0].Blocks)-1]; last.Kind == BlockContext && strings.Contains(last.Text, "last report") {
		t.Errorf("a footer that cannot show its link must be dropped, got %q", last.Text)
	}
}

func TestMultiLineTitleIsCutAtNewlinesFirst(t *testing.T) {
	lines := make([]string, 6)
	for i := range lines {
		lines[i] = fmt.Sprintf("line%d %s", i, strings.Repeat("w ", 600)) // ~1200 units each
	}
	got := packLines([]string{strings.Join(lines, "\n")}, 3000)
	if len(got) < 2 {
		t.Fatalf("expected several sections, got %d", len(got))
	}
	for _, g := range got {
		for _, l := range strings.Split(g, "\n") {
			if !strings.HasPrefix(l, "line") {
				t.Errorf("a line was cut mid-line: %.30q", l)
			}
		}
	}
}

func TestNewlinesInsideLinksAndCodeAreNotSplitPoints(t *testing.T) {
	label := strings.Repeat("l", 1000) + "\n" + strings.Repeat("m", 1000)
	line := strings.Repeat("a", 1500) + "\n<https://example.com/x|" + label + "> and `code\nspan` end"
	got := packLines([]string{line}, 3000)
	if len(got) < 2 {
		t.Fatalf("the leading line should push the link into a second section, got %d", len(got))
	}
	for _, g := range got {
		if bad := balancedFragment(g); bad != "" {
			t.Errorf("%s in %.60q", bad, g)
		}
		if utf16Len(g) > 3000 {
			t.Errorf("section of %d units", utf16Len(g))
		}
	}
	joined := strings.Join(got, "\n")
	if strings.Contains(joined, "l\nm") || strings.Contains(joined, "code\nspan") {
		t.Errorf("a newline inside a link or code span survived")
	}
}

func TestContinuationHeadingCapsLongNamesAndVersions(t *testing.T) {
	scan := pinned(scanner.ImageScan{Image: "big:1", Findings: []scanner.Finding{{
		Image: "big:1", Class: scanner.ClassOS, Package: strings.Repeat("n", 13000), InstalledVer: strings.Repeat("v", 5000),
		Status: scanner.StatusAffected, Severity: scanner.SeverityHigh, VulnID: "CVE-2043-0001", Title: strings.Repeat("t", 4000),
	}}}, goldenContentWeb)
	r := analyze.Build([]scanner.ImageScan{scan}, nil, triageRules(map[string]analyze.Enrichment{"CVE-2043-0001": {EPSS: 0.05, EPSSKnown: true}}), genTime)
	for _, lim := range []RenderLimits{defaultRenderLimits, {MaxBlocks: 10, MaxTextUnits: 3000, MaxMessageUnits: 3000, MaxFallbackUnits: 4000}} {
		msgs := buildThreadBlockMessages(r, Ages{}, enMessages, lim)
		checkMessageConstraints(t, "long name", msgs, lim.normalized())
		if len(msgs) < 2 {
			t.Fatalf("expected the card to be cut, got %d message(s)", len(msgs))
		}
		for i, m := range msgs[1:] {
			if n := utf16Len(m.Blocks[0].Text); n > 1200 {
				t.Errorf("continuation heading %d is %d units", i+2, n)
			}
		}
	}
	msgs := buildChannelMessages(Message{Report: r}, ChannelFooter{Kind: FooterThreadNotice}, enMessages, defaultRenderLimits)
	checkMessageConstraints(t, "long name channel", msgs, defaultRenderLimits)
}

func TestFallbackCountsImagesByFullName(t *testing.T) {
	prefix := "registry.example/" + strings.Repeat("a", 190)
	var scans []scanner.ImageScan
	enrich := map[string]analyze.Enrichment{}
	for i, tag := range []string{":1", ":2"} {
		img := prefix + tag
		id := fmt.Sprintf("CVE-2044-%04d", i)
		scans = append(scans, pinned(scanner.ImageScan{Image: img, Findings: []scanner.Finding{{
			Image: img, Class: scanner.ClassOS, Package: "p", InstalledVer: "1", Status: scanner.StatusAffected,
			Severity: scanner.SeverityHigh, VulnID: id}}}, fmt.Sprintf("sha256:%064d", i+1)))
		enrich[id] = analyze.Enrichment{EPSS: 0.05, EPSSKnown: true}
	}
	r := analyze.Build(scans, nil, triageRules(enrich), genTime)
	msgs := buildThreadBlockMessages(r, Ages{}, enMessages, defaultRenderLimits)
	if len(msgs) != 1 || !strings.Contains(msgs[0].Text, "+1 more image(s)") {
		t.Errorf("two images sharing a 200-unit prefix must count as two: %q", msgs[0].Text)
	}
	if n := utf16Len(msgs[0].Text); n > 400 {
		t.Errorf("fallback text of %d units: the displayed image name must be capped", n)
	}
}
