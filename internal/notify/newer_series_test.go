package notify

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/remediation"
)

// The jsoup targets of baseWaitImage (two CVEs in one package) and a
// finding outside them.
func jsoupTargets() []remediation.Target {
	fs := baseWaitFindings()
	return []remediation.Target{baseWaitTarget(fs[0]), baseWaitTarget(fs[1])}
}

func otherTarget() remediation.Target { return baseWaitTarget(baseWaitFindings()[2]) }

// newerCand is a checked tag whose comparison gives each target the outcome
// in outs, in order.
func newerCand(tag string, change remediation.SeriesChange, status remediation.NewerSeriesStatus, targets []remediation.Target, outs ...remediation.Outcome) remediation.NewerSeriesCandidate {
	c := remediation.NewerSeriesCandidate{Tag: tag, Change: change, Status: status, BaselineScan: "s1", CandidateScan: "s2",
		Candidate: &remediation.ImageState{Ref: "x:" + tag, Tag: tag, TopDigest: "sha256:top-" + tag, ManifestDigest: "sha256:m-" + tag}}
	vr := &remediation.VerificationResult{Comparable: true}
	n := &remediation.NewerSeriesCounts{Targets: len(targets)}
	for i, t := range targets {
		if i >= len(outs) {
			break
		}
		vr.Verdicts = append(vr.Verdicts, remediation.VulnVerdict{VulnID: t.VulnID, Package: t.Package, Outcome: outs[i]})
		switch outs[i] {
		case remediation.OutcomeResolved:
			n.Resolved++
		case remediation.OutcomeRemaining:
			n.Remaining++
		}
	}
	if status == remediation.NewerSeriesResolvesWithNew {
		n.Introduced = 3
		vr.Introduced = []remediation.VulnVerdict{{VulnID: "CVE-NEW", Outcome: remediation.OutcomeIntroduced}}
	}
	c.Comparison, c.Counts = vr, n
	return c
}

func newerOf(status remediation.NewerSeriesStatus, shown string, cands ...remediation.NewerSeriesCandidate) *remediation.NewerSeries {
	return &remediation.NewerSeries{Status: status, Shown: shown, Candidates: cands}
}

// imageNewerPlan is a plan with the pinned running image baseWaitImage
// (entity "a") whose own series gave nothing for reason own, and the check
// of newer series ns.
func imageNewerPlan(t *testing.T, own remediation.Reason, ns *remediation.NewerSeries) *PlanInfo {
	it := remediation.Item{
		Key: baseWaitImage + "|a", Kind: remediation.TagPinned, Category: remediation.CategoryNoCandidate, Reason: own,
		Current: remediation.ImageState{Ref: baseWaitImage, Entity: remediation.EntityKeyString(baseWaitKeyOf(t, "a"))},
		Targets: jsoupTargets(), NewerSeries: ns,
	}
	return &PlanInfo{Plan: &remediation.Plan{Items: []remediation.Item{it}}}
}

func resolved() remediation.Outcome  { return remediation.OutcomeResolved }
func remaining() remediation.Outcome { return remediation.OutcomeRemaining }

func TestNewerSeriesCardLines(t *testing.T) {
	r := baseWaitReport(t)
	ts := jsoupTargets()
	major := func(s remediation.NewerSeriesStatus, outs ...remediation.Outcome) remediation.NewerSeriesCandidate {
		return newerCand("2.0.1", remediation.SeriesChangeMajor, s, ts, outs...)
	}
	cases := []struct {
		name string
		own  remediation.Reason
		ns   *remediation.NewerSeries
		ja   string
		en   string
	}{
		{"resolved", remediation.ReasonNoNewerTag, newerOf(remediation.NewerSeriesResolves, "2.0.1", major(remediation.NewerSeriesResolves, resolved(), resolved())),
			"対応: イメージ shop-es 1 → 2.0.1 で解消（major の更新、同じ系列に新しい版なし）",
			"Action: image shop-es 1 → 2.0.1 resolves it (major update, no newer tag in the same series)"},
		{"partial", remediation.ReasonCandidateNotFixing, newerOf(remediation.NewerSeriesResolvesPartially, "2.0.1", major(remediation.NewerSeriesResolvesPartially, resolved(), remaining())),
			"対応: イメージ shop-es 1 → 2.0.1 で一部解消（2件中1件、major の更新、同じ系列の新しい版では未解消）",
			"Action: image shop-es 1 → 2.0.1 resolves part of it (1 of 2, major update, not resolved by the newer tag of the same series)"},
		{"with new findings", remediation.ReasonNoNewerTag, newerOf(remediation.NewerSeriesResolvesWithNew, "2.0.1", major(remediation.NewerSeriesResolvesWithNew, resolved(), resolved())),
			"対応: イメージ shop-es 1 → 2.0.1 で解消（major の更新、同じ系列に新しい版なし、新たな所見あり）",
			"Action: image shop-es 1 → 2.0.1 resolves it (major update, no newer tag in the same series, with new findings)"},
		{"remains in the shown tag", remediation.ReasonNoNewerTag, newerOf(remediation.NewerSeriesResolvesPartially, "2.0.1", major(remediation.NewerSeriesResolvesPartially, remaining(), remaining())),
			"対応: イメージ shop-es 1 の新しい版待ち（確認した 2.0.1 でも未解消）",
			"Action: waiting for a newer image of shop-es 1 (not resolved in the checked tag(s) 2.0.1 either)"},
		{"not resolving in either", remediation.ReasonNoNewerTag, newerOf(remediation.NewerSeriesNotResolving, "",
			newerCand("1.5.0", remediation.SeriesChangeMinor, remediation.NewerSeriesNotResolving, ts, remaining(), remaining()), major(remediation.NewerSeriesNotResolving, remaining(), remaining())),
			"対応: イメージ shop-es 1 の新しい版待ち（確認した 1.5.0 と 2.0.1 でも未解消）",
			"Action: waiting for a newer image of shop-es 1 (not resolved in the checked tag(s) 1.5.0 and 2.0.1 either)"},
		{"not resolving after the own series' newer tag", remediation.ReasonCandidateNotFixing, newerOf(remediation.NewerSeriesNotResolving, "", major(remediation.NewerSeriesNotResolving, remaining(), remaining())),
			"対応: イメージ shop-es の新しい版待ち（同じ系列の新しい版と、確認した 2.0.1 で未解消）",
			"Action: waiting for a newer image of shop-es (not resolved by the newer tag of the same series or the checked tag(s) 2.0.1)"},
		{"no newer series", remediation.ReasonNoNewerTag, newerOf(remediation.NewerSeriesNone, ""),
			"対応: イメージ shop-es 1 の新しい版待ち（同じ系列にも、条件に合う新しい系列にも新しい版なし）",
			"Action: waiting for a newer image of shop-es 1 (no newer tag in the same series or in a newer series of the same form)"},
	}
	for _, c := range cases {
		for lang, want := range map[Language]string{LanguageJA: c.ja, LanguageEN: c.en} {
			out := renderChannelWithPlan(r, imageNewerPlan(t, c.own, c.ns), lang)
			if n := strings.Count(out, want); n != 1 {
				t.Errorf("%s (%s): line appears %d times, want 1 (only jsoup):\n%s", c.name, lang, n, out)
			}
		}
	}
	// Outcomes that say nothing: no line, and never "no fix".
	for name, p := range map[string]*PlanInfo{
		"not checked": imageNewerPlan(t, remediation.ReasonNoNewerTag, &remediation.NewerSeries{Status: remediation.NewerSeriesNotChecked, Reason: remediation.ReasonCandidateScanLimit}),
		"no newer series after the own series' newer tag": imageNewerPlan(t, remediation.ReasonSameContent, newerOf(remediation.NewerSeriesNone, "")),
		"a finding not judged":                            imageNewerPlan(t, remediation.ReasonNoNewerTag, newerOf(remediation.NewerSeriesResolves, "2.0.1", major(remediation.NewerSeriesResolves, resolved()))),
	} {
		if out := renderChannelWithPlan(r, p, LanguageEN); strings.Contains(out, "Action: ") {
			t.Errorf("%s: a line is shown:\n%s", name, out)
		}
	}
}

// dfNewerPlan is baseWaitPlan with a check of newer series of the base:
// item is the item's result, ent the entity's.
func dfNewerPlan(t *testing.T, item, ent *remediation.NewerSeries) *PlanInfo {
	p := baseWaitNoNewer(t)
	p.Plan.DockerfileItems[0].NewerSeries = item
	p.Plan.DockerfileItems[0].Entities[0].NewerSeries = ent
	return p
}

func TestNewerSeriesCardLinesOfABase(t *testing.T) {
	r := baseWaitReport(t)
	ts := jsoupTargets()
	cand := newerCand("9.1.0", remediation.SeriesChangeMajor, remediation.NewerSeriesResolves, ts, resolved(), resolved())
	itemCand := cand
	itemCand.Comparison = nil
	resolves := dfNewerPlan(t, newerOf(remediation.NewerSeriesResolves, "9.1.0", itemCand), newerOf(remediation.NewerSeriesResolves, "9.1.0", cand))
	for lang, want := range map[Language]string{
		LanguageJA: "対応: 元イメージ elasticsearch 8.19.23 → 9.1.0 で解消（major の更新、同じ系列に新しい版なし、ベースの比較）",
		LanguageEN: "Action: base image elasticsearch 8.19.23 → 9.1.0 resolves it (major update, no newer tag in the same series, base images compared)",
	} {
		if out := renderChannelWithPlan(r, resolves, lang); strings.Count(out, want) != 1 {
			t.Errorf("%s: want %q in:\n%s", lang, want, out)
		}
	}
	// An unfinished check keeps the line the item had.
	unfinished := &remediation.NewerSeries{Status: remediation.NewerSeriesNotChecked, Reason: remediation.ReasonNewerSeriesReserved}
	if out := renderChannelWithPlan(r, dfNewerPlan(t, unfinished, unfinished), LanguageJA); !strings.Contains(out, "対応: 元イメージ elasticsearch 8.19.23 の新しい版待ち（同じ系列に新しい版なし）") {
		t.Errorf("the plain line is gone:\n%s", out)
	}
	// The running image's own tag says something else about the same
	// findings: no line.
	both := dfNewerPlan(t, newerOf(remediation.NewerSeriesResolves, "9.1.0", itemCand), newerOf(remediation.NewerSeriesResolves, "9.1.0", cand))
	own := imageNewerPlan(t, remediation.ReasonNoNewerTag, newerOf(remediation.NewerSeriesNone, ""))
	both.Plan.Items = own.Plan.Items
	if out := renderChannelWithPlan(r, both, LanguageEN); strings.Contains(out, "Action: ") {
		t.Errorf("a line is shown although the base and the image's own tag disagree:\n%s", out)
	}
}

func TestNewerSeriesPlanLines(t *testing.T) {
	ts := jsoupTargets()
	major := newerCand("2.0.1", remediation.SeriesChangeMajor, remediation.NewerSeriesResolves, ts, resolved(), resolved())
	info := imageNewerPlan(t, remediation.ReasonNoNewerTag, newerOf(remediation.NewerSeriesResolves, "2.0.1", major))
	for lang, wants := range map[Language][]string{
		LanguageEN: {"Newer series: shop-es 1 → 2.0.1 (major update, resolves 2 finding(s), compatibility not checked)", "1 resolved in a newer series"},
		LanguageJA: {"新しい系列: shop-es 1 → 2.0.1 (major の更新、所見2件が解消、互換性は未確認)", "新しい系列で解消 1件"},
	} {
		out := slackPlanText(planReport(), info, lang)
		for _, w := range wants {
			if !strings.Contains(out, w) {
				t.Errorf("%s: want %q in:\n%s", lang, w, out)
			}
		}
	}

	partial := newerCand("1.5.0", remediation.SeriesChangeMinor, remediation.NewerSeriesResolvesPartially, ts, resolved(), remaining())
	out := slackPlanText(planReport(), imageNewerPlan(t, remediation.ReasonNoNewerTag, newerOf(remediation.NewerSeriesResolvesPartially, "1.5.0", partial)), LanguageEN)
	if !strings.Contains(out, "Newer series: shop-es 1 → 1.5.0 (minor update, resolves 1 of 2 findings, compatibility not checked)") {
		t.Errorf("partial:\n%s", out)
	}

	withNew := newerCand("2.0.1", remediation.SeriesChangeMajor, remediation.NewerSeriesResolvesWithNew, ts, resolved(), resolved())
	out = slackPlanText(planReport(), imageNewerPlan(t, remediation.ReasonNoNewerTag, newerOf(remediation.NewerSeriesResolvesWithNew, "2.0.1", withNew)), LanguageEN)
	if !strings.Contains(out, "Needs a decision: shop-es 1 → 2.0.1 in a newer series resolves 2 finding(s) and adds 3 (major update, compatibility not checked)") || strings.Contains(out, "Newer series:") {
		t.Errorf("with new findings:\n%s", out)
	}

	for name, ns := range map[string]*remediation.NewerSeries{
		"not resolving": newerOf(remediation.NewerSeriesNotResolving, "", newerCand("2.0.1", remediation.SeriesChangeMajor, remediation.NewerSeriesNotResolving, ts, remaining(), remaining())),
		"not checked":   {Status: remediation.NewerSeriesNotChecked, Reason: remediation.ReasonCandidateScanLimit},
		"no newer":      newerOf(remediation.NewerSeriesNone, ""),
	} {
		info := imageNewerPlan(t, remediation.ReasonNoNewerTag, ns)
		if out := slackPlanText(planReport(), info, LanguageEN); strings.Contains(out, "shop-es") {
			t.Errorf("%s: the plan message shows the image:\n%s", name, out)
		}
	}
}

func TestNewerSeriesPlanLineOfABase(t *testing.T) {
	ts := jsoupTargets()
	cand := newerCand("9.1.0", remediation.SeriesChangeMajor, remediation.NewerSeriesResolves, ts, resolved(), resolved())
	cand.Comparison = nil
	p := dfNewerPlan(t, newerOf(remediation.NewerSeriesResolves, "9.1.0", cand), nil)
	p.Plan.DockerfileItems[0].Source = remediation.DockerfileSource{Repository: "ex/es", Path: "Dockerfile"}
	out := slackPlanText(planReport(), p, LanguageEN)
	for _, w := range []string{
		"File to change:",
		"Newer series: base image docker.elastic.co/elasticsearch/elasticsearch 8.19.23 → 9.1.0 (major update, resolves 2 finding(s), base images compared, the rebuilt image not checked, compatibility not checked)",
	} {
		if !strings.Contains(out, w) {
			t.Errorf("want %q in:\n%s", w, out)
		}
	}
}

func TestNewerSeriesSlackFingerprint(t *testing.T) {
	ts := jsoupTargets()
	fp := func(ns *remediation.NewerSeries) string {
		return imageNewerPlan(t, remediation.ReasonNoNewerTag, ns).SlackFingerprint()
	}
	notResolving := fp(newerOf(remediation.NewerSeriesNotResolving, "", newerCand("2.0.1", remediation.SeriesChangeMajor, remediation.NewerSeriesNotResolving, ts, remaining(), remaining())))
	resolves := fp(newerOf(remediation.NewerSeriesResolves, "2.0.1", newerCand("2.0.1", remediation.SeriesChangeMajor, remediation.NewerSeriesResolves, ts, resolved(), resolved())))
	if notResolving == resolves {
		t.Error("a tag that now resolves the findings does not change what the message shows")
	}
	// What only the cards show does not count here.
	a := fp(&remediation.NewerSeries{Status: remediation.NewerSeriesNotChecked, Reason: remediation.ReasonCandidateScanLimit})
	if b := fp(&remediation.NewerSeries{Status: remediation.NewerSeriesNotChecked, Reason: remediation.ReasonNewerSeriesReserved}); a != b || a != notResolving {
		t.Error("a change the message does not show changed its fingerprint")
	}
}

func TestNewerSeriesWebhook(t *testing.T) {
	r, _, _ := planCycleFixture()
	ts := jsoupTargets()
	cand := newerCand("2.0.1", remediation.SeriesChangeMajor, remediation.NewerSeriesResolves, append(ts, otherTarget()), resolved(), resolved(), resolved())
	cand.Counts.Targets, cand.Counts.Resolved = 2, 2
	info := imageNewerPlan(t, remediation.ReasonNoNewerTag, newerOf(remediation.NewerSeriesResolves, "2.0.1", cand))
	info.Plan.Scans = []remediation.ScanExecution{{ID: "s1", Role: remediation.RoleBaseline, Ref: baseWaitImage}, {ID: "s2", Role: remediation.RoleCandidate, Ref: "x:2.0.1"}}
	dfItem := dfNewerPlan(t, newerOf(remediation.NewerSeriesNotResolving, ""), newerOf(remediation.NewerSeriesNotResolving, "")).Plan.DockerfileItems
	info.Plan.DockerfileItems = dfItem

	rem := webhookJSON(t, BuildWebhookPayloadWithPlan(r, nil, info))["remediation"].(map[string]any)
	ns := rem["items"].([]any)[0].(map[string]any)["newer_series"].(map[string]any)
	if ns["status"] != "resolves" || ns["shown"] != "2.0.1" {
		t.Fatalf("newer_series = %v", ns)
	}
	c := ns["candidates"].([]any)[0].(map[string]any)
	cmp := c["comparison"].(map[string]any)
	if c["change"] != "major" || c["candidate"].(map[string]any)["top_digest"] != "sha256:top-2.0.1" || len(cmp["verdicts"].([]any)) != 2 || cmp["targets"] != float64(2) || cmp["resolved"] != float64(2) {
		t.Errorf("candidate = %v", c)
	}
	if scans := c["scans"].([]any); len(scans) != 2 || scans[1].(map[string]any)["role"] != "candidate" {
		t.Errorf("scans = %v", c["scans"])
	}
	raw, _ := json.Marshal(ns)
	if strings.Contains(string(raw), `"s1"`) || strings.Contains(string(raw), "baseline_scan") {
		t.Errorf("scan IDs are exposed: %s", raw)
	}
	df := rem["dockerfile_items"].([]any)[0].(map[string]any)
	if df["newer_series"].(map[string]any)["status"] != "not_resolving" || df["entities"].([]any)[0].(map[string]any)["newer_series"] == nil {
		t.Errorf("dockerfile item = %v", df)
	}
}

// Two running images of one Dockerfile item: the newer tag resolves the
// findings in one and leaves them in the other, so the item resolves none
// in every image. Each card speaks for its own image.
func TestNewerSeriesCardLinesPerRunningImage(t *testing.T) {
	r := baseWaitReportOf(t, baseWaitScan(t, "a", baseWaitFindings()), baseWaitScan(t, "b", baseWaitFindings()))
	ts := jsoupTargets()
	p := baseWaitNoNewer(t)
	it := &p.Plan.DockerfileItems[0]
	second := it.Entities[0]
	second.Running.Entity = remediation.EntityKeyString(baseWaitKeyOf(t, "b"))
	it.Entities = append(it.Entities, second)
	itemCand := remediation.NewerSeriesCandidate{Tag: "9.1.0", Change: remediation.SeriesChangeMajor, Status: remediation.NewerSeriesNotResolving}
	it.NewerSeries = newerOf(remediation.NewerSeriesNotResolving, "", itemCand)
	it.Entities[0].NewerSeries = newerOf(remediation.NewerSeriesResolves, "9.1.0", newerCand("9.1.0", remediation.SeriesChangeMajor, remediation.NewerSeriesResolves, ts, resolved(), resolved()))
	it.Entities[1].NewerSeries = newerOf(remediation.NewerSeriesNotResolving, "", newerCand("9.1.0", remediation.SeriesChangeMajor, remediation.NewerSeriesNotResolving, ts, remaining(), remaining()))

	out := renderChannelWithPlan(r, p, LanguageJA)
	for want, n := range map[string]int{
		"対応: 元イメージ elasticsearch 8.19.23 の新しい版待ち（確認した 9.1.0 でも未解消、ベースの比較）": 1,
		"対応: 元イメージ elasticsearch 8.19.23 の新しい版待ち（同じ系列に新しい版なし）":             1,
	} {
		if got := strings.Count(out, want); got != n {
			t.Errorf("%q appears %d times, want %d:\n%s", want, got, n, out)
		}
	}
}

// The note on new findings follows the tag the item shows, even where this
// running image's own comparison introduces none.
func TestNewerSeriesCardWithNewFollowsTheItem(t *testing.T) {
	ts := jsoupTargets()
	itemCand := remediation.NewerSeriesCandidate{Tag: "9.1.0", Change: remediation.SeriesChangeMajor, Status: remediation.NewerSeriesResolvesWithNew, Counts: &remediation.NewerSeriesCounts{Targets: 2, Resolved: 2, Introduced: 1}}
	p := dfNewerPlan(t, newerOf(remediation.NewerSeriesResolvesWithNew, "9.1.0", itemCand),
		newerOf(remediation.NewerSeriesResolves, "9.1.0", newerCand("9.1.0", remediation.SeriesChangeMajor, remediation.NewerSeriesResolves, ts, resolved(), resolved())))
	want := "対応: 元イメージ elasticsearch 8.19.23 → 9.1.0 で解消（major の更新、同じ系列に新しい版なし、新たな所見あり、ベースの比較）"
	if out := renderChannelWithPlan(baseWaitReport(t), p, LanguageJA); !strings.Contains(out, want) {
		t.Errorf("want %q in:\n%s", want, out)
	}
}

// A check the item could not judge as a whole, because one finding could not
// be judged, still says on the other findings' cards that the compared tag
// leaves them; a card with the finding that could not be judged keeps its
// line.
func TestNewerSeriesCardLinesWhenTheItemCouldNotBeJudged(t *testing.T) {
	r := baseWaitReport(t)
	all := append(jsoupTargets(), otherTarget())
	unknown := remediation.OutcomeUnknown
	plan := func(outs ...remediation.Outcome) *PlanInfo {
		cand := newerCand("9.5.5", remediation.SeriesChangeMajor, remediation.NewerSeriesNotChecked, all, outs...)
		cand.Reason = remediation.ReasonAnalysisIncomplete
		itemCand := remediation.NewerSeriesCandidate{Tag: "9.5.5", Change: remediation.SeriesChangeMajor, Status: remediation.NewerSeriesNotChecked, Reason: remediation.ReasonAnalysisIncomplete}
		p := dfNewerPlan(t,
			&remediation.NewerSeries{Status: remediation.NewerSeriesNotChecked, Reason: remediation.ReasonAnalysisIncomplete, Candidates: []remediation.NewerSeriesCandidate{itemCand}},
			&remediation.NewerSeries{Status: remediation.NewerSeriesNotChecked, Reason: remediation.ReasonAnalysisIncomplete, Candidates: []remediation.NewerSeriesCandidate{cand}})
		p.Plan.DockerfileItems[0].Entities[0].Targets = all
		return p
	}
	// The thread shows every card; the channel folds other-lib's away.
	render := func(p *PlanInfo) string {
		return allBlocksText(buildThreadBlockMessagesWithPlan(r, Ages{}, p, jaMessages, defaultRenderLimits))
	}
	remains := "対応: 元イメージ elasticsearch 8.19.23 の新しい版待ち（確認した 9.5.5 でも未解消、ベースの比較）"
	plain := "対応: 元イメージ elasticsearch 8.19.23 の新しい版待ち（同じ系列に新しい版なし）"

	out := render(plan(remaining(), remaining(), unknown))
	if actionOf(out, "org.jsoup:jsoup") != remains || actionOf(out, "other-lib") != plain {
		t.Errorf("want jsoup's card to remain and other-lib's to keep its line:\n%s", out)
	}
	// One of jsoup's findings could not be judged: its card keeps the plain
	// line.
	out = render(plan(remaining(), unknown, remaining()))
	if actionOf(out, "org.jsoup:jsoup") != plain || actionOf(out, "other-lib") != remains {
		t.Errorf("want jsoup's card plain and other-lib's to remain:\n%s", out)
	}
	// A tag compared that resolves a finding is never shown as remaining.
	out = render(plan(resolved(), resolved(), unknown))
	if strings.Contains(out, "確認した 9.5.5") {
		t.Errorf("a finding the compared tag resolves is shown as remaining:\n%s", out)
	}
	// A tag that was never compared gives no such line.
	noCmp := plan(remaining(), remaining(), unknown)
	noCmp.Plan.DockerfileItems[0].Entities[0].NewerSeries.Candidates[0].Comparison = nil
	if out := render(noCmp); strings.Contains(out, "確認した") || strings.Count(out, plain) != 2 {
		t.Errorf("a tag never compared is named:\n%s", out)
	}

	// The same for a pinned running image.
	cand := newerCand("2.0.1", remediation.SeriesChangeMajor, remediation.NewerSeriesNotChecked, jsoupTargets(), remaining(), remaining())
	img := imageNewerPlan(t, remediation.ReasonNoNewerTag, &remediation.NewerSeries{Status: remediation.NewerSeriesNotChecked, Reason: remediation.ReasonAnalysisIncomplete, Candidates: []remediation.NewerSeriesCandidate{cand}})
	if out := render(img); !strings.Contains(out, "対応: イメージ shop-es 1 の新しい版待ち（確認した 2.0.1 でも未解消）") {
		t.Errorf("published image:\n%s", out)
	}
}

// actionOf is the action line of the card of package pkg in a rendered
// message: the first such line after the card's heading.
func actionOf(out, pkg string) string {
	i := strings.Index(out, "*◆ "+pkg+"*")
	if i < 0 {
		return ""
	}
	for _, l := range strings.Split(out[i:], "\n")[1:] {
		if strings.HasPrefix(l, "*◆ ") {
			return ""
		}
		if strings.HasPrefix(l, "対応: ") || strings.HasPrefix(l, "Action: ") {
			return l
		}
	}
	return ""
}
