package remediation

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/registry"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

func fixedB() scanner.Finding { return finding("CVE-B", "openssl", "1", "2", scanner.SeverityHigh) }

// twoTargets is a pinned image with two fixed findings in two packages.
func twoTargets(ref string, h byte) ImageInput {
	in := input(ref, h, prepared, fixedA(), fixedB())
	in.Scan.Packages = pkgs("libc", "1", "openssl", "1")
	return in
}

// newerEnv is nginx:1.24.1 with no newer patch of its series, and the tags
// 1.26.0 (a newer minor) and 2.0.1 (a newer major) resolvable.
func newerEnv(tags ...string) *env {
	e := newEnv()
	if tags == nil {
		tags = []string{"1.24.1", "1.25.9", "1.26.0", "2.0.1"}
	}
	e.reg.tags["nginx"] = registry.TagList{Tags: tags, Pages: 1}
	e.reg.res["nginx:1.25.9"] = resolution('5', '6')
	e.reg.res["nginx:1.26.0"] = resolution('b', 'c')
	e.reg.res["nginx:2.0.1"] = resolution('d', 'e')
	return e
}

func checkNewer(t *testing.T, e *env, lim Limits, opts NewerSeriesOptions, inputs ...ImageInput) (Plan, Plan, NewerSeriesSummary) {
	t.Helper()
	p := e.planner(t, lim, nil)
	plan := p.Plan(context.Background(), inputs)
	before := plan
	before.Items = append([]Item(nil), plan.Items...)
	sum := p.CheckNewerSeries(context.Background(), &plan, opts)
	return before, plan, sum
}

func tagsOf(ns *NewerSeries) []string {
	var out []string
	for _, c := range ns.Candidates {
		out = append(out, c.Tag+":"+string(c.Status))
	}
	return out
}

func TestNewerTagsChoice(t *testing.T) {
	cases := []struct {
		name string
		cur  string
		tags []string
		want []newerTag
	}{
		{"minor by number, then major, skipping prereleases and other forms", "9.2.1",
			[]string{"9.2.1", "9.2.9", "9.9.9", "9.10.0", "9.11.0-alpine", "v9.12.0", "9.12.0-rc1", "10.0.1", "10.1.0", "11.0.0-beta1", "latest", "9.10"},
			[]newerTag{{"9.10.0", SeriesChangeMinor}, {"10.1.0", SeriesChangeMajor}}},
		{"suffix kept", "1.2.3-alpine",
			[]string{"1.3.0", "1.3.0-alpine", "1.4.0-bookworm", "2.0.0-alpine"},
			[]newerTag{{"1.3.0-alpine", SeriesChangeMinor}, {"2.0.0-alpine", SeriesChangeMajor}}},
		{"prefix kept", "v0.71.2",
			[]string{"0.76.1", "v0.76.1", "v0.75.0"},
			[]newerTag{{"v0.76.1", SeriesChangeMinor}}},
		{"only a newer major", "1.24.1",
			[]string{"1.24.1", "1.24.3", "2.0.0", "2.1.4"},
			[]newerTag{{"2.1.4", SeriesChangeMajor}}},
	}
	for _, c := range cases {
		fake := newFakeRegistry()
		fake.tags["r"] = registry.TagList{Tags: c.tags, Pages: 1}
		got, ns := tagRun(fake, 5).newerTags(ParseImageRef("r:" + c.cur))
		if ns != nil || !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: tags = %v, %+v; want %v", c.name, got, ns, c.want)
		}
	}

	fake := newFakeRegistry()
	fake.tags["r"] = registry.TagList{Tags: []string{"1.24.1", "1.24.9", "1.24.10-rc1", "1.23.0", "0.9.0"}, Pages: 1}
	if got, ns := tagRun(fake, 5).newerTags(ParseImageRef("r:1.24.1")); got != nil || ns == nil || ns.Status != NewerSeriesNone {
		t.Errorf("no newer series: tags = %v, %+v", got, ns)
	}
	fake.tagErr["r"] = errors.New("boom")
	if got, ns := tagRun(fake, 5).newerTags(ParseImageRef("r:1.24.1")); got != nil || ns == nil || ns.Status != NewerSeriesNotChecked || ns.Reason != ReasonRegistryError {
		t.Errorf("failed listing: tags = %v, %+v; a failure is never no newer series", got, ns)
	}
}

func TestNewerSeriesResolvesWithTheFirstCandidate(t *testing.T) {
	e := newerEnv()
	e.candidateScan("nginx:1.26.0", nil, pkgs("libc", "2"))
	before, plan, sum := checkNewer(t, e, bigLimits, NewerSeriesOptions{}, input("nginx:1.24.1", 'a', prepared, fixedA()))
	it := item(t, plan, 0)
	ns := it.NewerSeries
	if ns == nil || ns.Status != NewerSeriesResolves || ns.Shown != "1.26.0" || len(ns.Candidates) != 1 {
		t.Fatalf("newer series = %+v", ns)
	}
	c := ns.Candidates[0]
	if c.Change != SeriesChangeMinor || c.Candidate == nil || c.Candidate.ManifestDigest != "sha256:"+hex64('b') || c.Comparison == nil ||
		c.BaselineScan == "" || c.CandidateScan == "" || *c.Counts != (NewerSeriesCounts{Targets: 1, Resolved: 1}) {
		t.Errorf("candidate = %+v counts %+v", c, c.Counts)
	}
	// The item's own outcome is untouched.
	it.NewerSeries = nil
	if !reflect.DeepEqual(it, before.Items[0]) || it.Reason != ReasonNoNewerTag {
		t.Errorf("item changed:\n%+v\nwas\n%+v", it, before.Items[0])
	}
	if plan.Usage.CandidateScans != 1 || len(plan.Scans) != 2 || sum.Items != 1 || sum.Resolving != 1 || sum.CandidateScans != 1 {
		t.Errorf("usage = %+v, scans %d, summary %+v", plan.Usage, len(plan.Scans), sum)
	}
}

func TestNewerSeriesSecondCandidate(t *testing.T) {
	t.Run("the minor does not resolve, the major does", func(t *testing.T) {
		e := newerEnv()
		e.candidateScan("nginx:1.26.0", []scanner.Finding{fixedA()}, pkgs("libc", "1"))
		e.candidateScan("nginx:2.0.1", nil, pkgs("libc", "2"))
		_, plan, _ := checkNewer(t, e, bigLimits, NewerSeriesOptions{}, input("nginx:1.24.1", 'a', prepared, fixedA()))
		ns := item(t, plan, 0).NewerSeries
		if ns.Status != NewerSeriesResolves || ns.Shown != "2.0.1" || !reflect.DeepEqual(tagsOf(ns), []string{"1.26.0:not_resolving", "2.0.1:resolves"}) {
			t.Errorf("newer series = %+v %v", ns, tagsOf(ns))
		}
	})
	t.Run("neither resolves", func(t *testing.T) {
		e := newerEnv()
		e.candidateScan("nginx:1.26.0", []scanner.Finding{fixedA()}, pkgs("libc", "1"))
		e.candidateScan("nginx:2.0.1", []scanner.Finding{fixedA()}, pkgs("libc", "1"))
		_, plan, sum := checkNewer(t, e, bigLimits, NewerSeriesOptions{}, input("nginx:1.24.1", 'a', prepared, fixedA()))
		ns := item(t, plan, 0).NewerSeries
		if ns.Status != NewerSeriesNotResolving || ns.Shown != "" || len(ns.Candidates) != 2 || sum.Resolving != 0 {
			t.Errorf("newer series = %+v %v", ns, tagsOf(ns))
		}
	})
	t.Run("partial, then more with new findings", func(t *testing.T) {
		e := newerEnv()
		e.candidateScan("nginx:1.26.0", []scanner.Finding{fixedB()}, pkgs("libc", "2", "openssl", "1"))
		e.candidateScan("nginx:2.0.1", []scanner.Finding{finding("CVE-X", "zlib", "1", "2", scanner.SeverityHigh)}, pkgs("libc", "2", "openssl", "2", "zlib", "1"))
		_, plan, _ := checkNewer(t, e, bigLimits, NewerSeriesOptions{}, twoTargets("nginx:1.24.1", 'a'))
		ns := item(t, plan, 0).NewerSeries
		if ns.Status != NewerSeriesResolvesWithNew || ns.Shown != "2.0.1" || !reflect.DeepEqual(tagsOf(ns), []string{"1.26.0:resolves_partially", "2.0.1:resolves_with_new"}) {
			t.Errorf("newer series = %+v %v", ns, tagsOf(ns))
		}
	})
	t.Run("partial, then stopped by the scan limit: the partial shows", func(t *testing.T) {
		e := newerEnv()
		e.candidateScan("nginx:1.26.0", []scanner.Finding{fixedB()}, pkgs("libc", "2", "openssl", "1"))
		e.candidateScan("nginx:2.0.1", nil, pkgs("libc", "2", "openssl", "2"))
		_, plan, _ := checkNewer(t, e, Limits{MaxCandidateScans: 1, MaxBaselineRescans: 5, MaxTagPages: 5}, NewerSeriesOptions{}, twoTargets("nginx:1.24.1", 'a'))
		ns := item(t, plan, 0).NewerSeries
		if ns.Status != NewerSeriesResolvesPartially || ns.Shown != "1.26.0" || len(ns.Candidates) != 2 || ns.Candidates[1].Reason != ReasonCandidateScanLimit {
			t.Errorf("newer series = %+v %v", ns, tagsOf(ns))
		}
	})
	t.Run("not checked, then not tried", func(t *testing.T) {
		e := newerEnv()
		e.reg.resErr["nginx:1.26.0"] = errors.New("boom")
		_, plan, _ := checkNewer(t, e, bigLimits, NewerSeriesOptions{}, input("nginx:1.24.1", 'a', prepared, fixedA()))
		ns := item(t, plan, 0).NewerSeries
		if ns.Status != NewerSeriesNotChecked || ns.Reason != ReasonRegistryError || len(ns.Candidates) != 1 || e.reg.resolveCnt["nginx:2.0.1"] != 0 {
			t.Errorf("newer series = %+v %v", ns, tagsOf(ns))
		}
	})
	t.Run("only a newer major is checked first", func(t *testing.T) {
		e := newerEnv("1.24.1", "2.0.1")
		e.candidateScan("nginx:2.0.1", nil, pkgs("libc", "2"))
		_, plan, _ := checkNewer(t, e, bigLimits, NewerSeriesOptions{}, input("nginx:1.24.1", 'a', prepared, fixedA()))
		ns := item(t, plan, 0).NewerSeries
		if ns.Status != NewerSeriesResolves || !reflect.DeepEqual(tagsOf(ns), []string{"2.0.1:resolves"}) || ns.Candidates[0].Change != SeriesChangeMajor {
			t.Errorf("newer series = %+v %v", ns, tagsOf(ns))
		}
	})
	t.Run("no newer series", func(t *testing.T) {
		e := newerEnv("1.24.1", "1.23.0")
		_, plan, _ := checkNewer(t, e, bigLimits, NewerSeriesOptions{}, input("nginx:1.24.1", 'a', prepared, fixedA()))
		if ns := item(t, plan, 0).NewerSeries; ns.Status != NewerSeriesNone || len(ns.Candidates) != 0 {
			t.Errorf("newer series = %+v", ns)
		}
	})
}

func TestNewerSeriesUnknownTargetIsNotChecked(t *testing.T) {
	e := newerEnv()
	// The candidate scan covers no package type of the target.
	e.scn.scans["nginx:1.26.0"] = func(t scanner.ScanTarget) scanner.ImageScan {
		s := remoteScan(t, nil, nil)
		return s
	}
	e.candidateScan("nginx:2.0.1", []scanner.Finding{fixedA()}, pkgs("libc", "1"))
	_, plan, _ := checkNewer(t, e, bigLimits, NewerSeriesOptions{}, input("nginx:1.24.1", 'a', prepared, fixedA()))
	ns := item(t, plan, 0).NewerSeries
	if ns.Candidates[0].Status != NewerSeriesNotChecked || len(ns.Candidates) != 1 || ns.Status != NewerSeriesNotChecked {
		t.Errorf("newer series = %+v %v", ns, tagsOf(ns))
	}
}

func TestNewerSeriesEligibility(t *testing.T) {
	e := newerEnv()
	e.reg.tags["redis"] = registry.TagList{Tags: []string{"7.2.0", "7.2.1", "8.0.0"}, Pages: 1}
	e.reg.res["redis:7.2.1"] = resolution('f', '9')
	e.candidateScan("redis:7.2.1", nil, pkgs("libc", "2"))
	e.reg.res["postgres:16"] = resolution('7', '8')
	e.candidateScan("postgres:16", []scanner.Finding{fixedA()}, pkgs("libc", "1"))
	e.candidateScan("nginx:1.26.0", nil, pkgs("libc", "2"))
	_, plan, sum := checkNewer(t, e, bigLimits, NewerSeriesOptions{},
		input("nginx:1.24.1", 'a', prepared, fixedA()), // no newer patch
		input("redis:7.2.0", 'b', prepared, fixedA()),  // a candidate of its own series
		input("postgres:16", 'c', prepared, fixedA()),  // a floating tag
		input("nginx:1.24.1", 'd', prepared),           // no target
	)
	got := map[string]bool{}
	for _, it := range plan.Items {
		got[it.Current.Ref] = it.NewerSeries != nil
	}
	if !got["nginx:1.24.1"] || got["redis:7.2.0"] || got["postgres:16"] || sum.Items != 1 {
		t.Errorf("checked = %v, summary %+v", got, sum)
	}
}

func TestSettleNewerSeries(t *testing.T) {
	cand := func(tag string, s NewerSeriesStatus, resolved int) NewerSeriesCandidate {
		return NewerSeriesCandidate{Tag: tag, Status: s, Counts: &NewerSeriesCounts{Resolved: resolved}, Reason: Reason("r-" + tag)}
	}
	cases := []struct {
		name   string
		cands  []NewerSeriesCandidate
		status NewerSeriesStatus
		shown  string
		reason Reason
	}{
		{"resolves wins over more resolved with new", []NewerSeriesCandidate{cand("a", NewerSeriesResolvesWithNew, 3), cand("b", NewerSeriesResolves, 2)}, NewerSeriesResolves, "b", ""},
		{"both resolve: the first", []NewerSeriesCandidate{cand("a", NewerSeriesResolves, 2), cand("b", NewerSeriesResolves, 2)}, NewerSeriesResolves, "a", ""},
		{"most resolved", []NewerSeriesCandidate{cand("a", NewerSeriesResolvesPartially, 1), cand("b", NewerSeriesResolvesWithNew, 2)}, NewerSeriesResolvesWithNew, "b", ""},
		{"as many: without new findings", []NewerSeriesCandidate{cand("a", NewerSeriesResolvesWithNew, 1), cand("b", NewerSeriesResolvesPartially, 1)}, NewerSeriesResolvesPartially, "b", ""},
		{"as many, same kind: the first", []NewerSeriesCandidate{cand("a", NewerSeriesResolvesPartially, 1), cand("b", NewerSeriesResolvesPartially, 1)}, NewerSeriesResolvesPartially, "a", ""},
		{"partial beside not checked", []NewerSeriesCandidate{cand("a", NewerSeriesResolvesPartially, 1), cand("b", NewerSeriesNotChecked, 2)}, NewerSeriesResolvesPartially, "a", ""},
		{"not resolving beside not checked", []NewerSeriesCandidate{cand("a", NewerSeriesNotResolving, 0), cand("b", NewerSeriesNotChecked, 0)}, NewerSeriesNotResolving, "", ""},
		{"all not resolving", []NewerSeriesCandidate{cand("a", NewerSeriesNotResolving, 0), cand("b", NewerSeriesNotResolving, 0)}, NewerSeriesNotResolving, "", ""},
		{"nothing checked", []NewerSeriesCandidate{cand("a", NewerSeriesNotChecked, 0)}, NewerSeriesNotChecked, "", "r-a"},
	}
	for _, c := range cases {
		ns := &NewerSeries{Candidates: c.cands}
		settleNewerSeries(ns)
		if ns.Status != c.status || ns.Shown != c.shown || ns.Reason != c.reason {
			t.Errorf("%s: %s/%q/%q, want %s/%q/%q", c.name, ns.Status, ns.Shown, ns.Reason, c.status, c.shown, c.reason)
		}
	}
	for s, want := range map[NewerSeriesStatus]bool{
		NewerSeriesResolves: false, NewerSeriesResolvesPartially: true, NewerSeriesResolvesWithNew: true,
		NewerSeriesNotResolving: true, NewerSeriesNotChecked: false,
	} {
		if checkNext(s) != want {
			t.Errorf("checkNext(%s) = %v", s, !want)
		}
	}
}

func TestClassifyNewer(t *testing.T) {
	vr := VerificationResult{Comparable: true}
	for name, c := range map[string]struct {
		vr   VerificationResult
		d    Decision
		want NewerSeriesStatus
	}{
		"not comparable":            {VerificationResult{Reason: ReasonScanFailed}, Decision{Targets: 1}, NewerSeriesNotChecked},
		"unknown target":            {vr, Decision{Targets: 2, Resolved: 1, Unknown: 1}, NewerSeriesNotChecked},
		"nothing detected":          {vr, Decision{Targets: 1, Undetected: 1}, NewerSeriesNotChecked},
		"none resolved":             {vr, Decision{Targets: 1, Remaining: 1, Introduced: 2}, NewerSeriesNotResolving},
		"resolved and introduced":   {vr, Decision{Targets: 1, Resolved: 1, Introduced: 1}, NewerSeriesResolvesWithNew},
		"resolved and new KEV":      {vr, Decision{Targets: 1, Resolved: 1, IntroducedKEV: []string{"K"}}, NewerSeriesResolvesWithNew},
		"partial":                   {vr, Decision{Targets: 2, Resolved: 1, Remaining: 1}, NewerSeriesResolvesPartially},
		"partial beside undetected": {vr, Decision{Targets: 2, Resolved: 1, Undetected: 1}, NewerSeriesNotChecked},
		"all":                       {vr, Decision{Targets: 2, Resolved: 2}, NewerSeriesResolves},
	} {
		if got, _ := classifyNewer(c.vr, c.d); got != c.want {
			t.Errorf("%s: %s, want %s", name, got, c.want)
		}
	}
}

func TestNewerSeriesReserve(t *testing.T) {
	t.Run("the time kept for later has come: reserved", func(t *testing.T) {
		e := newerEnv()
		e.candidateScan("nginx:1.26.0", nil, pkgs("libc", "2"))
		p := e.planner(t, bigLimits, nil)
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		plan := p.Plan(ctx, []ImageInput{input("nginx:1.24.1", 'a', prepared, fixedA()), input("nginx:1.24.1", 'b', prepared, fixedA())})
		sum := p.CheckNewerSeries(ctx, &plan, NewerSeriesOptions{ReserveTime: 2 * time.Minute})
		for i := range plan.Items {
			if ns := plan.Items[i].NewerSeries; ns.Status != NewerSeriesNotChecked || ns.Reason != ReasonNewerSeriesReserved {
				t.Errorf("item %d: %+v", i, ns)
			}
		}
		if len(e.scn.calls) != 0 || sum.NotChecked != 2 {
			t.Errorf("scans = %v, summary %+v", e.scn.calls, sum)
		}
	})
	t.Run("the time runs out during a scan", func(t *testing.T) {
		e := newerEnv()
		e.scn.scans["nginx:1.26.0"] = func(t scanner.ScanTarget) scanner.ImageScan {
			time.Sleep(300 * time.Millisecond)
			return remoteScan(t, nil, pkgs("libc", "2"))
		}
		p := e.planner(t, bigLimits, nil)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		plan := p.Plan(ctx, []ImageInput{input("nginx:1.24.1", 'a', prepared, fixedA()), input("nginx:1.24.1", 'b', prepared, fixedA())})
		dl, _ := ctx.Deadline()
		p.CheckNewerSeries(ctx, &plan, NewerSeriesOptions{ReserveTime: time.Until(dl) - 100*time.Millisecond})
		first, second := plan.Items[0].NewerSeries, plan.Items[1].NewerSeries
		if first.Status != NewerSeriesNotChecked || first.Candidates[0].Reason != ReasonNewerSeriesReserved || first.Candidates[0].CandidateScan == "" {
			t.Errorf("first = %+v", first)
		}
		if second.Status != NewerSeriesNotChecked || second.Reason != ReasonNewerSeriesReserved || len(second.Candidates) != 0 {
			t.Errorf("second = %+v", second)
		}
		if ctx.Err() != nil {
			t.Error("the cycle's context must outlive the stage")
		}
	})
	t.Run("the cycle's own deadline is told apart", func(t *testing.T) {
		e := newerEnv()
		p := e.planner(t, bigLimits, nil)
		ctx, cancel := context.WithCancel(context.Background())
		plan := p.Plan(ctx, []ImageInput{input("nginx:1.24.1", 'a', prepared, fixedA())})
		cancel()
		p.CheckNewerSeries(ctx, &plan, NewerSeriesOptions{ReserveTime: time.Second})
		if ns := item(t, plan, 0).NewerSeries; ns.Status != NewerSeriesNotChecked || ns.Reason != ReasonCycleDeadline {
			t.Errorf("newer series = %+v", ns)
		}
	})
	t.Run("requests kept for later: reserved, and the rest is not tried", func(t *testing.T) {
		e := newerEnv()
		e.reg.tags["redis"] = registry.TagList{Tags: []string{"7.2.0", "8.0.0"}, Pages: 1}
		e.reg.resErr["nginx:1.26.0"] = registry.ErrBudgetReserved
		_, plan, _ := checkNewer(t, e, bigLimits, NewerSeriesOptions{}, input("nginx:1.24.1", 'a', prepared, fixedA()), input("redis:7.2.0", 'b', prepared, fixedA()))
		for i := range plan.Items {
			if ns := plan.Items[i].NewerSeries; ns.Status != NewerSeriesNotChecked || ns.Reason != ReasonNewerSeriesReserved {
				t.Errorf("item %d: %+v", i, ns)
			}
		}
		if e.reg.resolveCnt["redis:8.0.0"] != 0 {
			t.Error("a halted check resolved another tag")
		}
	})
}

func TestNewerSeriesPriorityOrder(t *testing.T) {
	e := newerEnv()
	e.reg.tags["redis"] = registry.TagList{Tags: []string{"7.2.0", "8.0.0"}, Pages: 1}
	e.reg.res["redis:8.0.0"] = resolution('f', '9')
	e.candidateScan("redis:8.0.0", nil, pkgs("libc", "2"))
	e.candidateScan("nginx:1.26.0", nil, pkgs("libc", "2"))
	// The scan limit allows one: the item with the act_now finding gets it,
	// although it comes second.
	kev := finding("KEV-NEW", "libc", "1", "2", scanner.SeverityHigh)
	_, plan, _ := checkNewer(t, e, Limits{MaxCandidateScans: 1, MaxBaselineRescans: 5, MaxTagPages: 5}, NewerSeriesOptions{},
		input("nginx:1.24.1", 'a', prepared, fixedA()), input("redis:7.2.0", 'b', prepared, kev))
	got := map[string]NewerSeriesStatus{}
	for _, it := range plan.Items {
		got[it.Current.Ref] = it.NewerSeries.Status
	}
	if got["redis:7.2.0"] != NewerSeriesResolves || got["nginx:1.24.1"] != NewerSeriesNotChecked {
		t.Errorf("statuses = %v", got)
	}
}

func TestCheckNewerSeriesWithoutPlanDoesNothing(t *testing.T) {
	e := newEnv()
	p := e.planner(t, bigLimits, nil)
	plan := Plan{Items: []Item{{Kind: TagPinned, Category: CategoryNoCandidate, Reason: ReasonNoNewerTag}}}
	if sum := p.CheckNewerSeries(context.Background(), &plan, NewerSeriesOptions{}); sum.Items != 0 || plan.Items[0].NewerSeries != nil {
		t.Errorf("summary %+v, item %+v", sum, plan.Items[0])
	}
}

// newerDFEnv is a Dockerfile on python:3.12.3-slim whose series candidate
// 3.12.5-slim resolves nothing, with 3.13.0-slim and 4.0.1-slim as newer
// series.
func newerDFEnv(extra ...scanner.Finding) *dfEnv {
	e := newDFEnv()
	e.reg.tags["python"] = registry.TagList{Tags: []string{"3.12.3-slim", "3.12.5-slim", "3.13.0-slim", "4.0.1-slim"}, Pages: 1}
	e.gh.put("ex/app", ".", "Dockerfile", appDockerfile)
	base := append([]scanner.Finding{fixedA(), fixedB()}, extra...)
	e.base("3.12.3-slim", baseResolution('1', '2', 'a', 'b'), base, pkgs("libc", "1", "openssl", "1"))
	e.base("3.12.5-slim", baseResolution('3', '4', 'x', 'y'), base, pkgs("libc", "1", "openssl", "1"))
	return e
}

func TestNewerSeriesDockerfile(t *testing.T) {
	maps := []DockerfileMapping{dfMapping("compose/p/app", "Dockerfile", "")}
	e := newerDFEnv()
	e.base("3.13.0-slim", baseResolution('5', '6', 'p', 'q'), nil, pkgs("libc", "2", "openssl", "2"))
	plan := e.plan(t, bigLimits, maps, nil, dfInput("myapp:1", 'a', "app", appLayers, standardFindings()...))
	it := onlyDockerfile(t, plan)
	if it.Category != CategoryNoCandidate || it.Reason != ReasonCandidateNotFixing {
		t.Fatalf("item = %s/%s", it.Category, it.Reason)
	}
	p, _ := NewPlanner(Config{Registry: e.reg, Scanner: e.scn, Prepared: prepared, Limits: bigLimits, GitHub: e.gh, Dockerfiles: maps})
	plan = p.Plan(context.Background(), []ImageInput{dfInput("myapp:1", 'a', "app", appLayers, standardFindings()...)})
	before := onlyDockerfile(t, plan)
	before.Entities = append([]DockerfileEntity(nil), before.Entities...)
	scansBefore := len(e.scn.calls)
	p.CheckNewerSeries(context.Background(), &plan, NewerSeriesOptions{})
	it = onlyDockerfile(t, plan)
	ns := it.NewerSeries
	if ns == nil || ns.Status != NewerSeriesResolves || ns.Shown != "3.13.0-slim" || len(ns.Candidates) != 1 {
		t.Fatalf("newer series = %+v", ns)
	}
	c := ns.Candidates[0]
	if c.Comparison != nil || c.Candidate == nil || c.Candidate.Tag != "3.13.0-slim" || *c.Counts != (NewerSeriesCounts{Targets: 2, Resolved: 2}) {
		t.Errorf("item candidate = %+v counts %+v", c, c.Counts)
	}
	ent := it.Entities[0].NewerSeries
	if ent == nil || ent.Status != NewerSeriesResolves || ent.Candidates[0].Comparison == nil || ent.Candidates[0].BaselineScan != before.Entities[0].BaselineScan {
		t.Errorf("entity newer series = %+v; want its own comparison on the same scan of the current base", ent)
	}
	if got := e.scn.calls[scansBefore:]; !reflect.DeepEqual(got, []string{"python:3.13.0-slim"}) {
		t.Errorf("scans = %v; the scan of the current base is reused", got)
	}
	it.NewerSeries, it.Entities[0].NewerSeries = nil, nil
	if !reflect.DeepEqual(it, before) {
		t.Errorf("item changed:\n%+v\nwas\n%+v", it, before)
	}
}

func TestNewerSeriesDockerfileScansTheCurrentBaseWhenNotYetScanned(t *testing.T) {
	// With no newer patch the series check never scanned the current base.
	maps := []DockerfileMapping{dfMapping("compose/p/app", "Dockerfile", "")}
	e := newerDFEnv()
	e.reg.tags["python"] = registry.TagList{Tags: []string{"3.12.3-slim", "3.13.0-slim"}, Pages: 1}
	e.base("3.13.0-slim", baseResolution('5', '6', 'p', 'q'), []scanner.Finding{fixedB()}, pkgs("libc", "2", "openssl", "1"))
	p, _ := NewPlanner(Config{Registry: e.reg, Scanner: e.scn, Prepared: prepared, Limits: bigLimits, GitHub: e.gh, Dockerfiles: maps})
	plan := p.Plan(context.Background(), []ImageInput{dfInput("myapp:1", 'a', "app", appLayers, standardFindings()...)})
	if it := onlyDockerfile(t, plan); it.Entities[0].Reason != ReasonNoNewerTag {
		t.Fatalf("entity = %s", it.Entities[0].Reason)
	}
	p.CheckNewerSeries(context.Background(), &plan, NewerSeriesOptions{})
	ns := onlyDockerfile(t, plan).NewerSeries
	if ns.Status != NewerSeriesResolvesPartially || ns.Shown != "3.13.0-slim" || plan.Usage.BaselineRescans != 1 || plan.Usage.CandidateScans != 1 {
		t.Errorf("newer series = %+v, usage %+v", ns, plan.Usage)
	}
}

func TestNewerSeriesDockerfileBeforeLowerPriorityImages(t *testing.T) {
	maps := []DockerfileMapping{dfMapping("compose/p/app", "Dockerfile", "")}
	kev := finding("KEV-NEW", "libc", "1", "2", scanner.SeverityHigh)
	e := newerDFEnv(kev)
	e.base("3.13.0-slim", baseResolution('5', '6', 'p', 'q'), nil, pkgs("libc", "2", "openssl", "2"))
	e.reg.tags["nginx"] = registry.TagList{Tags: []string{"1.24.1", "1.26.0"}, Pages: 1}
	e.reg.res["nginx:1.26.0"] = resolution('b', 'c')
	e.candidateScan("nginx:1.26.0", nil, pkgs("libc", "2"))
	running := append(standardFindings(), layered(kev, 'b'))
	// The series check uses one candidate scan; one is left.
	p, _ := NewPlanner(Config{
		Registry: e.reg, Scanner: e.scn, Prepared: prepared, Limits: Limits{MaxCandidateScans: 2, MaxBaselineRescans: 5, MaxTagPages: 5},
		GitHub: e.gh, Dockerfiles: maps,
		Intel: func(id string) (VulnIntel, bool) {
			return VulnIntel{Priority: PriorityActNow, KEV: true}, id == "KEV-NEW"
		},
	})
	plan := p.Plan(context.Background(), []ImageInput{input("nginx:1.24.1", 'e', prepared, fixedA()), dfInput("myapp:1", 'a', "app", appLayers, running...)})
	p.CheckNewerSeries(context.Background(), &plan, NewerSeriesOptions{})
	var img *NewerSeries
	for _, it := range plan.Items {
		if it.Current.Ref == "nginx:1.24.1" {
			img = it.NewerSeries
		}
	}
	df := onlyDockerfile(t, plan).NewerSeries
	if df == nil || df.Status != NewerSeriesResolves || img == nil || img.Status != NewerSeriesNotChecked || img.Reason != ReasonCandidateScanLimit {
		t.Errorf("dockerfile = %+v, image = %+v; the act_now Dockerfile goes first", df, img)
	}
}

func TestNewerSeriesEligibleDockerfile(t *testing.T) {
	ent := func(c Category, r Reason) DockerfileEntity {
		return DockerfileEntity{Category: c, Reason: r, CurrentBase: &ImageState{}, Targets: []Target{{VulnID: "CVE-A"}}}
	}
	it := func(ents ...DockerfileEntity) DockerfileItem {
		return DockerfileItem{Category: CategoryManual, Reason: ReasonDockerfileSetNotAdopted, BaseKind: TagPinned, Entities: ents}
	}
	noTargets := ent(CategoryNoCandidate, ReasonNoNewerTag)
	noTargets.Targets = nil
	for name, c := range map[string]struct {
		it   DockerfileItem
		want bool
	}{
		"reasons differ":         {it(ent(CategoryNoCandidate, ReasonNoNewerTag), ent(CategoryNoCandidate, ReasonSameContent)), true},
		"one adopted":            {it(ent(CategoryNoCandidate, ReasonNoNewerTag), ent(CategoryPRCandidate, ReasonAdopted)), false},
		"one deferred":           {it(ent(CategoryNoCandidate, ReasonNoNewerTag), ent(CategoryDeferred, ReasonCandidateScanLimit)), false},
		"one without targets":    {it(ent(CategoryNoCandidate, ReasonNoNewerTag), noTargets), false},
		"other no_candidate":     {it(ent(CategoryNoCandidate, ReasonNoBaseFindings)), false},
		"floating base":          {DockerfileItem{BaseKind: TagFloating, Entities: []DockerfileEntity{ent(CategoryNoCandidate, ReasonNoNewerTag)}}, false},
		"current base not known": {it(DockerfileEntity{Category: CategoryNoCandidate, Reason: ReasonNoNewerTag, Targets: []Target{{}}}), false},
	} {
		if got := newerSeriesEligibleDockerfile(c.it); got != c.want {
			t.Errorf("%s: %v", name, got)
		}
	}
}

func TestAggregateNewerBase(t *testing.T) {
	a := Target{VulnID: "CVE-A", Package: PackageCoord{Name: "libc"}}
	b := Target{VulnID: "CVE-B", Package: PackageCoord{Name: "openssl"}}
	verdicts := func(outs map[string]Outcome) *VerificationResult {
		vr := &VerificationResult{Comparable: true}
		for _, t := range []Target{a, b} {
			if o, ok := outs[t.VulnID]; ok {
				vr.Verdicts = append(vr.Verdicts, VulnVerdict{VulnID: t.VulnID, Package: t.Package, Outcome: o})
			}
		}
		return vr
	}
	part := func(platform, top, manifest string, outs map[string]Outcome) NewerSeriesCandidate {
		return NewerSeriesCandidate{Status: NewerSeriesResolves, Candidate: &ImageState{Tag: "3.13.0", Platform: platform, TopDigest: top, ManifestDigest: manifest}, Comparison: verdicts(outs), Counts: &NewerSeriesCounts{}}
	}
	ents := []DockerfileEntity{{Targets: []Target{a, b}}, {Targets: []Target{a, b}}}
	nt := newerTag{"3.13.0", SeriesChangeMinor}
	sameAsCurrent := NewerSeriesCandidate{Status: NewerSeriesNotResolving, Reason: ReasonSameContent, Candidate: &ImageState{Platform: "linux/arm64", TopDigest: "i", ManifestDigest: "m2"}}
	sameAsCurrent.Comparison, sameAsCurrent.Counts = unchangedComparison([]Target{a, b})
	both := map[string]Outcome{"CVE-A": OutcomeResolved, "CVE-B": OutcomeResolved}

	cases := []struct {
		name   string
		parts  []NewerSeriesCandidate
		status NewerSeriesStatus
		reason Reason
	}{
		{"one platform each, one index", []NewerSeriesCandidate{part("linux/amd64", "i", "m1", both), part("linux/arm64", "i", "m2", both)}, NewerSeriesResolves, ""},
		{"different index", []NewerSeriesCandidate{part("linux/amd64", "i", "m1", both), part("linux/arm64", "j", "m2", both)}, NewerSeriesNotChecked, ReasonCandidateChanged},
		{"same platform, different manifest", []NewerSeriesCandidate{part("linux/amd64", "i", "m1", both), part("linux/amd64", "i", "m2", both)}, NewerSeriesNotChecked, ReasonCandidateChanged},
		{"resolved by one, remaining in the other", []NewerSeriesCandidate{part("linux/amd64", "i", "m1", both), part("linux/arm64", "i", "m2", map[string]Outcome{"CVE-A": OutcomeResolved, "CVE-B": OutcomeRemaining})}, NewerSeriesResolvesPartially, ""},
		{"one part not checked", []NewerSeriesCandidate{part("linux/amd64", "i", "m1", both), {Status: NewerSeriesNotChecked, Reason: ReasonCandidateScanLimit}}, NewerSeriesNotChecked, ReasonCandidateScanLimit},
		{"one image's candidate is its current base", []NewerSeriesCandidate{part("linux/amd64", "i", "m1", both), sameAsCurrent}, NewerSeriesNotResolving, ""},
		{"resolved by one, not shown by the other", []NewerSeriesCandidate{part("linux/amd64", "i", "m1", both), part("linux/arm64", "i", "m2", map[string]Outcome{"CVE-A": OutcomeResolved})}, NewerSeriesNotChecked, ReasonTargetsNotDetected},
	}
	for _, c := range cases {
		got := aggregateNewerBase(nt, ents, c.parts)
		if got.Status != c.status || got.Reason != c.reason {
			t.Errorf("%s: %s/%s, want %s/%s", c.name, got.Status, got.Reason, c.status, c.reason)
		}
	}
	withNew := part("linux/amd64", "i", "m1", both)
	withNew.Comparison.Introduced = []VulnVerdict{{VulnID: "KEV-NEW"}}
	withNew.kev = []string{"KEV-NEW"}
	got := aggregateNewerBase(nt, ents, []NewerSeriesCandidate{withNew, part("linux/arm64", "i", "m2", both)})
	if got.Status != NewerSeriesResolvesWithNew || got.Counts.IntroducedKEV != 1 || got.Counts.Introduced != 1 {
		t.Errorf("with new: %s %+v", got.Status, got.Counts)
	}
}

func TestNewerSeriesDockerfileTagOfTheCurrentBase(t *testing.T) {
	maps := []DockerfileMapping{dfMapping("compose/p/app", "Dockerfile", "")}
	e := newerDFEnv()
	e.reg.tags["python"] = registry.TagList{Tags: []string{"3.12.3-slim", "3.12.5-slim", "3.13.0-slim"}, Pages: 1}
	// 3.13.0-slim points at the content of the current base.
	e.reg.res["python:3.13.0-slim"] = baseResolution('1', '2', 'a', 'b')
	p, _ := NewPlanner(Config{Registry: e.reg, Scanner: e.scn, Prepared: prepared, Limits: bigLimits, GitHub: e.gh, Dockerfiles: maps})
	plan := p.Plan(context.Background(), []ImageInput{dfInput("myapp:1", 'a', "app", appLayers, standardFindings()...)})
	p.CheckNewerSeries(context.Background(), &plan, NewerSeriesOptions{})
	it := onlyDockerfile(t, plan)
	if ns := it.NewerSeries; ns.Status != NewerSeriesNotResolving || *ns.Candidates[0].Counts != (NewerSeriesCounts{Targets: 2, Remaining: 2}) {
		t.Errorf("newer series = %+v", ns)
	}
	if ns := it.Entities[0].NewerSeries; ns.Status != NewerSeriesNotResolving || ns.Candidates[0].Reason != ReasonSameContent {
		t.Errorf("entity newer series = %+v", ns)
	}
}

func TestNewerSeriesTagOfTheRunningContent(t *testing.T) {
	e := newerEnv()
	// 1.26.0 is the image already running (its config digest).
	e.reg.res["nginx:1.26.0"] = resolution('b', 'a')
	e.candidateScan("nginx:2.0.1", nil, pkgs("libc", "2"))
	_, plan, _ := checkNewer(t, e, bigLimits, NewerSeriesOptions{}, input("nginx:1.24.1", 'a', prepared, fixedA()))
	ns := item(t, plan, 0).NewerSeries
	c := ns.Candidates[0]
	if c.Status != NewerSeriesNotResolving || c.Reason != ReasonSameContent || c.Comparison == nil || len(c.Comparison.Verdicts) != 1 ||
		c.Comparison.Verdicts[0].Outcome != OutcomeRemaining || *c.Counts != (NewerSeriesCounts{Targets: 1, Remaining: 1}) || c.CandidateScan != "" {
		t.Errorf("candidate = %+v", c)
	}
	if ns.Status != NewerSeriesResolves || ns.Shown != "2.0.1" {
		t.Errorf("newer series = %+v", ns)
	}
}

// The order follows what a newer base can resolve, the base's targets, not
// a finding of the image's own layers.
func TestNewerSeriesDockerfileOrderedByItsBaseTargets(t *testing.T) {
	maps := []DockerfileMapping{dfMapping("compose/p/app", "Dockerfile", "")}
	kev := finding("KEV-NEW", "pylib", "1", "2", scanner.SeverityHigh)
	e := newerDFEnv()
	e.base("3.13.0-slim", baseResolution('5', '6', 'p', 'q'), nil, pkgs("libc", "2", "openssl", "2"))
	e.reg.tags["nginx"] = registry.TagList{Tags: []string{"1.24.1", "1.26.0"}, Pages: 1}
	e.reg.res["nginx:1.26.0"] = resolution('b', 'c')
	e.candidateScan("nginx:1.26.0", nil, pkgs("libc", "2"))
	running := append(standardFindings(), layered(kev, 'c'))
	p, _ := NewPlanner(Config{
		Registry: e.reg, Scanner: e.scn, Prepared: prepared, Limits: Limits{MaxCandidateScans: 2, MaxBaselineRescans: 5, MaxTagPages: 5},
		GitHub: e.gh, Dockerfiles: maps,
		Intel: func(id string) (VulnIntel, bool) {
			switch id {
			case "KEV-NEW":
				return VulnIntel{Priority: PriorityActNow, KEV: true}, true
			case "CVE-W":
				return VulnIntel{Priority: PriorityWatch}, true
			}
			return VulnIntel{}, false
		},
	})
	watch := finding("CVE-W", "libc", "1", "2", scanner.SeverityHigh)
	plan := p.Plan(context.Background(), []ImageInput{input("nginx:1.24.1", 'e', prepared, watch), dfInput("myapp:1", 'a', "app", appLayers, running...)})
	if df := onlyDockerfile(t, plan); df.Priority != PriorityActNow {
		t.Fatalf("Dockerfile item priority = %s; the test needs the image's own act_now finding", df.Priority)
	}
	p.CheckNewerSeries(context.Background(), &plan, NewerSeriesOptions{})
	var img *NewerSeries
	for _, it := range plan.Items {
		if it.Current.Ref == "nginx:1.24.1" {
			img = it.NewerSeries
		}
	}
	df := onlyDockerfile(t, plan).NewerSeries
	if img == nil || img.Status != NewerSeriesResolves || df == nil || df.Status != NewerSeriesNotChecked || df.Reason != ReasonCandidateScanLimit {
		t.Errorf("image = %+v, dockerfile = %+v; the watch image goes first", img, df)
	}
}

// budgetRegistry records how many requests were kept while it was asked.
type budgetRegistry struct {
	*fakeRegistry
	budget *registry.Budget
	kept   []int
}

func (b *budgetRegistry) Resolve(ctx context.Context, repo, ref string, p inventory.Platform) (registry.Resolution, error) {
	b.kept = append(b.kept, b.budget.Reserved())
	return b.fakeRegistry.Resolve(ctx, repo, ref, p)
}

func TestNewerSeriesKeepsRequestsOnlyWhileItRuns(t *testing.T) {
	e := newerEnv()
	e.candidateScan("nginx:1.26.0", nil, pkgs("libc", "2"))
	budget := registry.NewBudget(100)
	reg := &budgetRegistry{fakeRegistry: e.reg, budget: budget}
	p, _ := NewPlanner(Config{Registry: reg, Scanner: e.scn, Prepared: prepared, Limits: bigLimits, Budget: budget})
	plan := p.Plan(context.Background(), []ImageInput{input("nginx:1.24.1", 'a', prepared, fixedA())})
	p.CheckNewerSeries(context.Background(), &plan, NewerSeriesOptions{ReserveRequests: 25})
	if !reflect.DeepEqual(reg.kept, []int{25}) || budget.Reserved() != 0 {
		t.Errorf("kept while resolving = %v, after = %d; want 25 during the check and none after", reg.kept, budget.Reserved())
	}
}
