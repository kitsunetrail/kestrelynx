package remediation

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/registry"
)

// tagRun is a pass over reg with a tag page limit of maxPages per
// repository, for the tag listing steps alone.
func tagRun(reg Registry, maxPages int) *run {
	return &run{
		p:        &Planner{cfg: Config{Registry: reg, Limits: Limits{MaxTagPages: maxPages}}},
		ctx:      context.Background(),
		tags:     map[string]tagEntry{},
		tagUsed:  map[string]int{},
		fullTags: map[string]tagEntry{},
		resolved: map[string]resolveEntry{},
	}
}

func TestListPinnedSeriesReportsWholeListing(t *testing.T) {
	ctx := context.Background()
	fake := newFakeRegistry()
	fake.tags["r"] = registry.TagList{Tags: []string{"8.19.1", "8.19.3", "9.0.0"}, Pages: 1}

	if _, whole, err := listPinnedSeries(ctx, fake, "r", tv(t, "8.19.1"), 5); err != nil || !whole {
		t.Errorf("without a pager: whole = %v, %v; want the whole listing", whole, err)
	}
	if list, whole, err := listPinnedSeries(ctx, seriesRegistry{fake, newSortedPager(elasticLike())}, "r", tv(t, "8.19.16"), 40); err != nil || whole || list.Truncated {
		t.Errorf("complete series walk: whole = %v, list %+v, %v; a series list is never the whole listing", whole, list, err)
	}
	backwards := &sortedPager{misbehave: func(string, int) []string { return []string{"8.18.5", "8.18.4"} }}
	if _, whole, err := listPinnedSeries(ctx, seriesRegistry{fake, backwards}, "r", tv(t, "8.19.1"), 10); err != nil || !whole {
		t.Errorf("fallback: whole = %v, %v; want the whole listing", whole, err)
	}
	if _, whole, err := listPinnedSeries(ctx, seriesRegistry{fake, backwards}, "r", tv(t, "8.19.1"), 1); err != nil || whole {
		t.Errorf("fallback with no allowance left: whole = %v, %v; nothing of the whole listing was read", whole, err)
	}
	failing := newSortedPager(elasticLike())
	failing.err = errors.New("boom")
	if _, whole, err := listPinnedSeries(ctx, seriesRegistry{fake, failing}, "r", tv(t, "8.19.16"), 10); err == nil || whole {
		t.Errorf("failed walk: whole = %v, %v", whole, err)
	}
}

func TestFullTagListSharesTheSeriesListingWithoutPager(t *testing.T) {
	fake := newFakeRegistry()
	fake.tags["r"] = registry.TagList{Tags: []string{"8.19.1", "8.20.0", "9.0.0"}, Pages: 2}
	r := tagRun(fake, 10)
	var it Item
	var tag string
	r.pinnedCandidate(ParseImageRef("r:8.19.1"), &it, &tag)

	tags, out := r.fullTagList("r")
	if out != nil || !reflect.DeepEqual(tags, []string{"8.19.1", "8.20.0", "9.0.0"}) {
		t.Fatalf("full list = %v, %+v", tags, out)
	}
	if fake.listCalls != 1 || r.plan.Usage.TagPages != 2 {
		t.Errorf("listings = %d, tag pages = %d; want the one listing shared and counted once", fake.listCalls, r.plan.Usage.TagPages)
	}
}

func TestFullTagListSharesTheFallbackListing(t *testing.T) {
	fake := newFakeRegistry()
	fake.tags["r"] = registry.TagList{Tags: []string{"8.19.1", "8.20.0"}, Pages: 1}
	pager := &sortedPager{misbehave: func(string, int) []string { return []string{"8.18.5", "8.18.4"} }}
	r := tagRun(seriesRegistry{fake, pager}, 10)
	var it Item
	var tag string
	r.pinnedCandidate(ParseImageRef("r:8.19.1"), &it, &tag)

	tags, out := r.fullTagList("r")
	if out != nil || !reflect.DeepEqual(tags, []string{"8.19.1", "8.20.0"}) || fake.listCalls != 1 {
		t.Errorf("full list = %v, %+v, listings %d; want the fallback listing shared", tags, out, fake.listCalls)
	}
}

func TestFullTagListReadsTheListingAfterASeriesWalk(t *testing.T) {
	fake := newFakeRegistry()
	fake.tags["r"] = registry.TagList{Tags: []string{"8.19.16", "8.20.0", "9.0.0"}, Pages: 1}
	r := tagRun(seriesRegistry{fake, newSortedPager(elasticLike())}, 40)
	var it Item
	var tag string
	r.pinnedCandidate(ParseImageRef("r:8.19.16"), &it, &tag)
	walked := r.plan.Usage.TagPages
	if walked == 0 || fake.listCalls != 0 {
		t.Fatalf("walk requests = %d, listings = %d; want a series walk only", walked, fake.listCalls)
	}

	tags, out := r.fullTagList("r")
	if out != nil || !reflect.DeepEqual(tags, []string{"8.19.16", "8.20.0", "9.0.0"}) {
		t.Fatalf("full list = %v, %+v", tags, out)
	}
	if !reflect.DeepEqual(fake.allowances, []int{40 - walked}) {
		t.Errorf("allowance = %v, want what the walk left (%d)", fake.allowances, 40-walked)
	}
	if r.plan.Usage.TagPages != walked+1 {
		t.Errorf("tag pages = %d, want %d", r.plan.Usage.TagPages, walked+1)
	}
	// A second call reads nothing more.
	r.fullTagList("r")
	if fake.listCalls != 1 || r.plan.Usage.TagPages != walked+1 {
		t.Errorf("listings = %d, tag pages = %d after a second call", fake.listCalls, r.plan.Usage.TagPages)
	}
}

func TestFullTagListWithNoAllowanceReadsNothing(t *testing.T) {
	fake := newFakeRegistry()
	fake.tags["r"] = registry.TagList{Tags: []string{"8.19.16"}, Pages: 1}
	r := tagRun(fake, 3)
	r.tagUsed["docker.io/library/r"] = 3

	tags, out := r.fullTagList("r")
	if tags != nil || out == nil || out.reason != ReasonTagPageLimit {
		t.Errorf("full list = %v, %+v; want the tag page limit", tags, out)
	}
	if fake.listCalls != 0 {
		t.Errorf("listings = %d; with no allowance left nothing is read", fake.listCalls)
	}
}

func TestFullTagListFailureIsAnOutcomeCountedOnce(t *testing.T) {
	fake := newFakeRegistry()
	fake.tagErr["r"] = errors.New("boom")
	fake.errPages["r"] = 2
	r := tagRun(fake, 10)

	for i := 0; i < 2; i++ {
		tags, out := r.fullTagList("r")
		if tags != nil || out == nil || out.reason != ReasonRegistryError {
			t.Fatalf("call %d: full list = %v, %+v; a failure must not read as no newer tags", i, tags, out)
		}
	}
	if fake.listCalls != 1 || r.plan.Usage.TagPages != 2 || r.tagUsed["docker.io/library/r"] != 2 {
		t.Errorf("listings = %d, tag pages = %d, used = %d; want one listing counted once", fake.listCalls, r.plan.Usage.TagPages, r.tagUsed["docker.io/library/r"])
	}
}

func TestFullTagListCutShortIsAnOutcome(t *testing.T) {
	// The registry has more pages than the allowance.
	fake := newFakeRegistry()
	fake.tags["r"] = registry.TagList{Tags: []string{"8.19.16"}, Pages: 5}
	r := tagRun(fake, 3)
	if tags, out := r.fullTagList("r"); tags != nil || out == nil || out.reason != ReasonTagPageLimit {
		t.Errorf("full list = %v, %+v; want the tag page limit", tags, out)
	}

	// The listing stopped short of the allowance: the registry's own page
	// limit cut it.
	fake = newFakeRegistry()
	fake.tags["r"] = registry.TagList{Tags: []string{"8.19.16"}, Pages: 2, Truncated: true}
	r = tagRun(fake, 10)
	if tags, out := r.fullTagList("r"); tags != nil || out == nil || out.reason != ReasonNewerSeriesTagListIncomplete {
		t.Errorf("full list = %v, %+v; want an incomplete listing", tags, out)
	}
}

func TestFullTagListAfterAHaltReadsNothing(t *testing.T) {
	fake := newFakeRegistry()
	fake.tags["r"] = registry.TagList{Tags: []string{"8.19.16"}, Pages: 1}
	r := tagRun(fake, 10)
	r.halted = &halt{ReasonRegistryBudget, "registry request budget exhausted"}
	if tags, out := r.fullTagList("r"); tags != nil || out == nil || out.reason != ReasonRegistryBudget || fake.listCalls != 0 {
		t.Errorf("full list = %v, %+v, listings %d", tags, out, fake.listCalls)
	}
}
