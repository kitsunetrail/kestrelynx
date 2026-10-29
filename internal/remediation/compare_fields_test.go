package remediation

import (
	"context"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/registry"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

// What an item keeps of a comparison that stopped: a limit leaves the
// candidate and no scans, the deadline after the scans leaves the scans and
// no candidate.
func TestPlanStoppedComparisonFields(t *testing.T) {
	t.Run("candidate scan limit", func(t *testing.T) {
		e := newEnv()
		e.reg.res["postgres:16"] = resolution('b', 'c')
		e.candidateScan("postgres:16", nil, pkgs("libc", "2"))
		plan := e.planner(t, Limits{MaxCandidateScans: 0, MaxBaselineRescans: 5, MaxTagPages: 5}, nil).Plan(context.Background(), []ImageInput{input("postgres:16", 'a', prepared, fixedA())})
		it := item(t, plan, 0)
		if it.Reason != ReasonCandidateScanLimit || it.Candidate == nil || it.BaselineScan != "" || it.CandidateScan != "" || it.Comparison != nil {
			t.Errorf("item = %s, candidate %+v, scans %q %q, comparison %v", it.Reason, it.Candidate, it.BaselineScan, it.CandidateScan, it.Comparison)
		}
	})
	t.Run("deadline after the scans", func(t *testing.T) {
		e := newEnv()
		e.reg.res["postgres:16"] = resolution('b', 'c')
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		e.scn.scans["postgres:16"] = func(t scanner.ScanTarget) scanner.ImageScan {
			cancel()
			return remoteScan(t, nil, pkgs("libc", "2"))
		}
		plan := e.planner(t, bigLimits, nil).Plan(ctx, []ImageInput{input("postgres:16", 'a', prepared, fixedA())})
		it := item(t, plan, 0)
		if it.Reason != ReasonCycleDeadline || it.Candidate != nil || it.BaselineScan == "" || it.CandidateScan == "" || it.Comparison != nil {
			t.Errorf("item = %s, candidate %+v, scans %q %q, comparison %v", it.Reason, it.Candidate, it.BaselineScan, it.CandidateScan, it.Comparison)
		}
	})
}

// An entity keeps the resolved candidate base whatever stopped its
// comparison, and the scans only once they ran.
func TestDockerfileStoppedComparisonFields(t *testing.T) {
	maps := []DockerfileMapping{dfMapping("compose/p/app", "Dockerfile", "")}
	t.Run("candidate scan limit", func(t *testing.T) {
		e := newDFEnv()
		e.standard()
		plan := e.plan(t, Limits{MaxCandidateScans: 0, MaxBaselineRescans: 5, MaxTagPages: 5}, maps, nil,
			dfInput("myapp:1", 'a', "app", appLayers, standardFindings()...))
		ent := onlyDockerfile(t, plan).Entities[0]
		if ent.Reason != ReasonCandidateScanLimit || ent.CandidateBase == nil || ent.CandidateBase.Tag != "3.12.5-slim" || ent.BaselineScan != "" || ent.CandidateScan != "" {
			t.Errorf("entity = %s, candidate %+v, scans %q %q", ent.Reason, ent.CandidateBase, ent.BaselineScan, ent.CandidateScan)
		}
	})
	t.Run("deadline after the scans", func(t *testing.T) {
		e := newDFEnv()
		e.standard()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		next := e.scn.scans["python:3.12.5-slim"]
		e.scn.scans["python:3.12.5-slim"] = func(t scanner.ScanTarget) scanner.ImageScan {
			cancel()
			return next(t)
		}
		p, err := NewPlanner(Config{
			Registry: e.reg, Scanner: e.scn, Prepared: prepared, Limits: bigLimits, GitHub: e.gh, Dockerfiles: maps,
			Now: func() time.Time { return time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC) },
		})
		if err != nil {
			t.Fatal(err)
		}
		plan := p.Plan(ctx, []ImageInput{dfInput("myapp:1", 'a', "app", appLayers, standardFindings()...)})
		ent := onlyDockerfile(t, plan).Entities[0]
		if ent.Reason != ReasonCycleDeadline || ent.CandidateBase == nil || ent.BaselineScan == "" || ent.CandidateScan == "" || ent.Comparison != nil {
			t.Errorf("entity = %s, candidate %+v, scans %q %q, comparison %v", ent.Reason, ent.CandidateBase, ent.BaselineScan, ent.CandidateScan, ent.Comparison)
		}
	})
}

// Two series of one repository whose walks are both unreliable read the
// whole listing once.
func TestPlanSeriesShareTheWholeListing(t *testing.T) {
	e := newEnv()
	e.reg.tags["nginx"] = registry.TagList{Tags: []string{"1.24.1", "1.24.2", "1.25.3", "1.25.4"}, Pages: 1}
	for _, ref := range []string{"nginx:1.24.2", "nginx:1.25.4"} {
		e.reg.res[ref] = resolution('b', 'c')
		e.candidateScan(ref, nil, pkgs("libc", "2"))
	}
	pager := &sortedPager{misbehave: func(string, int) []string { return []string{"1.23.5", "1.23.4"} }}
	plan := e.seriesPlanner(t, pager, bigLimits).Plan(context.Background(), []ImageInput{
		input("nginx:1.24.1", 'a', prepared, fixedA()), input("nginx:1.25.3", 'd', prepared, fixedA()),
	})
	got := map[string]string{}
	for _, it := range plan.Items {
		if it.Candidate != nil {
			got[it.Current.Ref] = it.Candidate.Tag
		}
	}
	if got["nginx:1.24.1"] != "1.24.2" || got["nginx:1.25.3"] != "1.25.4" {
		t.Errorf("candidates = %v", got)
	}
	if e.reg.listCalls != 1 || len(pager.calls) != 1 || plan.Usage.TagPages != 2 {
		t.Errorf("listings = %d, walk requests = %d, tag pages = %d; want one walk request and one listing", e.reg.listCalls, len(pager.calls), plan.Usage.TagPages)
	}
}
