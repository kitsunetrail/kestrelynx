package remediation

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// newerSeriesBase is a pinned tag whose series has no newer patch, with newer
// minor releases published after it.
const newerSeriesBase = "aquasec/trivy:0.71.2"

// TestIntegrationNewerSeries checks newer series against the real registry
// and the real Trivy, for a container of the pinned image itself and for one
// built from a Dockerfile on it. Its own series has no newer patch, so the
// newest newer minor release is compared. It runs only when
// KESTRELYNX_DOCKER_IT=1 (see drunSetup). What the newer release resolves
// changes as it and the advisories do, so the test checks that the
// comparison was made and logs what it found; KESTRELYNX_NEWER_PLAN_OUT, when
// set, names a file the plan is written to as JSON.
func TestIntegrationNewerSeries(t *testing.T) {
	e := drunSetup(t)
	dockerCLI(t, "pull", "-q", newerSeriesBase)

	id := drunRandom(t)
	set := newDrunSet(t)
	tag := drunNamePrefix + id + ":1"
	df := "FROM " + newerSeriesBase + "\nCOPY marker.txt /marker.txt\n"
	set.build(tag, df, "first\n")
	built, pulled := drunNamePrefix+id+"-built", drunNamePrefix+id+"-pulled"
	for name, image := range map[string]string{built: tag, pulled: newerSeriesBase} {
		set.containers = append(set.containers, name)
		dockerCLI(t, "run", "-d", "--name", name, "--entrypoint", "sleep", image, "3600")
	}

	var inputs []ImageInput
	for _, name := range []string{pulled, built} {
		in, _ := e.input(t, e.observe(t, name), false)
		inputs = append(inputs, in)
	}
	h := newPRHarness(t)
	h.gh.commitFiles(testRepo, "main", map[string]string{"Dockerfile": df, "marker.txt": "x\n"})
	mapping := DockerfileMapping{Workload: "container/" + built, Repository: testRepo, BaseBranch: "main", Path: "Dockerfile"}
	p, _ := e.planner(t, prReader{h.gh}, []DockerfileMapping{mapping})
	plan := p.Plan(e.ctx, inputs)
	sum := p.CheckNewerSeries(e.ctx, &plan, NewerSeriesOptions{})
	t.Logf("summary %+v, usage %+v", sum, plan.Usage)

	logNewer := func(what string, own Reason, ns *NewerSeries) {
		if ns == nil {
			t.Fatalf("%s (%s): no newer series check", what, own)
		}
		t.Logf("%s (own series: %s): %s shown %q reason %q", what, own, ns.Status, ns.Shown, ns.Reason)
		for _, c := range ns.Candidates {
			t.Logf("  %s %s: %s %s counts %+v", c.Tag, c.Change, c.Status, c.Reason, c.Counts)
			if c.Comparison == nil {
				continue
			}
			for _, v := range c.Comparison.Verdicts {
				if strings.HasPrefix(v.Package.Name, "brotli") {
					t.Logf("    %s %s: %s", v.VulnID, v.Package.Name, v.Outcome)
				}
			}
		}
		if ns.Status == NewerSeriesNotChecked || ns.Status == NewerSeriesNone || len(ns.Candidates) == 0 || ns.Candidates[0].Change != SeriesChangeMinor {
			t.Errorf("%s: the newer minor release was not compared: %+v", what, ns)
		}
	}
	var item *Item
	for i := range plan.Items {
		if plan.Items[i].Current.Ref == newerSeriesBase {
			item = &plan.Items[i]
		}
	}
	if item == nil {
		t.Fatalf("no item for %s: %+v", newerSeriesBase, plan.Items)
	}
	if item.Category != CategoryNoCandidate || item.Reason != ReasonNoNewerTag {
		t.Fatalf("item = %s/%s (%s); the test needs a series with no newer patch", item.Category, item.Reason, item.Detail)
	}
	logNewer("published image", item.Reason, item.NewerSeries)

	if len(plan.DockerfileItems) != 1 {
		t.Fatalf("Dockerfile items = %+v", plan.DockerfileItems)
	}
	di := plan.DockerfileItems[0]
	logNewer("Dockerfile base", di.Entities[0].Reason, di.NewerSeries)
	logNewer("Dockerfile running image", di.Entities[0].Reason, di.Entities[0].NewerSeries)

	if out := os.Getenv("KESTRELYNX_NEWER_PLAN_OUT"); out != "" {
		data, err := json.Marshal(plan)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(out, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
