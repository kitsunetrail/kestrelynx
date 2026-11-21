package remediation

import (
	"reflect"
	"testing"
)

func prItemOf(t *testing.T, items []PRItemResult, workload string) PRItemResult {
	t.Helper()
	for _, r := range items {
		if r.Workload == workload {
			return r
		}
	}
	t.Fatalf("no result for workload %q in %+v", workload, items)
	return PRItemResult{}
}

func TestPRItems_ComposeAssignedAndUnmappedInOneItem(t *testing.T) {
	h := newPRHarness(t)
	it := nginxItem("1.25.4", '1', []string{"CVE-1"}, nil)
	res := h.run(testPlan(it))
	unit := onlyUnit(t, res)
	if len(res.Items) != 3 {
		t.Fatalf("items = %+v, want one per workload", res.Items)
	}
	// Workloads come in ascending order.
	for i, w := range []string{"compose/app/web", "compose/app/worker", "compose/other/extra"} {
		if res.Items[i].Workload != w || res.Items[i].ItemKey != it.Key || res.Items[i].Kind != PRItemKindImage {
			t.Errorf("items[%d] = %+v, want workload %s", i, res.Items[i], w)
		}
	}
	for _, w := range []string{"compose/app/web", "compose/app/worker"} {
		got := prItemOf(t, res.Items, w)
		if got.Status != PRItemAssigned || !reflect.DeepEqual(got.UnitKeys, []string{unit.Key}) || got.Reason != "" {
			t.Errorf("%s = %+v, want assigned to %s", w, got, unit.Key)
		}
	}
	got := prItemOf(t, res.Items, "compose/other/extra")
	if got.Status != PRItemNotApplicable || got.Reason != ReasonSourceMappingMissing || len(got.UnitKeys) != 0 {
		t.Errorf("unmapped service = %+v", got)
	}

	// The same results are attached to the plan.
	var p Plan
	res.Attach(&p)
	if !reflect.DeepEqual(p.PRItems, res.Items) {
		t.Errorf("attached items = %+v", p.PRItems)
	}
}

func TestPRItems_UnmappedKubernetesWorkload(t *testing.T) {
	h := newPRHarness(t)
	const metrics = "deployment/kube-system/metrics-server/metrics-server"
	it := kubeItemOf(kubeRunning, 'a', "1.25.4", '1', metrics)
	res := h.run(kubePlan(it))
	if len(res.Units) != 0 {
		t.Fatalf("units = %+v", res.Units)
	}
	want := []PRItemResult{{Kind: PRItemKindImage, ItemKey: it.Key, Workload: metrics, Status: PRItemNotApplicable, Reason: ReasonSourceMappingMissing}}
	if !reflect.DeepEqual(res.Items, want) {
		t.Errorf("items = %+v, want %+v", res.Items, want)
	}
}

func TestPRItems_ContainerStartedOutsideCompose(t *testing.T) {
	h := newPRHarness(t)
	it := kubeItemOf(kubeRunning, 'a', "1.25.4", '1')
	it.Services = []ServiceRef{{Container: "shop-api"}}
	res := h.run(kubePlan(it))
	want := []PRItemResult{{Kind: PRItemKindImage, ItemKey: it.Key, Workload: "container/shop-api", Status: PRItemNotApplicable, Reason: ReasonContainerImageTagUnsupported}}
	if !reflect.DeepEqual(res.Items, want) {
		t.Errorf("items = %+v, want %+v", res.Items, want)
	}
}

func TestPRItems_ServiceWithoutWorkloadKey(t *testing.T) {
	h := newPRHarness(t)
	it := kubeItemOf(kubeRunning, 'a', "1.25.4", '1')
	it.Services = []ServiceRef{{}, {}}
	res := h.run(kubePlan(it))
	if len(res.Items) != 1 || res.Items[0].Workload != "" || res.Items[0].Status != PRItemNotApplicable || res.Items[0].Reason != ReasonSourceMappingMissing {
		t.Errorf("items = %+v, want one result with no workload", res.Items)
	}
}

func TestPRItems_MappedWorkloadWithoutUnit(t *testing.T) {
	// A mapping names the workload, but no running container shows it, so no
	// unit is built for the item.
	tests := map[string]func(h *prHarness){
		"kubernetes": func(h *prHarness) {
			h.kube = []KubernetesMapping{kubeMapping("deployment/shop/ghost/app", "apps/ghost.yaml")}
		},
		"kustomize": func(h *prHarness) {
			h.kust = []KustomizeMapping{{Workload: "deployment/shop/other/app", Repository: testRepo, BaseBranch: "main", Path: "k/kustomization.yaml", Image: "nginx", Affects: []string{"deployment/shop/ghost/app"}}}
		},
		"helm values": func(h *prHarness) {
			h.helm = []HelmValuesMapping{{Workload: "deployment/shop/ghost/app", Repository: testRepo, BaseBranch: "main", Path: "values.yaml", Key: "image"}}
		},
	}
	for name, setup := range tests {
		t.Run(name, func(t *testing.T) {
			h := newPRHarness(t)
			setup(h)
			it := kubeItemOf(kubeRunning, 'a', "1.25.4", '1', "deployment/shop/ghost/app")
			res := h.run(kubePlan(it))
			want := []PRItemResult{{Kind: PRItemKindImage, ItemKey: it.Key, Workload: "deployment/shop/ghost/app", Status: PRItemNotProcessed, Reason: ReasonPRUnitUnavailable}}
			if !reflect.DeepEqual(res.Items, want) {
				t.Errorf("items = %+v, want %+v", res.Items, want)
			}
		})
	}
}

func TestPRItems_KubernetesAssigned(t *testing.T) {
	h := newKubePRHarness(t)
	it := kubeItemOf(kubeRunning, 'a', "1.25.4", '1', webApp)
	res := h.run(kubePlan(it))
	u := onlyUnit(t, res)
	if len(res.Items) != 1 || res.Items[0].Status != PRItemAssigned || !reflect.DeepEqual(res.Items[0].UnitKeys, []string{u.Key}) {
		t.Errorf("items = %+v, want assigned to %s", res.Items, u.Key)
	}
}

func TestPRItems_OnlyPRCandidateItems(t *testing.T) {
	h := newPRHarness(t)
	cand := nginxItem("1.25.4", '1', []string{"CVE-1"}, nil)
	other := kubeItemOf(kubeRunning, 'b', "1.25.4", '1', "deployment/kube-system/metrics-server/metrics-server")
	other.Category = CategoryManual
	pull := kubeItemOf(kubeRunning, 'c', "1.25.4", '1', "deployment/kube-system/dns/dns")
	pull.Category = CategoryPullAgain
	res := h.run(testPlan(other, cand, pull))
	for _, r := range res.Items {
		if r.ItemKey != cand.Key {
			t.Errorf("result for a non-candidate item: %+v", r)
		}
	}
	if len(res.Items) != 3 {
		t.Errorf("items = %+v", res.Items)
	}
}

func TestPRItems_ReturnedWhenTheStageCannotUseTheRecords(t *testing.T) {
	h := newPRHarness(t)
	unlock, err := h.store.Lock()
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	it := nginxItem("1.25.4", '1', []string{"CVE-1"}, nil)
	res := h.run(testPlan(it))
	wantStatus(t, onlyUnit(t, res), PRStatusWriteBlocked, ReasonStoreLocked)
	if len(res.Items) != 3 {
		t.Fatalf("items = %+v, want the same results as an ordinary run", res.Items)
	}
	if got := prItemOf(t, res.Items, "compose/app/web"); got.Status != PRItemAssigned || len(got.UnitKeys) != 1 {
		t.Errorf("web = %+v", got)
	}
	if got := prItemOf(t, res.Items, "compose/other/extra"); got.Reason != ReasonSourceMappingMissing {
		t.Errorf("extra = %+v", got)
	}
}

func TestNotProcessedPRItems(t *testing.T) {
	it := nginxItem("1.25.4", '1', []string{"CVE-1"}, nil)
	skipped := nginxItem("1.25.4", '1', nil, nil)
	skipped.Key = "other"
	skipped.Category = CategoryNoCandidate
	got := NotProcessedPRItems(testPlan(skipped, it), ReasonStorageFailed)
	if len(got) != 3 {
		t.Fatalf("results = %+v", got)
	}
	for _, r := range got {
		if r.ItemKey != it.Key || r.Status != PRItemNotProcessed || r.Reason != ReasonStorageFailed || len(r.UnitKeys) != 0 {
			t.Errorf("result = %+v", r)
		}
	}
	if len(NotProcessedPRItems(testPlan(), ReasonStorageFailed)) != 0 {
		t.Error("results for an empty plan")
	}
}

func TestFingerprint_PRItems(t *testing.T) {
	mk := func() Plan {
		p := samplePlan()
		p.PRItems = []PRItemResult{
			{Kind: PRItemKindImage, ItemKey: "a", Workload: "w1", Status: PRItemAssigned, UnitKeys: []string{"u1", "u2"}},
			{Kind: PRItemKindImage, ItemKey: "a", Workload: "w2", Status: PRItemNotApplicable, Reason: ReasonSourceMappingMissing},
		}
		return p
	}
	base := Fingerprint(mk())
	if base == Fingerprint(samplePlan()) {
		t.Error("fingerprint ignores PRItems")
	}

	reordered := mk()
	reordered.PRItems[0], reordered.PRItems[1] = reordered.PRItems[1], reordered.PRItems[0]
	reordered.PRItems[1].UnitKeys = []string{"u2", "u1"}
	if Fingerprint(reordered) != base {
		t.Error("fingerprint changed with the order of PRItems")
	}

	mutations := map[string]func(*Plan){
		"status":   func(p *Plan) { p.PRItems[1].Status = PRItemNotProcessed },
		"reason":   func(p *Plan) { p.PRItems[1].Reason = ReasonContainerImageTagUnsupported },
		"unit":     func(p *Plan) { p.PRItems[0].UnitKeys = []string{"u1"} },
		"workload": func(p *Plan) { p.PRItems[1].Workload = "w3" },
		"item key": func(p *Plan) { p.PRItems[1].ItemKey = "b" },
		"removed":  func(p *Plan) { p.PRItems = p.PRItems[:1] },
	}
	for name, mutate := range mutations {
		p := mk()
		mutate(&p)
		if Fingerprint(p) == base {
			t.Errorf("%s: fingerprint did not change", name)
		}
	}

	on, off := true, false
	a, b := mk(), mk()
	a.PullRequestsEnabled, b.PullRequestsEnabled = &on, &off
	if Fingerprint(a) == Fingerprint(b) || Fingerprint(a) == base {
		t.Error("fingerprint ignores PullRequestsEnabled")
	}
}

func TestPRItems_DockerfileAssigned(t *testing.T) {
	h := newDFPRHarness(t)
	it := dfPlanItem("3.12.5-slim", 'x', []string{"CVE-1"}, nil)
	res := h.run(dfPlan(it))
	u := onlyUnit(t, res)
	key, ok := DockerfileUnitKey(it)
	if !ok || key != u.Key {
		t.Fatalf("DockerfileUnitKey = %q %v, want the unit's key %q", key, ok, u.Key)
	}
	want := []PRItemResult{{Kind: PRItemKindDockerfile, ItemKey: it.Key, UnitKeys: []string{u.Key}, Status: PRItemAssigned}}
	if !reflect.DeepEqual(res.Items, want) {
		t.Errorf("items = %+v, want %+v", res.Items, want)
	}
}

func TestPRItems_DockerfileWithoutUnit(t *testing.T) {
	h := newDFPRHarness(t)
	// An adopted item that lacks the edited FROM gets no unit.
	it := dfPlanItem("3.12.5-slim", 'x', []string{"CVE-1"}, nil)
	it.Source.Stage = nil
	other := dfPlanItem("3.12.5-slim", 'x', []string{"CVE-1"}, nil)
	other.Key, other.Category, other.Reason = other.Key+"-other", CategoryManual, ReasonIntroducedFindings
	res := h.run(dfPlan(it, other))
	if _, ok := DockerfileUnitKey(it); ok || len(res.Units) != 0 {
		t.Fatalf("units = %+v", res.Units)
	}
	// An item that is not adopted has no result.
	want := []PRItemResult{{Kind: PRItemKindDockerfile, ItemKey: it.Key, Status: PRItemNotProcessed, Reason: ReasonPRUnitUnavailable}}
	if !reflect.DeepEqual(res.Items, want) {
		t.Errorf("items = %+v, want %+v", res.Items, want)
	}
}

func TestNotProcessedPRItems_Dockerfile(t *testing.T) {
	adopted := dfPlanItem("3.12.5-slim", 'x', []string{"CVE-1"}, nil)
	manual := dfPlanItem("3.12.5-slim", 'x', []string{"CVE-1"}, nil)
	manual.Key, manual.Category = manual.Key+"-other", CategoryManual
	got := NotProcessedPRItems(dfPlan(adopted, manual), ReasonStorageFailed)
	want := []PRItemResult{{Kind: PRItemKindDockerfile, ItemKey: adopted.Key, Status: PRItemNotProcessed, Reason: ReasonStorageFailed}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("items = %+v, want %+v", got, want)
	}
}
