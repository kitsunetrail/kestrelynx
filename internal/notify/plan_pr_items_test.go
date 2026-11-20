package notify

import (
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/remediation"
)

func TestWebhook_PullRequestItems(t *testing.T) {
	r, changed, _ := planCycleFixture()
	// A plan that records neither field has neither key.
	off := webhookJSON(t, BuildWebhookPayloadWithPlan(r, &changed, planInfoFixture()))["remediation"].(map[string]any)
	for _, k := range []string{"pull_requests_enabled", "pr_items"} {
		if _, ok := off[k]; ok {
			t.Errorf("%s present in a plan that does not record it", k)
		}
	}

	p := pullRequestFixture()
	enabled := true
	p.PullRequestsEnabled = &enabled
	p.PRItems = []remediation.PRItemResult{
		{Kind: remediation.PRItemKindImage, ItemKey: "api:2.0.1|c", Workload: "compose/app/api", Status: remediation.PRItemAssigned, UnitKeys: []string{"unit-1"}},
		{Kind: remediation.PRItemKindImage, ItemKey: "api:2.0.1|c", Workload: "deployment/kube-system/metrics-server/metrics-server", Status: remediation.PRItemNotApplicable, Reason: remediation.ReasonSourceMappingMissing},
	}
	rem := webhookJSON(t, BuildWebhookPayloadWithPlan(r, &changed, &PlanInfo{Plan: &p, Changed: true}))["remediation"].(map[string]any)
	if rem["pull_requests_enabled"] != true {
		t.Errorf("pull_requests_enabled = %v", rem["pull_requests_enabled"])
	}
	items, _ := rem["pr_items"].([]any)
	if len(items) != 2 {
		t.Fatalf("pr_items = %v", rem["pr_items"])
	}
	a, b := items[0].(map[string]any), items[1].(map[string]any)
	if a["kind"] != "image" || a["item_key"] != "api:2.0.1|c" || a["workload"] != "compose/app/api" || a["status"] != "assigned" ||
		len(a["unit_keys"].([]any)) != 1 || a["unit_keys"].([]any)[0] != "unit-1" {
		t.Errorf("assigned item = %v", a)
	}
	if b["status"] != "not_applicable" || b["reason"] != "source_mapping_missing" {
		t.Errorf("not applicable item = %v", b)
	}
	if _, ok := b["unit_keys"]; ok {
		t.Errorf("unit_keys on an item with no unit: %v", b)
	}

	// Disabled is shown as false, not left out.
	disabled := false
	p.PullRequestsEnabled, p.PRItems = &disabled, nil
	rem = webhookJSON(t, BuildWebhookPayloadWithPlan(r, &changed, &PlanInfo{Plan: &p, Changed: true}))["remediation"].(map[string]any)
	if v, ok := rem["pull_requests_enabled"]; !ok || v != false {
		t.Errorf("pull_requests_enabled = %v (present %v), want false", v, ok)
	}
	if _, ok := rem["pr_items"]; ok {
		t.Error("pr_items present without items")
	}
}

func TestPlanReasonTextsOfItemsWithoutUnit(t *testing.T) {
	for _, code := range []string{"source_mapping_missing", "container_image_tag_unsupported", "pr_unit_unavailable"} {
		if s, ok := planReasonTexts[code]; !ok || s.en == "" || s.ja == "" {
			t.Errorf("%s has no text: %+v", code, s)
		}
	}
}
