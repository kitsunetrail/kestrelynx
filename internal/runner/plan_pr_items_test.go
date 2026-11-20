package runner

import (
	"errors"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/remediation"
)

// wantNotProcessedItems checks that the plan has a pr_candidate item and that
// it has one not_processed result with the reason.
func wantNotProcessedItems(t *testing.T, p *remediation.Plan, reason remediation.Reason) {
	t.Helper()
	if p.Count(remediation.CategoryPRCandidate) == 0 {
		t.Fatalf("the plan has no pr_candidate item: %+v", p.Items)
	}
	if len(p.PRItems) != 1 {
		t.Fatalf("pr items = %+v, want one", p.PRItems)
	}
	got := p.PRItems[0]
	if got.Kind != remediation.PRItemKindImage || got.ItemKey != p.Items[0].Key || got.Workload != "compose/shop/web" ||
		got.Status != remediation.PRItemNotProcessed || got.Reason != reason || len(got.UnitKeys) != 0 {
		t.Errorf("pr item = %+v, want not_processed (%s)", got, reason)
	}
}

func TestPullRequests_EnabledIsRecordedInThePlan(t *testing.T) {
	h := newPRHarness(osFinding("CVE-1"))
	h.stage.result = createdResult()
	h.run(t)
	p := h.notif.msg.Plan.Plan
	if p.PullRequestsEnabled == nil || !*p.PullRequestsEnabled {
		t.Errorf("PullRequestsEnabled = %v, want true", p.PullRequestsEnabled)
	}
	// The stage's own results are attached as they are.
	if len(p.PRItems) != 0 {
		t.Errorf("pr items = %+v, want the stage's (none)", p.PRItems)
	}
	if len(h.plans.saved) != 1 || h.plans.saved[0].PullRequestsEnabled == nil || !*h.plans.saved[0].PullRequestsEnabled {
		t.Errorf("saved plan = %+v", h.plans.saved)
	}
}

func TestPullRequests_DisabledIsRecordedAsFalseWithoutItems(t *testing.T) {
	h := newPlanHarness(osFinding("CVE-1"))
	h.run(t)
	p := h.notif.msg.Plan.Plan
	if p.PullRequestsEnabled == nil || *p.PullRequestsEnabled {
		t.Errorf("PullRequestsEnabled = %v, want false", p.PullRequestsEnabled)
	}
	if len(p.PRItems) != 0 {
		t.Errorf("pr items = %+v, want none", p.PRItems)
	}
}

func TestPullRequests_UnsavedPlanLeavesItemsNotProcessed(t *testing.T) {
	h := newPRHarness(osFinding("CVE-1"))
	h.plans.err = errors.New("disk full")
	h.run(t)
	wantNotProcessedItems(t, h.notif.msg.Plan.Plan, remediation.ReasonStorageFailed)
}

func TestPullRequests_StageSetupFailureLeavesItemsNotProcessed(t *testing.T) {
	h := newPRHarness(osFinding("CVE-1"))
	h.newErr = errors.New("bad limits")
	h.run(t)
	wantNotProcessedItems(t, h.notif.msg.Plan.Plan, remediation.ReasonGitHubError)
}
