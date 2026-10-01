package notify

import (
	"encoding/json"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/analyze"
	"github.com/kitsunetrail/kestrelynx/internal/state"
)

// fullWebhookJSON marshals the generic webhook payload with every key, none
// filtered out, so any change to what a webhook consumer receives shows.
func fullWebhookJSON(t *testing.T, r analyze.Report, d *state.Diff) string {
	t.Helper()
	data, err := json.MarshalIndent(BuildWebhookPayload(r, d), "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(data) + "\n"
}

// TestGolden_WebhookFullPayload pins the complete, unfiltered generic webhook
// payload of representative cycles: the Slack rendering may change freely, the
// payload receivers parse may not.
func TestGolden_WebhookFullPayload(t *testing.T) {
	r, changed, _, _ := goldenCycle(goldenModes()[0], false)
	checkGolden(t, "webhookfull_status3_triage_diff", fullWebhookJSON(t, r, &changed))
	checkGolden(t, "webhookfull_status3_triage_full", fullWebhookJSON(t, r, nil))

	r, changed, _, _ = eolCycle(goldenModes()[0])
	checkGolden(t, "webhookfull_eolpkg_triage_diff", fullWebhookJSON(t, r, &changed))

	r, _, unchanged, _ := goldenCycle(goldenModes()[0], false)
	rcDiff := refChangeDiff(unchanged)
	checkGolden(t, "webhookfull_refchange_diff", fullWebhookJSON(t, r, &rcDiff))

	rt := rtGoldenReport(t)
	rtGoldenAttach(t, &rt)
	d, _ := state.Compute(state.State{}, rt)
	checkGolden(t, "webhookfull_runtime_healthy_diff", fullWebhookJSON(t, rt, &d))

	muted := muteGoldenReport(t)
	muteGoldenAttach(t, &muted, true)
	md, _ := state.Compute(state.State{}, muted)
	checkGolden(t, "webhookfull_mute_diff", fullWebhookJSON(t, muted, &md))
}

// refChangeDiff returns d with two reference changes added: a tag change and
// a change to a digest-pinned reference.
func refChangeDiff(d state.Diff) state.Diff {
	const hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	d.RefChanges = []state.RefChange{
		{
			Repository:  "ghcr.io/acme/web",
			PreviousRef: "ghcr.io/acme/web:sha-aaaa",
			Ref:         "ghcr.io/acme/web:sha-bbbb",
			Workloads:   []string{"compose/shop/web"},
		},
		{
			Repository:  "registry.example:5000/team/api",
			PreviousRef: "registry.example:5000/team/api@sha256:" + hex,
			Ref:         "registry.example:5000/team/api:1.4",
			Workloads:   []string{"compose/shop/api"},
		},
	}
	return d
}
