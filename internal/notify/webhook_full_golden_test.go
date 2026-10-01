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

	rt := rtGoldenReport(t)
	rtGoldenAttach(t, &rt)
	d, _ := state.Compute(state.State{}, rt)
	checkGolden(t, "webhookfull_runtime_healthy_diff", fullWebhookJSON(t, rt, &d))

	muted := muteGoldenReport(t)
	muteGoldenAttach(t, &muted, true)
	md, _ := state.Compute(state.State{}, muted)
	checkGolden(t, "webhookfull_mute_diff", fullWebhookJSON(t, muted, &md))
}
