package config

import (
	"strings"
	"testing"
)

func TestParse_SlackBotToken(t *testing.T) {
	c, err := Parse([]byte(`
notify:
  slack_bot_token: "xoxb-123"
  slack_channel: "C0123456789"
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if c.Notify.SlackBotToken != "xoxb-123" || c.Notify.SlackChannel != "C0123456789" {
		t.Errorf("token/channel = %q/%q", c.Notify.SlackBotToken, c.Notify.SlackChannel)
	}
}

func TestParse_SlackBotTokenRequiresChannel(t *testing.T) {
	for _, yml := range []string{
		"notify:\n  slack_bot_token: \"xoxb-123\"\n",
		"notify:\n  slack_channel: \"C0123456789\"\n",
	} {
		if _, err := Parse([]byte(yml)); err == nil || !strings.Contains(err.Error(), "set together") {
			t.Errorf("token/channel alone must fail, got %v\n%s", err, yml)
		}
	}
}

func TestParse_SlackTokenAndWebhookConflict(t *testing.T) {
	_, err := Parse([]byte(`
notify:
  slack_webhook_url: "https://hooks.slack.test/abc"
  slack_bot_token: "xoxb-123"
  slack_channel: "C0123456789"
`))
	if err == nil || !strings.Contains(err.Error(), "not both") {
		t.Errorf("webhook + bot token must fail, got %v", err)
	}
}
