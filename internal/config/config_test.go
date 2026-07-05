package config

import (
	"strings"
	"testing"
)

const minimal = `
notify:
  slack_webhook_url: "https://hooks.slack.test/abc"
`

func TestParse_Defaults(t *testing.T) {
	c, err := Parse([]byte(minimal))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got := c.Scan.Severity; len(got) != 2 || got[0] != "HIGH" || got[1] != "CRITICAL" {
		t.Errorf("default Severity = %v, want [HIGH CRITICAL]", got)
	}
	if c.Docker.Socket != "/var/run/docker.sock" {
		t.Errorf("default Socket = %q", c.Docker.Socket)
	}
	if !c.Schedule.RunOnStart {
		t.Errorf("default RunOnStart = false, want true")
	}
	if c.Notify.Mode != "diff" {
		t.Errorf("default Mode = %q, want diff", c.Notify.Mode)
	}
	if c.Notify.FullReportDay != "monday" {
		t.Errorf("default FullReportDay = %q, want monday", c.Notify.FullReportDay)
	}
	if c.State.Path != "/var/lib/stackwatch/state.json" {
		t.Errorf("default State.Path = %q", c.State.Path)
	}
}

func TestParse_NotifyModeAndFullReportDay(t *testing.T) {
	c, err := Parse([]byte(`
notify:
  slack_webhook_url: "https://x.test"
  mode: "FULL"
  full_report_day: "Friday"
state:
  path: "/data/state.json"
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if c.Notify.Mode != "full" {
		t.Errorf("Mode = %q, want normalized full", c.Notify.Mode)
	}
	if day, ok := c.Notify.FullReportWeekday(); !ok || day.String() != "Friday" {
		t.Errorf("FullReportWeekday = %v ok=%v, want Friday true", day, ok)
	}
	if c.State.Path != "/data/state.json" {
		t.Errorf("State.Path = %q", c.State.Path)
	}
}

func TestParse_FullReportDayNever(t *testing.T) {
	c, err := Parse([]byte(`
notify:
  slack_webhook_url: "https://x.test"
  full_report_day: "never"
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if _, ok := c.Notify.FullReportWeekday(); ok {
		t.Error("never should disable the weekly full report")
	}
}

func TestParse_InvalidModeAndDay(t *testing.T) {
	if _, err := Parse([]byte("notify: { slack_webhook_url: \"https://x.test\", mode: \"delta\" }")); err == nil {
		t.Fatal("expected error for invalid notify.mode")
	}
	if _, err := Parse([]byte("notify: { slack_webhook_url: \"https://x.test\", full_report_day: \"noday\" }")); err == nil {
		t.Fatal("expected error for invalid notify.full_report_day")
	}
}

func TestParse_FullOverride(t *testing.T) {
	yaml := `
schedule:
  daily_at: "06:30"
  run_on_start: false
scan:
  severity: [CRITICAL]
notify:
  slack_webhook_url: "https://hooks.slack.test/x"
  generic_webhook_url: "https://example.test/hook"
  notify_on_clean: true
docker:
  socket: "/run/docker.sock"
`
	c, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if c.Schedule.DailyAt != "06:30" || c.Schedule.RunOnStart {
		t.Errorf("schedule = %+v", c.Schedule)
	}
	if len(c.Scan.Severity) != 1 || c.Scan.Severity[0] != "CRITICAL" {
		t.Errorf("severity = %v", c.Scan.Severity)
	}
	if !c.Notify.NotifyOnClean || c.Notify.GenericWebhookURL == "" {
		t.Errorf("notify = %+v", c.Notify)
	}
	if c.Docker.Socket != "/run/docker.sock" {
		t.Errorf("socket = %q", c.Docker.Socket)
	}
}

func TestParse_RequiresNotifyTarget(t *testing.T) {
	_, err := Parse([]byte(`scan: { severity: [HIGH] }`))
	if err == nil {
		t.Fatal("expected error when no notify target configured")
	}
	if !strings.Contains(err.Error(), "notify") {
		t.Errorf("error should mention notify target: %v", err)
	}
}

func TestParse_NormalizesSeverityCase(t *testing.T) {
	c, err := Parse([]byte(`
scan:
  severity: [high, Critical]
notify:
  slack_webhook_url: "https://x.test"
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if c.Scan.Severity[0] != "HIGH" || c.Scan.Severity[1] != "CRITICAL" {
		t.Errorf("severity not normalized: %v", c.Scan.Severity)
	}
}

func TestParse_InvalidSeverity(t *testing.T) {
	_, err := Parse([]byte(`
scan:
  severity: [HIGH, BOGUS]
notify:
  slack_webhook_url: "https://x.test"
`))
	if err == nil {
		t.Fatal("expected error for invalid severity")
	}
}

func TestParse_InvalidDailyAt(t *testing.T) {
	_, err := Parse([]byte(`
schedule:
  daily_at: "9am"
notify:
  slack_webhook_url: "https://x.test"
`))
	if err == nil {
		t.Fatal("expected error for malformed daily_at")
	}
}

func TestParse_BadYAML(t *testing.T) {
	if _, err := Parse([]byte("notify: [unclosed")); err == nil {
		t.Fatal("expected error for malformed YAML")
	}
}

func TestDailyTime(t *testing.T) {
	c, _ := Parse([]byte(`
schedule:
  daily_at: "06:30"
notify:
  slack_webhook_url: "https://x.test"
`))
	h, m, ok := c.Schedule.DailyTime()
	if !ok || h != 6 || m != 30 {
		t.Errorf("DailyTime = %d:%d ok=%v, want 6:30 true", h, m, ok)
	}

	noTime, _ := Parse([]byte(minimal))
	if _, _, ok := noTime.Schedule.DailyTime(); ok {
		t.Errorf("empty daily_at should yield ok=false")
	}
}
