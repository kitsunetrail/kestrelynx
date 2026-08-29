// Package config loads and validates KestreLynx's single YAML config file
// (docs/ARCHITECTURE.md §5). Parsing applies defaults so a minimal file — just
// one notify target — is enough to run.
package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"gopkg.in/yaml.v3"
)

// Config is the validated runtime configuration.
type Config struct {
	Schedule    ScheduleConfig
	Scan        ScanConfig
	Notify      NotifyConfig
	Docker      DockerConfig
	State       StateConfig
	Triage      TriageConfig
	Environment EnvironmentConfig
}

// EnvironmentConfig names the environment this instance is watching
// (docs/development/environment-workload-model.md). Name is the only
// user-facing key; Kind is not configurable — it's set by the composition
// root to match whichever Runtime Adapter it wired up.
type EnvironmentConfig struct {
	Name string // "" = the unnamed default environment; current single-host behavior, unchanged.
}

type ScheduleConfig struct {
	DailyAt    string // "HH:MM" local time; empty means run every 24h from start
	RunOnStart bool   // run one scan immediately on startup
}

// DailyTime parses DailyAt into hour and minute. ok is false when DailyAt is
// empty (i.e. interval mode rather than wall-clock mode).
func (s ScheduleConfig) DailyTime() (hour, min int, ok bool) {
	if s.DailyAt == "" {
		return 0, 0, false
	}
	t, err := time.Parse("15:04", s.DailyAt)
	if err != nil {
		return 0, 0, false
	}
	return t.Hour(), t.Minute(), true
}

type ScanConfig struct {
	Severity []string // Trivy severities to report, e.g. HIGH, CRITICAL
}

type NotifyConfig struct {
	SlackWebhookURL string
	// Slack Web API delivery: a bot token (chat:write) plus destination
	// channel. Replaces the webhook and additionally posts the full report to
	// the summary's thread.
	SlackBotToken     string
	SlackChannel      string
	GenericWebhookURL string
	NotifyOnClean     bool   // also notify when nothing was found
	Mode              string // "diff" (default) or "full"
	FullReportDay     string // diff mode: weekday of the weekly full report; "never" disables
}

// FullReportWeekday parses FullReportDay into a time.Weekday. ok is false when
// the weekly full report is disabled ("never").
func (n NotifyConfig) FullReportWeekday() (time.Weekday, bool) {
	day, ok := weekdays[strings.ToLower(n.FullReportDay)]
	return day, ok
}

type DockerConfig struct {
	Socket string
}

type StateConfig struct {
	Path string // where diff-mode scan state is persisted
}

// TriageConfig controls the Phase 1+ triage layer (docs/TRIAGE_SPEC.md §7).
// Disabling it also stops the KEV/EPSS feed downloads — the explicit way out
// for users who don't want the extra egress.
type TriageConfig struct {
	Enabled    bool
	ActNowEPSS float64 // EPSS probability at or above which a CVE is act_now
	WatchEPSS  float64 // EPSS probability at or above which a CVE is at least watch
	KEVURL     string  // override for air-gapped mirrors; empty = CISA
	EPSSURL    string  // override for air-gapped mirrors; empty = FIRST/Empirical Security
	// DiscussionLinks looks up the HN discussion for act-now CVEs. Unlike the
	// bulk feeds this sends those CVE IDs (only) as search queries; off = zero
	// CVE egress (docs/TRIAGE_SPEC.md §8).
	DiscussionLinks bool
}

// rawConfig mirrors the YAML shape. Pointers are used where "absent" must be
// distinguished from a zero value (booleans whose default is true).
type rawConfig struct {
	Schedule struct {
		DailyAt    string `yaml:"daily_at"`
		RunOnStart *bool  `yaml:"run_on_start"`
	} `yaml:"schedule"`
	Scan struct {
		Severity []string `yaml:"severity"`
	} `yaml:"scan"`
	Notify struct {
		SlackWebhookURL   string `yaml:"slack_webhook_url"`
		SlackBotToken     string `yaml:"slack_bot_token"`
		SlackChannel      string `yaml:"slack_channel"`
		GenericWebhookURL string `yaml:"generic_webhook_url"`
		NotifyOnClean     bool   `yaml:"notify_on_clean"`
		Mode              string `yaml:"mode"`
		FullReportDay     string `yaml:"full_report_day"`
	} `yaml:"notify"`
	Docker struct {
		Socket string `yaml:"socket"`
	} `yaml:"docker"`
	State struct {
		Path string `yaml:"path"`
	} `yaml:"state"`
	Triage struct {
		Enabled         *bool    `yaml:"enabled"`
		ActNowEPSS      *float64 `yaml:"act_now_epss"`
		WatchEPSS       *float64 `yaml:"watch_epss"`
		KEVURL          string   `yaml:"kev_url"`
		EPSSURL         string   `yaml:"epss_url"`
		DiscussionLinks *bool    `yaml:"discussion_links"`
	} `yaml:"triage"`
	Environment struct {
		Name string `yaml:"name"`
	} `yaml:"environment"`
}

const (
	defaultSocket        = "/var/run/docker.sock"
	defaultStatePath     = "/var/lib/kestrelynx/state.json"
	defaultFullReportDay = "monday"
	// Default EPSS thresholds (docs/TRIAGE_SPEC.md §4): 10% predicted
	// exploitation probability is act_now territory, 1% is worth watching.
	defaultActNowEPSS = 0.10
	defaultWatchEPSS  = 0.01
)

var validSeverities = map[string]bool{
	"UNKNOWN": true, "LOW": true, "MEDIUM": true, "HIGH": true, "CRITICAL": true,
}

var weekdays = map[string]time.Weekday{
	"sunday": time.Sunday, "monday": time.Monday, "tuesday": time.Tuesday,
	"wednesday": time.Wednesday, "thursday": time.Thursday,
	"friday": time.Friday, "saturday": time.Saturday,
}

// Load reads and parses the config file at path.
func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config %s: %w", path, err)
	}
	return Parse(data)
}

// Parse parses YAML bytes, applies defaults, and validates.
func Parse(data []byte) (Config, error) {
	var raw rawConfig
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&raw); err != nil {
		return Config{}, fmt.Errorf("parse config: %w", err)
	}

	c := Config{
		Schedule: ScheduleConfig{
			DailyAt:    raw.Schedule.DailyAt,
			RunOnStart: boolOr(raw.Schedule.RunOnStart, true),
		},
		Scan:   ScanConfig{Severity: raw.Scan.Severity},
		Notify: NotifyConfig(raw.Notify),
		Docker: DockerConfig{Socket: raw.Docker.Socket},
		State:  StateConfig{Path: raw.State.Path},
		Triage: TriageConfig{
			Enabled:         boolOr(raw.Triage.Enabled, true),
			ActNowEPSS:      floatOr(raw.Triage.ActNowEPSS, defaultActNowEPSS),
			WatchEPSS:       floatOr(raw.Triage.WatchEPSS, defaultWatchEPSS),
			KEVURL:          raw.Triage.KEVURL,
			EPSSURL:         raw.Triage.EPSSURL,
			DiscussionLinks: boolOr(raw.Triage.DiscussionLinks, true),
		},
		Environment: EnvironmentConfig{Name: raw.Environment.Name},
	}

	applyDefaults(&c)
	if err := validate(&c); err != nil {
		return Config{}, err
	}
	return c, nil
}

func applyDefaults(c *Config) {
	// schedule.daily_at intentionally has no default: empty means interval mode
	// (run every 24h from start), per docs/ARCHITECTURE.md §5.
	if len(c.Scan.Severity) == 0 {
		c.Scan.Severity = []string{"HIGH", "CRITICAL"}
	}
	if c.Docker.Socket == "" {
		c.Docker.Socket = defaultSocket
	}
	if c.Notify.Mode == "" {
		c.Notify.Mode = "diff"
	}
	if c.Notify.FullReportDay == "" {
		c.Notify.FullReportDay = defaultFullReportDay
	}
	if c.State.Path == "" {
		c.State.Path = defaultStatePath
	}
}

func validate(c *Config) error {
	if (c.Notify.SlackBotToken == "") != (c.Notify.SlackChannel == "") {
		return fmt.Errorf("config: slack_bot_token and slack_channel must be set together")
	}
	if c.Notify.SlackBotToken != "" && c.Notify.SlackWebhookURL != "" {
		return fmt.Errorf("config: configure either slack_webhook_url or slack_bot_token, not both")
	}
	if c.Notify.SlackWebhookURL == "" && c.Notify.SlackBotToken == "" && c.Notify.GenericWebhookURL == "" {
		return fmt.Errorf("config: at least one notify target (slack_webhook_url, slack_bot_token, or generic_webhook_url) is required")
	}
	for i, s := range c.Scan.Severity {
		up := strings.ToUpper(strings.TrimSpace(s))
		if !validSeverities[up] {
			return fmt.Errorf("config: invalid scan.severity %q (allowed: UNKNOWN, LOW, MEDIUM, HIGH, CRITICAL)", s)
		}
		c.Scan.Severity[i] = up
	}
	// Empty daily_at is valid (interval mode). Only a non-empty, unparseable
	// value is an error.
	if _, _, ok := c.Schedule.DailyTime(); !ok && c.Schedule.DailyAt != "" {
		return fmt.Errorf("config: schedule.daily_at %q is not a valid HH:MM time", c.Schedule.DailyAt)
	}
	m := strings.ToLower(c.Notify.Mode)
	if m != "diff" && m != "full" {
		return fmt.Errorf("config: invalid notify.mode %q (allowed: diff, full)", c.Notify.Mode)
	}
	c.Notify.Mode = m
	if day := strings.ToLower(c.Notify.FullReportDay); day != "never" {
		if _, ok := weekdays[day]; !ok {
			return fmt.Errorf("config: invalid notify.full_report_day %q (a weekday name or \"never\")", c.Notify.FullReportDay)
		}
	}
	if c.Triage.Enabled {
		if c.Triage.WatchEPSS <= 0 || c.Triage.WatchEPSS > c.Triage.ActNowEPSS || c.Triage.ActNowEPSS > 1 {
			return fmt.Errorf("config: triage thresholds must satisfy 0 < watch_epss (%v) <= act_now_epss (%v) <= 1", c.Triage.WatchEPSS, c.Triage.ActNowEPSS)
		}
	}
	if err := inventory.ValidateEnvironmentName(c.Environment.Name); err != nil {
		return fmt.Errorf("config: environment.name: %w", err)
	}
	return nil
}

func boolOr(p *bool, def bool) bool {
	if p != nil {
		return *p
	}
	return def
}

func floatOr(p *float64, def float64) float64 {
	if p != nil {
		return *p
	}
	return def
}
