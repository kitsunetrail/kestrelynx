// Package config loads and validates StackWatch's single YAML config file
// (docs/ARCHITECTURE.md §5). Parsing applies defaults so a minimal file — just
// one notify target — is enough to run.
package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the validated runtime configuration.
type Config struct {
	Schedule ScheduleConfig
	Scan     ScanConfig
	Notify   NotifyConfig
	Docker   DockerConfig
	State    StateConfig
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
	SlackWebhookURL   string
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
}

const (
	defaultSocket        = "/var/run/docker.sock"
	defaultStatePath     = "/var/lib/stackwatch/state.json"
	defaultFullReportDay = "monday"
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
	if c.Notify.SlackWebhookURL == "" && c.Notify.GenericWebhookURL == "" {
		return fmt.Errorf("config: at least one notify target (slack_webhook_url or generic_webhook_url) is required")
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
	return nil
}

func boolOr(p *bool, def bool) bool {
	if p != nil {
		return *p
	}
	return def
}
