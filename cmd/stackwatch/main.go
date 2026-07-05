// Command stackwatch scans the host's running container images for HIGH/CRITICAL
// vulnerabilities and notifies Slack/webhook on a schedule. See docs/ for the
// full design.
package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/kitsunetrail/stackwatch/internal/config"
	"github.com/kitsunetrail/stackwatch/internal/docker"
	"github.com/kitsunetrail/stackwatch/internal/notify"
	"github.com/kitsunetrail/stackwatch/internal/runner"
	"github.com/kitsunetrail/stackwatch/internal/scanner"
	"github.com/kitsunetrail/stackwatch/internal/state"
)

func main() {
	configPath := flag.String("config", "/etc/stackwatch/config.yml", "path to config file")
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stdout, nil))

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Error("load config", "err", err)
		os.Exit(1)
	}

	notifier := buildNotifier(cfg.Notify)
	if notifier == nil {
		log.Error("no notify target configured")
		os.Exit(1)
	}

	r := runner.Runner{
		Lister:        docker.New(cfg.Docker.Socket),
		Scanner:       scanner.Trivy{Severity: cfg.Scan.Severity},
		Notifier:      notifier,
		NotifyOnClean: cfg.Notify.NotifyOnClean,
		FullReportDay: runner.NoFullReport,
		Now:           time.Now,
		Log:           log,
	}
	if cfg.Notify.Mode == "diff" {
		r.Store = state.FileStore{Path: cfg.State.Path}
		if day, ok := cfg.Notify.FullReportWeekday(); ok {
			r.FullReportDay = day
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log.Info("stackwatch started",
		"daily_at", cfg.Schedule.DailyAt,
		"run_on_start", cfg.Schedule.RunOnStart,
		"severity", cfg.Scan.Severity,
		"mode", cfg.Notify.Mode,
		"full_report_day", cfg.Notify.FullReportDay)

	if err := r.Loop(ctx, cfg.Schedule); err != nil && !errors.Is(err, context.Canceled) {
		log.Error("runner loop", "err", err)
		os.Exit(1)
	}
	log.Info("stackwatch stopped")
}

// buildNotifier assembles the configured notify targets into one Notifier.
func buildNotifier(c config.NotifyConfig) runner.Notifier {
	var notifiers []notify.Notifier
	if c.SlackWebhookURL != "" {
		notifiers = append(notifiers, notify.SlackNotifier{WebhookURL: c.SlackWebhookURL})
	}
	if c.GenericWebhookURL != "" {
		notifiers = append(notifiers, notify.WebhookNotifier{URL: c.GenericWebhookURL})
	}
	if len(notifiers) == 0 {
		return nil
	}
	return notify.Multi(notifiers...)
}
