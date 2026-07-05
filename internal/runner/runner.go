// Package runner wires the pipeline together: list running images, scan each,
// triage, and notify. It owns the once-per-cycle orchestration and the
// in-process scheduler (docs/ARCHITECTURE.md §2, ADR-003).
package runner

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/kitsunetrail/stackwatch/internal/analyze"
	"github.com/kitsunetrail/stackwatch/internal/config"
	"github.com/kitsunetrail/stackwatch/internal/notify"
	"github.com/kitsunetrail/stackwatch/internal/scanner"
	"github.com/kitsunetrail/stackwatch/internal/state"
)

// ImageLister enumerates running container images (implemented by docker.Client).
type ImageLister interface {
	RunningImages(ctx context.Context) ([]string, error)
}

// ImageScanner scans one image (implemented by scanner.Trivy).
type ImageScanner interface {
	Scan(ctx context.Context, image string) scanner.ImageScan
}

// Notifier delivers a message (implemented by notify.Notifier).
type Notifier interface {
	Send(ctx context.Context, m notify.Message) error
}

// StateStore persists scan state between cycles (implemented by state.FileStore).
type StateStore interface {
	Load() (state.State, error)
	Save(state.State) error
}

// Runner holds the collaborators for one scan cycle.
type Runner struct {
	Lister        ImageLister
	Scanner       ImageScanner
	Notifier      Notifier
	NotifyOnClean bool
	Store         StateStore   // nil = full mode (re-send everything each cycle)
	FullReportDay time.Weekday // diff mode: weekday of the full digest; NoFullReport disables
	Now           func() time.Time
	Log           *slog.Logger
}

// NoFullReport disables the weekly full report in diff mode.
const NoFullReport time.Weekday = -1

func (r Runner) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func (r Runner) log() *slog.Logger {
	if r.Log != nil {
		return r.Log
	}
	return slog.Default()
}

// RunOnce executes a single scan cycle. A failure to list images aborts the
// cycle; a failure to scan an individual image is captured in the report (so
// one bad image never sinks the run) and surfaced to the user.
func (r Runner) RunOnce(ctx context.Context) error {
	log := r.log()
	images, err := r.Lister.RunningImages(ctx)
	if err != nil {
		return fmt.Errorf("list running images: %w", err)
	}
	log.Info("scanning images", "count", len(images))

	scans := make([]scanner.ImageScan, 0, len(images))
	for _, img := range images {
		scan := r.Scanner.Scan(ctx, img)
		if scan.Err != nil {
			log.Warn("image scan failed", "image", img, "err", scan.Err)
		}
		scans = append(scans, scan)
	}

	report := analyze.Build(scans, r.now())
	if r.Store == nil {
		return r.sendFull(ctx, report)
	}
	return r.sendDiff(ctx, report)
}

// sendFull is the stateless full mode: re-send everything whenever there is
// anything to say.
func (r Runner) sendFull(ctx context.Context, report analyze.Report) error {
	log := r.log()
	if !report.HasIssues() && !r.NotifyOnClean {
		log.Info("no issues found; skipping notification")
		return nil
	}
	if err := r.Notifier.Send(ctx, notify.Message{Report: report}); err != nil {
		return fmt.Errorf("send notification: %w", err)
	}
	log.Info("notification sent",
		"affected", report.AffectedImageCount(),
		"eosl", len(report.EOSLImages),
		"scan_errors", len(report.ScanErrors))
	return nil
}

// sendDiff is diff mode: notify what changed since the previous scan, send a
// one-line heartbeat while findings stay open (so silence always means "all
// clear", never "the scanner died"), and stay quiet on clean-and-unchanged
// unless NotifyOnClean. State is saved only after a successful (or skipped)
// delivery, so a failed send is re-reported as new next cycle instead of lost.
func (r Runner) sendDiff(ctx context.Context, report analyze.Report) error {
	log := r.log()
	prev, err := r.Store.Load()
	if err != nil {
		// Corrupt state: fall back to re-reporting everything as new rather
		// than failing the cycle or silently dropping history.
		log.Warn("load state failed; treating all findings as new", "err", err)
	}
	diff, next := state.Compute(prev, report)

	fullToday := r.FullReportDay != NoFullReport && r.now().Weekday() == r.FullReportDay
	send := report.HasIssues() || diff.HasChanges() || r.NotifyOnClean
	if !send {
		log.Info("no issues and no changes; skipping notification")
		return r.saveState(next)
	}

	m := notify.Message{Report: report, Diff: &diff, FullReport: fullToday}
	if err := r.Notifier.Send(ctx, m); err != nil {
		return fmt.Errorf("send notification: %w", err)
	}
	log.Info("notification sent",
		"new", len(diff.Changes),
		"resolved", len(diff.Resolved),
		"open_critical", diff.OpenCritical,
		"open_high", diff.OpenHigh,
		"full_report", fullToday,
		"scan_errors", len(report.ScanErrors))
	return r.saveState(next)
}

// saveState persists the next state. Failure is surfaced (some changes may be
// re-announced next cycle) but has already been preceded by a successful send.
func (r Runner) saveState(next state.State) error {
	if err := r.Store.Save(next); err != nil {
		return fmt.Errorf("save state: %w", err)
	}
	return nil
}

// Loop runs RunOnce on the schedule until ctx is cancelled. A cycle error is
// logged but does not stop the loop, so a transient failure (e.g. Slack down)
// doesn't kill the agent.
func (r Runner) Loop(ctx context.Context, sched config.ScheduleConfig) error {
	log := r.log()
	if sched.RunOnStart {
		if err := r.RunOnce(ctx); err != nil {
			log.Error("initial scan cycle failed", "err", err)
		}
	}
	for {
		wait := untilNext(sched, r.now())
		log.Info("next scan scheduled", "in", wait.Round(time.Second).String())
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
			if err := r.RunOnce(ctx); err != nil {
				log.Error("scan cycle failed", "err", err)
			}
		}
	}
}

// untilNext computes the wait until the next run: to the daily wall-clock time
// if configured, otherwise a fixed 24h interval.
func untilNext(sched config.ScheduleConfig, now time.Time) time.Duration {
	if hour, min, ok := sched.DailyTime(); ok {
		return nextDaily(now, hour, min).Sub(now)
	}
	return 24 * time.Hour
}

// nextDaily returns the next occurrence of hour:min strictly after now.
func nextDaily(now time.Time, hour, min int) time.Time {
	next := time.Date(now.Year(), now.Month(), now.Day(), hour, min, 0, 0, now.Location())
	if !next.After(now) {
		next = next.AddDate(0, 0, 1)
	}
	return next
}
