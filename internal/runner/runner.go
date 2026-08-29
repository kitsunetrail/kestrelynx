// Package runner wires the pipeline together: list running images, scan each,
// triage, and notify. It owns the once-per-cycle orchestration and the
// in-process scheduler (docs/ARCHITECTURE.md §2, ADR-003).
package runner

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/analyze"
	"github.com/kitsunetrail/kestrelynx/internal/config"
	"github.com/kitsunetrail/kestrelynx/internal/intel"
	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/notify"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
	"github.com/kitsunetrail/kestrelynx/internal/state"
)

// ContainerLister enumerates running containers (implemented by docker.Client).
type ContainerLister interface {
	RunningContainers(ctx context.Context) ([]inventory.Container, error)
}

// ImageScanner scans one image target (implemented by scanner.Trivy).
type ImageScanner interface {
	Scan(ctx context.Context, target scanner.ScanTarget) scanner.ImageScan
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

// IntelSource supplies exploitation intel for the triage layer (implemented by
// intel.Source). Discussions is only consulted for act-now CVEs and only when
// discussion links are enabled.
type IntelSource interface {
	Lookup(ctx context.Context, ids []string) (map[string]intel.Enrichment, intel.Freshness, error)
	Discussions(ctx context.Context, ids []string) map[string]intel.Discussion
}

// Runner holds the collaborators for one scan cycle.
type Runner struct {
	Lister          ContainerLister
	Scanner         ImageScanner
	Notifier        Notifier
	NotifyOnClean   bool
	Store           StateStore   // nil = full mode (re-send everything each cycle)
	FullReportDay   time.Weekday // diff mode: weekday of the full digest; NoFullReport disables
	Intel           IntelSource  // nil = triage off (Phase 1 severity-only output)
	ActNowEPSS      float64      // triage thresholds (config.Triage)
	WatchEPSS       float64
	DiscussionLinks bool // look up HN discussions for act-now CVEs
	// Environment identifies the runtime instance this Runner scans. It is
	// stamped onto every Report (RunOnce) and, via cmd/kestrelynx wiring,
	// shares its Name with the StateStore so state and notifications agree
	// on which environment they describe. The zero value is the unnamed
	// default environment.
	Environment inventory.Environment
	Now         func() time.Time
	Log         *slog.Logger
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
	containers, err := r.Lister.RunningContainers(ctx)
	if err != nil {
		return fmt.Errorf("list running containers: %w", err)
	}
	images := inventory.DistinctImages(containers)
	log.Info("scanning images", "count", len(images))

	scans := r.scanAll(ctx, images)

	report := analyze.Build(scans, containers, r.triage(ctx, scans), r.now())
	report.Environment = r.Environment
	if r.Store == nil {
		return r.sendFull(ctx, report)
	}
	return r.sendDiff(ctx, report)
}

// scanAll scans every running image, de-duplicating on the boundary-validated
// ContentID: the same content running under several references is scanned
// once and the result is replicated to each alias reference. Images whose
// ContentID did not resolve are scanned individually by reference and never
// join the ContentID de-duplication (they already can't collide there, since
// inventory.DistinctImages itself de-duplicates on (Ref, ContentID)).
func (r Runner) scanAll(ctx context.Context, images []inventory.RunningImage) []scanner.ImageScan {
	log := r.log()
	scans := make([]scanner.ImageScan, 0, len(images))
	byContentID := map[string]scanner.ImageScan{}

	for _, img := range images {
		if img.ContentID == "" {
			result := r.Scanner.Scan(ctx, scanner.ScanTarget{Ref: img.Ref})
			if result.Err != nil {
				log.Warn("image scan failed", "image", img.Ref, "resolved", false, "err", result.Err)
			}
			log.Info("scanned image", "ref", img.Ref, "resolved", false)
			scans = append(scans, result)
			continue
		}

		result, ok := byContentID[img.ContentID]
		if !ok {
			result = r.Scanner.Scan(ctx, scanner.ScanTarget{Ref: img.Ref, ContentID: img.ContentID})
			if result.Err != nil {
				log.Warn("image scan failed", "image", img.Ref, "content_id", img.ContentID, "resolved", true, "err", result.Err)
			}
			byContentID[img.ContentID] = result
		}
		log.Info("scanned image", "ref", img.Ref, "content_id", img.ContentID, "resolved", true)
		scans = append(scans, retarget(result, img.Ref))
	}
	return scans
}

// retarget deep-copies scan and relabels it for ref. A ContentID-pinned scan
// result is shared across every alias reference running the same content, so
// each alias must get its own Findings slice — mutating one ref's copy must
// never reach another's.
func retarget(scan scanner.ImageScan, ref string) scanner.ImageScan {
	out := scan
	out.Image = ref
	if scan.Findings != nil {
		out.Findings = make([]scanner.Finding, len(scan.Findings))
		for i, f := range scan.Findings {
			f.Image = ref
			out.Findings[i] = f
		}
	}
	if scan.RegistryDigests != nil {
		out.RegistryDigests = append([]string(nil), scan.RegistryDigests...)
	}
	return out
}

// triage looks up exploitation intel for every vulnerability the scans found
// and assembles the triage input for analyze.Build. Intel failures never fail
// the cycle: the triage degrades (and says so in the notification) while the
// scan and delivery proceed (docs/TRIAGE_SPEC.md §3).
func (r Runner) triage(ctx context.Context, scans []scanner.ImageScan) analyze.Triage {
	if r.Intel == nil {
		return analyze.Triage{}
	}
	log := r.log()

	seen := map[string]bool{}
	ids := []string{}
	for _, s := range scans {
		for _, f := range s.Findings {
			if !seen[f.VulnID] {
				seen[f.VulnID] = true
				ids = append(ids, f.VulnID)
			}
		}
	}

	enrich, fresh, err := r.Intel.Lookup(ctx, ids)
	if err != nil {
		log.Warn("intel lookup incomplete", "err", err)
	}
	if fresh.Degraded() {
		log.Warn("vulnerability intel unavailable; falling back to severity-only triage")
	}

	converted := make(map[string]analyze.Enrichment, len(enrich))
	for id, e := range enrich {
		converted[id] = analyze.Enrichment(e)
	}
	tr := analyze.Triage{
		Enabled:    true,
		ActNowEPSS: r.ActNowEPSS,
		WatchEPSS:  r.WatchEPSS,
		Enrich:     converted,
		Intel:      analyze.IntelStatus{KEVOK: fresh.KEVOK, EPSSOK: fresh.EPSSOK, StaleDays: fresh.StaleDays},
	}
	tr.Refs = r.discussionRefs(ctx, tr)
	return tr
}

// discussionRefs collects HN discussion links for the CVEs whose intel already
// signals act_now. Only those IDs are ever sent as search queries (the
// documented exception to "nothing leaves the host" — a handful of world-famous
// CVEs, and only with DiscussionLinks on). Degraded intel means no act-now
// signals to trust, so nothing is queried.
func (r Runner) discussionRefs(ctx context.Context, tr analyze.Triage) map[string][]analyze.Ref {
	if !r.DiscussionLinks || tr.Intel.Degraded() {
		return nil
	}
	var ids []string
	for id, e := range tr.Enrich {
		if tr.SignalsActNow(e) {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return nil
	}
	sort.Strings(ids) // deterministic query order

	refs := map[string][]analyze.Ref{}
	for id, d := range r.Intel.Discussions(ctx, ids) {
		refs[id] = []analyze.Ref{{
			Kind:  "discussion",
			Label: fmt.Sprintf("HN (%d pts)", d.Points),
			URL:   d.URL,
		}}
	}
	return refs
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
	// The last-full-report ref carries over verbatim unless this cycle posts a
	// fresh thread: a failed (or skipped) post must keep the old link alive.
	next.LastFullReport = prev.LastFullReport

	fullToday := r.FullReportDay != NoFullReport && r.now().Weekday() == r.FullReportDay
	send := report.HasIssues() || diff.HasChanges() || r.NotifyOnClean
	if !send {
		log.Info("no issues and no changes; skipping notification")
		return r.saveState(next)
	}

	res := &notify.ThreadResult{}
	m := notify.Message{
		Report:     report,
		Diff:       &diff,
		FullReport: fullToday,
		// The thread mirrors the channel: post the full state when something
		// changed (or on the weekly digest day); on quiet days the summary
		// links to the previous thread instead.
		Thread:     diff.HasChanges() || fullToday,
		FirstSeen:  next.FirstSeen,
		LastReport: prev.LastFullReport,
		Result:     res,
	}
	if err := r.Notifier.Send(ctx, m); err != nil {
		return fmt.Errorf("send notification: %w", err)
	}
	if res.Ref.TS != "" {
		ref := res.Ref
		next.LastFullReport = &ref
	}
	log.Info("notification sent",
		"new", len(diff.Changes),
		"resolved", len(diff.Resolved),
		"open_critical", diff.OpenCritical,
		"open_high", diff.OpenHigh,
		"full_report", fullToday,
		"thread_report", res.Ref.TS != "",
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
