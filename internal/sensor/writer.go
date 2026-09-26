package sensor

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/kitsunetrail/kestrelynx/internal/evidence"
)

// writeReport is the writer goroutine's answer to one snapshot it wrote (or
// failed to write): whether the write itself succeeded, whether
// enforceWriteLimits had to drop or trim anything to fit the reader's own
// limits — loop folds modified into the next status it reports
// (SensorDegraded), since a snapshot that needed trimming means some
// evidence this Sensor accumulated could not all be kept — and
// consecutiveFailures, runWriter's own running count of how many writes in
// a row have now failed, up to and including this one (0 if this one
// succeeded).
//
// consecutiveFailures exists because loop can never safely count this
// itself from how many failure reports it happens to receive:
// submitSnapshot's own single-slot "latest wins" coalescing (see its own
// doc comment) means an ordinary report loop has not yet read can be
// silently replaced by a newer one before loop ever sees it — three
// genuinely consecutive failures could reach loop as a single report if
// loop was slow to drain reportCh in between, and a success sandwiched
// between two failures could vanish the same way, making two unrelated
// failures look adjacent. runWriter itself never has this problem: it
// processes every job in strict order, one at a time, so it is the only
// goroutine that can correctly count a genuine streak — loop just copies
// whatever value the latest report carries.
type writeReport struct {
	err                 error
	modified            bool
	consecutiveFailures int
}

// writerJob is one snapshot submitted to the writer goroutine. done is nil
// for an ordinary, fire-and-forget submission (its outcome goes to
// runWriter's own reportCh instead, for loop's own degraded-status
// bookkeeping — see runWriter's own doc comment for why that send is itself
// a non-blocking, single-slot "latest wins" send, never able to stall this
// goroutine); non-nil only for submitFinalSnapshot's own use, where the
// caller blocks on it to know the exact write it asked for has actually
// completed (see writeFinalSnapshotAndWait's own doc comment for why that
// matters, and why a final write's own outcome is never routed through
// reportCh instead: nothing may be left reading reportCh once a Sensor
// session is ending, so only a dedicated, per-call channel can guarantee
// this specific outcome is ever actually delivered).
type writerJob struct {
	snap evidence.Snapshot
	done chan<- writeReport
}

// submitSnapshot hands snap to the writer goroutine over ch, replacing
// whatever job (if any) is already queued there rather than blocking: ch
// always has capacity 1, and only loop ever sends to it, so a job still
// sitting there unread is necessarily stale (a newer sample already
// happened) by the time loop has another one ready. This is what keeps a
// slow write from ever making loop block, and from making the writer
// goroutine work through a backlog of outdated snapshots once it catches
// up — it only ever sees the latest. Never used for a job carrying a done
// channel — see submitFinalSnapshot for that.
func submitSnapshot(ch chan writerJob, snap evidence.Snapshot) {
	select {
	case <-ch:
	default:
	}
	ch <- writerJob{snap: snap}
}

// submitFinalSnapshot hands snap to the writer goroutine the same way
// submitSnapshot does, but attaches a done channel and blocks until the
// writer goroutine actually reports this exact job's own outcome on it,
// returning that outcome. It is safe against the same coalescing that
// makes submitSnapshot's "replace whatever is already queued" behavior
// correct for an ordinary write: only loop's own single goroutine ever
// calls either function, and it does so sequentially, so nothing can race
// this submission with a later one of its own and have the writer discard
// this one, still-unprocessed, before ever reading it — see
// writeFinalSnapshotAndWait's own doc comment.
func submitFinalSnapshot(ch chan writerJob, snap evidence.Snapshot) writeReport {
	select {
	case <-ch:
	default:
	}
	done := make(chan writeReport, 1)
	ch <- writerJob{snap: snap, done: done}
	return <-done
}

// runWriter is the whole body of the writer goroutine: the sole owner of
// the evidence file descriptor for this Sensor session's whole lifetime. It
// applies enforceWriteLimits to every snapshot immediately before writing
// it — proactively fitting the reader's own limits rather than leaving that
// to chance — and reports the outcome of each write, either to reportCh (an
// ordinary submission) or to that job's own done channel (see writerJob's
// own doc comment). A write failure is logged to stderr (fd 2, inherited
// before this process's own seccomp filter was installed and never itself
// write-restricted by that filter, unlike every openat/open/creat path —
// see docker-compose.sensor.yml's own notes on the observer's write-fd
// discipline) on a best-effort basis: whether or not that log line actually
// reaches anywhere, the report's own err field is what loop's
// degraded-status decision actually depends on.
func runWriter(evidenceFD int, jobCh <-chan writerJob, reportCh chan writeReport) {
	// consecutiveFailures is local to this goroutine, which is the only one
	// that ever processes a write and can see every single one of them, in
	// order — see writeReport.consecutiveFailures' own doc comment for why
	// loop itself cannot safely keep this count.
	var consecutiveFailures int
	for job := range jobCh {
		gens, modified := enforceWriteLimits(job.snap.Generations)
		job.snap.Generations = gens
		err := evidence.WriteFD(evidenceFD, job.snap)
		if err != nil {
			fmt.Fprintf(os.Stderr, "kestrelynx sensor: write evidence: %v\n", err)
			consecutiveFailures++
		} else {
			consecutiveFailures = 0
		}
		rep := writeReport{err: err, modified: modified, consecutiveFailures: consecutiveFailures}
		if job.done != nil {
			job.done <- rep
			continue
		}
		// Never blocks: reportCh is a single-slot "latest wins" channel on
		// this send side too, the same way jobCh/writerCh already are on
		// loop's own submission side (see submitSnapshot's own doc
		// comment) — an ordinary report loop has not yet read is
		// necessarily stale by the time a newer one is ready. This
		// goroutine must never be stuck unable to move on to its next job
		// merely because loop has stopped draining reportCh for a while —
		// in particular, while loop is itself blocked waiting on a later
		// job's own done channel (submitFinalSnapshot): a blocking send
		// here, with reportCh's buffer already holding one undrained
		// report, would leave this goroutine unable to ever reach that
		// later job at all, and loop unable to ever reach the report that
		// would unblock it — the exact deadlock this non-blocking send
		// exists to avoid.
		select {
		case <-reportCh:
		default:
		}
		reportCh <- rep
	}
}

// mirrorMaxGenerations, mirrorMaxEntitiesPerGeneration and
// mirrorMaxFileBytes mirror evidence's own snapshot limits (unexported
// there, since only its own Reader needs them for validation) the same way
// maxProcessObservations already mirrors maxObservationsPerEntity in
// generation.go — so a snapshot this Sensor writes is enforced against the
// same limits proactively, rather than left depending on the reader's own
// leniency to come back readable at all. writeSizeMargin leaves room, below
// mirrorMaxFileBytes, for the small, roughly-fixed cost of SensorInfo and
// the trailer line the byte-budget check below does not itself account for
// (it measures only the marshaled Generations slice).
const (
	mirrorMaxGenerations           = 5000
	mirrorMaxEntitiesPerGeneration = 50000
	mirrorMaxFileBytes             = 64 << 20
	writeSizeMargin                = 64 << 10
	// maxNoFileListPerGeneration bounds PackageDB.NoFileList — a field
	// entity-trimming never touches (it is not one of
	// OSPackages/Unavailable/Executables), enforced instead where it is
	// populated (applyBuildResult) so a database with an extraordinary
	// number of file-list-less packages cannot make this one field alone
	// threaten the byte budget on its own.
	maxNoFileListPerGeneration = 5000
)

// enforceWriteLimits returns gens trimmed to fit evidence's own read
// contract, always in this order:
//
//  1. Trim any single generation whose own combined OSPackages/Unavailable/
//     Executables count already exceeds mirrorMaxEntitiesPerGeneration on
//     its own — Executables first, then Unavailable, then OSPackages —
//     marking it Truncated. This catches a generation with many small
//     entities on its own terms, independent of the whole snapshot's own
//     byte size (step 3 below would not otherwise notice it: many small
//     entities can total fewer bytes than the size budget while still
//     exceeding the reader's own per-generation count limit).
//  2. Drop StateEnded generations, oldest EndedAt first, until at or under
//     mirrorMaxGenerations or none remain to drop — a generation still
//     running has nothing less relevant to drop in its place. If still
//     over mirrorMaxGenerations (every remaining generation is live), drop
//     the newest-started live ones instead: there is nothing "less
//     relevant" left to sacrifice by StateEnded's own logic, and a
//     generation that started most recently has had the least time to
//     accumulate evidence worth keeping.
//  3. If the marshaled result would still exceed mirrorMaxFileBytes minus
//     writeSizeMargin, trim entities from whichever generation currently
//     holds the most of them — same removal order as step 1 — until it
//     fits or nothing is left to trim.
//
// Steps 1 and 3 are both guaranteed to terminate: step 1 removes exactly
// the known overage from one already-identified generation (a bounded
// count); step 3's loop removes at least one entity from the generation
// currently holding the most, every time it does not already fit (see
// trimToByteBudget/trimGenerationBySize), so the total entity count across
// every generation strictly decreases every time, bounded below by zero.
//
// modified reports whether anything was dropped or trimmed at all — loop's
// own signal to report SensorDegraded for this sample, since it means some
// evidence this Sensor accumulated could not all be kept in this write.
func enforceWriteLimits(gens []evidence.Generation) (result []evidence.Generation, modified bool) {
	for i := range gens {
		if trimGenerationEntityCount(&gens[i], mirrorMaxEntitiesPerGeneration) {
			modified = true
		}
	}

	for len(gens) > mirrorMaxGenerations {
		if !dropOldestEnded(&gens) {
			break
		}
		modified = true
	}
	for len(gens) > mirrorMaxGenerations {
		if !dropNewestLive(&gens) {
			break
		}
		modified = true
	}

	if trimToByteBudget(&gens, mirrorMaxFileBytes-writeSizeMargin) {
		modified = true
	}

	return gens, modified
}

// trimToByteBudget is step 3 of enforceWriteLimits: if the marshaled result
// would exceed budget, first trim entities from whichever generation
// currently holds the most of them (Executables first, then Unavailable,
// then OSPackages), marking it Truncated; once every generation's own
// entities are already exhausted and the snapshot is still over budget —
// meaning the remaining size lives in fields entity-trimming never touches
// (PackageDB.NoFileList, ParseFailed, or simply many generations each with
// a little of everything left over) — fall back to omitting whole
// generations outright, oldest-ended first and then newest-live, the same
// priority enforceWriteLimits' own generation-count cap already uses. It
// reports whether it changed anything.
//
// Unlike marshaling the whole gens slice on every entity removed (which
// this function deliberately avoids — repeatedly re-encoding everything,
// including every generation not being touched, does not scale to many
// generations or many entities), each generation's own encoded size is
// measured once per outer pass and then adjusted incrementally within a
// pass: only the one generation actually being trimmed in a given
// iteration is re-marshaled, and the running total is corrected by the
// difference.
//
// The loop is guaranteed to terminate: every iteration that has not
// already met budget either removes at least one entity from whichever
// generation currently holds the most (see trimGenerationBySize) or drops
// one whole generation outright, so the total amount of data across every
// generation strictly decreases every time, bounded below by an empty
// slice.
func trimToByteBudget(gens *[]evidence.Generation, budget int) bool {
	modified := false
	for {
		sizes, total := measureGenerationSizes(*gens)
		if total <= budget {
			return modified
		}

		largest := -1
		for i := range *gens {
			g := &(*gens)[i]
			count := len(g.Executables) + len(g.Unavailable) + len(g.OSPackages)
			if count == 0 {
				continue
			}
			if largest == -1 || sizes[i] > sizes[largest] {
				largest = i
			}
		}
		if largest != -1 {
			before := sizes[largest]
			if trimGenerationBySize(&(*gens)[largest], total-budget, before) {
				modified = true
				continue
			}
		}

		// No generation has any entities left to trim: the overage is in
		// non-entity fields, or is spread too thin for entity-trimming
		// alone to ever reach — the only remaining option is to omit whole
		// generations, oldest-ended first, then newest-live.
		if dropOldestEnded(gens) || dropNewestLive(gens) {
			modified = true
			continue
		}

		// Nothing left to drop at all (gens is empty, or every remaining
		// generation is somehow still over budget on its own with zero
		// entities — a pathological case this function accepts rather than
		// loop forever or destroy fields no trimming step is meant to
		// touch).
		return modified
	}
}

// measureGenerationSizes returns each generation's own encoded size and
// their sum.
func measureGenerationSizes(gens []evidence.Generation) (sizes []int, total int) {
	sizes = make([]int, len(gens))
	for i := range gens {
		b, err := json.Marshal(gens[i])
		if err != nil {
			continue
		}
		sizes[i] = len(b)
		total += len(b)
	}
	return sizes, total
}

// trimGenerationEntityCount removes entities from g (Executables first,
// then Unavailable, then OSPackages) until its own combined count is at
// most limit, marking it Truncated if anything was removed. Reports
// whether it changed g at all.
func trimGenerationEntityCount(g *evidence.Generation, limit int) bool {
	over := len(g.Executables) + len(g.Unavailable) + len(g.OSPackages) - limit
	if over <= 0 {
		return false
	}
	g.Truncated = true
	for over > 0 {
		switch {
		case len(g.Executables) > 0:
			g.Executables = g.Executables[:len(g.Executables)-1]
		case len(g.Unavailable) > 0:
			g.Unavailable = g.Unavailable[:len(g.Unavailable)-1]
		case len(g.OSPackages) > 0:
			g.OSPackages = g.OSPackages[:len(g.OSPackages)-1]
		default:
			return true
		}
		over--
	}
	return true
}

// dropOldestEnded removes the StateEnded generation in *gens with the
// oldest EndedAt, reporting false (and leaving *gens unchanged) when none
// remain to drop.
func dropOldestEnded(gens *[]evidence.Generation) bool {
	oldest := -1
	for i, g := range *gens {
		if g.EndedAt == nil {
			continue
		}
		if oldest == -1 || g.EndedAt.Before(*(*gens)[oldest].EndedAt) {
			oldest = i
		}
	}
	if oldest == -1 {
		return false
	}
	*gens = append((*gens)[:oldest], (*gens)[oldest+1:]...)
	return true
}

// dropNewestLive removes the non-ended (EndedAt == nil) generation in
// *gens with the most recent StartedAt, reporting false (and leaving *gens
// unchanged) when none remain — every generation left is already ended, so
// dropOldestEnded is what should still be making progress instead.
func dropNewestLive(gens *[]evidence.Generation) bool {
	newest := -1
	for i, g := range *gens {
		if g.EndedAt != nil {
			continue
		}
		if newest == -1 || g.StartedAt.After((*gens)[newest].StartedAt) {
			newest = i
		}
	}
	if newest == -1 {
		return false
	}
	*gens = append((*gens)[:newest], (*gens)[newest+1:]...)
	return true
}

// trimGenerationBySize removes entities from g (Executables first, then
// Unavailable, then OSPackages), marking it Truncated, estimating how many
// to remove in one call from ownSize (g's own most recently measured
// encoded size) and overBudget (how far the whole snapshot currently is
// over budget) — proportionally, so a generation far over budget converges
// in a small, bounded number of calls rather than one entity at a time. The
// estimate never removes more than g actually has, and always removes at
// least one entity when g has any at all, which is what guarantees
// trimToByteBudget's own loop terminates regardless of how the estimate
// turns out. Reports whether anything was removed.
func trimGenerationBySize(g *evidence.Generation, overBudget, ownSize int) bool {
	count := len(g.Executables) + len(g.Unavailable) + len(g.OSPackages)
	if count == 0 {
		return false
	}

	avgBytesPerEntity := 1
	if ownSize > 0 {
		avgBytesPerEntity = ownSize / count
		if avgBytesPerEntity < 1 {
			avgBytesPerEntity = 1
		}
	}
	toRemove := overBudget/avgBytesPerEntity + 1
	if toRemove < 1 {
		toRemove = 1
	}
	if toRemove > count {
		toRemove = count
	}

	g.Truncated = true
	for i := 0; i < toRemove; i++ {
		switch {
		case len(g.Executables) > 0:
			g.Executables = g.Executables[:len(g.Executables)-1]
		case len(g.Unavailable) > 0:
			g.Unavailable = g.Unavailable[:len(g.Unavailable)-1]
		case len(g.OSPackages) > 0:
			g.OSPackages = g.OSPackages[:len(g.OSPackages)-1]
		default:
			return true
		}
	}
	return true
}
