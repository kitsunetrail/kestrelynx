package sensor

import (
	"errors"
	"fmt"
	"hash/fnv"
	"sort"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/kitsunetrail/kestrelynx/internal/evidence"
	"github.com/kitsunetrail/kestrelynx/internal/sensor/pkgdb"
	"github.com/kitsunetrail/kestrelynx/internal/sensor/procfs"
	"github.com/kitsunetrail/kestrelynx/internal/sensor/rootfs"
)

// dbJobKind names what a dbJob asks the dbworker goroutine to do.
type dbJobKind int

const (
	dbJobBuild dbJobKind = iota
	dbJobLookup
	dbJobForget
)

// dbJob is one unit of work for the dbworker goroutine — the sole owner of
// the parser socket fd for this Sensor session's whole lifetime. Only the
// loop goroutine ever constructs or sends one, over a single FIFO channel;
// the dbworker processes exactly one job at a time, in order, never more
// than one request outstanding against the parser at once.
type dbJob struct {
	kind   dbJobKind
	genKey string
	// epoch is generationState.idxEpoch as of the moment loop submitted
	// this job — see runDBWorker's own epoch check. For a build, it is the
	// index generation this build is establishing; for a lookup, it is the
	// index generation the candidates being looked up were observed
	// against.
	epoch int
	// seq identifies one specific lookup request, from
	// generationState.nextLookupSeq (lookup jobs only; zero and unused for a
	// build or forget job). epoch alone cannot tell two lookups for the same
	// generation apart when neither one has caused a rebuild in between (the
	// ordinary case): a lookup abandoned after pendingLookupTTL and a fresh
	// one submitted in its place would otherwise carry the identical epoch,
	// so applyLookupResult could not tell the abandoned one's own
	// eventually-arriving answer apart from the new one it must not be
	// mistaken for — see applyLookupResult's own doc comment.
	seq uint64

	// build only: the process whose root this generation's index is built
	// from, and an immutable snapshot of its outstanding ParseFailure
	// records at the moment loop decided to (re)try — the dbworker applies
	// the exact same per-file backoff rule (shouldSkipForBackoff) loop
	// itself would, without needing to share loop's own state at all.
	rootPID       int
	starttime     int64
	knownFailures []evidence.ParseFailure
	interval      time.Duration
	now           time.Time

	// lookup only
	paths []string
}

// fileIdentity is the (input, path, dev, inode, size) tuple a ParseFailure
// is keyed on — see generationState.recordParseFailure's own doc comment
// for why content identity, not just a name, decides whether a repeat
// failure is the same input or a new one.
type fileIdentity struct {
	input string
	path  string
	dev   string
	inode uint64
	size  int64
}

// dbResult is the dbworker's answer to one dbJob, applied by loop alone —
// see generationState's own doc comment on why nothing but loop ever
// transitions a generation's idxState.
type dbResult struct {
	kind   dbJobKind
	genKey string

	// build: settled means idxState moves straight to ready with no failure
	// at all (an absent or unsupported database is a permanent fact, not a
	// transient one). noChange means nothing was sent to the parser this
	// round at all (every input, or specifically the mandatory one, was
	// still within its own backoff window) — idxState stays failed with its
	// existing idxRetryAfter untouched. hadFailure names a build-level
	// failure (the mandatory file's own identity — see mandatoryIdentity)
	// distinct from succeededFiles/failedFiles, which are per-file outcomes
	// from a build that otherwise reached a terminal parser response.
	settled        bool
	dbKind         evidence.PackageDBKind
	dbStatus       evidence.PackageDBStatus
	truncated      bool
	noFileList     []string
	noChange       bool
	buildOK        bool
	hadFailure     bool
	failIdentity   fileIdentity
	succeededFiles []fileIdentity
	failedFiles    []fileIdentity
	// failuresTruncated mirrors buildResult.FailuresTruncated: the parser's
	// own Failures list was itself cut short, so which files besides the
	// ones actually named failed is unknown — loop folds this into
	// Incomplete, since NoFileList/attribution both depend on knowing the
	// full set of what did and did not parse.
	failuresTruncated bool
	// basis is the mount-namespace/root identity handleBuildJob actually
	// built this index from (see generationState.idxBasis's own doc
	// comment) — reported back so loop can store it without itself ever
	// reading procfs/rootfs. Left at its zero value (ok == false) whenever
	// no build was actually attempted (noChange from an unresolvable
	// basis) or the identity could not be confirmed.
	basis mountBasis

	// lookup: owners has one entry per path the parser actually answered
	// (see lookupOutcome's own doc comment for the truncated flag);
	// lookupFailed is true when the parser rejected the whole lookup
	// outright (e.g. the size-budget fallback in parser.Run's own send
	// path) without the connection itself being lost — a normal, non-fatal
	// rejection this generation's own pending candidates simply could not
	// be resolved by this round. epochStale is true instead when
	// runDBWorker itself refused to even ask the parser at all, because
	// job.epoch no longer matched the epoch it last recorded a build job
	// for this same genKey under (see runDBWorker's own epoch check) — the
	// index this lookup was submitted against has already been superseded,
	// possibly by a build that has not even finished yet, so its answer
	// could describe an entirely different root. epoch echoes job.epoch
	// back either way.
	owners       map[string]lookupOutcome
	lookupFailed bool
	// lookupErr is the parser rejection behind lookupFailed, kept only for
	// the incomplete-reason log line.
	lookupErr  error
	epochStale bool
	epoch      int
	// seq echoes job.seq back — see dbJob.seq's own doc comment.
	// applyLookupResult uses this, not epoch alone, to refuse a stale
	// lookup's own delayed answer.
	seq uint64

	// fatal is set whenever the parser connection itself failed (as opposed
	// to answering with a rejection) during this job. The dbworker goroutine
	// exits immediately after reporting a fatal dbResult; loop is
	// responsible for writing a final snapshot and ending the Sensor
	// session — see loop's own doc comment. A fatal build job may also
	// carry hadFailure/failIdentity (see buildContainerIndex's own doc
	// comment on lastWasFinal); a fatal lookup or forget job never does —
	// per this Sensor's own attribution rule, only a build's own accumulated
	// input files ever get a ParseFailure recorded against them.
	fatalErr error
}

// buildSoftCap bounds how long one build job spends sending files to the
// parser before giving up on the remaining ones — the observer's own
// watchdog on a build that would otherwise run unbounded (a container with
// an extraordinary number of tiny package-database files). It intentionally
// does not abort the file already in flight, only stops before starting the
// next one; see buildContainerIndex's own deadline parameter.
const buildSoftCap = 30 * time.Second

// runDBWorker is the whole body of the dbworker goroutine: read jobs from
// jobCh in order, process exactly one at a time against sockFD, and send
// each one's dbResult to resultCh. It returns (ending the goroutine) the
// moment any job reports a fatal error — the parser connection is
// considered permanently unusable for the rest of this Sensor session at
// that point, and loop is expected to react to the fatal dbResult by ending
// the session, not by expecting further results.
func runDBWorker(sockFD int, jobCh <-chan dbJob, resultCh chan<- dbResult) {
	// epochByGenKey is this goroutine's own record of which index epoch
	// (see generationState.idxEpoch's own doc comment) is currently loaded
	// for each generation it has ever built for. Updated the instant a
	// build job for that genKey is dequeued — regardless of whether the
	// build itself goes on to succeed, since loop's own idxEpoch was
	// already bumped, and a new build job submitted, the moment the
	// previous index was invalidated; there is nothing left for a lookup
	// tagged with the old epoch to still be valid against, build outcome
	// notwithstanding. Checked against every lookup job's own carried
	// epoch before ever asking the parser to match anything: loop can only
	// ever have one lookup outstanding per generation at a time, but that
	// one lookup can still be sitting in this very channel, already
	// stale, behind a build job for the same genKey that was submitted
	// (and reaches the front of this FIFO) after it — the build finishing
	// before the lookup is even dequeued would otherwise let the lookup's
	// own answer come from a package database describing a completely
	// different root. Local to this one goroutine, never shared — no
	// synchronization needed.
	epochByGenKey := map[string]int{}

	for job := range jobCh {
		var res dbResult
		switch job.kind {
		case dbJobBuild:
			epochByGenKey[job.genKey] = job.epoch
			res = handleBuildJob(sockFD, job)
		case dbJobLookup:
			if job.epoch != epochByGenKey[job.genKey] {
				res = dbResult{kind: dbJobLookup, genKey: job.genKey, epoch: job.epoch, seq: job.seq, epochStale: true}
			} else {
				res = handleLookupJob(sockFD, job)
				res.epoch = job.epoch
				res.seq = job.seq
			}
		case dbJobForget:
			// The generation this genKey named is gone for good (see
			// endGeneration) — its own entry here would otherwise sit
			// unused for the rest of this Sensor session.
			delete(epochByGenKey, job.genKey)
			res = handleForgetJob(sockFD, job)
		}
		resultCh <- res
		if res.fatalErr != nil {
			return
		}
	}
}

// handleBuildJob performs one generation's package-database indexing
// through the container root of job.rootPID (after confirming its
// starttime still matches job.starttime — the process this job's identity
// names may have gone stale in the time since loop decided to submit this
// job). It never blocks on anything but the parser round trips
// buildContainerIndex/fetchLedger themselves make.
func handleBuildJob(sockFD int, job dbJob) dbResult {
	init := InitProcess{PID: job.rootPID, Starttime: job.starttime}

	// basis and the root fd this build actually reads through are resolved
	// together, from the same open — see openRootWithBasis's own doc
	// comment for why an earlier version of this function (which resolved
	// basis via its own open/close and then reopened root separately for
	// the real read) could let a chroot/unshare happening in between mean
	// this build's own result got attributed to a different root than the
	// one it was actually read from.
	r, basis := openRootWithBasis(init)
	if !basis.ok {
		return dbResult{kind: dbJobBuild, genKey: job.genKey, noChange: true}
	}
	defer r.Close()

	res := buildFromRoot(sockFD, job.genKey, r, job.knownFailures, job.interval, job.now)

	// Post-build starttime re-check: gathering and sending this build's own
	// files can take up to buildSoftCap, during which the process job.
	// rootPID identifies could have exited and had its PID reused by
	// something else entirely. The bytes already read came through a root
	// descriptor pinned to the original process's own mount namespace
	// regardless of anything that happens to the PID number afterward (see
	// procfs.Handle's own doc comment on why), so what was built is not
	// itself wrong — but this result is not reported as usable unless the
	// same identity is confirmed once more right after finishing.
	h2, err := procfs.Open(job.rootPID)
	same := err == nil && h2.Starttime() == job.starttime
	if err == nil {
		h2.Close()
	}
	if !same {
		return discardUnconfirmedBuild(res, job.genKey)
	}

	res.basis = basis
	return res
}

// discardUnconfirmedBuild is handleBuildJob's own verdict once the
// post-build identity re-check has failed (same == false there): this
// generation's own attribution can no longer be trusted (buildOK,
// succeededFiles, noFileList, ... are all discarded, reported as a plain
// noChange instead), but a fatal parser connection error is a fact
// independent of that — the shared parser dying is exactly what makes loop
// end the whole Sensor session (see runDBWorker's own doc comment), and
// silently swallowing it here, folded into a mere noChange, would leave the
// next job to run against the same already-dead connection, most likely
// recording an unrelated input as the cause instead. hadFailure/failIdentity
// are kept alongside a fatal error too, same as dbResult's own doc comment
// already documents for a fatal build result. Factored out of handleBuildJob
// so this decision can be exercised directly, without needing a real PID
// reuse race to produce same == false.
func discardUnconfirmedBuild(res dbResult, genKey string) dbResult {
	if res.fatalErr != nil {
		return dbResult{
			kind: dbJobBuild, genKey: genKey,
			fatalErr: res.fatalErr, hadFailure: res.hadFailure, failIdentity: res.failIdentity,
		}
	}
	return dbResult{kind: dbJobBuild, genKey: genKey, noChange: true}
}

// streamOutcome is streamBuildFiles' whole result: either a completed
// buildResult (Result, once SawLast is true), or exactly one reason nothing
// useful came of this round — never more than one of MandatoryUnreadable,
// MandatoryStillBackingOff, SoftCapped, or Err is set on a return.
type streamOutcome struct {
	// Result and SawLast: the parser's own answer, once the file marked
	// Last was actually sent and acknowledged.
	Result  buildResult
	SawLast bool

	// Sent names every candidate actually transmitted this round (whether
	// the parser eventually reported it as failed or not) — the caller
	// correlates these against Result.Failures itself, the same way it
	// would a pre-gathered batch.
	Sent []indexFile
	// Unreadable names every non-mandatory candidate that could not even be
	// opened this round (a race with the container's own filesystem) — see
	// candidateFile.PkgName's own doc comment for why these are already
	// package names, not raw file names.
	Unreadable []string
	// SkippedForBackoff counts candidates that opened fine but were left
	// unsent because their own identity matched an existing, not-yet-due
	// ParseFailure — distinct from Unreadable (never opened at all).
	SkippedForBackoff int

	// MandatoryIdentity is the one candidate whose Role is
	// roleStatus/roleInstalled's own identity, captured the moment it opens
	// successfully and clears its own backoff check — regardless of
	// whether sending it (or anything sent after it) later succeeds. A
	// caller attributing a build-level failure (a soft cap, a lost
	// connection, a hard parser rejection) to "the build's own mandatory
	// file" uses this directly instead of searching Sent for it, since a
	// Last-file disconnect can leave the mandatory file already flushed
	// into Sent, still pending, or (if it was the only candidate) neither —
	// this field covers all three. Left nil for distroless, which has no
	// such candidate at all (see mandatoryIdentity's own doc comment); a
	// caller building a distroless index falls back to that function's own
	// synthetic branch instead.
	MandatoryIdentity *fileIdentity

	// MandatoryUnreadable is set when the one candidate whose Role is
	// roleStatus/roleInstalled itself could not be opened this round — the
	// whole build has nothing to index at all in that case.
	MandatoryUnreadable bool
	// MandatoryStillBackingOff is set when that same mandatory candidate
	// opened fine but is still within its own existing ParseFailure's
	// backoff window: nothing else in this build can succeed without it,
	// so nothing else was even opened this round (see the per-candidate
	// loop below for the check this reports).
	MandatoryStillBackingOff bool
	// SoftCapped is set when buildSoftCap elapsed before every candidate
	// had been dealt with; whatever was already sent stands, but the
	// parser's own half-built session for this generation must be
	// forgotten, same as buildContainerIndex's own SoftCapped.
	SoftCapped bool

	// FailedAt/LastWasFinal/Err: a parser connection failure while sending
	// a file — see buildContainerIndex's own doc comment for why a Last
	// failure is not attributed to FailedAt at all (the caller uses
	// mandatoryIdentity instead once LastWasFinal is true).
	FailedAt     *fileIdentity
	LastWasFinal bool
	Err          error
}

// streamBuildFiles opens, sends, and closes each of candidates' files one at
// a time — never more than the one just opened plus, briefly, the one
// immediately before it (held only long enough to learn whether this new
// candidate survives its own backoff check, which is what decides whether
// the earlier one was actually Last) — rather than opening every surviving
// candidate up front and holding all of them until a batch send works
// through the whole list. A build with tens of thousands of tiny
// per-package files never holds more than two descriptors open at once
// because of this, no matter how many candidates there are in total.
//
// deadline is buildSoftCap applied to the whole build, fixed once at
// buildFromRoot's own entrance (not just the send step here): checked
// before every candidate but the first — regardless of whether one is
// already pending, so a long run of unreadable or still-backing-off
// candidates that never becomes pending at all still trips it — and once
// more immediately before the final, Last-marked send, which is otherwise
// just another request to the parser, not exempt from the budget for being
// the last one.
//
// The one candidate whose Role is roleStatus/roleInstalled is handled
// specially, wherever it appears in candidates: an unreadable or
// still-backing-off mandatory candidate ends the round immediately (see
// streamOutcome's own doc comment), since nothing else in this build can
// succeed without it — distroless has no such candidate at all (see
// mandatoryIdentity's own doc comment), so callers building a distroless
// index perform that same "is the whole build still backing off" check
// themselves, against the synthetic status.d-directory identity, before
// ever calling this function.
func streamBuildFiles(sockFD int, r *rootfs.Reader, gen string, dbKind evidence.PackageDBKind, candidates []candidateFile, knownFailures []evidence.ParseFailure, now time.Time, deadline time.Time) streamOutcome {
	var out streamOutcome
	var pending *indexFile

	sendPending := func(last bool) bool {
		id := fileIdentity{input: inputForRole(pending.Role), path: pending.Path, dev: pending.Dev, inode: pending.Inode, size: pending.Size}
		sent := *pending
		res, serr := sendOneIndexFile(sockFD, gen, dbKind, pending, last)
		pending.File.Close()
		pending = nil
		if serr != nil {
			out.Err = serr
			out.FailedAt = &id
			out.LastWasFinal = last
			return false
		}
		out.Sent = append(out.Sent, sent)
		if last {
			out.Result = res
			out.SawLast = true
		}
		return true
	}

	for i, c := range candidates {
		// Checked before every candidate but the first (which always gets
		// a chance, the same guarantee buildContainerIndex's own batch
		// loop makes), regardless of whether pending is currently set —
		// not only when it is: a long run of unreadable or
		// still-backing-off candidates never becomes pending at all, and
		// must not be able to spend the whole budget without this ever
		// tripping.
		if i > 0 && time.Now().After(deadline) {
			if pending != nil {
				pending.File.Close()
				pending = nil
			}
			out.SoftCapped = true
			return out
		}

		mandatoryRole := c.Role == roleStatus || c.Role == roleInstalled
		f, ferr := openIndexFile(r, c.Role, c.Name, c.Path)
		if ferr != nil {
			if mandatoryRole {
				if pending != nil {
					pending.File.Close()
					pending = nil
				}
				out.MandatoryUnreadable = true
				return out
			}
			out.Unreadable = append(out.Unreadable, c.PkgName)
			continue
		}

		if shouldSkipForBackoff(knownFailures, inputForRole(f.Role), f.Path, f.Dev, f.Inode, f.Size, now) {
			f.File.Close()
			if mandatoryRole {
				if pending != nil {
					pending.File.Close()
					pending = nil
				}
				out.MandatoryStillBackingOff = true
				return out
			}
			out.SkippedForBackoff++
			continue
		}

		if mandatoryRole {
			id := fileIdentity{input: inputForRole(f.Role), path: f.Path, dev: f.Dev, inode: f.Inode, size: f.Size}
			out.MandatoryIdentity = &id
		}

		if pending != nil {
			if !sendPending(false) {
				f.File.Close()
				return out
			}
		}
		pending = &f
	}
	if pending != nil {
		// The same per-request deadline check every earlier candidate's
		// own send already went through, applied here too: the file marked
		// Last is still just another request to the parser, not exempt
		// from the budget merely for being the final one.
		if time.Now().After(deadline) {
			pending.File.Close()
			pending = nil
			out.SoftCapped = true
			return out
		}
		sendPending(true)
	}
	return out
}

// buildFromRoot is handleBuildJob's core logic once its generation's
// container root is already open — split out so it can be exercised
// directly against a synthetic rootfs in tests, the same way
// detectPackageDB/gatherIndexFiles already are (see dbbuild_test.go's
// openTestRoot), without needing a real process whose /proc/<pid>/root
// happens to point at a controlled directory.
func buildFromRoot(sockFD int, genKey string, r *rootfs.Reader, knownFailures []evidence.ParseFailure, interval time.Duration, now time.Time) dbResult {
	// Fixed here, at this build's own true entrance, and applied
	// uniformly across every step below it — detection, enumeration, each
	// candidate's own open, each request sent to the parser, and the
	// ledger's own pages — never only from the point streamBuildFiles
	// itself begins. A container whose package-database directory alone
	// is unusually large or slow to enumerate must not be able to spend
	// this whole budget before a single file is ever even opened.
	deadline := time.Now().Add(buildSoftCap)
	res := dbResult{kind: dbJobBuild, genKey: genKey}

	kind, status := detectPackageDB(r)
	res.dbKind = kind
	role, path := expectedMandatoryPath(kind)
	mandatoryInput := inputForRole(role)

	if status != evidence.DBStatusOK {
		// Absent/unsupported is a permanent fact about this container's
		// image, not a transient failure — nothing to back off or retry.
		// DBStatusError (a database exists but could not be opened) falls
		// through to the retryable path below instead.
		if status != evidence.DBStatusError {
			res.settled = true
			res.dbStatus = status
			return res
		}
		res.dbStatus = evidence.DBStatusError
		res.hadFailure = true
		res.failIdentity = fileIdentity{input: mandatoryInput, path: path}
		return res
	}

	gathered, err := gatherIndexFiles(r, kind, pkgdb.DefaultLimits())
	if err != nil {
		// distroless's status.d directory itself could not even be listed,
		// or has no entries at all, moments after detectPackageDB confirmed
		// it exists — tracked as a retryable failure on its own expected
		// identity (unknown dev/inode/size, since nothing could be
		// fstatted) rather than a permanent DBStatusError-forever. dpkg and
		// apk never fail here at all (see gatherIndexFiles' own doc
		// comment) — their own mandatory candidate's existence is only
		// discovered later, by streamBuildFiles.
		res.dbStatus = evidence.DBStatusError
		res.hadFailure = true
		res.failIdentity = fileIdentity{input: mandatoryInput, path: path}
		return res
	}
	res.truncated = gathered.Truncated

	// distrolessFingerprint is computed once, here, before any backoff
	// decision or streaming begins, and reused for every mandatoryFallback
	// call below within this same build attempt — never recomputed per
	// call, which would reopen every candidate again for each one. Left at
	// its zero value for dpkg/apk, which never actually reach
	// mandatoryIdentity at all (see its own doc comment).
	var distrolessFingerprint int64
	if kind == evidence.DBKindDistroless {
		fp, ok := distrolessChildrenFingerprint(r, gathered.Files, deadline)
		if !ok {
			// The deadline elapsed partway through fingerprinting
			// distroless's own children (see distrolessChildrenFingerprint's
			// own doc comment) — this build's own identity cannot be
			// trusted for a backoff comparison at all, so this round is a
			// plain failure instead, on the status.d directory's own
			// (dev, inode) alone: Size is left at its zero value, standing
			// in for "unknown" rather than claiming any specific content
			// count, which also guarantees the next round's own fingerprint
			// (assuming it completes) is seen as a changed identity and
			// retried immediately rather than held to a backoff schedule
			// seeded from a meaningless placeholder.
			res.dbStatus = evidence.DBStatusError
			res.hadFailure = true
			res.failIdentity = mandatoryIdentity(r, kind, 0)
			return res
		}
		distrolessFingerprint = fp
	}

	// mandatoryFallback is this build's own mandatory-file identity for
	// attributing a failure that cannot be pinned on one specific file (see
	// streamOutcome.MandatoryIdentity's own doc comment): whichever
	// streamBuildFiles itself captured while actually opening the
	// candidates, or — for distroless, which has no such candidate at all —
	// mandatoryIdentity's own synthetic status.d-directory identity.
	mandatoryFallback := func() fileIdentity {
		return mandatoryIdentity(r, kind, distrolessFingerprint)
	}

	if kind == evidence.DBKindDistroless {
		// distroless has no single mandatory candidate to check
		// individually (see mandatoryIdentity's own doc comment), so this
		// Sensor's own "if the build's mandatory input hasn't changed and
		// is still backing off, skip the whole attempt" rule is applied
		// here, against the synthetic status.d-directory identity —
		// distrolessFingerprint above has already had to open every
		// candidate once, transiently, to compute it (detecting a child's
		// own content change requires knowing its current identity), so
		// this check no longer avoids that cost the way skipping the whole
		// build once did; it still avoids the more expensive part, the
		// actual streamBuildFiles send below, whenever nothing changed.
		synthetic := mandatoryFallback()
		if shouldSkipForBackoff(knownFailures, synthetic.input, synthetic.path, synthetic.dev, synthetic.inode, synthetic.size, now) {
			res.dbStatus = evidence.DBStatusError
			res.noChange = true
			return res
		}
	}

	if time.Now().After(deadline) {
		// Detection and enumeration alone (an unusually large or slow to
		// list package-database directory) already exhausted this build's
		// own budget, before a single candidate was ever opened. Nothing
		// has been sent to the parser yet at this point, so there is no
		// half-built dbBuildSession to forget (see the SoftCapped handling
		// below, once streamBuildFiles has actually started sending).
		res.dbStatus = evidence.DBStatusError
		res.hadFailure = true
		res.failIdentity = mandatoryFallback()
		return res
	}

	stream := streamBuildFiles(sockFD, r, genKey, kind, gathered.Files, knownFailures, now, deadline)
	if stream.MandatoryUnreadable {
		// The one mandatory file (dpkg status / apk installed) could not be
		// opened, moments after detectPackageDB confirmed some database
		// exists here — tracked as a retryable failure on its own expected
		// identity (unknown dev/inode/size, since it could not be
		// fstatted) rather than a permanent DBStatusError-forever.
		res.dbStatus = evidence.DBStatusError
		res.hadFailure = true
		res.failIdentity = fileIdentity{input: mandatoryInput, path: path}
		return res
	}
	if stream.MandatoryStillBackingOff {
		// dpkg/apk's own version of the same "whole build still backing
		// off" rule the distroless check above already applied: nothing
		// about this build attempt has changed since last time — the whole
		// attempt is skipped, not just that one file, since every other
		// file's own content is irrelevant until the mandatory one is even
		// readable in a form pkgdb can use.
		res.dbStatus = evidence.DBStatusError
		res.noChange = true
		return res
	}
	if len(stream.Sent) == 0 && stream.SkippedForBackoff == 0 && stream.Err == nil && !stream.SoftCapped {
		// Every distroless candidate this round was unreadable outright —
		// the closest a directory of otherwise-nameable control files comes
		// to dpkg/apk's own "mandatory file missing" case (dpkg/apk cannot
		// reach this branch: their one candidate either succeeds, is
		// MandatoryUnreadable, or is MandatoryStillBackingOff above).
		res.dbStatus = evidence.DBStatusError
		res.hadFailure = true
		res.failIdentity = mandatoryFallback()
		return res
	}
	if len(stream.Sent) == 0 && stream.SkippedForBackoff > 0 && stream.Err == nil && !stream.SoftCapped {
		// Every remaining input is still backing off from a previous
		// failure, with no change in identity since; nothing changed this
		// round.
		res.dbStatus = evidence.DBStatusError
		res.noChange = true
		return res
	}
	if stream.SoftCapped {
		// The parser's own dbBuildSession for this generation is left
		// half-built (never reached the file marked Last); forget it so
		// the next attempt starts clean rather than silently appending
		// onto stale, partial content.
		_ = forgetIndex(sockFD, genKey)
		res.dbStatus = evidence.DBStatusError
		res.hadFailure = true
		if stream.MandatoryIdentity != nil {
			res.failIdentity = *stream.MandatoryIdentity
		} else {
			res.failIdentity = mandatoryFallback()
		}
		return res
	}
	if stream.Err != nil {
		if errors.Is(stream.Err, errParserConnectionLost) {
			res.fatalErr = stream.Err
			switch {
			case stream.LastWasFinal:
				// The disconnect happened while sending the file marked
				// Last — exactly when pkgdb.Parse* actually runs against
				// everything accumulated so far. The true cause could be
				// any earlier file's content, which this process has no
				// way to identify; attributed to the build's own mandatory
				// file identity instead of whichever file was in flight.
				res.hadFailure = true
				if stream.MandatoryIdentity != nil {
					res.failIdentity = *stream.MandatoryIdentity
				} else {
					res.failIdentity = mandatoryFallback()
				}
			case stream.FailedAt != nil:
				res.hadFailure = true
				res.failIdentity = *stream.FailedAt
			}
			return res
		}
		// The parser rejected the whole build outright (a hard
		// pkgdb.Parse* error — not one of the per-file diagnostics
		// result.Failures reports on success).
		res.dbStatus = evidence.DBStatusError
		res.hadFailure = true
		if stream.MandatoryIdentity != nil {
			res.failIdentity = *stream.MandatoryIdentity
		} else {
			res.failIdentity = mandatoryFallback()
		}
		return res
	}

	result := stream.Result
	toSend := stream.Sent
	res.dbStatus = evidence.DBStatusOK
	if result.Truncated {
		res.truncated = true
	}

	ledger, lerr := fetchLedger(sockFD, genKey, deadline)
	if lerr != nil {
		if errors.Is(lerr, errParserConnectionLost) {
			res.fatalErr = lerr
			return res
		}
		// The build itself succeeded, but this round could not confirm
		// which packages have no file list — treated as a build failure
		// (retried next sample) rather than reporting a stale or empty
		// NoFileList as if it were current.
		res.dbStatus = evidence.DBStatusError
		res.hadFailure = true
		if stream.MandatoryIdentity != nil {
			res.failIdentity = *stream.MandatoryIdentity
		} else {
			res.failIdentity = mandatoryFallback()
		}
		return res
	}

	// NoFileList names every package this build's own database knows about
	// but cannot give a file list for: a metapackage with no files of its
	// own (from the ledger), plus any package whose own .list/.md5sums
	// streamBuildFiles itself could not open this round (stream.Unreadable)
	// — a path that happens to resolve to one of them is never claimed as
	// either "in use" or "not observed" (JudgeOSPackage checks this by
	// exact name).
	var noFileList []string
	for _, l := range ledger {
		if !l.FileListPresent {
			noFileList = append(noFileList, l.Name)
		}
	}
	for _, name := range stream.Unreadable {
		if !containsString(noFileList, name) {
			noFileList = append(noFileList, name)
		}
	}
	res.noFileList = noFileList
	res.failuresTruncated = result.FailuresTruncated

	failedNames := make(map[string]bool, len(result.Failures))
	for _, f := range result.Failures {
		failedNames[f.Name] = true
	}
	for _, f := range toSend {
		id := fileIdentity{input: inputForRole(f.Role), path: f.Path, dev: f.Dev, inode: f.Inode, size: f.Size}
		switch {
		case failedNames[f.Name]:
			res.failedFiles = append(res.failedFiles, id)
		case result.FailuresTruncated:
			// The Failures list itself was cut short (see
			// boundFailures/dbop.go's own doc comment): a file not named in
			// it might still have genuinely failed and simply been dropped
			// from the report, so this build must not assume success for
			// it — recordParseSuccess would otherwise clear a real,
			// still-outstanding backoff. Left as neither succeeded nor
			// failed; its own previous ParseFailure entry (if any) is
			// retried on its existing schedule untouched.
		default:
			res.succeededFiles = append(res.succeededFiles, id)
		}
	}
	res.buildOK = len(res.failedFiles) == 0 && !result.FailuresTruncated

	if res.buildOK {
		// A build that fully succeeds also clears any outstanding
		// synthetic mandatory-identity failure (distroless's own
		// status.d-directory-level ParseFailure — see mandatoryIdentity's
		// own doc comment): recordParseSuccess for real per-file failures
		// above only ever matches a real file's own (input, path), never
		// this synthetic one, so without this it would never self-clear
		// once the build that caused it stops recurring.
		var mandatory fileIdentity
		if stream.MandatoryIdentity != nil {
			mandatory = *stream.MandatoryIdentity
		} else {
			mandatory = mandatoryFallback()
		}
		res.succeededFiles = append(res.succeededFiles, mandatory)
	}
	return res
}

// mandatoryIdentity names distroless's own synthetic per-database identity
// — the identity a build-level failure this process cannot attribute to a
// single specific file (see handleBuildJob's own doc comment) is recorded
// against, for the one kind whose "database" is a whole directory of
// per-package control files with no single one of them individually
// mandatory (dpkg/apk each have a real mandatory file instead — status,
// installed — whose own identity streamBuildFiles captures directly, via
// streamOutcome.MandatoryIdentity, without ever reaching this function).
//
// The status.d directory's own (dev, inode) stands in for "this specific
// database object", so a genuinely different directory (the image was
// rebuilt, say) is not confused with the same one — and fingerprint (see
// distrolessChildrenFingerprint) is carried as this identity's own Size:
// shouldSkipForBackoff's existing (dev, inode, size)-changed-means-
// different-input rule then releases an existing backoff on its own
// whenever any child control file's own name, dev, inode, size or mtime
// changes — packages added or removed, a file's content replaced in place,
// or one control file swapped for another under an unchanged name —
// without needing a dedicated comparison of its own.
func mandatoryIdentity(r *rootfs.Reader, kind evidence.PackageDBKind, fingerprint int64) fileIdentity {
	role, path := expectedMandatoryPath(kind)
	id := fileIdentity{input: inputForRole(role), path: path, size: fingerprint}
	if dev, ino, err := r.Stat(strings.TrimPrefix(path, "/")); err == nil {
		id.dev, id.inode = dev, ino
	}
	return id
}

// distrolessChildrenFingerprint computes a single, naming-order-independent
// fingerprint of every distroless candidate's own on-disk identity (name,
// dev, inode, size, mtime) — mandatoryIdentity's own synthetic Size for a
// distroless build. A plain file-count proxy alone (an earlier version of
// this Sensor's own approach) cannot detect one control file's content
// being replaced in place, or one file swapped for another under an
// unchanged name, since neither changes how many files exist under
// status.d at all; this does, since it changes at least one of these five
// properties for the file involved.
//
// Each candidate is opened, fstatted, and closed immediately — mirroring
// gatherIndexFiles' own "never held open" discipline (see its own doc
// comment) — never kept open across this whole pass, and never held
// simultaneously with any other candidate's own fd.
//
// deadline is the same build-wide soft cap buildFromRoot applies to every
// other step, checked before every candidate but the first (the same
// guarantee every other deadline check in this build makes — see
// streamBuildFiles' own doc comment): a distroless directory with many
// slow-to-open control files must not be able to spend this whole budget
// fingerprinting alone, holding up every other generation's own build or
// lookup on the one dbworker goroutine, before ever reaching a send. ok is
// false once the deadline is exceeded partway through — the caller must
// then treat this build's own identity as unknown, never as a value fit to
// compare a backoff schedule against.
func distrolessChildrenFingerprint(r *rootfs.Reader, candidates []candidateFile, deadline time.Time) (fingerprint int64, ok bool) {
	names := make([]string, len(candidates))
	byName := make(map[string]candidateFile, len(candidates))
	for i, c := range candidates {
		names[i] = c.Name
		byName[c.Name] = c
	}
	sort.Strings(names)

	h := fnv.New64a()
	for i, name := range names {
		if i > 0 && time.Now().After(deadline) {
			return 0, false
		}
		c := byName[name]
		fmt.Fprintf(h, "%s\x00", c.Name)
		f, err := r.OpenFile(c.Path)
		if err != nil {
			fmt.Fprintf(h, "unreadable\x00")
			continue
		}
		var st unix.Stat_t
		ferr := unix.Fstat(int(f.Fd()), &st)
		f.Close()
		if ferr != nil {
			fmt.Fprintf(h, "unreadable\x00")
			continue
		}
		fmt.Fprintf(h, "%s\x00%d\x00%d\x00%d\x00%d\x00", formatDevForCompare(st.Dev), st.Ino, st.Size, st.Mtim.Sec, st.Mtim.Nsec)
	}
	return int64(h.Sum64()), true
}

// inputForRole names the ParseFailure.Input category for one dbOp role
// (e.g. "dpkg_status" for roleStatus).
func inputForRole(role string) string {
	switch role {
	case roleStatus:
		return "dpkg_status"
	case roleList:
		return "dpkg_list"
	case roleInstalled:
		return "apk_installed"
	case roleControl:
		return "distroless_control"
	case roleMD5Sums:
		return "distroless_md5sums"
	default:
		return role
	}
}

// expectedMandatoryPath names the one per-database file gatherIndexFiles
// requires, for a ParseFailure record when that file could not even be
// opened (so there is no indexFile carrying its own Path yet), or when it
// stands in as a build-level failure's own identity (see mandatoryIdentity).
func expectedMandatoryPath(kind evidence.PackageDBKind) (role, path string) {
	switch kind {
	case evidence.DBKindDpkg:
		return roleStatus, "/var/lib/dpkg/status"
	case evidence.DBKindApk:
		return roleInstalled, "/lib/apk/db/installed"
	case evidence.DBKindDistroless:
		return roleControl, "/var/lib/dpkg/status.d"
	default:
		return "", ""
	}
}

// handleLookupJob resolves job.paths against job.genKey's already-built
// index.
func handleLookupJob(sockFD int, job dbJob) dbResult {
	res := dbResult{kind: dbJobLookup, genKey: job.genKey}
	owners, err := lookupPaths(sockFD, job.genKey, job.paths)
	if err != nil {
		// A lookup never records a ParseFailure either way — only a
		// build's own accumulated input files ever do — but a real
		// connection failure and a normal, non-fatal rejection (the
		// parser's own size-budget fallback, most likely) are not the same
		// thing: only the former ends the Sensor session. errors.Is is
		// what actually distinguishes them (see lookupPaths' own doc
		// comment); treating a normal rejection as if it were a lost
		// connection is exactly the mistake this branch exists to avoid.
		if errors.Is(err, errParserConnectionLost) {
			res.fatalErr = err
		} else {
			res.lookupFailed = true
			res.lookupErr = err
		}
		return res
	}
	res.owners = owners
	return res
}

// handleForgetJob releases job.genKey's retained index in the parser.
func handleForgetJob(sockFD int, job dbJob) dbResult {
	res := dbResult{kind: dbJobForget, genKey: job.genKey}
	if err := forgetIndex(sockFD, job.genKey); err != nil {
		res.fatalErr = err
	}
	return res
}
