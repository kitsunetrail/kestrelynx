package sensor

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/kitsunetrail/kestrelynx/internal/evidence"
	"github.com/kitsunetrail/kestrelynx/internal/inventory"
)

func newTestGenerationForIndex() *generationState {
	return newGenerationState(evidence.ContainerRef{Runtime: "docker", ID: strings64('a')}, InitProcess{PID: 1, Starttime: 1}, time.Unix(0, 0), evidence.CoverageNone)
}

// applyBuild runs the same (*Session).applyBuildResult production code path
// a real loop goroutine would, against a throwaway Session carrying only
// what that method reads (now, cfg.Interval) — so these tests exercise
// exactly the same state-machine transition logic loop itself relies on,
// not a reimplementation of it.
func applyBuild(g *generationState, res dbResult, interval time.Duration, now time.Time) {
	s := &Session{now: func() time.Time { return now }, cfg: Config{Interval: interval}}
	s.applyBuildResult(g, res)
}

func TestBuildFromRoot_CleanBuildSettles(t *testing.T) {
	sockFD, cleanup := spawnTestParser(t)
	defer cleanup()
	r, dir := openTestRoot(t)
	defer r.Close()
	writeTestFile(t, dir, "var/lib/dpkg/status", testDpkgStatus)
	writeTestFile(t, dir, "var/lib/dpkg/info/libssl3.list", testLibsslList)

	g := newTestGenerationForIndex()
	interval := 30 * time.Second
	now := time.Unix(1000, 0)

	res := buildFromRoot(sockFD, g.key(), r, g.parseFailed, interval, now)
	applyBuild(g, res, interval, now)

	if g.idxState != indexReady {
		t.Errorf("idxState = %v, want indexReady after a clean build", g.idxState)
	}
	if g.packageDB.Status != evidence.DBStatusOK {
		t.Errorf("packageDB.Status = %q, want ok", g.packageDB.Status)
	}
	if len(g.parseFailed) != 0 {
		t.Errorf("parseFailed = %+v, want none", g.parseFailed)
	}
}

// TestBuildFromRoot_MandatoryFileMissingRetries covers the case where
// detectPackageDB recognizes a database (an empty status.d directory still
// reads successfully) but gatherIndexFiles then finds nothing usable in it
// — the closest this test package can get, without a real race, to "the
// mandatory file could not even be opened". It must be recorded as a
// retryable ParseFailure (10x interval), not a permanent DBStatusError with
// no way back.
func TestBuildFromRoot_MandatoryFileMissingRetries(t *testing.T) {
	sockFD, cleanup := spawnTestParser(t)
	defer cleanup()
	r, dir := openTestRoot(t)
	defer r.Close()
	if err := os.MkdirAll(filepath.Join(dir, "var/lib/dpkg/status.d"), 0o755); err != nil {
		t.Fatal(err)
	}

	g := newTestGenerationForIndex()
	interval := 30 * time.Second
	now := time.Unix(1000, 0)

	res := buildFromRoot(sockFD, g.key(), r, g.parseFailed, interval, now)
	applyBuild(g, res, interval, now)

	if g.idxState == indexReady {
		t.Errorf("idxState = ready, want not ready — the mandatory input never succeeded")
	}
	if g.packageDB.Status != evidence.DBStatusError {
		t.Errorf("packageDB.Status = %q, want error", g.packageDB.Status)
	}
	if derivePublishedState(g) != evidence.StateParseFailed {
		t.Errorf("state = %q, want parse_failed", derivePublishedState(g))
	}
	if len(g.parseFailed) != 1 {
		t.Fatalf("parseFailed = %+v, want exactly one entry", g.parseFailed)
	}
	pf := g.parseFailed[0]
	if pf.Input != "distroless_control" {
		t.Errorf("Input = %q, want distroless_control", pf.Input)
	}
	wantRetry := now.Add(10 * interval)
	if !pf.RetryAfter.Equal(wantRetry) {
		t.Errorf("RetryAfter = %v, want %v (10x interval)", pf.RetryAfter, wantRetry)
	}
	if now.Before(g.nextRetryTime()) == false {
		t.Errorf("nextRetryTime() = %v, want still in the future relative to now (%v)", g.nextRetryTime(), now)
	}
}

func TestBuildFromRoot_PerFileFailureIsRetryableNotFatal(t *testing.T) {
	sockFD, cleanup := spawnTestParser(t)
	defer cleanup()
	r, dir := openTestRoot(t)
	defer r.Close()
	writeTestFile(t, dir, "var/lib/dpkg/status", testDpkgStatus)
	// Exceeds pkgdb's own MaxListBytes (1 MiB), which pkgdb.ParseDpkg reports
	// as a per-file FileError/Truncated rather than a hard `error` return —
	// the parser's Response still comes back OK, with this file named in
	// buildResult.Failures.
	huge := strings.Repeat("/.\n", (1<<20)/3+100)
	writeTestFile(t, dir, "var/lib/dpkg/info/libssl3.list", huge)

	g := newTestGenerationForIndex()
	interval := 30 * time.Second
	now := time.Unix(1000, 0)

	res := buildFromRoot(sockFD, g.key(), r, g.parseFailed, interval, now)
	applyBuild(g, res, interval, now)

	// The build as a whole still succeeds (status parsed fine); only the
	// oversized list file is a retryable failure.
	if g.packageDB.Status != evidence.DBStatusOK {
		t.Errorf("packageDB.Status = %q, want ok (the database itself was read)", g.packageDB.Status)
	}
	if g.idxState == indexReady {
		t.Errorf("idxState = ready, want not ready — one input is still outstanding")
	}
	if derivePublishedState(g) != evidence.StateParseFailed {
		t.Errorf("state = %q, want parse_failed", derivePublishedState(g))
	}
	if len(g.parseFailed) != 1 || g.parseFailed[0].Input != "dpkg_list" {
		t.Fatalf("parseFailed = %+v, want exactly one dpkg_list entry", g.parseFailed)
	}
}

func TestBuildFromRoot_SkipsFileStillInBackoff(t *testing.T) {
	sockFD, cleanup := spawnTestParser(t)
	defer cleanup()
	r, dir := openTestRoot(t)
	defer r.Close()
	writeTestFile(t, dir, "var/lib/dpkg/status", testDpkgStatus)
	writeTestFile(t, dir, "var/lib/dpkg/info/libssl3.list", testLibsslList)
	listPath := filepath.Join(dir, "var/lib/dpkg/info/libssl3.list")
	var st unix.Stat_t
	if err := unix.Stat(listPath, &st); err != nil {
		t.Fatalf("stat: %v", err)
	}
	dev := formatDevForCompare(st.Dev)

	g := newTestGenerationForIndex()
	interval := 30 * time.Second
	now := time.Unix(1000, 0)
	// Pre-seed a ParseFailure for this exact file identity, still backing
	// off well into the future.
	g.recordParseFailure("dpkg_list", "/var/lib/dpkg/info/libssl3.list", dev, st.Ino, st.Size, now, interval)

	later := now.Add(time.Second)
	res := buildFromRoot(sockFD, g.key(), r, g.parseFailed, interval, later)
	applyBuild(g, res, interval, later)

	// The list file was never sent this round (still backing off), so the
	// package it would have described is not in the index at all: a lookup
	// against a path only libssl3.list would have recorded must come back
	// with no owner.
	owners, err := lookupPaths(sockFD, g.key(), []string{"/usr/lib/x86_64-linux-gnu/libssl.so.3"})
	if err != nil {
		t.Fatalf("lookupPaths: %v", err)
	}
	if o := owners["/usr/lib/x86_64-linux-gnu/libssl.so.3"]; len(o.owners) != 0 {
		t.Errorf("owners = %+v, want none — libssl3.list should have been skipped for backoff", o)
	}
	// The ParseFailure entry itself must be unchanged (not touched by this
	// round at all, since the file was skipped, not re-attempted).
	pf, ok := g.parseFailureFor("dpkg_list", "/var/lib/dpkg/info/libssl3.list")
	if !ok || pf.Count != 1 {
		t.Errorf("ParseFailure = %+v (ok=%v), want unchanged Count=1", pf, ok)
	}
}

// TestBuildFromRoot_BackoffCheckedPerFileNotWholeGeneration is the
// regression test confirming a whole-generation "still backing off, skip
// everything" early return never happens: a file whose content changed (a
// different dev/inode/size than what failed before) must be retried
// immediately even while its own path's previous failure's retry_after has
// not arrived yet, since the earlier failure describes different content
// that is no longer even there — gatherIndexFiles/shouldSkipForBackoff must
// run against every file every time, so a replaced file is noticed as soon
// as it appears rather than only once the old failure's own retry_after
// finally elapses.
func TestBuildFromRoot_BackoffCheckedPerFileNotWholeGeneration(t *testing.T) {
	sockFD, cleanup := spawnTestParser(t)
	defer cleanup()
	r, dir := openTestRoot(t)
	defer r.Close()
	writeTestFile(t, dir, "var/lib/dpkg/status", testDpkgStatus)
	writeTestFile(t, dir, "var/lib/dpkg/info/libssl3.list", testLibsslList)

	g := newTestGenerationForIndex()
	interval := 30 * time.Second
	now := time.Unix(1000, 0)

	// Seed a ParseFailure against libssl3.list's ORIGINAL identity, with a
	// retry_after far in the future (well beyond this test's own "now").
	listPath := filepath.Join(dir, "var/lib/dpkg/info/libssl3.list")
	var st unix.Stat_t
	if err := unix.Stat(listPath, &st); err != nil {
		t.Fatalf("stat: %v", err)
	}
	g.recordParseFailure("dpkg_list", "/var/lib/dpkg/info/libssl3.list", formatDevForCompare(st.Dev), st.Ino, st.Size, now, interval)
	if now.Add(9 * interval).After(g.nextRetryTime()) {
		t.Fatalf("test precondition: nextRetryTime() = %v, want well after now+9*interval", g.nextRetryTime())
	}

	// The file at that same path is now different content: os.WriteFile
	// truncates and rewrites the same inode, but its size changes, which is
	// enough on its own for shouldSkipForBackoff's (dev, inode, size)
	// identity comparison to recognize this as a different input than the
	// one that failed before.
	laterButStillBackingOff := now.Add(time.Second)
	writeTestFile(t, dir, "var/lib/dpkg/info/libssl3.list", testLibsslList+"/extra/entry/here\n")

	res := buildFromRoot(sockFD, g.key(), r, g.parseFailed, interval, laterButStillBackingOff)
	applyBuild(g, res, interval, laterButStillBackingOff)

	// The replaced file must have been sent and resolved this round — a
	// lookup against its newly added entry must find an owner — which is
	// only possible if gatherIndexFiles/shouldSkipForBackoff actually ran
	// against it despite the whole generation still nominally "backing off"
	// by the old (now-stale) ParseFailure's own retry_after.
	owners, err := lookupPaths(sockFD, g.key(), []string{"/extra/entry/here"})
	if err != nil {
		t.Fatalf("lookupPaths: %v", err)
	}
	if o := owners["/extra/entry/here"]; len(o.owners) != 1 || o.owners[0].Name != "libssl3" {
		t.Errorf("owners of the replaced file's new entry = %+v, want [libssl3] — the changed file should have been retried immediately, not skipped for the old failure's own backoff", o)
	}
}

// TestMaybeSubmitBuild_AlreadyReadyIsNeverResubmitted covers the loop-level
// guard that replaces this Sensor's earlier "dbIndexBuilt" check: a
// generation whose own idxState is already indexReady must never have
// another build job submitted for it at all — deciding that is loop's own
// job now (maybeSubmitBuild), not something buildFromRoot/handleBuildJob
// checks for themselves (they always perform a real build attempt
// whenever actually invoked).
func TestMaybeSubmitBuild_AlreadyReadyIsNeverResubmitted(t *testing.T) {
	g := newTestGenerationForIndex()
	g.idxState = indexReady
	g.packageDB = evidence.PackageDBInfo{Kind: evidence.DBKindDpkg, Status: evidence.DBStatusOK}

	s := &Session{now: time.Now, cfg: Config{Interval: 30 * time.Second}, generations: map[string]*generationState{g.key(): g}, dbJobCh: make(chan dbJob, 1)}
	s.maybeSubmitBuild(g, s.now())

	select {
	case job := <-s.dbJobCh:
		t.Fatalf("maybeSubmitBuild submitted a job (%+v) for an already-ready generation", job)
	default:
	}
	if g.packageDB.Status != evidence.DBStatusOK || g.packageDB.Kind != evidence.DBKindDpkg {
		t.Errorf("packageDB = %+v changed for an already-ready generation", g.packageDB)
	}
}

func TestBuildFromRoot_ParserConnectionLostIsFatal(t *testing.T) {
	sockFD, cleanup := spawnTestParser(t)
	defer cleanup()
	r, dir := openTestRoot(t)
	defer r.Close()
	writeTestFile(t, dir, "var/lib/dpkg/status", testDpkgStatus)

	// Kill only the raw socket; the parserhelper child eventually notices
	// EOF and exits on its own (cleanup still waits for/cleans that up).
	unix.Close(sockFD)

	g := newTestGenerationForIndex()
	res := buildFromRoot(sockFD, g.key(), r, g.parseFailed, 30*time.Second, time.Unix(1000, 0))
	if res.fatalErr == nil {
		t.Fatalf("buildFromRoot: got nil fatalErr, want one wrapping errParserConnectionLost (the parser process is gone)")
	}
	if !errors.Is(res.fatalErr, errParserConnectionLost) {
		t.Errorf("fatalErr = %v, want it to wrap errParserConnectionLost", res.fatalErr)
	}
}

// TestBuildFromRoot_NoFileListForMetapackage covers the no_file_list
// contract: a package the database's status file declares but whose own
// .list/.md5sums this build never read (a metapackage with no files of its
// own, or one this test simply never created a .list for) must be named in
// PackageDB.NoFileList — never silently dropped, and never confused with a
// package that has a normal, present file list.
func TestBuildFromRoot_NoFileListForMetapackage(t *testing.T) {
	sockFD, cleanup := spawnTestParser(t)
	defer cleanup()
	r, dir := openTestRoot(t)
	defer r.Close()
	writeTestFile(t, dir, "var/lib/dpkg/status", testDpkgStatus) // declares libssl3 and zlib1g
	writeTestFile(t, dir, "var/lib/dpkg/info/libssl3.list", testLibsslList)
	// Deliberately no zlib1g.list: zlib1g has no file list this build can see.

	g := newTestGenerationForIndex()
	interval := 30 * time.Second
	now := time.Unix(1000, 0)
	res := buildFromRoot(sockFD, g.key(), r, g.parseFailed, interval, now)
	applyBuild(g, res, interval, now)

	if g.idxState != indexReady {
		t.Fatalf("idxState = %v, want ready (no file ever failed — a missing .list for a package is not a parse failure)", g.idxState)
	}
	if len(g.parseFailed) != 0 {
		t.Errorf("parseFailed = %+v, want none — a package with no .list file at all is not a retryable failure", g.parseFailed)
	}
	if len(g.packageDB.NoFileList) != 1 || g.packageDB.NoFileList[0] != "zlib1g" {
		t.Errorf("NoFileList = %v, want [zlib1g]", g.packageDB.NoFileList)
	}
	for _, name := range g.packageDB.NoFileList {
		if name == "libssl3" {
			t.Errorf("libssl3 (which has a real, present .list file) must not appear in NoFileList")
		}
	}
}

// TestBuildFromRoot_NoFileListClearsOnceListAppears confirms NoFileList is
// recomputed from the current build each time, not merely appended to: once
// a previously-missing .list file becomes readable (the backoff for some
// unrelated file clears, triggering a rebuild that now finds it), the
// package must no longer be reported as having no file list.
func TestBuildFromRoot_NoFileListClearsOnceListAppears(t *testing.T) {
	sockFD, cleanup := spawnTestParser(t)
	defer cleanup()
	r, dir := openTestRoot(t)
	defer r.Close()
	writeTestFile(t, dir, "var/lib/dpkg/status", testDpkgStatus)
	writeTestFile(t, dir, "var/lib/dpkg/info/libssl3.list", testLibsslList)

	g := newTestGenerationForIndex()
	interval := 30 * time.Second
	now := time.Unix(1000, 0)
	res := buildFromRoot(sockFD, g.key(), r, g.parseFailed, interval, now)
	applyBuild(g, res, interval, now)
	if len(g.packageDB.NoFileList) != 1 || g.packageDB.NoFileList[0] != "zlib1g" {
		t.Fatalf("NoFileList after first build = %v, want [zlib1g]", g.packageDB.NoFileList)
	}

	// The file appears; force a rebuild the way loop would if this
	// generation were not already indexReady (a settled generation is
	// never rebuilt at all, which is exactly why this test forces past
	// that rather than relying on it).
	writeTestFile(t, dir, "var/lib/dpkg/info/zlib1g.list", testZlibList)
	g.idxState = indexIdle
	res2 := buildFromRoot(sockFD, g.key(), r, g.parseFailed, interval, now)
	applyBuild(g, res2, interval, now)
	if len(g.packageDB.NoFileList) != 0 {
		t.Errorf("NoFileList after the file appeared = %v, want none", g.packageDB.NoFileList)
	}
}

// TestNoFileList_AffectsJudgeOSPackageEligibility closes the loop between
// this Sensor's own NoFileList population and the main body's existing
// evidence.JudgeOSPackage: a Finding matching a NoFileList package name must
// come back unavailable(no_file_list), never a false not_observed — a
// package with no file list at all cannot honestly be claimed either
// "in use" or "not observed".
func TestNoFileList_AffectsJudgeOSPackageEligibility(t *testing.T) {
	sockFD, cleanup := spawnTestParser(t)
	defer cleanup()
	r, dir := openTestRoot(t)
	defer r.Close()
	writeTestFile(t, dir, "var/lib/dpkg/status", testDpkgStatus)
	writeTestFile(t, dir, "var/lib/dpkg/info/libssl3.list", testLibsslList)
	// No zlib1g.list: zlib1g ends up in NoFileList.

	g := newTestGenerationForIndex()
	interval := 30 * time.Second
	now := time.Unix(1000, 0)
	res := buildFromRoot(sockFD, g.key(), r, g.parseFailed, interval, now)
	applyBuild(g, res, interval, now)
	g.lastGoodSample(now, false)
	// This test is about NoFileList/JudgeOSPackage, not the separate
	// post-ready confirmation window derivePublishedState also requires
	// (see postIndexConfirmed's own doc comment) — set directly, standing
	// in for a sample that already confirmed the freshly-built index.
	g.postIndexConfirmed = true // -> StateObserving, since idxState is now ready too

	gen := g.toEvidence(false)
	if gen.State != evidence.StateObserving {
		t.Fatalf("generation state = %q, want observing (precondition for this test)", gen.State)
	}

	verdict := evidence.JudgeOSPackage(gen, inventory.PackageRef{
		Class: inventory.ClassOS, Name: "zlib1g", Version: "1:1.2.13.dfsg-1",
	})
	if verdict.Usage != evidence.UsageUnavailable || verdict.Reason != evidence.ReasonNoFileList {
		t.Errorf("JudgeOSPackage(zlib1g) = %+v, want Usage=unavailable Reason=no_file_list", verdict)
	}

	// A package that does have a file list, and was never observed running,
	// is genuinely not_observed — NoFileList must not overreach and swallow
	// this case too.
	verdict2 := evidence.JudgeOSPackage(gen, inventory.PackageRef{
		Class: inventory.ClassOS, Name: "libssl3", Version: "3.0.15-1~deb12u1",
	})
	if verdict2.Usage != evidence.UsageNotObserved {
		t.Errorf("JudgeOSPackage(libssl3) = %+v, want Usage=not_observed", verdict2)
	}
}
