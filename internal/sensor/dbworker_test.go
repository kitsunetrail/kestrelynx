package sensor

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/kitsunetrail/kestrelynx/internal/evidence"
)

// TestBuildContainerIndex_NonLastDisconnectAttributesToThatFile covers the
// non-Last half of the parser-disconnect attribution rule: when the
// connection breaks while sending a file that is not the one marked Last,
// the failure is attributed to that exact file's own identity — never to
// the build's own mandatory file, even when (as here) the file that failed
// is not the mandatory one at all.
func TestBuildContainerIndex_NonLastDisconnectAttributesToThatFile(t *testing.T) {
	sockFD, cleanup := spawnTestParser(t)
	defer cleanup()

	// list is sent first (non-Last); status second (Last) — the reverse of
	// gatherIndexFiles' own usual order, deliberately, so a test failure
	// here cannot be explained away by list and status coincidentally
	// naming the same file the way the mandatory one usually would.
	listFile := indexFile{Role: roleList, Name: "libssl3.list", Path: "/var/lib/dpkg/info/libssl3.list", Dev: "08:01", Inode: 111, Size: 42, File: pipeWith(t, testLibsslList)}
	statusFile := indexFile{Role: roleStatus, Name: "status", Path: "/var/lib/dpkg/status", Dev: "08:01", Inode: 222, Size: 99, File: pipeWith(t, testDpkgStatus)}

	// Kill the connection before any send at all: the very first send (list,
	// at position 0 of 2, so not Last) is what fails.
	unix.Close(sockFD)

	_, failedAt, lastWasFinal, softCapped, err := buildContainerIndex(sockFD, "test-gen-nonlast", evidence.DBKindDpkg, []indexFile{listFile, statusFile}, time.Now().Add(time.Hour))
	if softCapped {
		t.Fatalf("softCapped = true, want false")
	}
	if err == nil || !errors.Is(err, errParserConnectionLost) {
		t.Fatalf("err = %v, want one wrapping errParserConnectionLost", err)
	}
	if lastWasFinal {
		t.Errorf("lastWasFinal = true, want false — the failure was on the non-Last file")
	}
	if failedAt == nil || failedAt.Path != listFile.Path {
		t.Fatalf("failedAt = %+v, want the list file (%s)", failedAt, listFile.Path)
	}
}

// TestBuildFromRoot_LastDisconnectAttributesToMandatoryNotTheFileInFlight
// covers the Last half of the same rule: when the connection breaks while
// sending the file marked Last, the failure must be attributed to the
// build's own mandatory-file identity, never to whichever file was
// literally in flight — the true cause of a crash triggered by the Last
// request (the point pkgdb.Parse* actually runs) could be any earlier
// file's content. distroless has no single mandatory *file* (see
// mandatoryIdentity's own doc comment), so this is exercised with a
// single-file distroless build: the one file sent is trivially both
// "in flight" and "Last" (with two or more files, killing the connection
// before any send would only ever fail the non-Last file at index 0), yet
// the recorded failure identity must still be the synthetic
// status.d-directory identity (its own dev/inode, plus a fingerprint of
// its children as a change-detection proxy for Size — see
// distrolessChildrenFingerprint's own doc comment), not that one file's own
// real (dev, inode, size) — proving the code path taken is genuinely
// "Last -> mandatory identity", not merely "the file in flight, which
// happens to be the last one too".
func TestBuildFromRoot_LastDisconnectAttributesToMandatoryNotTheFileInFlight(t *testing.T) {
	sockFD, cleanup := spawnTestParser(t)
	defer cleanup()
	r, dir := openTestRoot(t)
	defer r.Close()
	writeTestFile(t, dir, "var/lib/dpkg/status.d/libssl3", "Package: libssl3\nVersion: 3.0.15\n")
	dirDev, dirIno, err := r.Stat("var/lib/dpkg/status.d")
	if err != nil {
		t.Fatalf("stat status.d: %v", err)
	}
	fileDev, fileIno, err := r.Stat("var/lib/dpkg/status.d/libssl3")
	if err != nil {
		t.Fatalf("stat control file: %v", err)
	}
	if fileIno == dirIno {
		t.Fatalf("test precondition: the control file and its directory must not share an inode")
	}
	wantFingerprint, fpOK := distrolessChildrenFingerprint(r, []candidateFile{
		{Role: roleControl, Name: "libssl3", Path: "var/lib/dpkg/status.d/libssl3", PkgName: "libssl3"},
	}, noDeadline())
	if !fpOK {
		t.Fatalf("distrolessChildrenFingerprint: ok = false, want true")
	}

	unix.Close(sockFD)

	res := buildFromRoot(sockFD, "test-gen-last", r, nil, 30*time.Second, time.Unix(1000, 0))
	if res.fatalErr == nil || !errors.Is(res.fatalErr, errParserConnectionLost) {
		t.Fatalf("fatalErr = %v, want one wrapping errParserConnectionLost", res.fatalErr)
	}
	if !res.hadFailure {
		t.Fatalf("hadFailure = false, want true")
	}
	id := res.failIdentity
	if id.input != "distroless_control" || id.path != "/var/lib/dpkg/status.d" {
		t.Fatalf("failIdentity input/path = %q/%q, want distroless_control//var/lib/dpkg/status.d", id.input, id.path)
	}
	if id.dev != dirDev || id.inode != dirIno {
		t.Errorf("failIdentity dev/inode = %s/%d, want the status.d directory's own %s/%d — not the control file's own (%s/%d)", id.dev, id.inode, dirDev, dirIno, fileDev, fileIno)
	}
	if id.size != wantFingerprint {
		t.Errorf("failIdentity size = %d, want %d (distrolessChildrenFingerprint over the one file this build actually saw under status.d)", id.size, wantFingerprint)
	}
}

// TestLedgerAndLookupPagination_ExceedsSingleResponseBudget covers paging
// through a real parser process for a response that cannot possibly fit in
// one message: 200 packages, each with an ~8 KiB version string, comfortably
// exceeding both maxResponsePayloadBytes (this package's own soft budget)
// and the hard 128 KiB response ceiling (internal/sensor/parser/run.go) if
// ever returned in one message. fetchLedger/lookupPaths must still retrieve
// every one of them by following More/HasMore to the end.
func TestLedgerAndLookupPagination_ExceedsSingleResponseBudget(t *testing.T) {
	sockFD, cleanup := spawnTestParser(t)
	defer cleanup()

	const packageCount = 200
	longVersion := strings.Repeat("v", 8*1024)

	var status strings.Builder
	var listFiles []indexFile
	paths := make([]string, 0, packageCount)
	for i := 0; i < packageCount; i++ {
		name := fmt.Sprintf("pkg%d", i)
		path := fmt.Sprintf("/usr/lib/%s/lib%s.so", name, name)
		fmt.Fprintf(&status, "Package: %s\nStatus: install ok installed\nVersion: %s\nArchitecture: amd64\n\n", name, longVersion)
		listFiles = append(listFiles, indexFile{Role: roleList, Name: name + ".list", File: pipeWith(t, "/.\n"+path+"\n")})
		paths = append(paths, path)
	}
	files := append([]indexFile{{Role: roleStatus, Name: "status", File: pipeWith(t, status.String())}}, listFiles...)

	gen := "test-gen-pagination"
	_, _, _, _, err := buildContainerIndex(sockFD, gen, evidence.DBKindDpkg, files, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatalf("buildContainerIndex: %v", err)
	}

	ledger, err := fetchLedger(sockFD, gen, noDeadline())
	if err != nil {
		t.Fatalf("fetchLedger: %v", err)
	}
	if len(ledger) != packageCount {
		t.Fatalf("len(ledger) = %d, want %d — pagination must retrieve every entry, not just the first page", len(ledger), packageCount)
	}
	seen := map[string]bool{}
	for _, l := range ledger {
		if len(l.Version) != len(longVersion) {
			t.Errorf("ledger entry %s has version length %d, want %d (an entry got corrupted or truncated across pages)", l.Name, len(l.Version), len(longVersion))
		}
		seen[l.Name] = true
	}
	if len(seen) != packageCount {
		t.Errorf("got %d distinct package names, want %d (pagination must not duplicate or skip)", len(seen), packageCount)
	}

	owners, err := lookupPaths(sockFD, gen, paths)
	if err != nil {
		t.Fatalf("lookupPaths: %v", err)
	}
	if len(owners) != packageCount {
		t.Fatalf("len(owners) = %d, want %d", len(owners), packageCount)
	}
	for _, p := range paths {
		o, ok := owners[p]
		if !ok || len(o.owners) != 1 {
			t.Errorf("owners[%s] = %+v (ok=%v), want exactly one owner", p, o, ok)
		}
	}
}

// TestDiscardUnconfirmedBuild_FatalErrSurvivesAnUnconfirmedIdentity covers
// handleBuildJob's own post-build identity re-check failing (job.rootPID's
// starttime no longer matches — the process behind that PID exited and was
// reused by something else during the build) at the same time buildFromRoot
// already reported the parser connection itself as lost: the shared parser
// dying must always reach loop (a fatal dbResult is what ends the whole
// Sensor session), regardless of whether this one generation's own
// attribution can still be trusted — the two are separate facts, and losing
// the fatal signal here would leave the next job to run against an
// already-dead connection, most likely recording an unrelated input as the
// cause instead.
func TestDiscardUnconfirmedBuild_FatalErrSurvivesAnUnconfirmedIdentity(t *testing.T) {
	res := dbResult{
		kind: dbJobBuild, genKey: "test-gen",
		fatalErr:   errParserConnectionLost,
		hadFailure: true,
		failIdentity: fileIdentity{
			input: "dpkg_status", path: "/var/lib/dpkg/status", dev: "08:01", inode: 42, size: 99,
		},
		// These would-be-successful fields must never survive an
		// unconfirmed identity, fatal or not.
		buildOK:        true,
		succeededFiles: []fileIdentity{{input: "dpkg_list", path: "/var/lib/dpkg/info/libssl3.list"}},
		noFileList:     []string{"some-metapackage"},
	}

	out := discardUnconfirmedBuild(res, "test-gen")

	if !errors.Is(out.fatalErr, errParserConnectionLost) {
		t.Fatalf("fatalErr = %v, want it to survive (wrapping errParserConnectionLost)", out.fatalErr)
	}
	if !out.hadFailure || out.failIdentity != res.failIdentity {
		t.Errorf("hadFailure/failIdentity = %v/%+v, want them carried through unchanged: true/%+v", out.hadFailure, out.failIdentity, res.failIdentity)
	}
	if out.buildOK {
		t.Errorf("buildOK = true, want false — this generation's own attribution is not confirmed and must not be trusted")
	}
	if out.succeededFiles != nil || out.noFileList != nil {
		t.Errorf("succeededFiles/noFileList = %+v/%+v, want both discarded", out.succeededFiles, out.noFileList)
	}
	if out.genKey != "test-gen" {
		t.Errorf("genKey = %q, want test-gen", out.genKey)
	}
}

// TestDiscardUnconfirmedBuild_NonFatalUnconfirmedIdentityBecomesNoChange is
// the fatal test's own control case: without a fatal error, an unconfirmed
// identity becomes a plain noChange, exactly as before — confirming the
// fatal-preserving branch above is not merely always keeping everything.
func TestDiscardUnconfirmedBuild_NonFatalUnconfirmedIdentityBecomesNoChange(t *testing.T) {
	res := dbResult{
		kind: dbJobBuild, genKey: "test-gen",
		buildOK:        true,
		succeededFiles: []fileIdentity{{input: "dpkg_list", path: "/var/lib/dpkg/info/libssl3.list"}},
	}

	out := discardUnconfirmedBuild(res, "test-gen")

	if out.fatalErr != nil {
		t.Errorf("fatalErr = %v, want nil", out.fatalErr)
	}
	if !out.noChange {
		t.Errorf("noChange = false, want true")
	}
	if out.buildOK || out.succeededFiles != nil {
		t.Errorf("buildOK/succeededFiles = %v/%+v, want both discarded", out.buildOK, out.succeededFiles)
	}
}

// TestStreamBuildFiles_DeadlineCheckedEvenWhenNothingIsEverPending covers
// the whole-build soft cap firing during a long run of candidates that
// never becomes "pending" at all (every one of them fails to open) — an
// earlier version of this function only checked the deadline when a
// candidate was already pending, so a container whose package-database
// directory names many entries that are all unreadable (a race with its
// own filesystem, say) could spend the whole budget on that alone without
// ever tripping the cap.
func TestStreamBuildFiles_DeadlineCheckedEvenWhenNothingIsEverPending(t *testing.T) {
	sockFD, cleanup := spawnTestParser(t)
	defer cleanup()
	r, _ := openTestRoot(t) // empty root: every candidate below fails to open
	defer r.Close()

	const candidateCount = 5
	candidates := make([]candidateFile, candidateCount)
	for i := range candidates {
		candidates[i] = candidateFile{
			Role: roleList, Name: fmt.Sprintf("missing%d.list", i),
			Path: fmt.Sprintf("var/lib/dpkg/info/missing%d.list", i), PkgName: fmt.Sprintf("missing%d", i),
		}
	}

	expired := time.Now().Add(-time.Second)
	out := streamBuildFiles(sockFD, r, "test-gen-deadline", evidence.DBKindDpkg, candidates, nil, time.Unix(1000, 0), expired)

	if !out.SoftCapped {
		t.Fatalf("SoftCapped = false, want true — the deadline had already passed before this call even started")
	}
	if len(out.Unreadable) == 0 || len(out.Unreadable) >= candidateCount {
		t.Errorf("len(Unreadable) = %d, want more than 0 (the first candidate always gets a chance) but fewer than all %d (the deadline must stop the run partway through, even though none of them were ever pending)", len(out.Unreadable), candidateCount)
	}
}

// TestFetchLedger_StopsPagingOncePastDeadline covers the whole-build soft
// cap applying to the ledger's own pagination too, not just file sending:
// an already-expired deadline must stop fetchLedger after at most one page
// (the first always gets a chance, the same guarantee every other step of
// this build makes), never silently paging through an entire, genuinely
// large ledger regardless of how long that takes.
func TestFetchLedger_StopsPagingOncePastDeadline(t *testing.T) {
	sockFD, cleanup := spawnTestParser(t)
	defer cleanup()

	const packageCount = 200
	longVersion := strings.Repeat("v", 8*1024)
	var status strings.Builder
	var listFiles []indexFile
	for i := 0; i < packageCount; i++ {
		name := fmt.Sprintf("pkg%d", i)
		fmt.Fprintf(&status, "Package: %s\nStatus: install ok installed\nVersion: %s\nArchitecture: amd64\n\n", name, longVersion)
		listFiles = append(listFiles, indexFile{Role: roleList, Name: name + ".list", File: pipeWith(t, "/.\n/usr/lib/"+name+"\n")})
	}
	files := append([]indexFile{{Role: roleStatus, Name: "status", File: pipeWith(t, status.String())}}, listFiles...)

	gen := "test-gen-ledger-deadline"
	if _, _, _, _, err := buildContainerIndex(sockFD, gen, evidence.DBKindDpkg, files, noDeadline()); err != nil {
		t.Fatalf("buildContainerIndex: %v", err)
	}

	expired := time.Now().Add(-time.Second)
	ledger, err := fetchLedger(sockFD, gen, expired)
	if err == nil {
		t.Fatalf("fetchLedger with an already-expired deadline returned no error (got %d entries), want a deadline error", len(ledger))
	}
	if errors.Is(err, errParserConnectionLost) {
		t.Errorf("err = %v wraps errParserConnectionLost, want a plain deadline error — the parser is still alive and responding normally", err)
	}
	if len(ledger) != 0 {
		t.Errorf("ledger = %d entries, want none returned alongside a deadline error", len(ledger))
	}
}

// TestDistrolessChildrenFingerprint_ReleasesBackoffOnContentChangeAlone
// covers the whole reason mandatoryIdentity's own synthetic distroless
// identity now includes a fingerprint of its children (name, dev, inode,
// size, mtime), not merely a file count: replacing one control file's own
// content in place — the file's name is unchanged, so the count of files
// under status.d never changes at all — must still be recognized as a
// different input and release an existing backoff immediately, rather than
// waiting out up to 24h of a schedule recorded against content that no
// longer even exists.
func TestDistrolessChildrenFingerprint_ReleasesBackoffOnContentChangeAlone(t *testing.T) {
	sockFD, cleanup := spawnTestParser(t)
	defer cleanup()
	r, dir := openTestRoot(t)
	defer r.Close()
	writeTestFile(t, dir, "var/lib/dpkg/status.d/libssl3", "Package: libssl3\nVersion: 3.0.15\n")

	g := newTestGenerationForIndex()
	interval := 30 * time.Second
	now := time.Unix(1000, 0)

	// Seed a ParseFailure against the file's current (soon-to-be-stale)
	// synthetic identity, with a retry_after far in the future.
	candidates := []candidateFile{{Role: roleControl, Name: "libssl3", Path: "var/lib/dpkg/status.d/libssl3", PkgName: "libssl3"}}
	originalFingerprint, fpOK := distrolessChildrenFingerprint(r, candidates, noDeadline())
	if !fpOK {
		t.Fatalf("distrolessChildrenFingerprint: ok = false, want true")
	}
	dirDev, dirIno, err := r.Stat("var/lib/dpkg/status.d")
	if err != nil {
		t.Fatalf("stat status.d: %v", err)
	}
	g.recordParseFailure("distroless_control", "/var/lib/dpkg/status.d", dirDev, dirIno, originalFingerprint, now, interval)
	if now.Add(9 * interval).After(g.nextRetryTime()) {
		t.Fatalf("test precondition: nextRetryTime() = %v, want well after now+9*interval", g.nextRetryTime())
	}

	// Replace the SAME-named file's own content in place, with a different
	// length (a plain version-string bump of the same length could
	// coincide with an unchanged mtime too, on a filesystem whose mtime
	// resolution is coarser than this test's own two writes land within —
	// the file count under status.d never changes either way, but this
	// choice guarantees the size itself does).
	laterButStillBackingOff := now.Add(time.Second)
	writeTestFile(t, dir, "var/lib/dpkg/status.d/libssl3", "Package: libssl3\nVersion: 3.0.15-2\n")
	newFingerprint, fpOK := distrolessChildrenFingerprint(r, candidates, noDeadline())
	if !fpOK {
		t.Fatalf("distrolessChildrenFingerprint: ok = false, want true")
	}
	if newFingerprint == originalFingerprint {
		t.Fatalf("test precondition: the fingerprint did not change after rewriting the file's own content")
	}

	res := buildFromRoot(sockFD, g.key(), r, g.parseFailed, interval, laterButStillBackingOff)
	applyBuild(g, res, interval, laterButStillBackingOff)

	if g.idxState != indexReady {
		t.Errorf("idxState = %v after the content-changed file was retried, want ready — the changed fingerprint should have released the old backoff immediately", g.idxState)
	}
	if len(g.parseFailed) != 0 {
		t.Errorf("parseFailed = %+v, want none — a successful retry clears the old (now-stale) synthetic failure", g.parseFailed)
	}
}

// TestDistrolessChildrenFingerprint_DeadlineStopsPartwayThrough covers the
// whole-build soft cap applying to fingerprinting itself: an already-
// expired deadline must stop the pass after at most one candidate (the
// first always gets a chance, the same guarantee every other deadline
// check in this build makes) and report ok = false, never silently opening
// every remaining candidate regardless of how long that takes — a
// distroless directory with many slow-to-open control files would
// otherwise be able to hold up every other generation's own build or
// lookup on the one dbworker goroutine.
func TestDistrolessChildrenFingerprint_DeadlineStopsPartwayThrough(t *testing.T) {
	r, dir := openTestRoot(t)
	defer r.Close()
	writeTestFile(t, dir, "var/lib/dpkg/status.d/a", "content-a")
	writeTestFile(t, dir, "var/lib/dpkg/status.d/b", "content-b")

	candidates := []candidateFile{
		{Role: roleControl, Name: "a", Path: "var/lib/dpkg/status.d/a", PkgName: "a"},
		{Role: roleControl, Name: "b", Path: "var/lib/dpkg/status.d/b", PkgName: "b"},
	}

	if _, ok := distrolessChildrenFingerprint(r, candidates, noDeadline()); !ok {
		t.Fatalf("ok = false with a generous deadline, want true")
	}
	if _, ok := distrolessChildrenFingerprint(r, candidates, time.Now().Add(-time.Second)); ok {
		t.Errorf("ok = true with an already-expired deadline and more than one candidate, want false — the deadline must stop the pass before the second candidate")
	}
}
