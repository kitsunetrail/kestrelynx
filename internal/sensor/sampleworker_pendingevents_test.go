package sensor

import (
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/kitsunetrail/kestrelynx/internal/evidence"
)

// statForPendingEventTest stats path (an absolute path under this process's
// own root, "/", which is what job.init being this real process resolves
// its root to) and returns the (dev, inode) a pendingEventItem would record
// for it — the same formatDevForCompare form runSampleWorker's own
// verification compares against.
func statForPendingEventTest(t *testing.T, path string) (dev string, ino uint64) {
	t.Helper()
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		t.Fatalf("stat %q: %v", path, err)
	}
	return formatDevForCompare(st.Dev), st.Ino
}

func TestRunSampleWorker_PendingEventVerifiedWhenStillMatching(t *testing.T) {
	pid := os.Getpid()
	starttime := mustStarttime(t, pid)

	f, err := os.CreateTemp("", "kestrelynx-pending-event-*")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	path := f.Name()
	f.Close()
	defer os.Remove(path)
	dev, ino := statForPendingEventTest(t, path)

	job := sampleJob{
		genKey:     "g",
		init:       InitProcess{PID: pid, Starttime: starttime},
		indexReady: true,
		now:        time.Now(),
		pendingEvents: []pendingEventItem{
			{seq: 1, path: path, dev: dev, inode: ino, kind: evidence.KindExecEvent, receivedAt: time.Now()},
		},
	}

	res := runSampleWorker(job)

	if len(res.lostEventItems) != 0 {
		t.Errorf("lostEventItems = %+v, want none", res.lostEventItems)
	}
	if len(res.verifiedEvents) != 1 || res.verifiedEvents[0].seq != 1 {
		t.Fatalf("verifiedEvents = %+v, want the one item (seq 1) confirmed", res.verifiedEvents)
	}
}

func TestRunSampleWorker_PendingEventLostWhenFileReplaced(t *testing.T) {
	pid := os.Getpid()
	starttime := mustStarttime(t, pid)

	f, err := os.CreateTemp("", "kestrelynx-pending-event-*")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	path := f.Name()
	f.Close()
	defer os.Remove(path)

	job := sampleJob{
		genKey:     "g",
		init:       InitProcess{PID: pid, Starttime: starttime},
		indexReady: true,
		now:        time.Now(),
		pendingEvents: []pendingEventItem{
			// A dev/inode that does not match the real file at path: the
			// same shape a file replaced since the event fired would
			// produce.
			{seq: 2, path: path, dev: "ff:ff", inode: 999999999, kind: evidence.KindExecEvent, receivedAt: time.Now()},
		},
	}

	res := runSampleWorker(job)

	if len(res.verifiedEvents) != 0 {
		t.Errorf("verifiedEvents = %+v, want none — dev/inode mismatch must never verify", res.verifiedEvents)
	}
	if len(res.lostEventItems) != 1 || res.lostEventItems[0].seq != 2 {
		t.Fatalf("lostEventItems = %+v, want the one mismatched item (seq 2)", res.lostEventItems)
	}
}

func TestRunSampleWorker_PendingEventLostWhenFileGone(t *testing.T) {
	pid := os.Getpid()
	starttime := mustStarttime(t, pid)

	job := sampleJob{
		genKey:     "g",
		init:       InitProcess{PID: pid, Starttime: starttime},
		indexReady: true,
		now:        time.Now(),
		pendingEvents: []pendingEventItem{
			{seq: 3, path: "/no/such/file/kestrelynx-test", dev: "1:1", inode: 1, kind: evidence.KindExecEvent, receivedAt: time.Now()},
		},
	}

	res := runSampleWorker(job)

	if len(res.verifiedEvents) != 0 {
		t.Errorf("verifiedEvents = %+v, want none for a path that no longer resolves", res.verifiedEvents)
	}
	if len(res.lostEventItems) != 1 {
		t.Fatalf("lostEventItems = %+v, want the one unresolvable item", res.lostEventItems)
	}
}

// TestRunSampleWorker_PendingEventLostWhenFileDeletedAndRecreated covers a
// pending event's own target file being deleted and recreated before the
// package index becomes ready to verify it: the original file the event was
// about is removed and a brand new file takes its place at the same path (a
// genuinely different inode) — unrelated to the file the eBPF event
// actually reported, so re-verification must reject it and count it as
// lost, never silently attribute the new file's identity to the old event.
func TestRunSampleWorker_PendingEventLostWhenFileDeletedAndRecreated(t *testing.T) {
	pid := os.Getpid()
	starttime := mustStarttime(t, pid)

	f, err := os.CreateTemp("", "kestrelynx-pending-event-*")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	path := f.Name()
	f.Close()
	defer os.Remove(path)
	originalDev, originalIno := statForPendingEventTest(t, path)

	// Keep the original inode alive through a second hard link, so the
	// filesystem cannot hand the very same inode number straight back to the
	// recreated file (ext4 readily reuses a just-freed inode).
	keep := path + ".keep"
	if err := os.Link(path, keep); err != nil {
		t.Fatalf("Link: %v", err)
	}
	defer os.Remove(keep)

	// Delete the original file and recreate a new one at the exact same
	// path — a genuinely different inode, the same shape unlink+recreate
	// (or an atomic rename-over-path) produces.
	if err := os.Remove(path); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	f2, err := os.Create(path)
	if err != nil {
		t.Fatalf("Create (recreate): %v", err)
	}
	f2.Close()
	newDev, newIno := statForPendingEventTest(t, path)
	if newDev == originalDev && newIno == originalIno {
		t.Fatalf("recreated file has the same (dev, inode) as the original (%s, %d) — this test needs a genuinely different inode to be meaningful", originalDev, originalIno)
	}

	job := sampleJob{
		genKey:     "g",
		init:       InitProcess{PID: pid, Starttime: starttime},
		indexReady: true,
		now:        time.Now(),
		pendingEvents: []pendingEventItem{
			// Still carries the *original* file's own identity, exactly as
			// the eBPF event reported it when it fired.
			{seq: 5, path: path, dev: originalDev, inode: originalIno, kind: evidence.KindExecEvent, receivedAt: time.Now()},
		},
	}

	res := runSampleWorker(job)

	if len(res.verifiedEvents) != 0 {
		t.Errorf("verifiedEvents = %+v, want none — the recreated file's own new identity must never verify the original event", res.verifiedEvents)
	}
	if len(res.lostEventItems) != 1 || res.lostEventItems[0].seq != 5 {
		t.Fatalf("lostEventItems = %+v, want the one item (seq 5) lost", res.lostEventItems)
	}
}

// TestRunSampleWorker_PendingEventVerifiedWhenRewrittenSameInode covers a
// pending event's own target file being rewritten in place (truncated and
// replaced without ever being removed or renamed) before the package index
// becomes ready to verify it: it keeps the same (dev, inode) the original
// eBPF event reported, so re-verification cannot tell the two apart — an
// accepted risk, this still verifies. This test locks that behavior in as
// intentional, not accidental: if a future change to the re-verification
// logic starts rejecting a same-inode rewrite, this test will say so.
func TestRunSampleWorker_PendingEventVerifiedWhenRewrittenSameInode(t *testing.T) {
	pid := os.Getpid()
	starttime := mustStarttime(t, pid)

	f, err := os.CreateTemp("", "kestrelynx-pending-event-*")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	path := f.Name()
	if _, err := f.WriteString("original content"); err != nil {
		t.Fatalf("WriteString: %v", err)
	}
	f.Close()
	defer os.Remove(path)
	dev, ino := statForPendingEventTest(t, path)

	// Rewritten in place: truncate and replace the content, but never
	// remove or rename the path — the same shape a package manager's
	// in-place file update, or a container process overwriting its own
	// config, can produce.
	if err := os.WriteFile(path, []byte("rewritten content, much longer than the original"), 0o644); err != nil {
		t.Fatalf("WriteFile (rewrite in place): %v", err)
	}
	rewrittenDev, rewrittenIno := statForPendingEventTest(t, path)
	if rewrittenDev != dev || rewrittenIno != ino {
		t.Fatalf("rewriting in place changed (dev, inode) from (%s, %d) to (%s, %d) — this test needs the identity to survive an in-place rewrite to be meaningful", dev, ino, rewrittenDev, rewrittenIno)
	}

	job := sampleJob{
		genKey:     "g",
		init:       InitProcess{PID: pid, Starttime: starttime},
		indexReady: true,
		now:        time.Now(),
		pendingEvents: []pendingEventItem{
			{seq: 6, path: path, dev: dev, inode: ino, kind: evidence.KindExecEvent, receivedAt: time.Now()},
		},
	}

	res := runSampleWorker(job)

	if len(res.lostEventItems) != 0 {
		t.Errorf("lostEventItems = %+v, want none — a same-inode in-place rewrite is accepted as verified (an accepted risk)", res.lostEventItems)
	}
	if len(res.verifiedEvents) != 1 || res.verifiedEvents[0].seq != 6 {
		t.Fatalf("verifiedEvents = %+v, want the one item (seq 6) verified", res.verifiedEvents)
	}
}

func TestRunSampleWorker_PendingEventStillPendingWithoutBasis(t *testing.T) {
	pid := os.Getpid()
	starttime := mustStarttime(t, pid)

	job := sampleJob{
		genKey: "g",
		// Deliberately wrong starttime: openRootWithBasis(job.init) then
		// fails, exactly like TestRunSampleWorker_UnresolvableBasisWithdrawsProcessEntirely.
		init:       InitProcess{PID: pid, Starttime: starttime + 1},
		indexReady: true,
		now:        time.Now(),
		pendingEvents: []pendingEventItem{
			{seq: 4, path: "/etc/hostname", dev: "1:1", inode: 1, receivedAt: time.Now()},
		},
	}

	res := runSampleWorker(job)

	if len(res.verifiedEvents) != 0 || len(res.lostEventItems) != 0 {
		t.Errorf("verifiedEvents=%v lostEventItems=%v, want both empty when no root could be opened at all", res.verifiedEvents, res.lostEventItems)
	}
	if len(res.stillPendingEvents) != 1 || res.stillPendingEvents[0].seq != 4 {
		t.Fatalf("stillPendingEvents = %+v, want the one item carried through unchanged", res.stillPendingEvents)
	}
}

func TestApplyEventVerificationResult_RemovesOnlyProcessedItems(t *testing.T) {
	s := newTestSessionForEvents()
	g := newGenerationState(evidence.ContainerRef{Runtime: "docker", ID: strings64('m')}, InitProcess{PID: 1, Starttime: 1}, s.now(), evidence.CoverageSinceStart)
	g.idxState = indexReady
	g.packageDB.Status = evidence.DBStatusOK
	s.generations[g.key()] = g

	g.recordPendingEvent(pendingEventItem{path: "/a", dev: "1:1", inode: 1, kind: evidence.KindExecEvent, receivedAt: s.now()})
	g.recordPendingEvent(pendingEventItem{path: "/b", dev: "1:1", inode: 2, kind: evidence.KindExecEvent, receivedAt: s.now()})
	verified := g.pendingEvents[0] // "/a"
	lost := g.pendingEvents[1]     // "/b"
	// A brand new event arrives concurrently (simulating one that queued
	// while the sample worker whose result is about to be applied was
	// already in flight) and must survive being untouched by this apply.
	g.recordPendingEvent(pendingEventItem{path: "/c", dev: "1:1", inode: 3, kind: evidence.KindExecEvent, receivedAt: s.now()})

	res := sampleResult{
		verifiedEvents: []pendingEventItem{verified},
		lostEventItems: []pendingEventItem{lost},
	}
	s.applyEventVerificationResult(g, res)

	if len(g.pendingEvents) != 1 || g.pendingEvents[0].path != "/c" {
		t.Fatalf("pendingEvents = %+v, want only /c (the concurrently-arrived item) left", g.pendingEvents)
	}
	if g.eventsLost != 1 {
		t.Errorf("eventsLost = %d, want 1 (the one lostEventItems entry)", g.eventsLost)
	}
	// recordExecutable is not applyEventVerificationResult's own job (it
	// already happened, if at all, when the event was first dispatched —
	// see dispatchUsageEvent's own doc comment); this test only exercises
	// the OS-package candidate submission and pendingEvents bookkeeping.
	select {
	case job := <-s.dbJobCh:
		if len(job.paths) != 1 || job.paths[0] != "/a" {
			t.Errorf("submitted dbJob.paths = %v, want [/a]", job.paths)
		}
	default:
		t.Fatal("no dbJob submitted for the verified pending event")
	}
}

// TestApplyEventVerificationResult_IgnoresResultPastItsOwnTTL confirms that
// a pendingEventItem still physically present in g.pendingEvents (the
// periodic expirePendingEvents sweep has not reached it yet) but already
// past its own pendingEventTTL by the time a
// worker's verification result for it is applied must not have that result
// adopted — a worker dispatched just before the item's own TTL, but only
// answering after crossing it, must not resurrect a stale verification as if
// it arrived in time. The item stays in g.pendingEvents for the next
// expirePendingEvents sweep to count as lost exactly once, instead.
func TestApplyEventVerificationResult_IgnoresResultPastItsOwnTTL(t *testing.T) {
	s := newTestSessionForEvents()
	g := newGenerationState(evidence.ContainerRef{Runtime: "docker", ID: strings64('n')}, InitProcess{PID: 1, Starttime: 1}, s.now(), evidence.CoverageSinceStart)
	g.idxState = indexReady
	g.packageDB.Status = evidence.DBStatusOK
	s.generations[g.key()] = g

	// receivedAt is already well past pendingEventTTL as of s.now(), but the
	// item has not yet been swept by expirePendingEvents (nothing has called
	// it in this test).
	g.recordPendingEvent(pendingEventItem{path: "/expired", dev: "1:1", inode: 1, kind: evidence.KindExecEvent, receivedAt: s.now().Add(-pendingEventTTL - time.Second)})
	expired := g.pendingEvents[0]

	res := sampleResult{verifiedEvents: []pendingEventItem{expired}}
	s.applyEventVerificationResult(g, res)

	if len(g.pendingEvents) != 1 {
		t.Fatalf("pendingEvents = %+v, want the expired item left in place for expirePendingEvents to count", g.pendingEvents)
	}
	select {
	case job := <-s.dbJobCh:
		t.Fatalf("dbJob %+v submitted for an already-expired verification result, want none", job)
	default:
	}

	// The next discovery pass' own expirePendingEvents sweep is what
	// actually counts this as lost.
	g.expirePendingEvents(s.now())
	if g.eventsLost != 1 {
		t.Errorf("eventsLost = %d, want 1 (counted once, by expirePendingEvents, not twice)", g.eventsLost)
	}
}
