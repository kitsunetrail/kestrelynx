package sensor

import (
	"context"
	"fmt"
	"os"
	"sort"
	"time"

	"golang.org/x/sys/unix"

	"github.com/kitsunetrail/kestrelynx/internal/evidence"
	"github.com/kitsunetrail/kestrelynx/internal/sensor/ebpf"
	"github.com/kitsunetrail/kestrelynx/internal/sensor/procfs"
	"github.com/kitsunetrail/kestrelynx/internal/sensor/sandbox"
)

// Config is `kestrelynx sensor`'s own configuration, gathered from CLI
// flags (the Sensor never reads config.yml).
type Config struct {
	EvidenceDir      string
	Interval         time.Duration
	ExcludeIDs       []string
	RequireIsolation bool
	// RingBufferBytes overrides kl_events' own ring buffer size (see
	// ebpf.LoadWithRingBufferBytes); zero means "use ebpf.DefaultRingBufferBytes",
	// the same value Load itself always used before this field existed. Set
	// from the Sensor's own --ring-buffer-bytes flag, which cmd/kestrelynx
	// validates (ebpf.ValidateRingBufferBytes) before Run ever starts.
	RingBufferBytes uint32
}

const (
	// sampleWorkerBudget is how long loop waits for one generation's sample
	// worker before giving up on it for this round (see sampleEnvelope's
	// own doc comment): a slow or stuck container's own worker must never
	// hold up any other container's sampling or the heartbeat.
	sampleWorkerBudget = 5 * time.Second
	// maxConcurrentSampleWorkers bounds how many sample workers run at
	// once, including ones already abandoned to their own budget (an
	// abandoned worker keeps counting against this until it actually
	// finishes — see the ledger fields on generationState and Session).
	// Counted across the whole Session's lifetime, not reset every sample.
	maxConcurrentSampleWorkers = 8
	// discoveryStaleAfter bounds how long loop waits for one discovery
	// pass before allowing a new one to start anyway — discovery has no
	// way to be canceled once started (a plain scanProcs() call), so this
	// is a last resort against a single wedged discovery goroutine
	// permanently blocking every future one.
	discoveryStaleAfter = 60 * time.Second
	// buildSoftStall is how long the oldest still-outstanding build job
	// (queued or building) may wait before loop stops submitting new ones
	// and reports SensorDegraded — existing jobs still in flight are not
	// themselves affected.
	buildSoftStall = 5 * time.Minute
	// writeFailureDegradeThreshold is how many consecutive evidence-write
	// failures in a row make loop report SensorDegraded.
	writeFailureDegradeThreshold = 3
	// heartbeatInterval is the write contract's own ceiling: a snapshot is
	// written at least this often even when --interval is longer — see
	// heartbeatPeriod and loop's own doc comment for the full rule (the
	// actual ticker period is whichever of --interval and this is
	// shorter).
	heartbeatInterval = 60 * time.Second
	// dbJobChCapacity and sampleResultChCapacity are sized generously
	// enough that loop's own sends to them are for all practical purposes
	// never blocking (see submitDBJob's own doc comment on what happens on
	// the rare occasion one is actually full).
	dbJobChCapacity = 4096
	// lookupWriteWaitBudget bounds how long requestWrite holds a snapshot
	// write back while some live generation has a package-database lookup
	// outstanding (g.pendingLookup != nil), waiting for it to answer, before
	// giving up and writing anyway — see requestWrite's own doc comment. An
	// ordinary lookup round trip (a single local dbworker goroutine) is
	// expected to resolve in well under this; ASSUMED: this value needs
	// tuning once real lookup latency under concurrent build load is
	// measured in production, the same way pendingEventTTL's own doc
	// comment already flags for that queue.
	lookupWriteWaitBudget = 2 * time.Second
)

// heartbeatPeriod returns whichever is shorter of interval and floor: the
// heartbeat ticker's own period never exceeds --interval itself, only
// floor (heartbeatEvery, 60s in production) once --interval grows past it.
// This keeps heartbeat_at advancing at least as often as
// evidence.StalenessThreshold's own interval-derived floor assumes a
// healthy Sensor would — see loop's own doc comment for why a slower
// cadence would risk a false "stale" verdict purely from how rarely this
// Sensor writes, independent of anything actually being wrong.
func heartbeatPeriod(interval, floor time.Duration) time.Duration {
	if interval < floor {
		return interval
	}
	return floor
}

// Session is the Sensor's observer. Every mutable field below is touched
// only by loop's own goroutine (run by (*Session).loop): a sample worker or
// the dbworker/writer goroutines never hold a pointer into a Session or a
// generationState at all, exchanging only immutable job/result values with
// loop over channels instead. Nothing here needs a mutex.
type Session struct {
	cfg Config
	now func() time.Time
	// heartbeatEvery is heartbeatInterval's value in production (Run sets
	// it); overridable in tests so the heartbeat ticker path can be
	// exercised without a real 60-second wait.
	heartbeatEvery time.Duration
	// sampleTimeout is sampleWorkerBudget's value in production (Run sets
	// it); overridable in tests so the worker-abandonment path can be
	// exercised without a real 5-second wait.
	sampleTimeout time.Duration
	// lookupWaitBudget is lookupWriteWaitBudget's value in production (Run
	// sets it); overridable in tests so requestWrite's own deferred-write
	// path can be exercised without a real 2-second wait. Left at its zero
	// value by a test that constructs a Session directly (bypassing Run) is
	// harmless as long as that test never gives a sample worker any
	// candidates at all: with nothing ever setting a generation's own
	// pendingLookup, anyPendingLookupOutstanding is always false and
	// requestWrite always takes its immediate-write branch regardless of
	// this field's value.
	lookupWaitBudget time.Duration
	// sampleFn is runSampleWorker in production (the zero value); a test
	// double in tests that need to control a worker's own timing without
	// depending on real procfs state.
	sampleFn func(sampleJob) sampleResult
	// discoverFn is loop's own discovery pass in production (the zero
	// value: scanProcs()+groupContainers against this process's real
	// /proc — see defaultDiscover); a test double in tests that need loop
	// to react to a synthetic set of container groups, since a real
	// discovery pass can never be made to recognize a container that does
	// not actually exist on this machine. Leaving it nil never changes
	// production behavior at all. The second return (cgroup seeds — see
	// computeCgroupSeeds) is nil from every existing test double, which is
	// fine: a test using this seam synthesizes containerGroup directly and
	// has no real /proc cgroup tree to seed from anyway. The third return
	// (a non-ENOENT cgroup stat failure count — see computeCgroupSeeds' own
	// doc comment) is 0 from every existing test double, for the same reason.
	discoverFn func() (map[string]containerGroup, []cgroupSeed, int, error)
	// genConfirmFn is confirmGenerationAlive in production (the zero
	// value); a test double in tests that need genconfirm.go's own
	// liveness check to answer deterministically for a synthetic
	// InitProcess (one that does not actually correspond to a running
	// process on this machine) — the same seam sampleFn/discoverFn already
	// give a sample worker and a discovery pass.
	genConfirmFn func(pid int, starttime int64) bool

	evidenceFD       int
	sessionID        string
	sessionStartedAt time.Time
	isolation        evidence.Isolation
	ownContainerID   string
	ownUserNS        string

	parserPID int

	ebpfHandle       *ebpf.Handle
	eventsStatus     evidence.EventsStatus
	eventsReason     evidence.EventsReason
	eventsAttachedAt time.Time
	eventsLost       int64
	// attachedAtBootTicks is the boot-relative clock-tick instant eBPF
	// attached this session (bootTicksNow, captured once at startup) — only
	// meaningful when eventsStatus is EventsOK. initialEventsCoverage
	// compares a freshly discovered generation's own init.Starttime against
	// this to decide since_start vs. partial (see that function's own doc
	// comment).
	attachedAtBootTicks int64

	// eventCh carries every decoded eBPF event from the dedicated reader
	// goroutine (runEventReader) to loop, which is the only goroutine that
	// ever applies one (events.go's applyEvent) — the same
	// receive-only-goroutine-feeds-loop-a-channel shape sampleResCh and
	// dbResultCh already use for a sample worker and the dbworker.
	eventCh chan ebpf.Event
	// cgroupRoute, pathIdx and pendingRouteEvents are loop's own eBPF event-
	// routing state — see cgroupmap.go and events.go for what each does.
	// Read and written only by loop's own goroutine, exactly like
	// s.generations.
	cgroupRoute        cgroupRoute
	pathIdx            pathIndex
	pendingRouteEvents []pendingRouteEvent
	// cgroupRouteContradictions counts how many times reconcileCgroupRoute
	// saw a discovery-computed seed classify a cgroup ID differently than
	// cgroupRoute already had it classified — see that method's own doc
	// comment. Purely diagnostic (not part of the evidence schema): this
	// should never happen for a real cgroup ID, so a nonzero value means
	// something upstream needs investigating, not that this session's own
	// current attribution is wrong (the newest seed's own classification is
	// always adopted regardless).
	cgroupRouteContradictions int64
	// pathIndexKernelDeleteFailures counts how many times
	// deletePathSeenKey's own ebpf.Handle.DeletePathSeen call returned an
	// error other than "key not found" (already-evicted-by-the-kernel-itself
	// is expected and not counted here — see that method's own doc
	// comment). Purely diagnostic (not part of the evidence schema): a
	// failure here only means one evicted path's own kernel-side suppression
	// entry was not cleared early, which self-corrects once
	// bpf/kestrelynx.c's own KL_DEDUP_WINDOW_NS elapses regardless, not that
	// this session's own current attribution is wrong.
	pathIndexKernelDeleteFailures int64
	// ownUserNSInode is this observer's own user namespace's inode number,
	// resolved once at startup (parseNSInode on s.ownUserNS) — the event-
	// derived equivalent of ownUserNS itself, which a sampled process's own
	// /proc/<pid>/ns/user link is compared against instead (see
	// eventInDistinctUserNS vs. ownsDistinctUserNS).
	ownUserNSInode uint32
	// hostMntNSID is the real host's own (PID 1's) mount namespace inode
	// number, resolved once at startup by reading /proc/1/ns/mnt — reliably
	// the actual host's own PID 1 only because this Sensor's own deployment
	// always runs with pid: host (see docker-compose.sensor.yml), which
	// shares the PID namespace but never the mount one, so this Sensor's own
	// process still has its own, distinct mount namespace even though
	// /proc/1 names the real host init. Left 0 if that read fails for any
	// reason (e.g. pid: host is somehow not in effect), which
	// resolveEventGeneration's own check treats as "no host mount namespace
	// known", never matching anything. See resolveEventGeneration's own doc
	// comment for what this is used for.
	hostMntNSID uint32

	// hostRootDev/hostRootIno identify the real host's own (PID 1's) root
	// directory, resolved once at startup the same way a generation's own
	// root identity is (major:minor, inode). A process whose root is still
	// the host's is container-runtime setup that has not switched into the
	// container's root filesystem yet (runc's own setup stages run in the
	// container's cgroup before pivot_root), never a container's own
	// workload: none of the files it runs can be the container image's own
	// packages, so its events are discarded before routing (see
	// applyUsageEvent). Empty when PID 1's root could not be resolved, in
	// which case nothing is discarded on this basis.
	hostRootDev string
	hostRootIno uint64
	// lastLostByCgroup and lastLostFallback are reconcileEventLossCounters'
	// own memory of the eBPF ring buffer's loss counters as of the last time
	// it ran, so it can attribute only the increase since then rather than
	// re-attributing every loss on every call.
	lastLostByCgroup map[uint64]uint64
	lastLostFallback uint64

	// lastLossCounterReadAt is when reconcileEventLossCounters last read the
	// kernel loss counters (zero before the first read). Loss found in the
	// next read happened after this instant, so a generation that ended
	// before it cannot own that loss; one that ended after it still can.
	lastLossCounterReadAt time.Time
	// pendingLossDeltas holds every per-cgroup ring-buffer loss delta
	// (attributeEventLossDeltas) this session could not yet resolve to a
	// specific generation — see pendingLossDelta's own doc comment. Read and
	// written only by loop's own goroutine, exactly like pendingRouteEvents.
	pendingLossDeltas []pendingLossDelta
	// forcedGapWatermarkTicks/forcedGapWatermarkSet are applyForcedGapEviction's
	// own record of the most recent boot-relative instant (in clock ticks)
	// this session was ever forced to evict a not-yet-classified loss from a
	// pending queue without waiting for discovery — a high-water mark, never
	// decreased. forcedGapWatermarkSet is false until the first such
	// eviction ever happens (0 is a real, reachable tick value very early in
	// a real boot, so it cannot double as its own "unset" sentinel). See
	// initialEventsCoverage's own use of this pair.
	forcedGapWatermarkTicks int64
	forcedGapWatermarkSet   bool
	// cgroupStatFailures is the running total of every computeCgroupSeeds
	// stat(2) failure other than ENOENT (see that function's own doc
	// comment) — diagnostic only, never published to the evidence file.
	// cgroupStatFailureLogged gates the one-line stderr log to its first
	// occurrence only, so a permission problem affecting the same cgroup
	// tree every discovery pass does not spam this Sensor's own log once
	// per pass for the rest of the session.
	cgroupStatFailures      int64
	cgroupStatFailureLogged bool
	// unattributedEventsLost is recordContainerGapLoss's own running total:
	// one per routeGapLoss event (a proven, permanent, container-scoped gap
	// — see that function's own doc comment). Folded into s.eventsLost by
	// buildSnapshot, alongside reconcileEventLossCounters' own kernel-side
	// total. Every other former source of this counter (a pendingRouteEvent
	// evicted/expired without resolving, and genconfirm.go's own pool-
	// capacity paths) now uses classifyUnattributedExpiry's own three-tier
	// rule, downgradeContainerPartial, or recordUnclassifiedEventLoss
	// instead, none of which touch this field.
	unattributedEventsLost int64
	// eventsUnclassified is recordUnclassifiedEventLoss's own running total:
	// every eBPF usage event (or aggregate kernel loss-counter delta) this
	// session could neither resolve to a specific generation nor even
	// narrow to one plausible candidate by mount namespace
	// (classifyUnattributedExpiry's own tier 3) once given a fair chance —
	// at least one discovery pass that started after the event was
	// received must have already completed (reconcileCgroupRoute is now
	// the primary way a cgroup ever gets classified at all on a host where
	// tp_btf/cgroup_mkdir's own event delivery cannot be relied on — see
	// cgroupRoute's own doc comment) before an event may count here at all.
	// Deliberately never folded into s.eventsLost or used to downgrade any
	// generation's own eventsCoverage (see classifyUnattributedExpiry's own
	// doc comment on why mixing the two would make an otherwise-healthy
	// generation's own since_start/lost=0 evidence look self-contradictory)
	// — reported to the evidence file as its own field
	// (SensorInfo.Events.Unclassified) instead, precisely so a high value
	// here is itself the operator-visible signal that cgroup classification
	// is not keeping up, without silently corrupting any generation's own
	// coverage.
	eventsUnclassified int64
	// lastCompletedDiscoveryStartedAt is the most recent discoveryResult
	// applyDiscoveryResult actually applied (disc.err == nil, disc.gen still
	// current) own "as-of" instant (disc.now — captured right before that
	// pass's own scanProcs()+computeCgroupSeeds() ran, not when its result
	// was applied) — classifyUnattributedExpiry's own tier-3 readiness
	// check compares a pending item's own receivedAt against this: only
	// once a discovery pass that started after an item was received has
	// itself completed can that item safely be given up on as unclassified,
	// since an earlier discovery pass's own seeds could not possibly have
	// covered a cgroup that did not even exist yet when it ran.
	lastCompletedDiscoveryStartedAt time.Time
	// pathResolveCh carries every resolvePathAsync answer (a path-unknown
	// success event's own live-/proc/<pid>/maps fallback lookup) back to
	// loop, the only goroutine that ever applies one (pathresolve.go's
	// applyPathResolveResult) — the same receive-only-goroutine-feeds-loop-
	// a-channel shape eventCh/sampleResCh/dbResultCh already use.
	pathResolveCh chan pathResolveResult
	// pathResolveInFlight and pathResolveQueue are the maps-fallback worker
	// pool's own bookkeeping (pathresolve.go's submitPathResolveRequest/
	// dispatchPathResolve/applyPathResolveResult) — at most
	// maxConcurrentPathResolves goroutines running at once, with
	// maxQueuedPathResolves more waiting for a slot.
	pathResolveInFlight int
	pathResolveQueue    []pathResolveRequest

	// genConfirmCh carries every confirmGenerationAlive answer (genconfirm.go)
	// back to loop, the only goroutine that ever applies one
	// (applyGenConfirmResult) — the same receive-only-goroutine-feeds-loop-a-
	// channel shape eventCh/pathResolveCh/sampleResCh/dbResultCh already use.
	// genConfirmInFlight and genConfirmQueue are that pool's own bookkeeping
	// (submitGenConfirmRequest/dispatchGenConfirm/applyGenConfirmResult) — at
	// most maxConcurrentGenConfirms goroutines running at once, with
	// maxQueuedGenConfirms more waiting for a slot.
	genConfirmCh       chan genConfirmResult
	genConfirmInFlight int
	genConfirmQueue    []genConfirmRequest
	// lastEarlyDiscoveryRequest is requestEarlyDiscovery's own memory of the
	// last time it actually started a discovery pass early (outside
	// sampleTicker's own cadence) on an event handler's behalf — the rate
	// limit that keeps a generation stuck in routeUnresolved/routeUnconfirmed
	// from triggering a fresh /proc scan on every single retry.
	lastEarlyDiscoveryRequest time.Time

	generations map[string]*generationState

	// aliveSampleWorkers is the ledger's own count of sample workers loop
	// has started but has not yet heard sampleEnvFinished for (whether they
	// answered in time, were abandoned as stalled, or are still running
	// past their own budget) — see maxConcurrentSampleWorkers.
	aliveSampleWorkers int

	discoveryInFlight bool
	discoveryStarted  time.Time
	// discoveryGen counts every discovery ever started, so a late result
	// from one loop has since given up waiting for can be told apart from
	// the current one — see discoveryResult's own doc comment.
	discoveryGen int
	// discoveryCh carries every discovery pass' own result back to loop —
	// a Session field (not a local variable inside loop, as it used to be)
	// so that resolveEventGeneration's own "could not confirm the candidate
	// generation is still alive" case (events.go) can call s.startDiscovery
	// directly, outside sampleTicker's own cadence, without loop itself
	// needing to hand it anything.
	discoveryCh chan discoveryResult

	dbJobCh     chan dbJob
	dbResultCh  chan dbResult
	sampleResCh chan sampleEnvelope

	writerCh       chan writerJob
	writerReportCh chan writeReport

	// writePending and writeDelayCh are requestWrite's own bookkeeping for a
	// snapshot write held back while some live generation has a package-
	// database lookup outstanding — see that method's own doc comment.
	// writeDelayCh is nil whenever writePending is false; loop's own select
	// simply never fires a nil channel's case, which is exactly "no write is
	// currently deferred".
	writePending bool
	writeDelayCh <-chan time.Time

	buildQueueStalled  bool
	writeFailureStreak int
	lastWriteModified  bool

	isolationStatus    evidence.SensorStatus
	capSysPtraceOK     bool
	capDacReadSearchOK bool
}

// Run performs the full startup sequence and then drives the sampling loop
// until ctx is canceled or the parser connection fails unrecoverably (in
// which case Run returns a non-nil error, and the caller — cmd/kestrelynx —
// is expected to exit non-zero so the container's restart policy brings up
// a fresh Sensor session).
func Run(ctx context.Context, cfg Config) error {
	s := &Session{
		cfg: cfg, now: time.Now, heartbeatEvery: heartbeatInterval, sampleTimeout: sampleWorkerBudget, lookupWaitBudget: lookupWriteWaitBudget, generations: map[string]*generationState{},
		dbJobCh: make(chan dbJob, dbJobChCapacity), dbResultCh: make(chan dbResult, dbJobChCapacity),
		sampleResCh:    make(chan sampleEnvelope, maxConcurrentSampleWorkers*2),
		writerCh:       make(chan writerJob, 1),
		writerReportCh: make(chan writeReport, 1),
		eventCh:        make(chan ebpf.Event, eventChCapacity),
		pathResolveCh:  make(chan pathResolveResult, pathResolveChCapacity),
		genConfirmCh:   make(chan genConfirmResult, genConfirmChCapacity),
		discoveryCh:    make(chan discoveryResult, 1),
	}
	return s.run(ctx)
}

func (s *Session) run(ctx context.Context) error {
	s.sessionID = newSessionID()
	s.sessionStartedAt = s.now()

	// --- 1. Raise transient capabilities from the file capability's
	// permitted set.
	caps, _ := RaiseTransientCapabilities()
	s.capSysPtraceOK = caps["CAP_SYS_PTRACE"].RaisedEffective
	s.capDacReadSearchOK = caps["CAP_DAC_READ_SEARCH"].RaisedEffective

	// --- 2. NO_NEW_PRIVS + non-dumpable on every thread.
	nnpErr := sandbox.SetNoNewPrivsAll()
	dumpableErr := sandbox.SetNonDumpable()

	// --- 3. Open the evidence file (fixed name, read/write, created if
	// absent) before anything touches untrusted input, and before this
	// process's own filter (installed at step 7) would deny the open.
	if err := os.MkdirAll(s.cfg.EvidenceDir, 0o755); err != nil {
		return fmt.Errorf("sensor: create evidence dir: %w", err)
	}
	evidencePath := s.cfg.EvidenceDir + "/" + evidence.FileName
	// 0644 (world-readable), not merely group-readable: the main body's own
	// container is not given a coordinated UID or GID with this one (its own
	// compose service sets no `user:` at all, so it runs as whatever its
	// image's default is), and the shared volume is mounted only into the
	// Sensor and, opt-in, the main body — nothing else. Given that, 0644
	// lets the main body read regardless of which UID it runs as, and the
	// volume's own mount list is what actually bounds who else can reach the
	// file, not its mode. The file is still only writable by the Sensor's
	// own UID, and it carries nothing secret the way config.yml's token
	// does.
	fd, err := unix.Open(evidencePath, unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC, 0o644)
	if err != nil {
		return fmt.Errorf("sensor: open evidence file: %w", err)
	}
	s.evidenceFD = fd

	// The writer goroutine starts as soon as the evidence fd exists, well
	// before the isolation self-check below — an isolation_failed or
	// --require-isolation stop is exactly the case this Sensor most needs
	// to report, and it can only do that if something is already listening
	// on s.writerCh by the time it tries to.
	go runWriter(s.evidenceFD, s.writerCh, s.writerReportCh)

	// This observer's own cgroup ID (needed for eBPF self-exclusion) and
	// container ID (to exclude the Sensor's own container from discovery).
	cgInfo, cgID, cgErr := OwnCgroupInfo()
	if err := hostCgroupNamespaceError(cgInfo); err != nil {
		return err
	}
	s.ownContainerID = ownContainerID()
	s.ownUserNS, _ = ownNamespaceLink("user")
	s.ownUserNSInode, _ = parseUserNSInode(s.ownUserNS)
	if hostMntNS, err := os.Readlink("/proc/1/ns/mnt"); err == nil {
		s.hostMntNSID, _ = parseMntNSInode(hostMntNS)
	}
	var hostRoot unix.Stat_t
	if err := unix.Stat("/proc/1/root/", &hostRoot); err == nil {
		s.hostRootDev, s.hostRootIno = formatDevForCompare(hostRoot.Dev), hostRoot.Ino
	}

	// --- 4. Load and attach eBPF before dropping CAP_BPF/CAP_PERFMON.
	btfReadable := false
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err == nil {
		btfReadable = true
	}
	ringBufferBytes := s.cfg.RingBufferBytes
	if ringBufferBytes == 0 {
		ringBufferBytes = ebpf.DefaultRingBufferBytes
	}
	var loadErr error
	if cgErr == nil {
		s.ebpfHandle, loadErr = ebpf.LoadWithRingBufferBytes(cgID, uint64(s.hostMntNSID), ringBufferBytes)
	} else {
		loadErr = cgErr
	}
	if s.ebpfHandle != nil {
		// Closing here unblocks runEventReader's own pending h.Read() (see
		// that function's own doc comment) on every path out of run(),
		// including the early isolation-failure return below — the
		// (*ebpf.Handle).Close doc comment guarantees this is safe even
		// when nothing has actually attached a reader goroutine yet, and
		// buildSnapshot's own reconcileEventLossCounters call always runs,
		// and completes, before this deferred Close (loop's own return
		// path calls writeFinalSnapshotAndWait, which calls buildSnapshot,
		// strictly before loop itself returns to here).
		defer s.ebpfHandle.Close()
	}
	s.eventsStatus, s.eventsReason = ClassifyEBPFStatus(cgErr, btfReadable,
		caps["CAP_BPF"].RaisedEffective, caps["CAP_PERFMON"].RaisedEffective, loadErr)
	if s.eventsStatus == evidence.EventsOK {
		// Seeded once, here, from the host's own cgroup2 tree: every
		// cgroup that already exists when eBPF just attached (container or
		// not) needs to be classified immediately, not only once its own
		// cgroup_mkdir event (which will never come for one that already
		// existed before this Sensor session started) happens to arrive.
		// See scanCgroupTree's own doc comment. A failed or truncated scan
		// means this table cannot be trusted to have fully classified the
		// host's own cgroup tree, so events.status must not report ok over
		// it — attributing an event via a table that silently missed part
		// of the tree risks exactly the misattribution/leaked-loss-count
		// problems a clean classification exists to prevent.
		var scanTruncated, scanFailed bool
		s.cgroupRoute, scanTruncated, scanFailed = scanCgroupTree(cgroupHostRoot)
		if scanTruncated || scanFailed {
			s.eventsStatus, s.eventsReason = evidence.EventsUnavailable, evidence.EventsReasonAttachFailed
		}
	}
	if s.eventsStatus == evidence.EventsOK {
		s.eventsAttachedAt = s.now()
		if ticks, err := bootTicksNow(); err == nil {
			s.attachedAtBootTicks = ticks
		} else {
			// Without a boot-relative reference point, no generation
			// discovered from here on could be correctly classified
			// since_start vs. partial (initialEventsCoverage) — safer to
			// report events as unavailable than to guess.
			s.eventsStatus, s.eventsReason = evidence.EventsUnavailable, evidence.EventsReasonAttachFailed
		}
	}
	if s.eventsStatus == evidence.EventsOK {
		// Wired only once eBPF is actually attached: s.pathIdx starts
		// recording FILE_OPEN/EXEC_OPEN paths (and therefore evicting them)
		// the moment applyEvent runs at all, which never happens without a
		// live s.ebpfHandle to read events from in the first place.
		s.pathIdx.onEvict = s.deletePathSeenKey
		go runEventReader(s.ebpfHandle, s.eventCh)
	} else {
		// Whether Load itself failed (s.ebpfHandle already nil), or it
		// succeeded but a later check (the cgroup scan, or bootTicksNow)
		// downgraded eventsStatus anyway: no reader goroutine is ever
		// started in this branch, so a still-open ebpfHandle's own links,
		// ring buffer and maps must be released right now, not left open
		// until this process exits — every hook stays attached and the ring
		// buffer keeps filling for the whole rest of this session otherwise,
		// with nothing ever draining it. See closeEBPFHandle's own doc
		// comment for why the deferred Close registered above is still safe
		// alongside this early one.
		s.closeEBPFHandle()
		fmt.Fprintf(os.Stderr, "kestrelynx sensor: eBPF event collection unavailable (%s); continuing with procfs sampling only\n", s.eventsReason)
	}

	// --- 5. Drop CAP_BPF/CAP_PERFMON unconditionally.
	dropErr := sandbox.DropAll(unix.CAP_BPF, unix.CAP_PERFMON)

	// --- 6. Spawn the parser over a socketpair.
	unsafeProbes, unsafeErr := sandbox.RunUnsafeProbesInSubprocess()
	parserPID, parserFD, parserReport, parserErr := SpawnParserChild("--parser-child")
	s.parserPID = parserPID

	// --- 7. Install the observer's own seccomp filter.
	filterErr := installObserverFilter()

	// --- 8. Self-check.
	scReport, scErr := sandbox.RunObserverSelfCheck(sandbox.ObserverSelfCheckInput{
		ParserPID:    parserPID,
		GuardedCaps:  []uintptr{unix.CAP_BPF, unix.CAP_PERFMON},
		UnsafeProbes: unsafeProbes,
	})
	landlockABI := 0
	if parserErr == nil {
		landlockABI = parserReport.LandlockABI
	}
	s.isolation = evidence.Isolation{
		NoNewPrivs:  nnpErr == nil,
		NonDumpable: dumpableErr == nil,
		Seccomp:     filterErr == nil,
		LandlockABI: landlockABI,
	}

	status := evidence.SensorOK
	switch {
	case parserErr != nil || scErr != nil || !scReport.OK() && len(scReport.Failed) > 0:
		status = evidence.SensorIsolationFailed
	case unsafeErr != nil || nnpErr != nil || dumpableErr != nil || filterErr != nil || dropErr != nil:
		status = evidence.SensorIsolationDegraded
	case len(scReport.Degraded) > 0:
		status = evidence.SensorIsolationDegraded
	case !parserReport.LandlockApplied:
		// The parser's own self-check reported Landlock either unsupported
		// on this kernel or failed to apply to every thread (see parser.
		// Report's own doc comment). Treated the same as any other
		// degraded-but-not-failed condition: the parser still runs,
		// contained by its seccomp allow-list alone, but with one fewer
		// layer than intended.
		status = evidence.SensorIsolationDegraded
	}

	s.isolationStatus = status
	if status == evidence.SensorIsolationFailed || (status == evidence.SensorIsolationDegraded && s.cfg.RequireIsolation) {
		// A failed self-check never starts observation regardless of any
		// flag: there is nothing safe to sample without a confirmed
		// sandbox. A degraded one normally still observes (with the main
		// body expected to surface a warning from this same status field),
		// but --require-isolation asks this Sensor to refuse that too.
		s.writeFinalSnapshotAndWait(status)
		<-ctx.Done()
		return nil
	}

	// --- 9. Read the previous evidence file (after the isolation sequence
	// above, per the startup order: only now does untrusted input get
	// touched).
	s.loadPreviousEvidence()

	go runDBWorker(parserFD, s.dbJobCh, s.dbResultCh)

	return s.loop(ctx, status)
}

// closeEBPFHandle releases s.ebpfHandle's own links, ring buffer and maps
// right now, if it is still open, and sets it back to nil — called the
// moment eventsStatus is downgraded away from EventsOK after a successful
// Load (run's own startup sequence: a failed or truncated cgroup scan, or a
// failed bootTicksNow), since no reader goroutine is ever started for such a
// session and nothing else would otherwise close these resources before
// this process exits.
//
// This runs alongside, not instead of, run's own `defer s.ebpfHandle.Close()`
// registered right after Load succeeds: that defer's receiver expression
// (s.ebpfHandle) was already evaluated — to this exact *Handle value — the
// moment the defer statement itself executed, per Go's own defer semantics,
// so setting the field to nil here does not change what that deferred call
// invokes; it will still call Close on the same handle this method just
// closed. (*ebpf.Handle).Close's own doc comment guarantees a second Close
// is safe, so this is never a double-free, only a redundant one.
func (s *Session) closeEBPFHandle() {
	if s.ebpfHandle == nil {
		return
	}
	s.ebpfHandle.Close()
	s.ebpfHandle = nil
}

// deletePathSeenKey is s.pathIdx's own onEvict hook once eBPF is attached
// (see run's own wiring above): it asks the kernel to forget the
// kl_dedup_path entry matching k, so the next open of that exact file
// resends its own path record instead of staying suppressed under a
// since-forgotten pathIndex entry for the rest of bpf/kestrelynx.c's own
// KL_DEDUP_WINDOW_NS — see pathIndex's own doc comment for why this matters.
// s.ebpfHandle being nil (closeEBPFHandle already ran, or Load itself never
// produced one) is handled defensively, even though onEvict is never wired
// at all in that case, since nothing else forbids pathIndex eviction from
// racing a concurrent close. Any error DeletePathSeen itself does not
// already treat as expected (ebpf.ErrKeyNotExist) is counted, never acted on
// further — see s.pathIndexKernelDeleteFailures' own doc comment for why.
func (s *Session) deletePathSeenKey(k evictedPathKey) {
	if s.ebpfHandle == nil {
		return
	}
	if err := s.ebpfHandle.DeletePathSeen(k.mntNsID, k.rawRootDev, k.rootIno, k.dev, k.ino); err != nil {
		s.pathIndexKernelDeleteFailures++
	}
}

// installObserverFilter builds and installs the observer's own seccomp
// filter using this process's own PID.
func installObserverFilter() error {
	filter, err := sandbox.ObserverFilter(int32(os.Getpid()))
	if err != nil {
		return err
	}
	return sandbox.InstallFilter(filter)
}

// ownContainerID resolves this observer's own container ID via its own
// /proc/self/cgroup — used to exclude its own container from discovery.
// Empty when this process is not itself running inside a Docker container
// (e.g. a local, non-containerized test run), which excludes nothing.
func ownContainerID() string {
	h, err := procfs.Open(unix.Getpid())
	if err != nil {
		return ""
	}
	defer h.Close()
	id, ok, err := h.ContainerID()
	if err != nil || !ok {
		return ""
	}
	return id
}

// loadPreviousEvidence reads this evidence directory's existing file (from a
// prior Sensor session) and seeds s.generations from every generation whose
// state is not StateEnded, so accumulated OS-package/executable evidence
// survives a Sensor restart. Each seeded generation's package-database index
// always starts idxIdle (a fresh build is always attempted this session:
// the parser process is new and holds no index for anything). Any read
// failure (no file yet, or one that fails validation) is not an error —
// Session simply starts from empty: a Sensor restart with an unreadable
// previous evidence file starts fresh rather than blocking startup on it.
func (s *Session) loadPreviousEvidence() {
	r := evidence.NewReader(s.cfg.EvidenceDir)
	prev, err := r.Read(s.now(), nil)
	if err != nil {
		return
	}
	for _, g := range prev.Generations {
		if g.State == evidence.StateEnded {
			continue
		}
		// initialCoverage is never CoverageSinceStart regardless of this
		// session's own eventsStatus: a restarted Sensor's own reattachment
		// happens after a gap (parser/observer restart), so a generation
		// carried over from a previous session can never claim since_start
		// now — see newGenerationState's own doc comment for why
		// since_start is only ever assigned to a generation discovered
		// fresh, after eBPF has already had a chance to attach before that
		// generation's own start. If this session's own eBPF did attach,
		// though, events are flowing for it again as of now, just with a
		// gap already known to exist — CoveragePartial, not CoverageNone.
		initialCoverage := evidence.CoverageNone
		if s.eventsStatus == evidence.EventsOK {
			initialCoverage = evidence.CoveragePartial
		}
		gs := newGenerationState(g.Container, InitProcess{PID: g.Init.PID, Starttime: g.Init.Starttime}, g.StartedAt, initialCoverage)
		// Incomplete/Truncated carry over too: both describe a gap in what
		// this generation's evidence can positively claim (a withdrawn
		// not-observed verdict, a cut-short directory listing) that a fresh
		// Sensor session has no way to re-derive on its own — starting a
		// restarted session as if neither gap had ever happened would claim
		// more confidence in the carried-over OSPackages/Executables below
		// than this generation has actually earned.
		gs.incomplete = g.Incomplete
		gs.truncated = g.Truncated
		for _, p := range g.OSPackages {
			p := p
			gs.osPackages[pkgKey{Name: p.Name, Version: p.Version}] = &p
		}
		for _, u := range g.Unavailable {
			u := u
			gs.unavailable[pkgKey{Name: u.Name, Version: u.Version}] = &u
		}
		for _, e := range g.Executables {
			e := e
			gs.executables[e.Path] = &e
		}
		// ParseFailed's backoff schedule carries over too: a Sensor restart
		// must not forget an outstanding retry_after and immediately
		// re-attempt a file that was deliberately backed off for up to 24h.
		// (Its own published state — parse_failed, since this list is
		// non-empty — follows automatically from derivePublishedState;
		// nothing here needs to set it directly.)
		gs.parseFailed = append(gs.parseFailed, g.ParseFailed...)
		s.generations[gs.key()] = gs
	}
}

// newSessionID returns a short, printable identifier for this Sensor
// session — a fresh random-looking value each run, never parsed back apart,
// only ever compared for equality or shown for debugging.
func newSessionID() string {
	var buf [16]byte
	if _, err := unix.Getrandom(buf[:], 0); err != nil {
		// Getrandom is not expected to fail on any kernel this Sensor
		// targets; falling back to the current time keeps startup from
		// failing outright over a session identifier, which nothing security-
		// relevant depends on being unpredictable.
		return fmt.Sprintf("fallback-%d", time.Now().UnixNano())
	}
	return fmt.Sprintf("%x", buf)
}

// discoveryResult is what a discovery goroutine sends back to loop: one
// scanProcs()+groupContainers() pass, taken at Now. gen is the value
// s.discoveryGen held at the moment this discovery was started — loop
// discards any discoveryResult whose gen does not match its own current
// s.discoveryGen, since that means a newer discovery has since been started
// (see discoveryStaleAfter) and this one is a late straggler: applying it
// would reconcile against a possibly-already-superseded view of which
// containers exist (a container that was recreated, say, in between).
type discoveryResult struct {
	groups map[string]containerGroup
	// seeds is computeCgroupSeeds' own output for this same pass — applied
	// to cgroupRoute by applyDiscoveryResult (reconcileCgroupRoute) before
	// groups is reconciled into generations, so a cgroup newly classified
	// this pass can immediately help route anything already queued for it.
	seeds []cgroupSeed
	// cgroupStatFailures is computeCgroupSeeds' own second return value for
	// this same pass: how many of its own stat(2) calls failed with
	// something other than ENOENT — accumulated into s.cgroupStatFailures
	// and logged (once) by applyDiscoveryResult, the first point back on
	// loop's own goroutine this count reaches.
	cgroupStatFailures int
	now                time.Time
	err                error
	gen                int
}

// sampleEnvelopeKind distinguishes the three things loop's own sampleResCh
// ever carries for one dispatched sample worker.
type sampleEnvelopeKind int

const (
	// sampleEnvResult: the worker answered within its own budget; apply it.
	sampleEnvResult sampleEnvelopeKind = iota
	// sampleEnvTimeout: loop gave up waiting; mark the generation stalled,
	// but it stays in the ledger as alive (see generationState.sampleAlive)
	// and is not restarted.
	sampleEnvTimeout
	// sampleEnvFinished: the (possibly already-abandoned) worker goroutine
	// has now actually returned; clear the ledger entirely, discarding
	// whatever it produced if this arrives after sampleEnvTimeout already
	// did for the same generation.
	sampleEnvFinished
)

type sampleEnvelope struct {
	kind   sampleEnvelopeKind
	genKey string
	result sampleResult
}

// applyDiscoveryResult applies one discoveryResult, discarding it instead
// (reporting false, and — beyond clearing discoveryInFlight on an error —
// touching nothing else) if disc.gen no longer matches s.discoveryGen: a
// stale straggler from a discovery loop already gave up waiting for (see
// discoveryStaleAfter and discoveryResult's own doc comment) can complete
// after a newer discovery has already been started and even already
// applied — reconciling against that stale straggler's own, possibly
// superseded view of which containers exist would risk undoing what the
// newer discovery already established. Reports whether disc was applied.
func (s *Session) applyDiscoveryResult(disc discoveryResult) bool {
	if disc.gen != s.discoveryGen {
		// A newer discovery is presumably still in flight, so
		// discoveryInFlight is left untouched rather than cleared here.
		return false
	}
	s.discoveryInFlight = false
	if disc.err != nil {
		return false // transient (e.g. /proc briefly unreadable); try again next tick
	}
	s.lastCompletedDiscoveryStartedAt = disc.now
	if disc.cgroupStatFailures > 0 {
		s.cgroupStatFailures += int64(disc.cgroupStatFailures)
		if !s.cgroupStatFailureLogged {
			s.cgroupStatFailureLogged = true
			fmt.Fprintf(os.Stderr, "kestrelynx sensor: cgroup reseed stat failure other than ENOENT (count=%d); further occurrences are still counted but not logged again\n", disc.cgroupStatFailures)
		}
	}
	// reconcileCgroupRoute, then reconcileGenerations, then dispatchWork (the
	// only place any pendingRouteEvent this pass could newly unblock is
	// actually retried) — never the other order: a cgroup this call newly
	// classifies can name a container reconcileGenerations is *also* about
	// to register for the first time in this same pass, and a retry that
	// ran before that registration would find the cgroup resolved but no
	// generation yet to attribute anything to, discarding the event for
	// good. See reconcileCgroupRoute's own doc comment.
	s.reconcileCgroupRoute(disc.seeds)
	s.reconcileGenerations(disc.groups, disc.now)
	s.dispatchWork(disc.now)
	s.pruneEndedGenerations(disc.now)
	return true
}

// defaultDiscover is loop's own production discovery pass: one
// scanProcs()+groupContainers() round against this process's real /proc.
// Factored out so loop itself only ever calls it through s.discoverFn (nil
// in production, resolving straight back to this), never scanProcs/
// groupContainers directly — the same seam sampleFn already gives a test
// over a sample worker's own timing, given here to a test that needs loop
// to react to a synthetic set of container groups instead of whatever real
// containers (usually none) happen to exist on the machine running the
// test.
func defaultDiscover(ownContainerID string, excludeIDs []string) (map[string]containerGroup, []cgroupSeed, int, error) {
	scan, err := scanProcs()
	if err != nil {
		return nil, nil, 0, err
	}
	groups := groupContainers(scan.Procs, ownContainerID, excludeIDs)
	seeds, statFailures := computeCgroupSeeds(cgroupHostRoot, scan.Procs)
	return groups, seeds, statFailures, nil
}

// discoverOnce resolves loop's own discovery function: s.discoverFn if a
// test has set one, else the real scanProcs()+groupContainers() pass
// (defaultDiscover) against this process's own /proc.
func (s *Session) discoverOnce() (map[string]containerGroup, []cgroupSeed, int, error) {
	if s.discoverFn != nil {
		return s.discoverFn()
	}
	return defaultDiscover(s.ownContainerID, s.cfg.ExcludeIDs)
}

// earlyDiscoveryMinInterval is requestEarlyDiscovery's own absolute floor,
// regardless of --interval: even a very short --interval must not let event
// resolution alone drive discovery any faster than this.
const earlyDiscoveryMinInterval = 2 * time.Second

// requestEarlyDiscovery is the only path an event handler (resolveEventGeneration
// or applyGenConfirmResult, in events.go/genconfirm.go) uses to ask for a
// discovery pass sooner than sampleTicker's own cadence would provide one —
// never s.startDiscovery() directly. Without a floor of its own, a container
// stuck in routeUnresolved (no boot-tick-matched candidate yet) or
// routeUnconfirmed-then-unconfirmed (a candidate whose liveness check just
// failed) would have every single retry of every single still-pending event
// trigger its own fresh /proc scan — a continuous, back-to-back discovery
// loop for as long as sampling itself is delayed or stalled, exactly when
// this Sensor can least afford one. At most one early request is honored per
// max(--interval/4, earlyDiscoveryMinInterval); every other call in between
// is a silent no-op, relying on the next request (or sampleTicker's own
// regular cadence) to eventually run one anyway.
func (s *Session) requestEarlyDiscovery(now time.Time) {
	floor := s.cfg.Interval / 4
	if floor < earlyDiscoveryMinInterval {
		floor = earlyDiscoveryMinInterval
	}
	if !s.lastEarlyDiscoveryRequest.IsZero() && now.Sub(s.lastEarlyDiscoveryRequest) < floor {
		return
	}
	s.lastEarlyDiscoveryRequest = now
	s.startDiscovery()
}

// startDiscovery starts a new discovery pass unless one is already in
// flight and not yet stale (discoveryStaleAfter). Called by loop itself on
// every sampleTicker tick and once at loop startup, and indirectly (via
// requestEarlyDiscovery, never directly) by event resolution when it finds a
// container it cannot yet fully account for: rather than guess, it asks for
// a discovery pass sooner than sampleTicker's own cadence would provide one,
// so a genuinely new generation (a restart this session has not yet
// noticed) gets registered as quickly as possible. Safe to call from within
// an event handler: it only ever starts a goroutine and returns, exactly
// like every other call site.
func (s *Session) startDiscovery() {
	if s.discoveryInFlight && s.now().Sub(s.discoveryStarted) < discoveryStaleAfter {
		return // already in flight and not yet considered stale
	}
	s.discoveryGen++
	gen := s.discoveryGen
	s.discoveryInFlight = true
	s.discoveryStarted = s.now()
	go func() {
		now := s.now()
		groups, seeds, statFailures, err := s.discoverOnce()
		if err != nil {
			s.discoveryCh <- discoveryResult{now: now, err: err, gen: gen}
			return
		}
		s.discoveryCh <- discoveryResult{groups: groups, seeds: seeds, cgroupStatFailures: statFailures, now: now, gen: gen}
	}()
}

// loop is the whole body of the loop goroutine: the sole owner of every
// mutable field on Session and of every generationState reachable from
// s.generations. Every other goroutine this Session starts (discovery, a
// sample worker, the dbworker, the writer) exchanges only immutable values
// with loop over a channel; none of them ever holds a pointer to anything
// loop owns.
//
// Sampling and writing are decoupled but not independent: cfg.Interval
// drives sampleTicker (how often a discovery pass runs and sample workers
// get dispatched), and the evidence file is written (via requestWrite) on
// two triggers — heartbeatTicker, whose own period is whichever is shorter
// of cfg.Interval and heartbeatEvery (see heartbeatPeriod), and whenever one
// generation's sample result has been fully applied (see
// handleSampleEnvelope's own sampleEnvResult case). Neither of these two
// triggers writes immediately by itself when some live generation has a
// package-database lookup outstanding — see requestWrite's own doc comment
// for why, and writeDelayCh (this select's own budget-exceeded case) for
// the bounded fallback that still guarantees a write happens. Capping the
// ticker's period at cfg.Interval (never longer than it, only ever shorter
// once heartbeatEvery's own 60-second ceiling takes over) is what keeps
// heartbeat_at from ever lagging behind evidence.StalenessThreshold's own
// interval-derived floor: that threshold scales with intervalSeconds (10x,
// floored at 5 minutes), so a heartbeat cadence slower than --interval
// itself risks a healthy Sensor's own evidence looking stale to the main
// body purely from how rarely it writes, not from anything actually wrong.
// Requesting a write a second time before the first has actually happened —
// not only from the ticker — is safe and expected to happen often: the
// writer goroutine's own channel is a single "latest wins" slot (see
// submitSnapshot), so any number of submissions between one actual write and
// the next just replace each other rather than queuing up.
func (s *Session) loop(ctx context.Context, initialStatus evidence.SensorStatus) error {
	sampleTicker := time.NewTicker(s.cfg.Interval)
	defer sampleTicker.Stop()
	heartbeatTicker := time.NewTicker(heartbeatPeriod(s.cfg.Interval, s.heartbeatEvery))
	defer heartbeatTicker.Stop()

	if s.discoveryCh == nil {
		s.discoveryCh = make(chan discoveryResult, 1)
	}
	s.startDiscovery() // discover immediately at startup, same as every tick after
	s.lastWriteModified = false
	_ = initialStatus // status is recomputed fresh on every write; nothing more to seed here

	for {
		select {
		case <-ctx.Done():
			// A graceful shutdown (SIGINT/SIGTERM) still owes the main body
			// one last, definitely-durable snapshot of whatever this
			// session's own state was at the moment it was asked to stop —
			// not merely whatever the last heartbeat or sample-triggered
			// write happened to leave on disk, and not merely queued: Run
			// (and, through it, the whole process) must not exit before
			// this write is confirmed done.
			s.writeFinalSnapshotAndWait(s.computeStatus())
			return nil

		case <-sampleTicker.C:
			s.startDiscovery()

		case disc := <-s.discoveryCh:
			s.applyDiscoveryResult(disc)

		case env := <-s.sampleResCh:
			s.handleSampleEnvelope(env)

		case ev := <-s.eventCh:
			s.applyEvent(ev)

		case res := <-s.pathResolveCh:
			s.applyPathResolveResult(res)

		case res := <-s.genConfirmCh:
			s.applyGenConfirmResult(res)

		case res := <-s.dbResultCh:
			if fatal := s.applyDBResult(res); fatal != nil {
				s.writeParseFailedAndExit(fatal)
				return fatal
			}
			// A lookup answer just applied (applyLookupResult) may have been
			// the one thing a deferred write (requestWrite) was still
			// waiting on — a no-op otherwise (writePending false, or some
			// other generation's own lookup still outstanding).
			s.resumeDeferredWrite()

		case <-s.writeDelayCh:
			// requestWrite's own write-wait budget elapsed before every
			// outstanding lookup answered — write now regardless; whichever
			// generation's own lookup is still outstanding reports Incomplete
			// for this write (see toEvidence's own doc comment on
			// g.pendingLookup != nil).
			s.writePending = false
			s.writeDelayCh = nil
			s.writeSnapshotNow(s.computeStatus())

		case <-heartbeatTicker.C:
			s.requestWrite()

		case rep := <-s.writerReportCh:
			// rep.consecutiveFailures is runWriter's own count, not
			// something loop derives from how many failure reports it
			// happens to receive — see writeReport's own doc comment for
			// why counting received reports here would be wrong once
			// submitSnapshot's own coalescing is in play.
			s.writeFailureStreak = rep.consecutiveFailures
			s.lastWriteModified = rep.modified
		}
	}
}

// anyPendingLookupOutstanding reports whether some live generation is
// currently waiting on a package-database lookup answer it has already
// submitted (g.pendingLookup != nil) — requestWrite's own gate for whether a
// write must be held back rather than performed right now.
func (s *Session) anyPendingLookupOutstanding() bool {
	for _, g := range s.generations {
		if !g.ended && g.pendingLookup != nil {
			return true
		}
	}
	return false
}

// requestWrite is loop's own single entry point for asking for a snapshot
// write, used by both handleSampleEnvelope's sampleEnvResult case and
// heartbeatTicker: written immediately if no live generation currently has a
// package-database lookup outstanding, otherwise held back until either
// every one of them has answered (resumeDeferredWrite, called once a lookup
// answer is applied) or lookupWriteWaitBudget elapses, whichever comes first
// (loop's own writeDelayCh case).
//
// This is what keeps an ordinary sample-triggered write from ever
// publishing a generation's freshly advanced LastVerifiedAt before the very
// package-database lookup that same sample's own candidates were just
// submitted for has actually answered: writing at that exact instant would
// always show g.pendingLookup != nil (see toEvidence's own Incomplete
// computation), since applySampleResult only ever sets it moments before —
// never because the lookup was genuinely slow. Deferring instead means the
// overwhelmingly common case (a local dbworker lookup answers in well under
// lookupWriteWaitBudget) never marks anything Incomplete purely because of
// this ordering at all.
//
// Deliberately one Session-wide gate, not one per generation:
// submitSnapshot itself only ever has one "latest wins" slot to write into
// (see its own doc comment), so there is only ever one write to hold back
// at a time regardless of how many generations' own lookups happen to be
// outstanding at once, and writing more often than strictly necessary once
// the gate clears is always safe.
func (s *Session) requestWrite() {
	if !s.anyPendingLookupOutstanding() {
		s.writeSnapshotNow(s.computeStatus())
		return
	}
	if !s.writePending {
		s.writePending = true
		s.writeDelayCh = time.After(s.lookupWaitBudget)
	}
}

// resumeDeferredWrite performs a write requestWrite previously held back,
// once every live generation's own package-database lookup has answered — a
// no-op if no write is currently deferred (writePending false) or some
// generation's own lookup is still outstanding.
func (s *Session) resumeDeferredWrite() {
	if !s.writePending || s.anyPendingLookupOutstanding() {
		return
	}
	s.writePending = false
	s.writeDelayCh = nil
	s.writeSnapshotNow(s.computeStatus())
}

// handleSampleEnvelope applies one sample worker's outcome (see
// sampleEnvelopeKind's own doc comment for the three shapes this can take).
// A sampleEnvResult also requests a snapshot write, once that generation's
// own result has been fully folded into it — see requestWrite's own doc
// comment for why this is not always an immediate write, and submitSnapshot's
// own doc comment for why asking this often, on top of heartbeatTicker's own
// fixed schedule, is safe.
func (s *Session) handleSampleEnvelope(env sampleEnvelope) {
	g, ok := s.generations[env.genKey]
	if !ok {
		return
	}
	switch env.kind {
	case sampleEnvResult:
		s.aliveSampleWorkers--
		g.sampleAlive = false
		g.sampleStalled = false
		if !g.ended {
			s.applySampleResult(g, env.result)
			s.requestWrite()
		}
	case sampleEnvTimeout:
		if !g.ended {
			g.sampleStalled = true
		}
	case sampleEnvFinished:
		s.aliveSampleWorkers--
		g.sampleAlive = false
		// sampleStalled is deliberately left as it is here, not cleared:
		// this worker's own result is discarded entirely (loop already
		// moved on from this sample), so nothing has actually improved —
		// clearing it now would publish a falsely reassuring state (e.g.
		// initializing/observing) for a generation that still has no
		// timely sample to show. Only a genuinely applied sampleEnvResult,
		// above, is allowed to clear it. sampleAlive still clears
		// unconditionally so dispatchWork is free to start this
		// generation's next worker.
	}
}

// applySampleResult folds one in-time sample worker's result into g, and —
// if it produced any candidate paths and this generation's own index is
// ready — submits a lookup job to resolve them, storing the material that
// answer will need in g.pendingLookup.
func (s *Session) applySampleResult(g *generationState, res sampleResult) {
	now := s.now()
	if res.truncated {
		g.truncated = true
	}
	if res.incomplete {
		g.incomplete = true
	}
	mountViewJustConfirmed := g.mntNsID == 0 && res.basis.ok
	if g.mntNsID == 0 && res.basis.ok {
		// Recorded once, the first time any sample resolves this
		// generation's own mount namespace — see generationState.mntNsID's
		// own doc comment for what this gates (matchesMountView) and what
		// it is used for afterward (pruning s.pathIdx once this generation
		// ends).
		if id, ok := parseMntNSInode(res.basis.mntNS); ok {
			g.mntNsID = id
		}
	}
	if g.rootDev == "" && res.basis.ok {
		// Recorded once, the first time any sample resolves this
		// generation's own root identity — see generationState.rootDev's own
		// doc comment. res.basis.rootIno is never legitimately 0 once
		// res.basis.ok is true (every real inode number is nonzero), so
		// checking g.rootDev alone (rather than also g.rootIno) is enough to
		// tell "not yet recorded" from "already recorded".
		g.rootDev, g.rootIno = res.basis.rootDev, res.basis.rootIno
	}
	if mountViewJustConfirmed && g.mntNsID != 0 {
		// This exact sample is what just confirmed this generation's own
		// mount view for the first time — every usage event that arrived
		// before now and was held for exactly this reason (see
		// dispatchUsageEvent's own doc comment) gets its one genuine chance
		// to be judged, rather than staying held until its own TTL expires
		// it as a loss it was never actually given a fair shot at.
		s.drainPendingMountViewEvents(g)
	}
	if res.initAliveNsOK && (!g.lastAliveNsOK || res.initAliveNs > g.lastAliveNs) {
		// This ordinary sample's own openRootWithBasis call already
		// performed exactly the init-alive-with-matching-starttime-and-not-
		// zombie check resolveEventGeneration's own proof rule needs — see
		// generationState.lastAliveNs' own doc comment. Never decreased: a
		// later sample's own result applied out of order (never actually
		// expected, since sampleAlive/aliveSampleWorkers prevent two
		// concurrent samples for the same generation, but not asserted
		// here) must not un-prove an already-established later instant.
		g.lastAliveNs = res.initAliveNs
		g.lastAliveNsOK = true
	}
	if res.mergedUsrDirs != nil {
		// Refreshed on every sample that resolves one, not just the first —
		// see generationState.mergedUsrDirs' own doc comment for why an
		// eBPF event's own candidateBatch reads this cached table instead
		// of ever opening rootfs itself.
		g.mergedUsrDirs = res.mergedUsrDirs
	}
	for _, e := range res.executables {
		g.recordExecutable(e.path, e.dev, e.inode, e.kind, now, &e.obs)
	}

	// basisMismatch is computed here, before applyEventVerificationResult is
	// ever called below, so a verifiedEvents lookup this exact sample's own
	// worker just confirmed is never submitted against an index this same
	// res.basis is about to invalidate a few lines further down. Submitting
	// first and only detecting the mismatch afterward would let a file this
	// sample actually confirmed under a *new* root be credited to whatever
	// package the *old* root's now-stale index still says lived at that same
	// (dev, inode) — exactly the kind of guess this whole check exists to
	// rule out. See the mismatch branch below for what basisMismatch itself
	// means and why it invalidates the index.
	basisMismatch := g.idxState == indexReady && g.idxBasis.ok && res.basis.ok && !sameMountBasis(g.idxBasis, res.basis)
	if !basisMismatch {
		s.applyEventVerificationResult(g, res)
	}

	denied := res.attempted > 0 && res.denied == res.attempted
	// last_verified_at only advances when this pass actually confirmed
	// something about this generation: either it read at least one process
	// to completion, or every process it attempted was positively denied
	// (itself a confirmed outcome, StateDenied). A pass where every process
	// merely vanished mid-read, neither succeeding nor being denied, has
	// confirmed nothing new and must not be reported as a fresh
	// verification.
	confirmed := res.succeeded > 0 || denied
	if confirmed {
		g.lastGoodSample(now, denied)
	}

	// A sample loop dispatched before the index became ready must never
	// attribute OS candidates, nor confirm the index, no matter what
	// idxState reads by the time this result is actually applied — a build
	// completing while this exact sample was still in flight must not
	// retroactively count it as having confirmed the freshly-built index
	// (see sampleResult.indexReadyAtStart's own doc comment).
	if !res.indexReadyAtStart {
		return
	}

	// The index this generation currently reports ready was built from
	// init's own root as of whichever sample last (re)built it — g.idxBasis
	// (see applyBuildResult). If init's own root has since changed without
	// its PID/starttime changing too (a chroot, or unshare(CLONE_NEWNS)),
	// the sample worker's own freshly-resolved basis for this same init
	// disagrees with it — resolving anything against that index, or
	// continuing to trust postIndexConfirmed's own earlier confirmation of
	// it, would describe a root init no longer actually has. This must be
	// checked before candidate count is ever considered: a chroot/unshare
	// that leaves every process in this sample either vanished mid-read or
	// otherwise contributing nothing (see runSampleWorker's own per-process
	// discard cases) still reports res.basis correctly, resolved once for
	// init itself regardless of what happened to any individual process —
	// checking this only when candidates happens to be non-empty would let
	// a generation already showing observing/postIndexConfirmed keep
	// claiming that confirmation, unrevoked, against a root nothing this
	// sample actually read confirms it still describes. basisMismatch itself
	// was already computed above, before applyEventVerificationResult ran.
	if basisMismatch {
		g.idxState = indexIdle
		g.incomplete = true
		// A confirmation earned against the old root does not carry over
		// to whatever the rebuilt index turns out to describe — the next
		// index needs its own first post-ready sample and lookup all over
		// again (see postIndexConfirmed's own doc comment).
		g.postIndexConfirmed = false
		// idxEpoch is bumped exactly once per detected mismatch, the
		// moment the previous index is invalidated — never merely because
		// a rebuild attempt ran (see idxEpoch's own doc comment). Every
		// candidateBatch already queued (or outstanding) from before this
		// point now describes a root the *next* index will not have been
		// built from; flushQueuedCandidates and runDBWorker's own epoch
		// check are what actually keep either from being matched against
		// it once it exists.
		g.idxEpoch++
		return
	}

	if len(res.candidates) == 0 {
		// A sample taken while the index is already ready, that also
		// genuinely confirmed something this round (confirmed, above —
		// not merely one where every process vanished mid-read, which
		// confirms nothing at all), with nothing whatsoever to attribute,
		// confirms the ready index just as fully as one that had
		// candidates and got them looked up: there is nothing left to
		// wait on before this generation's own (necessarily empty)
		// OSPackages can be trusted. See postIndexConfirmed's own doc
		// comment.
		if confirmed && g.idxState == indexReady && g.packageDB.Status == evidence.DBStatusOK {
			g.postIndexConfirmed = true
		}
		return
	}
	if g.idxState != indexReady || g.packageDB.Status != evidence.DBStatusOK {
		return
	}

	batch := candidateBatch{
		candidates: res.candidates, mergedUsrDirs: res.mergedUsrDirs,
		verified: res.verified, replaced: res.replaced,
		// The same single "now" this whole sample was confirmed at (used
		// above for lastGoodSample too), carried through to whenever the
		// lookup answer actually arrives — see candidateBatch's own doc
		// comment on observedAt for why using a fresh timestamp there
		// instead would be wrong.
		observedAt: now,
		// The index this batch's own candidates are eligible to be matched
		// against — see candidateBatch's own doc comment on epoch/basis.
		epoch: g.idxEpoch, basis: res.basis,
	}

	if g.pendingLookup != nil {
		// A lookup for this generation is already outstanding: this
		// sample's own candidates are queued behind it, never dropped —
		// see queuedCandidates' own doc comment — and folded into the very
		// next lookup once the outstanding one answers (applyLookupResult,
		// via flushQueuedCandidates), unless the queue is already at its
		// own cap, in which case this batch is the one that does not fit
		// and is lost for good (candidatesLostPermanently).
		if !g.canQueueCandidateBatch(batch) {
			g.candidatesLostPermanently = true
			return
		}
		g.queuedCandidates = append(g.queuedCandidates, batch)
		return
	}

	s.submitCandidateBatches(g, g.idxEpoch, []candidateBatch{batch})
}

// submitCandidateBatches builds one lookup set from batches — one or more
// samples' own worth of candidates, more than one only when flushing
// queuedCandidates (see flushQueuedCandidates) — and submits it as g's new
// pendingLookup. If the job channel is unexpectedly full, every batch's own
// candidates are lost for this round: marked Incomplete (sticky) rather
// than silently dropped, since an observed-but-unresolved candidate is
// exactly the kind of gap Incomplete exists to withdraw not-observed for.
func (s *Session) submitCandidateBatches(g *generationState, epoch int, batches []candidateBatch) {
	var lookupSet []string
	for _, b := range batches {
		for _, p := range append(append([]string(nil), b.verified...), b.replaced...) {
			lookupSet = append(lookupSet, p)
			if alias, ok := usrmergeAlias(p, b.mergedUsrDirs); ok {
				lookupSet = append(lookupSet, alias)
			}
		}
	}
	if len(lookupSet) == 0 {
		return
	}
	// epoch is carried on the dbJob itself so the dbworker goroutine can
	// refuse to match this lookup against an index it already knows was
	// rebuilt out from under it by the time this job is actually processed
	// — see runDBWorker's own epoch check. seq is this lookup's own separate
	// identity (see dbJob.seq's own doc comment). A seq that ends up unused
	// (submitDBJob below refuses to enqueue it) is harmless: nothing will
	// ever answer with it, so no gap in the sequence is ever observed.
	g.nextLookupSeq++
	seq := g.nextLookupSeq
	if s.submitDBJob(dbJob{kind: dbJobLookup, genKey: g.key(), paths: lookupSet, epoch: epoch, seq: seq}) {
		g.pendingLookup = &pendingLookup{batches: batches, epoch: epoch, seq: seq, submittedAt: s.now()}
		return
	}
	g.incomplete = true
}

// applyDBResult applies one dbworker result (build, lookup or forget),
// after confirming the generation it names still exists and has not ended
// — a result for a generation loop has already moved on from is silently
// discarded, per "結果を適用する前に、世代キーがまだ同じで、終わっていない
// ことを確かめる". It returns the fatal error to end the session on, if
// any — a fatal build's own ParseFailure (if it identified one) is still
// recorded first, before that return, since the parser dying and the
// identity of whatever input triggered it are separate facts (see
// dbResult's own doc comment).
func (s *Session) applyDBResult(res dbResult) error {
	g, ok := s.generations[res.genKey]
	live := ok && !g.ended

	if live {
		switch res.kind {
		case dbJobBuild:
			s.applyBuildResult(g, res)
		case dbJobLookup:
			s.applyLookupResult(g, res)
		case dbJobForget:
			// Nothing to apply; forget is fire-and-forget cleanup.
		}
	}

	return res.fatalErr
}

// applyBuildResult transitions g's own idxState machine — see
// generationState's own doc comment on indexState for the full transition
// table — from exactly what runDBWorker's dbResult reports. The published
// evidence.GenerationState itself is never set here (or anywhere but
// derivePublishedState): idxState/parseFailed changing is what that
// function reacts to, the next time g.toEvidence() runs.
func (s *Session) applyBuildResult(g *generationState, res dbResult) {
	now := s.now()
	g.packageDB.Kind = res.dbKind

	switch {
	case res.settled:
		g.packageDB.Status = res.dbStatus
		g.idxState = indexReady
		g.idxBasis = res.basis
		// Absent/unsupported is a permanent fact needing no sample to
		// confirm at all — there is no database a later sample's own
		// candidates could ever be attributed against, so there is nothing
		// a post-ready sample would add (see postIndexConfirmed's own doc
		// comment, which is about the real-index case below instead).
		g.postIndexConfirmed = true
		return
	case res.noChange:
		g.packageDB.Status = res.dbStatus
		g.idxState = indexFailed
		return
	}

	g.packageDB.Status = res.dbStatus
	if res.truncated {
		g.truncated = true
	}
	if res.failuresTruncated {
		// The parser's own Failures list was itself cut short: which files
		// besides the ones actually named failed is unknown, so this
		// generation cannot claim full confidence in its own NoFileList or
		// per-file attribution this round.
		g.incomplete = true
	}
	if res.hadFailure {
		g.recordParseFailure(res.failIdentity.input, res.failIdentity.path, res.failIdentity.dev, res.failIdentity.inode, res.failIdentity.size, now, s.cfg.Interval)
	}
	for _, f := range res.succeededFiles {
		g.recordParseSuccess(f.input, f.path)
	}
	for _, f := range res.failedFiles {
		g.recordParseFailure(f.input, f.path, f.dev, f.inode, f.size, now, s.cfg.Interval)
	}
	if res.dbStatus == evidence.DBStatusOK && res.buildOK {
		noFileList := res.noFileList
		if len(noFileList) > maxNoFileListPerGeneration {
			noFileList = noFileList[:maxNoFileListPerGeneration]
			g.truncated = true
		}
		g.packageDB.NoFileList = noFileList
	}

	if res.buildOK && len(g.parseFailed) == 0 {
		g.idxState = indexReady
		g.idxBasis = res.basis
		// A real, just-(re)built index: nothing has been attributed
		// against it yet by any sample that actually knew it was ready —
		// see postIndexConfirmed's own doc comment. Reset unconditionally
		// (not only on the idle -> ready transition) since a rebuild
		// forced by a mount-basis mismatch (applySampleResult) can bring
		// idxState back to ready describing a genuinely different root
		// than whatever the previous confirmation was about.
		g.postIndexConfirmed = false
	} else {
		g.idxState = indexFailed
		g.idxRetryAfter = g.nextRetryTime()
	}
}

// applyLookupResult folds one dbworker lookup answer into g, using the
// pendingLookup g.applySampleResult stashed when it submitted the job. A
// lookup result with no matching pendingLookup (a duplicate, or one that
// arrived after g was reset some other way) is silently ignored.
//
// res.seq must also name the exact lookup g.pendingLookup currently holds,
// checked before anything else here touches g.pendingLookup at all: a lookup
// abandoned by expirePendingLookup after pendingLookupTTL, with a fresh one
// already submitted in its place, can still have its own dbworker goroutine
// answer arrive later (the TTL only ever governs how long loop waits, never
// what the dbworker itself is still doing) — since that fresh lookup shares
// the exact same genKey and, ordinarily, the same epoch too (nothing rebuilt
// the index in between), matching on those alone would let the abandoned
// lookup's own stale answer be adopted as if it were the fresh one's,
// clearing g.pendingLookup out from under the answer that is actually still
// outstanding. A seq mismatch is silently ignored, exactly like pl == nil:
// g.pendingLookup (the fresh lookup) is left untouched either way, so its
// own eventual, correctly-seq'd answer can still be applied normally.
func (s *Session) applyLookupResult(g *generationState, res dbResult) {
	pl := g.pendingLookup
	if pl == nil || res.seq != pl.seq {
		return
	}
	g.pendingLookup = nil
	// Whatever this exact lookup answered, any batches that queued up
	// behind it while it was outstanding get their own turn next — folded
	// into a fresh lookup rather than left waiting indefinitely, and
	// regardless of whether pl's own batches below turn out fully
	// resolved, partially resolved, or rejected outright: a queued batch
	// is a newer, entirely separate sample that deserves its own attempt
	// either way. See flushQueuedCandidates' own doc comment.
	defer s.flushQueuedCandidates(g)

	if res.epochStale {
		// The dbworker goroutine itself refused to match this lookup: by
		// the time it actually processed the job, it already knew (from a
		// build job for this same genKey received afterward — see
		// runDBWorker's own epoch check) that the index this lookup was
		// submitted against had since been rebuilt. None of pl's own
		// batches were resolved at all, and unlike a normal
		// lookupFailed rejection, re-deriving them fresh on the next
		// sample is not an option either — those batches described a root
		// that no longer exists to re-sample from. Marked permanently, the
		// same as any other observation this session can never recover.
		g.candidatesLostPermanently = true
		return
	}

	if res.lookupFailed {
		// A normal, non-fatal parser rejection (see handleLookupJob's own
		// doc comment) — none of this pending lookup's candidates were
		// resolved at all. The next sample re-derives them fresh; for this
		// one, withdraw not-observed rather than silently drop it.
		g.incomplete = true
		return
	}

	// lookupResult reports both the answer and whether the parser was ever
	// actually asked about path at all, checking path's own usrmerge alias
	// whenever the primary spelling came back with no owner — a path
	// recorded under one spelling (e.g. a package database's own pre-merge
	// "/bin/sleep") must not be missed just because the kernel-resolved
	// path this generation observed was the other spelling
	// ("/usr/bin/sleep"): an empty answer at one spelling is not itself
	// proof of "unowned" while the other spelling has not been checked too.
	// truncated is set whenever either spelling's own owner list was cut
	// short (OwnersTruncated) — the true owner set may include packages
	// beyond the ones actually reported, so a caller must never treat this
	// as a complete answer even when it names some real owners.
	lookupResult := func(mergedUsrDirs map[string]bool, path string) (owners []lookupOwner, answered, truncated bool) {
		primary, primaryOK := res.owners[path]
		if len(primary.owners) > 0 {
			return primary.owners, true, primary.truncated
		}
		if alias, ok := usrmergeAlias(path, mergedUsrDirs); ok {
			aliasResult, aliasOK := res.owners[alias]
			if len(aliasResult.owners) > 0 {
				return aliasResult.owners, true, aliasResult.truncated
			}
			return nil, primaryOK || aliasOK, primary.truncated || aliasResult.truncated
		}
		return primary.owners, primaryOK, primary.truncated
	}

	// Every batch this lookup actually covered (ordinarily just one; more
	// than one when it was itself submitted from flushQueuedCandidates) is
	// applied against the very same res — each keeps its own candidates
	// and observedAt, so mergeKindObservation still counts one Samples
	// increment per distinct batch/sample, never conflating two different
	// samples' own observations of the same path into one.
	for _, batch := range pl.batches {
		for _, path := range batch.verified {
			result, answered, truncated := lookupResult(batch.mergedUsrDirs, path)
			if !answered {
				g.incomplete = true
				continue
			}
			if truncated {
				// The true owner set extends beyond what was actually
				// reported (see maxOwnersPerPath) — this generation cannot
				// honestly claim to have ruled out every one of them.
				g.incomplete = true
			}
			switch len(result) {
			case 0:
				// Not recorded by this generation's package database at
				// all — not an OS package file. Nothing to record.
			case 1:
				for _, c := range batch.candidates[path] {
					g.recordOSPackage(result[0].Name, result[0].Version, c.kind, batch.observedAt, &c.obs)
				}
			default:
				for _, owner := range result {
					g.recordUnavailableOSPackage(owner.Name, owner.Version, evidence.ReasonAttributionAmbiguous)
				}
			}
		}
		for _, path := range batch.replaced {
			result, answered, truncated := lookupResult(batch.mergedUsrDirs, path)
			if !answered {
				g.incomplete = true
				continue
			}
			if truncated {
				g.incomplete = true
			}
			for _, owner := range result {
				g.recordUnavailableOSPackage(owner.Name, owner.Version, evidence.ReasonFileReplaced)
			}
		}
	}

	// pl only ever came from batches taken while idxState was already
	// ready and this exact sample started after that too (see
	// applySampleResult's own guards before it ever creates or queues a
	// batch at all), and every one of their answers has now been fully
	// folded in above — this is exactly the "post-ready sample and its
	// lookup both completed" confirmation postIndexConfirmed's own doc
	// comment describes, regardless of individual per-path
	// answered/truncated gaps (each already marked g.incomplete on its own
	// where it matters).
	g.postIndexConfirmed = true
}

// flushQueuedCandidates submits every still-current batch queued in
// g.queuedCandidates as one fresh lookup, together, and clears the queue —
// called once the lookup that was outstanding when they queued up has
// itself been fully applied (applyLookupResult), so they are never left
// waiting once the pipe is free again. A no-op when nothing is queued.
//
// "Still-current" is checked here, against g.idxEpoch, before any of them
// are ever handed to submitCandidateBatches: the index can be invalidated
// and rebuilt (idxEpoch bumped) at any point while a batch sits queued
// behind an outstanding lookup, and a batch whose own epoch no longer
// matches describes a root the current (or next) index was never built
// from — see candidateBatch's own doc comment. Submitting it anyway would
// let its own candidates be matched against an unrelated package database
// once the dbworker's own reply comes back OK; discarded instead, with
// Incomplete kept (sticky, via candidatesLostPermanently — reused here for
// exactly the same "lost for good" meaning, not only a capacity overflow)
// since these observations can never be recovered.
func (s *Session) flushQueuedCandidates(g *generationState) {
	if len(g.queuedCandidates) == 0 {
		return
	}
	queued := g.queuedCandidates
	g.queuedCandidates = nil
	current := queued[:0]
	for _, b := range queued {
		if b.epoch == g.idxEpoch {
			current = append(current, b)
			continue
		}
		// This batch's own index was rebuilt out from under it while it
		// sat queued — its own candidates describe a root the generation's
		// current index was never built from and can never be matched
		// against it.
		g.candidatesLostPermanently = true
	}
	if len(current) == 0 {
		return
	}
	s.submitCandidateBatches(g, g.idxEpoch, current)
}

// submitDBJob hands job to the dbworker's own FIFO channel without ever
// blocking loop: dbJobChCapacity is sized generously enough that a full
// channel is not expected in ordinary operation, but if it ever happens,
// this simply reports false and the caller retries (a build) or accepts
// one round's lost freshness (a lookup) rather than stalling loop's own
// select over it.
func (s *Session) submitDBJob(job dbJob) bool {
	select {
	case s.dbJobCh <- job:
		return true
	default:
		return false
	}
}

// dispatchWork is called once per discovery pass: it decides, for every
// live generation, whether to (re)resolve its mount basis and start a
// sample worker, and whether to (re)submit a package-database build job —
// the two "台帳で上限と重複を制御する" ledgers (aliveSampleWorkers/
// sampleAlive for sample workers, idxState for builds) are what keep either
// from starting twice for the same generation while one is already
// outstanding.
func (s *Session) dispatchWork(now time.Time) {
	s.checkBuildQueueHealth(now)
	s.retryPendingRouteEvents(now)
	// Every generation's own pendingEvents/pendingMountViewEvents/
	// pendingLookup are expired here, including one that has already ended:
	// an ended generation's evidence is still shown (and its own Incomplete
	// flag still read) for the whole 7-day retention window, so an entry it
	// can no longer do anything about must still be aged out rather than
	// left to hold Incomplete true indefinitely.
	for _, g := range s.generations {
		g.expirePendingEvents(now)
		g.expirePendingMountViewEvents(now)
		g.expirePendingLookup(now)
	}
	// A pendingLookup expiring above may have been the one thing a deferred
	// write (requestWrite) was still waiting on — this is normally already
	// handled well before pendingLookupTTL by writeDelayCh's own much
	// shorter budget, so this is only a defensive backstop, never expected
	// to be the thing that actually resumes a write in practice.
	s.resumeDeferredWrite()

	// Sample workers are dispatched oldest-verified-first, so that with
	// more live generations than maxConcurrentSampleWorkers, every
	// container eventually gets a turn rather than the same few (by map
	// iteration order) always winning.
	var candidates []*generationState
	for _, g := range s.generations {
		if g.ended || g.sampleAlive {
			continue
		}
		candidates = append(candidates, g)
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].lastVerifiedAt.Before(candidates[j].lastVerifiedAt) })
	for _, g := range candidates {
		if s.aliveSampleWorkers >= maxConcurrentSampleWorkers {
			break
		}
		s.startSampleWorker(g, now)
	}

	for _, g := range s.generations {
		if g.ended {
			continue
		}
		s.maybeSubmitBuild(g, now)
	}
}

// startSampleWorker starts g's sample worker goroutine — which resolves its
// own mount basis itself (see mountBasis's own doc comment for why that
// never happens here, in loop's own goroutine) — plus the small supervisor
// goroutine that enforces sampleWorkerBudget and reports exactly one of
// sampleEnvResult/sampleEnvTimeout, followed eventually by
// sampleEnvFinished, back through s.sampleResCh.
func (s *Session) startSampleWorker(g *generationState, now time.Time) {
	job := sampleJob{
		genKey:     g.key(),
		init:       g.init,
		processes:  g.pendingProcesses,
		indexReady: g.idxState == indexReady,
		ownUserNS:  s.ownUserNS,
		now:        now,
	}
	if job.indexReady && len(g.pendingEvents) > 0 {
		// Only handed to the worker once there is an index for the
		// eventual candidateBatch (submitted by applySampleResult once this
		// result comes back) to be looked up against — see
		// pendingEventItem's own doc comment.
		job.pendingEvents = append([]pendingEventItem(nil), g.pendingEvents...)
	}
	g.sampleAlive = true
	s.aliveSampleWorkers++

	sampleFn := s.sampleFn
	if sampleFn == nil {
		sampleFn = runSampleWorker
	}
	done := make(chan sampleResult, 1)
	go func() { done <- sampleFn(job) }()
	go func() {
		select {
		case r := <-done:
			s.sampleResCh <- sampleEnvelope{kind: sampleEnvResult, genKey: job.genKey, result: r}
			return
		case <-time.After(s.sampleTimeout):
			s.sampleResCh <- sampleEnvelope{kind: sampleEnvTimeout, genKey: job.genKey}
		}
		<-done // the abandoned worker eventually finishes
		s.sampleResCh <- sampleEnvelope{kind: sampleEnvFinished, genKey: job.genKey}
	}()
}

// maybeSubmitBuild submits a build job for g if its own index is idle or
// failed (queued/building/ready need no new job — see indexState's own doc
// comment) and the build queue is not currently reporting itself stalled
// (buildQueueStalled). Every outstanding ParseFailure is handed to the job
// as an immutable snapshot so the dbworker can apply the exact same
// per-file backoff rule loop itself would, without sharing any state.
func (s *Session) maybeSubmitBuild(g *generationState, now time.Time) {
	if g.idxState != indexIdle && g.idxState != indexFailed {
		return
	}
	if s.buildQueueStalled {
		return
	}
	prev := g.idxState
	g.idxState = indexQueued
	job := dbJob{
		kind: dbJobBuild, genKey: g.key(), rootPID: g.init.PID, starttime: g.init.Starttime,
		knownFailures: append([]evidence.ParseFailure(nil), g.parseFailed...),
		interval:      s.cfg.Interval, now: now,
		// epoch tells the dbworker goroutine which index generation this
		// build is for — recorded there as soon as this job is dequeued
		// (see runDBWorker's own epoch check), regardless of whether the
		// build itself succeeds, since g.idxEpoch was already bumped (see
		// applySampleResult's own mount-basis-mismatch branch) the moment
		// this rebuild was decided to be necessary at all.
		epoch: g.idxEpoch,
	}
	if !s.submitDBJob(job) {
		g.idxState = prev
		return
	}
	g.idxState = indexBuilding
	g.idxQueuedAt = now
}

// checkBuildQueueHealth reports SensorDegraded (via buildQueueStalled) and
// stops new build submissions once the oldest still-outstanding build job
// (queued or building) has been waiting more than buildSoftStall — jobs
// already in flight are unaffected; this only ever suppresses starting new
// ones.
func (s *Session) checkBuildQueueHealth(now time.Time) {
	var oldest time.Time
	for _, g := range s.generations {
		if g.idxState != indexQueued && g.idxState != indexBuilding {
			continue
		}
		if oldest.IsZero() || g.idxQueuedAt.Before(oldest) {
			oldest = g.idxQueuedAt
		}
	}
	s.buildQueueStalled = !oldest.IsZero() && now.Sub(oldest) > buildSoftStall
}

// writeParseFailedAndExit is the startup order's own contract for a parser
// that has died: mark every not-yet-ended generation StateParseFailed and
// write one final evidence snapshot before this process exits, letting the
// container runtime's restart policy bring up a fresh Sensor.
func (s *Session) writeParseFailedAndExit(err error) {
	for _, g := range s.generations {
		if !g.ended {
			g.forceParseFailed = true
		}
	}
	s.writeFinalSnapshotAndWait(evidence.SensorDegraded)
}

// computeStatus derives this sample's Sensor-wide status from every
// permission/failure condition that has a SensorInfo.Status value at all,
// in priority order (most severe first):
//
//  1. isolationStatus != SensorOK — the startup self-check's own verdict.
//     Fixed at startup, never overridden by anything a later sample
//     observes.
//  2. !capSysPtraceOK, or every live generation that has been sampled at
//     least once is StateDenied — SensorPermissionDenied. Unlike an
//     earlier version of this Sensor, this is checked against the
//     generations' own current State directly rather than a per-sample
//     attempted/denied tally: sampling is no longer organized into
//     discrete, all-at-once passes (see loop's own doc comment), so there
//     is no single "this sample" attempted/denied count to check instead.
//  3. !capDacReadSearchOK, the build queue reporting itself stalled
//     (buildQueueStalled), writeFailureDegradeThreshold consecutive write
//     failures, or the last write needing to drop/trim anything to fit the
//     reader's own limits (lastWriteModified) — SensorDegraded.
//
// A single container's reads being refused on its own (an AppArmor
// mismatch specific to that container) becomes StateDenied on that one
// generationState (see lastGoodSample), never a Sensor-wide status by
// itself.
func (s *Session) computeStatus() evidence.SensorStatus {
	if s.isolationStatus != evidence.SensorOK {
		return s.isolationStatus
	}
	if !s.capSysPtraceOK {
		return evidence.SensorPermissionDenied
	}
	liveCount, deniedCount := 0, 0
	for _, g := range s.generations {
		if g.ended || g.lastVerifiedAt.IsZero() {
			continue
		}
		liveCount++
		if derivePublishedState(g) == evidence.StateDenied {
			deniedCount++
		}
	}
	if liveCount > 0 && deniedCount == liveCount {
		return evidence.SensorPermissionDenied
	}
	if !s.capDacReadSearchOK || s.buildQueueStalled || s.writeFailureStreak >= writeFailureDegradeThreshold || s.lastWriteModified {
		return evidence.SensorDegraded
	}
	return evidence.SensorOK
}

// reconcileGenerations creates a new generationState for a container this
// Sensor has not seen before or whose init process changed (a restart or
// recreation — either way, evidence does not carry over: see evidence's own
// generation-identity doc comment), and marks StateEnded for any generation
// whose container is no longer present in groups at all. It never removes a
// generationState from the map itself — pruneEndedGenerations does that,
// after the 7-day retention window evidence.Generation.EndedAt documents.
// It also refreshes pendingProcesses for every generation that continues
// unchanged, which is what dispatchWork's next sample worker actually reads.
func (s *Session) reconcileGenerations(groups map[string]containerGroup, now time.Time) {
	liveByContainer := map[string]*generationState{}
	for _, g := range s.generations {
		if !g.ended {
			liveByContainer[g.container.ID] = g
		}
	}

	for containerID, group := range groups {
		existing, ok := liveByContainer[containerID]
		if ok && existing.init.PID == group.Init.PID && existing.init.Starttime == group.Init.Starttime {
			existing.pendingProcesses = group.Processes
			continue // same generation continues
		}
		if ok {
			s.endGeneration(existing, now)
		}
		ref := evidence.ContainerRef{Runtime: "docker", ID: containerID}
		initialCoverage, watermarkProtected := s.initialEventsCoverage(group.Init.Starttime)
		gs := newGenerationState(ref, group.Init, now, initialCoverage)
		if watermarkProtected {
			// This generation was not even discovered yet at the moment
			// some other, unclassifiable kernel loss had to be forced out
			// of a pending queue without waiting for discovery — see
			// initialEventsCoverage's own doc comment for why CoveragePartial
			// alone would not be enough to keep a package that loss was
			// itself evidence for from later being judged not_observed.
			// Sticky, like every other incomplete=true: a permanent fact
			// about this generation's own coverage having a gap from its
			// own start, not a transient condition later classification
			// resolves away.
			gs.incomplete = true
		}
		gs.pendingProcesses = group.Processes
		s.generations[gs.key()] = gs
	}
	// A newly (re)resolved generation may unblock events that were sitting
	// in the pending-route queue only because no live generationState
	// existed yet for their own container ID (see
	// resolveEventGeneration's own doc comment on that startup race).
	s.retryPendingRouteEvents(now)

	for containerID, g := range liveByContainer {
		if _, ok := groups[containerID]; !ok {
			s.endGeneration(g, now)
			// Pruned here, not on every endGeneration call: a same-ID
			// restart (the branch above, ending the old generation only to
			// immediately create a new one for the same container ID) keeps
			// the same underlying cgroup, so its own mapping must survive.
			// Only "no longer present in groups at all" means the container
			// itself is confirmed gone and its own cgroup(s) will never
			// produce another event.
			s.cgroupRoute.pruneContainer(containerID)
			if g.mntNsID != 0 {
				s.pathIdx.pruneMountNamespace(g.mntNsID)
			}
		}
	}
}

// endGeneration marks g ended and asks the dbworker to forget any index it
// built for it — best-effort and non-blocking: if the parser connection is
// already broken, the next build's own attempt to use it will surface that
// as a fatal error through the dbworker instead.
func (s *Session) endGeneration(g *generationState, now time.Time) {
	g.ended = true
	g.endedAt = &now
	// now is the discovery pass's own start, which can precede the moment
	// the process actually exited. The loop's own clock at the time the end
	// is applied never precedes it, and is on the same clock
	// reconcileEventLossCounters reads the loss counters on.
	g.endAppliedAt = s.now()
	s.submitDBJob(dbJob{kind: dbJobForget, genKey: g.key()})
}

// endedRetention is how long a StateEnded generation is kept in the evidence
// file before pruneEndedGenerations removes it.
const endedRetention = 7 * 24 * time.Hour

func (s *Session) pruneEndedGenerations(now time.Time) {
	for key, g := range s.generations {
		if g.ended && g.endedAt != nil && now.Sub(*g.endedAt) > endedRetention {
			// A worker still alive for a generation this old would mean a
			// goroutine has been blocked for a week; left as ASSUMED-safe
			// rather than specially guarded against, since nothing in this
			// package can force such a goroutine to exit anyway (see
			// sampleEnvFinished's own doc comment).
			delete(s.generations, key)
		}
	}
}

// writeSnapshotNow assembles the current Session state into an
// evidence.Snapshot and hands it to the writer goroutine via submitSnapshot
// (never blocking loop). It is called only from loop's own goroutine, at
// heartbeatInterval's own fixed cadence, on startup's own early isolation-
// failure exit, and once, finally, from writeParseFailedAndExit.
func (s *Session) writeSnapshotNow(status evidence.SensorStatus) {
	submitSnapshot(s.writerCh, s.buildSnapshot(status))
}

// writeFinalSnapshotAndWait is writeSnapshotNow's own final-write variant:
// called only when this Sensor session is about to end (the parser died,
// isolation could not be established, or ctx was canceled), it blocks until
// the writer goroutine has actually finished this exact write (or failed
// trying) before returning, so Run never returns — and the container's own
// process exits — while the last thing this session had to say is still
// only queued, not on disk. Safe to call exactly because only loop's own
// goroutine ever submits to s.writerCh at all: nothing else can race this
// submission with one of its own and steal the single coalescing slot
// before the writer gets to this one (see submitFinalSnapshot's own doc
// comment).
func (s *Session) writeFinalSnapshotAndWait(status evidence.SensorStatus) {
	rep := submitFinalSnapshot(s.writerCh, s.buildSnapshot(status))
	// rep.consecutiveFailures is runWriter's own count — see writeReport's
	// own doc comment and the same assignment in loop's own select.
	s.writeFailureStreak = rep.consecutiveFailures
	s.lastWriteModified = rep.modified
}

// buildSnapshot assembles the current Session state into an
// evidence.Snapshot reporting status. Reading and attributing the eBPF ring
// buffer's own loss counters (reconcileEventLossCounters) happens here, once
// per snapshot, rather than on some independent schedule of its own: every
// path that produces a snapshot (a heartbeat tick, an applied sample result,
// the final snapshot on shutdown or an isolation failure) shares the one
// place every generation's own EventsLost/EventsCoverage actually get
// updated from the kernel's own counters, before s.eventsLost (the
// Sensor-wide total) is itself derived from them — the sum of every
// generation's own events_lost plus s.unattributedEventsLost (every loss
// this session could never charge to a specific generation at all: a
// pendingRouteEvent that expired unresolved, a pendingEventItem that expired
// waiting on an index build, a maps-fallback or genConfirm request dropped
// for exceeding its own pool's queue, and reconcileEventLossCounters' own
// unattributable share of the kernel's counters). This is the one running
// total everything else contributes to; it is never derived from the
// kernel's own counter values directly, which would double-count whatever
// has already been attributed via recordEventLoss.
func (s *Session) buildSnapshot(status evidence.SensorStatus) evidence.Snapshot {
	now := s.now()
	s.reconcileEventLossCounters()
	var attributedLost int64
	for _, g := range s.generations {
		attributedLost += g.eventsLost
	}
	s.eventsLost = attributedLost + s.unattributedEventsLost
	snap := evidence.Snapshot{
		Schema: evidence.Schema,
		Sensor: evidence.SensorInfo{
			Version:          "dev",
			SessionID:        s.sessionID,
			SessionStartedAt: s.sessionStartedAt,
			HeartbeatAt:      now,
			IntervalSeconds:  int(s.cfg.Interval / time.Second),
			Isolation:        s.isolation,
			Status:           status,
			Events: evidence.EventsInfo{
				Status:       s.eventsStatus,
				Reason:       s.eventsReason,
				AttachedAt:   s.eventsAttachedAt,
				Lost:         s.eventsLost,
				Unclassified: s.eventsUnclassified,
			},
		},
	}
	incompletePending := s.pendingRouteEventGating()
	// A kernel per-cgroup ring-buffer loss delta this session cannot yet
	// resolve (pendingLossDeltas) carries no mount namespace at all — unlike
	// a pendingRouteEvent, there is nothing here to narrow which live
	// generation it might belong to (see pendingRouteEventGating's own
	// tier-2-style narrowing, which needs at least a mount namespace to
	// work with) — so every live generation publishes Incomplete for as
	// long as anything sits in this queue at all, not sticky: the moment
	// retryPendingLossDeltas actually resolves or finalizes every entry
	// (queue empties), this reverts on its own, the next snapshot.
	anyPendingLossDelta := len(s.pendingLossDeltas) > 0
	for _, g := range s.generations {
		hasPendingRouteEvent := !g.ended && (incompletePending[g.container.ID] || anyPendingLossDelta)
		snap.Generations = append(snap.Generations, g.toEvidence(hasPendingRouteEvent))
	}
	return snap
}

// pendingRouteEventGating inspects every event still sitting in
// s.pendingRouteEvents — every event this session has received but has not
// yet been able to place in any specific generation at all (see
// pendingRouteEvent's own doc comment) — and returns the set of container
// IDs whose own live generation must be marked Incomplete because of at
// least one of them:
//
//   - a pending item whose own cgroup is already classified (s.cgroupRoute
//     resolves it to a real, non-excluded container) marks only that one
//     container's own live generation, since the item could still turn out
//     to belong to it once fully routed.
//   - a pending item whose own cgroup cannot be classified at all right now
//     (s.cgroupRoute has never seen it, or it was evicted since — see
//     maxCgroupRouteEntries — or applyCgroupMkdirEvent refused a
//     truncated/empty path for it) is narrowed by the same rule
//     classifyUnattributedExpiry's own tier 2 uses at TTL-expiry time,
//     rather than marking every live generation this session holds the way
//     an earlier version of this method did: it marks a live generation
//     whose own mount view is not yet confirmed at all (g.mntNsID == 0,
//     nothing to rule it out on yet), or whose own already-confirmed mount
//     view this item's own mount namespace actually matches — never one
//     this item's own mount namespace demonstrably could not belong to.
//
// Computed once per snapshot (buildSnapshot) and consulted only for a live
// generation — an event that might belong to a container could equally turn
// out to belong to whichever generation is its *current* one, never to one
// already ended.
func (s *Session) pendingRouteEventGating() map[string]bool {
	var incomplete map[string]bool
	mark := func(containerID string) {
		if incomplete == nil {
			incomplete = map[string]bool{}
		}
		incomplete[containerID] = true
	}
	for _, item := range s.pendingRouteEvents {
		containerID, isKnown := s.cgroupRoute.lookup(item.ev.CgroupID)
		if isKnown {
			if containerID == "" || matchesExcludedID(containerID, s.cfg.ExcludeIDs) {
				continue
			}
			mark(containerID)
			continue
		}
		mnt := uint32(item.ev.MountNamespaceID)
		for _, g := range s.generations {
			if g.ended {
				continue
			}
			if g.mntNsID == 0 || (mnt != 0 && g.mntNsID == mnt) {
				mark(g.container.ID)
			}
		}
	}
	return incomplete
}
