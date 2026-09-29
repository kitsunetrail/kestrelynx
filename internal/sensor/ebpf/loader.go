package ebpf

import (
	"errors"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"
)

// excludedCgroupSlot and lostEventsSlot are the single index each of
// kl_excluded_cgroup and kl_lost_events holds its one value at.
const (
	excludedCgroupSlot uint32 = 0
	lostEventsSlot     uint32 = 0
	hostMntNSSlot      uint32 = 0
	pidNSSlot          uint32 = 0
)

// DefaultRingBufferBytes is kl_events' own compiled-in size (2 MiB, 512
// pages on a 4 KiB page): a starting size, to be revisited once real drop
// counts are measured under load — see bpf/kestrelynx.c's own comment on the
// kl_events map definition. Load always uses this value;
// LoadWithRingBufferBytes lets a caller override it.
const DefaultRingBufferBytes uint32 = 1 << 21

// ValidateRingBufferBytes reports whether n is an acceptable kl_events ring
// buffer size for LoadWithRingBufferBytes: nonzero, representable in the
// 32-bit field the BPF map spec itself uses, a multiple of the host's own
// page size, and a power of two. The last two are not this package's own
// preference — BPF_MAP_TYPE_RINGBUF rejects any other max_entries value
// in-kernel — so callers (in particular, a command-line flag) should call
// this before Load/LoadWithRingBufferBytes ever runs, to turn a bad value
// into a startup error rather than a Load-time one.
func ValidateRingBufferBytes(n uint64) error {
	if n == 0 || uint64(uint32(n)) != n {
		return fmt.Errorf("ebpf: ring buffer size %d is out of range", n)
	}
	pageSize := uint64(unix.Getpagesize())
	if n%pageSize != 0 {
		return fmt.Errorf("ebpf: ring buffer size %d is not a multiple of the page size (%d)", n, pageSize)
	}
	if n&(n-1) != 0 {
		return fmt.Errorf("ebpf: ring buffer size %d is not a power of two", n)
	}
	return nil
}

// attachPoint pairs a loaded program with the attach type its SEC() prefix
// in bpf/kestrelynx.c compiles to. link.AttachTracing needs this explicitly:
// leaving TracingOptions.AttachType at its zero value does not mean "use
// whatever the program was compiled for", it means AttachNone, which
// attachBTFID resolves to the legacy RawTracepointOpen path instead of the
// fentry/fexit/tp_btf link the program actually needs.
type attachPoint struct {
	name string
	prog *ebpf.Program
	at   ebpf.AttachType
}

func attachPoints(objs *kestrelynxebpfObjects) []attachPoint {
	return []attachPoint{
		{kestrelynxebpfProgKlExecSuccess, objs.KlExecSuccess, ebpf.AttachTraceRawTp},
		{kestrelynxebpfProgKlFileOpen, objs.KlFileOpen, ebpf.AttachTraceFEntry},
		{kestrelynxebpfProgKlMmapSuccess, objs.KlMmapSuccess, ebpf.AttachTraceFExit},
		{kestrelynxebpfProgKlMmapOpen, objs.KlMmapOpen, ebpf.AttachTraceFEntry},
		{kestrelynxebpfProgKlCgroupMkdir, objs.KlCgroupMkdir, ebpf.AttachTraceRawTp},
	}
}

// Handle is what remains usable once Load has created the maps and ring
// buffer, written the Sensor's own cgroup ID into the exclusion map, and
// attached all five programs. It deliberately exposes only map and ring
// buffer operations. By the time a caller holds a Handle, the observer is
// expected to have already dropped CAP_BPF and CAP_PERFMON (Load itself
// does not touch capabilities; dropping them is a separate builder's job in
// sensor/sandbox), and no further program load, map creation or link attach
// is expected to work or to be attempted.
type Handle struct {
	objs   kestrelynxebpfObjects
	links  []link.Link
	reader *ringbuf.Reader
}

// Read blocks until the next event is available, Close is called, or an
// error occurs. Per (*ringbuf.Reader).Read's own contract, calling Close
// concurrently from another goroutine unblocks a pending Read with
// ringbuf.ErrClosed rather than leaving it blocked forever.
func (h *Handle) Read() (Event, error) {
	record, err := h.reader.Read()
	if err != nil {
		return Event{}, err
	}
	return DecodeEvent(record.RawSample)
}

// LostEvents returns kl_lost_events, the fallback counter for a lost event
// that could not be attributed to any one cgroup's own counter (cgroup ID
// unknown, or kl_lost_by_cgroup itself was full) — not the Sensor-wide
// total. A caller that wants the Sensor-wide total adds this to the sum of
// every value LostEventsByCgroup returns.
func (h *Handle) LostEvents() (uint64, error) {
	var count uint64
	if err := h.objs.KlLostEvents.Lookup(lostEventsSlot, &count); err != nil {
		return 0, fmt.Errorf("ebpf: read lost-events counter: %w", err)
	}
	return count, nil
}

// LostEventsByCgroup returns kl_lost_by_cgroup's full contents: how many
// events were dropped (bpf_ringbuf_reserve failed) for each cgroup ID that
// has lost at least one, since the programs attached. A cgroup ID absent
// from the returned map has lost none. Combined with LostEvents (the
// fallback counter for a loss that could not be attributed this way), this
// is what lets a caller mark only the generations that actually lost events
// "partial" rather than every generation whenever the ring buffer is
// briefly oversubscribed by one noisy container.
func (h *Handle) LostEventsByCgroup() (map[uint64]uint64, error) {
	out := map[uint64]uint64{}
	var key uint64
	var value uint64
	it := h.objs.KlLostByCgroup.Iterate()
	for it.Next(&key, &value) {
		out[key] = value
	}
	if err := it.Err(); err != nil {
		return nil, fmt.Errorf("ebpf: iterate lost-by-cgroup counter: %w", err)
	}
	return out, nil
}

// DeletePathSeen removes one entry from kl_dedup_path — the kernel's own
// (mount namespace, root identity, dev, inode)-keyed suppression window for
// fentry/security_file_open's own FILE_OPEN/EXEC_OPEN records (see
// bpf/kestrelynx.c's kl_path_key/kl_path_seen). Called once the Sensor's own
// userspace correlation table evicts the path it had recorded for this exact
// tuple (sensor.pathIndex's own onEvict hook), so a later open of the same
// file is not left suppressed, silently, for the rest of that window purely
// because userspace has already forgotten the path it would have resolved
// to — without this, the kernel's own suppression state and userspace's own
// correlation table are free to disagree about whether a path is still
// "known" for up to that window's own duration.
//
// rootDev, rootIno, dev, ino are all in the kernel's own encoding — the same
// raw values an ebpf.Event's own RootDev/RootIno/Dev/Ino fields carry,
// never formatted or reinterpreted. A missing key (ebpf.ErrKeyNotExist) is
// not treated as an error: kl_dedup_path is itself a BPF_MAP_TYPE_LRU_HASH
// map that may have already evicted this exact key on its own, under its
// own memory pressure, which leaves this call with nothing left to do but
// already satisfies its whole purpose (no stale suppression left behind for
// this tuple).
func (h *Handle) DeletePathSeen(mntNsID uint32, rootDev, rootIno, dev, ino uint64) error {
	key := kestrelynxebpfKlPathKey{MntNsId: mntNsID, RootDev: rootDev, RootIno: rootIno, Dev: dev, Ino: ino}
	return ignoreKeyNotExist(h.objs.KlDedupPath.Delete(key))
}

// Close releases the ring buffer reader, every attached link, and every map
// and program file descriptor. It is safe to call more than once; later
// calls return the error(s) from closing already-closed resources, which
// cilium/ebpf's Close methods tolerate.
func (h *Handle) Close() error {
	var errs []error
	if h.reader != nil {
		errs = append(errs, h.reader.Close())
	}
	for _, l := range h.links {
		errs = append(errs, l.Close())
	}
	errs = append(errs, h.objs.Close())
	return errors.Join(errs...)
}

// Load creates the Sensor's BPF maps and ring buffer, writes
// excludedCgroupID into the self-exclusion map and hostMntNSID into the
// host-mount-namespace filter map, then loads and attaches all five
// programs in bpf/kestrelynx.c, in that order: both maps must hold their
// values before any program can run, or the Sensor's own early file opens
// (reading its own package DB, etc.) could be captured before any program
// is told to ignore them.
//
// excludedCgroupID is the cgroup ID the observer and parser processes share
// (they run in the same container, hence the same cgroup). It must be
// nonzero: the BPF side treats 0 as "no exclusion configured" so that a
// forgotten call site fails open to "excludes nothing" rather than to
// "excludes cgroup 0", which could be a real cgroup.
//
// hostMntNSID is the real host's own (PID 1's) mount namespace inode number
// (session.go's own s.hostMntNSID, resolved once at startup) — kl_file_open
// drops a file open reporting this exact mount namespace before doing any
// further work at all (see kl_host_mnt_ns's own doc comment). Unlike
// excludedCgroupID, 0 is accepted here (never rejected as a caller error):
// resolving the host's own mount namespace can fail for reasons that should
// not themselves prevent the Sensor from starting at all (see
// kl_is_host_mnt_ns's own doc comment on 0 meaning "no filter configured,
// fail open" — this hook still runs normally, just without this one
// optimization).
//
// If any step fails, Load closes everything it created so far — both maps,
// any objects loaded before the failing step, the ring buffer reader, any
// links already attached — and returns the error. It never leaves maps,
// programs or links behind on failure.
//
// Load always sizes kl_events at DefaultRingBufferBytes; LoadWithRingBufferBytes
// is the same sequence with that size overridable, for a caller (the
// Sensor's own --ring-buffer-bytes flag, and the integration test that
// deliberately forces ring-buffer overflow) that needs a different one.
func Load(excludedCgroupID uint64, hostMntNSID uint64) (*Handle, error) {
	return LoadWithRingBufferBytes(excludedCgroupID, hostMntNSID, DefaultRingBufferBytes)
}

// LoadWithRingBufferBytes is Load with kl_events' own ring buffer size, in
// bytes, overridable rather than fixed at DefaultRingBufferBytes.
// ringBufferBytes must already satisfy ValidateRingBufferBytes — this
// function does not itself validate it, since by the time a caller holds a
// value it wants loaded, that value should already have been rejected at
// startup if it were bad; an invalid value here just surfaces as whatever
// error the kernel itself returns for a malformed BPF_MAP_TYPE_RINGBUF spec.
func LoadWithRingBufferBytes(excludedCgroupID uint64, hostMntNSID uint64, ringBufferBytes uint32) (_ *Handle, err error) {
	if excludedCgroupID == 0 {
		return nil, errors.New("ebpf: excludedCgroupID must be nonzero")
	}

	spec, err := loadKestrelynxebpf()
	if err != nil {
		return nil, fmt.Errorf("ebpf: load collection spec: %w", err)
	}
	// Overridden on this same spec instance, before it is ever loaded below
	// (via spec.LoadAndAssign, not the generated loadKestrelynxebpfObjects
	// helper, which would silently reload its own fresh copy of the spec and
	// discard this override): kl_events is not one of the maps replaced via
	// MapReplacements, so its MaxEntries is whatever this spec's own
	// MapSpec says at load time.
	spec.Maps[kestrelynxebpfMapKlEvents].MaxEntries = ringBufferBytes

	excludedMap, err := ebpf.NewMap(spec.Maps[kestrelynxebpfMapKlExcludedCgroup])
	if err != nil {
		return nil, fmt.Errorf("ebpf: create exclusion map: %w", err)
	}
	// CollectionOptions.MapReplacements below clones this map rather than
	// adopting it, so it is ours to close unconditionally once the objects
	// are loaded (or once loading fails).
	defer excludedMap.Close()

	if err := excludedMap.Put(excludedCgroupSlot, excludedCgroupID); err != nil {
		return nil, fmt.Errorf("ebpf: write excluded cgroup ID: %w", err)
	}

	hostMntNSMap, err := ebpf.NewMap(spec.Maps[kestrelynxebpfMapKlHostMntNs])
	if err != nil {
		return nil, fmt.Errorf("ebpf: create host mount namespace map: %w", err)
	}
	defer hostMntNSMap.Close()

	if err := hostMntNSMap.Put(hostMntNSSlot, hostMntNSID); err != nil {
		return nil, fmt.Errorf("ebpf: write host mount namespace ID: %w", err)
	}

	pidNS, err := ownPIDNamespace()
	if err != nil {
		return nil, err
	}
	pidNSMap, err := ebpf.NewMap(spec.Maps[kestrelynxebpfMapKlPidNs])
	if err != nil {
		return nil, fmt.Errorf("ebpf: create PID namespace map: %w", err)
	}
	defer pidNSMap.Close()

	if err := pidNSMap.Put(pidNSSlot, pidNS); err != nil {
		return nil, fmt.Errorf("ebpf: write PID namespace ID: %w", err)
	}

	var objs kestrelynxebpfObjects
	opts := &ebpf.CollectionOptions{
		MapReplacements: map[string]*ebpf.Map{
			kestrelynxebpfMapKlExcludedCgroup: excludedMap,
			kestrelynxebpfMapKlHostMntNs:      hostMntNSMap,
			kestrelynxebpfMapKlPidNs:          pidNSMap,
		},
	}
	// spec.LoadAndAssign, not loadKestrelynxebpfObjects: the latter reloads
	// its own fresh CollectionSpec internally and would silently discard the
	// kl_events MaxEntries override made on this spec above.
	if err := spec.LoadAndAssign(&objs, opts); err != nil {
		return nil, fmt.Errorf("ebpf: load objects: %w", err)
	}
	defer func() {
		if err != nil {
			objs.Close()
		}
	}()

	reader, err := ringbuf.NewReader(objs.KlEvents)
	if err != nil {
		return nil, fmt.Errorf("ebpf: open ring buffer reader: %w", err)
	}
	defer func() {
		if err != nil {
			reader.Close()
		}
	}()

	links, err := attachAll(&objs)
	if err != nil {
		return nil, fmt.Errorf("ebpf: attach programs: %w", err)
	}

	return &Handle{objs: objs, links: links, reader: reader}, nil
}

// attachAll attaches every program in attachPoints(objs), closing any links
// it already created before returning an error.
func attachAll(objs *kestrelynxebpfObjects) ([]link.Link, error) {
	return attachAllWith(attachPoints(objs), func(p attachPoint) (link.Link, error) {
		return link.AttachTracing(link.TracingOptions{Program: p.prog, AttachType: p.at})
	})
}

// attachAllWith drives the attach-or-unwind loop attachAll needs, but is
// generic over what "attach" produces: link.Link cannot be implemented
// outside the link package (its isLink method is unexported), so a test
// double for "something with a Close method" can only stand in for T here,
// not for link.Link itself. attachAll is the only production caller; tests
// call attachAllWith directly with a fake attach func to exercise the
// partial-failure unwind without a kernel that can actually load BPF
// programs.
func attachAllWith[T io.Closer](points []attachPoint, attach func(attachPoint) (T, error)) (_ []T, err error) {
	created := make([]T, 0, len(points))
	defer func() {
		if err != nil {
			for _, c := range created {
				c.Close()
			}
		}
	}()

	for _, p := range points {
		v, attachErr := attach(p)
		if attachErr != nil {
			return nil, fmt.Errorf("attach %s: %w", p.name, attachErr)
		}
		created = append(created, v)
	}

	return created, nil
}

// ownPIDNamespace returns the inode number of this process's own PID
// namespace. Events then report tgids in the same namespace this process
// reads /proc from.
func ownPIDNamespace() (uint64, error) {
	var st unix.Stat_t
	if err := unix.Stat("/proc/self/ns/pid", &st); err != nil {
		return 0, fmt.Errorf("ebpf: stat own PID namespace: %w", err)
	}
	return st.Ino, nil
}
