package ebpf

import (
	"errors"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

// excludedCgroupSlot and lostEventsSlot are the single index each of
// kl_excluded_cgroup and kl_lost_events holds its one value at.
const (
	excludedCgroupSlot uint32 = 0
	lostEventsSlot     uint32 = 0
)

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

// LostEvents returns the count of events dropped, Sensor-wide, because
// bpf_ringbuf_reserve failed (the ring buffer was full at submission time)
// since the programs attached.
func (h *Handle) LostEvents() (uint64, error) {
	var count uint64
	if err := h.objs.KlLostEvents.Lookup(lostEventsSlot, &count); err != nil {
		return 0, fmt.Errorf("ebpf: read lost-events counter: %w", err)
	}
	return count, nil
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
// excludedCgroupID into the self-exclusion map, then loads and attaches all
// five programs in bpf/kestrelynx.c, in that order: the exclusion map must
// hold its value before any program can run, or the Sensor's own early file
// opens (reading its own package DB, etc.) could be captured before any
// program is told to ignore them.
//
// excludedCgroupID is the cgroup ID the observer and parser processes share
// (they run in the same container, hence the same cgroup). It must be
// nonzero: the BPF side treats 0 as "no exclusion configured" so that a
// forgotten call site fails open to "excludes nothing" rather than to
// "excludes cgroup 0", which could be a real cgroup.
//
// If any step fails, Load closes everything it created so far — the
// exclusion map, any objects loaded before the failing step, the ring
// buffer reader, any links already attached — and returns the error. It
// never leaves maps, programs or links behind on failure.
func Load(excludedCgroupID uint64) (_ *Handle, err error) {
	if excludedCgroupID == 0 {
		return nil, errors.New("ebpf: excludedCgroupID must be nonzero")
	}

	spec, err := loadKestrelynxebpf()
	if err != nil {
		return nil, fmt.Errorf("ebpf: load collection spec: %w", err)
	}

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

	var objs kestrelynxebpfObjects
	opts := &ebpf.CollectionOptions{
		MapReplacements: map[string]*ebpf.Map{
			kestrelynxebpfMapKlExcludedCgroup: excludedMap,
		},
	}
	if err := loadKestrelynxebpfObjects(&objs, opts); err != nil {
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
