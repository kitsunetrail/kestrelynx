package ebpf

import (
	"errors"
	"fmt"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

// SetReadDeadline bounds how long the next call to Read blocks, exactly as
// (*ringbuf.Reader).SetDeadline does: a zero Time clears the deadline, and
// Read then blocks until an event arrives or Close is called. A caller that
// wants to sample events for a fixed window instead of blocking forever
// sets a deadline before calling Read and expects
// os.ErrDeadlineExceeded once no event has arrived by then.
func (h *Handle) SetReadDeadline(t time.Time) {
	h.reader.SetDeadline(t)
}

// ExcludedCgroupID reads back the cgroup ID Load wrote into the
// self-exclusion map, so a caller can confirm the value actually stored in
// the kernel is the one it asked Load to exclude (rather than trusting that
// the write in Load silently succeeded).
func (h *Handle) ExcludedCgroupID() (uint64, error) {
	var id uint64
	if err := h.objs.KlExcludedCgroup.Lookup(excludedCgroupSlot, &id); err != nil {
		return 0, fmt.Errorf("ebpf: read excluded cgroup ID: %w", err)
	}
	return id, nil
}

// MapOpsProbe is the result of exercising every basic bpf(2) map operation
// (lookup, update, iterate, delete) directly against the Sensor's own maps.
// It exists to be run once the observer has already dropped
// CAP_BPF/CAP_PERFMON and installed its final seccomp filter, which is
// meant to still allow exactly these four operations on maps already open
// (see sandbox.ObserverFilter's bpf allow-list) — a nil field means that
// operation reached the kernel's map code (including a well-formed "no such
// key" answer, which still proves the operation was not rejected outright);
// a non-nil field means it was denied.
type MapOpsProbe struct {
	Lookup  error
	Update  error
	NextKey error
	Delete  error
}

// selftestKey is the one key ProbeMapOps ever uses in kl_selftest.
const selftestKey uint32 = 1

// ProbeMapOps runs lookup, update, iterate, and delete entirely against
// kl_selftest — a map bpf/kestrelynx.c dedicates to exactly this purpose and
// no attach point ever reads or writes. It never touches kl_lost_events (a
// live counter an attached program may be incrementing concurrently) or
// kl_dedup (whose contents an attach point may depend on for suppression),
// so running this probe cannot perturb either one's real state. A "key not
// found" result from NextKey/Delete before this probe's own Update has ever
// run still counts as reaching the kernel rather than being denied, per
// MapOpsProbe's doc comment.
func (h *Handle) ProbeMapOps() MapOpsProbe {
	var out MapOpsProbe

	var val uint64
	out.Lookup = ignoreKeyNotExist(h.objs.KlSelftest.Lookup(selftestKey, &val))
	out.Update = h.objs.KlSelftest.Update(selftestKey, uint64(0xdeadbeef), ebpf.UpdateAny)

	var nextKey uint32
	out.NextKey = ignoreKeyNotExist(h.objs.KlSelftest.NextKey(nil, &nextKey))
	out.Delete = ignoreKeyNotExist(h.objs.KlSelftest.Delete(selftestKey))
	return out
}

// ignoreKeyNotExist folds ebpf.ErrKeyNotExist into nil: see ProbeMapOps'
// doc comment for why that specific error still counts as success for this
// probe's purpose.
func ignoreKeyNotExist(err error) error {
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return nil
	}
	return err
}

// LoadForFaultInjectionTest behaves exactly like Load, except it
// deliberately corrupts one attach point (a nil program, standing in for a
// nonexistent one) before attaching, forcing attachAllWith to fail partway
// through the five attach points bpf/kestrelynx.c defines. It exists for
// the deployment-verification tool (kestrelynx sensor --probe) to confirm,
// against a real partial-attach failure rather than only the fake-closer
// unit test in attach_test.go, that every map, program, and link created so
// far is closed on that failure and the caller can continue without eBPF —
// never used by the real observer.
func LoadForFaultInjectionTest(excludedCgroupID uint64) (_ *Handle, err error) {
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
	defer excludedMap.Close()
	if err := excludedMap.Put(excludedCgroupSlot, excludedCgroupID); err != nil {
		return nil, fmt.Errorf("ebpf: write excluded cgroup ID: %w", err)
	}

	var objs kestrelynxebpfObjects
	opts := &ebpf.CollectionOptions{
		MapReplacements: map[string]*ebpf.Map{kestrelynxebpfMapKlExcludedCgroup: excludedMap},
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

	points := attachPoints(&objs)
	if len(points) < 3 {
		return nil, fmt.Errorf("ebpf: fault injection test needs at least 3 attach points, got %d", len(points))
	}
	// A throwaway, already-closed program (not one of objs's own — closing
	// one of those here would make Handle's later Close double-close it)
	// stands in for the third attach point: link.AttachTracing dereferences
	// its Program argument's fields directly, so a literal nil there
	// segfaults instead of returning an error, but a real *ebpf.Program
	// whose fd has already been closed fails the same way a genuinely
	// broken attach point would — cleanly, with an error link.AttachTracing
	// itself returns.
	badProg, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type:         ebpf.SocketFilter,
		License:      "GPL",
		Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 0), asm.Return()},
	})
	if err != nil {
		return nil, fmt.Errorf("ebpf: fault injection test: build throwaway program: %w", err)
	}
	badProg.Close()
	points[2].prog = badProg

	links, err := attachAllWith(points, func(p attachPoint) (link.Link, error) {
		return link.AttachTracing(link.TracingOptions{Program: p.prog, AttachType: p.at})
	})
	if err != nil {
		return nil, fmt.Errorf("ebpf: simulated attach failure (fault injection test): %w", err)
	}
	// Not reached in practice (the corrupted attach point always fails
	// first), but handled correctly if the fault injection above ever stops
	// producing a failure: callers must not depend on this ever returning a
	// live Handle.
	return &Handle{objs: objs, links: links, reader: reader}, nil
}
