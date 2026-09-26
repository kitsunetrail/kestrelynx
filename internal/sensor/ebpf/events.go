package ebpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

// EventKind identifies which of the five attach points in bpf/kestrelynx.c
// produced an Event. Values are a hand-written mirror of that file's
// KL_EVENT_* constants; TestEventKindMatchesBPFSource greps the C source to
// keep the two from drifting apart.
type EventKind uint8

const (
	EventExecSuccess EventKind = 1
	EventExecOpen    EventKind = 2
	EventMmapSuccess EventKind = 3
	EventFileOpen    EventKind = 4
	EventCgroupMkdir EventKind = 5
	EventMmapOpen    EventKind = 6
)

func (k EventKind) String() string {
	switch k {
	case EventExecSuccess:
		return "exec_success"
	case EventExecOpen:
		return "exec_open"
	case EventMmapSuccess:
		return "mmap_success"
	case EventFileOpen:
		return "file_open"
	case EventCgroupMkdir:
		return "cgroup_mkdir"
	case EventMmapOpen:
		return "mmap_open"
	default:
		return fmt.Sprintf("event_kind(%d)", uint8(k))
	}
}

// Event is the decoded form of one ring buffer record. Which fields are
// meaningful depends on Kind (see bpf/kestrelynx.c's per-program comments):
//
//   - EventExecSuccess, EventMmapSuccess: usage evidence. CgroupID, Dev, Ino
//     identify the executed or mapped file; Path is empty, since these fire
//     from tp_btf/fexit hooks that cannot call bpf_d_path. A consumer
//     resolves the path from a correlated EventFileOpen sharing the same
//     (MountNamespaceID, Dev, Ino).
//   - EventExecOpen, EventFileOpen: path resolution only, from
//     fentry/security_file_open. EventExecOpen additionally carries the
//     same process identifiers as EventExecSuccess, captured at open time
//     rather than at exec-success time (see the C source for why these can
//     differ for setuid/file-capability binaries).
//   - EventMmapOpen: an executable-mapping attempt from
//     fentry/security_mmap_file, recorded separately from EventMmapSuccess.
//     Not usage evidence (it fires before do_mmap runs) and carries no path
//     (security_mmap_file cannot call bpf_d_path).
//   - EventCgroupMkdir: CgroupID and Path only, everything else zero.
//
// One event per occurrence is not guaranteed: the BPF side suppresses a
// repeat of the same (CgroupID, Dev, Ino, Kind) tuple for a window after it
// is sent (see bpf/kestrelynx.c's dedup map), so a later occurrence of the
// same tuple from a different process, a different EUID, or a different
// CapEffective within that window is not reported at all, not merged into
// the one that was.
type Event struct {
	Kind             EventKind
	CgroupID         uint64
	MountNamespaceID uint64
	UserNamespaceID  uint64
	TGID             uint64
	StartBoottimeNs  uint64
	CapEffective     uint64
	Dev              uint64
	Ino              uint64
	// RootDev/RootIno are the calling task's own fs->root identity at the
	// moment a success event fired (kl_current_root_identity in
	// bpf/kestrelynx.c) — set only for EventExecSuccess/EventMmapSuccess,
	// zero for every other Kind. RootDev is the kernel-internal dev_t
	// encoding, exactly like Dev; a caller decodes both the same way.
	RootDev       uint64
	RootIno       uint64
	KtimeNs       uint64
	EUID          uint32
	Prot          uint32
	PathTruncated bool
	Path          string
}

// ErrShortRecord is returned by DecodeEvent when a record is smaller than a
// kl_event. The Sensor's own programs always reserve a full kl_event, so
// this should never happen in practice; DecodeEvent checks it anyway
// because a ring buffer record is untrusted input regardless of source.
var ErrShortRecord = errors.New("ebpf: ring buffer record shorter than a kl_event")

// kl_event's wire size, computed once from the generated decode struct
// rather than hardcoded, so it can never drift from what DecodeEvent
// actually reads.
var klEventSize = binary.Size(kestrelynxebpfKlEvent{})

// DecodeEvent decodes one ring buffer record (a ringbuf.Record's RawSample)
// into an Event.
func DecodeEvent(raw []byte) (Event, error) {
	if klEventSize < 0 {
		// binary.Size returns -1 for a type it cannot size, which would be
		// a bug in the generated struct (e.g. a field type binary.Read
		// cannot handle), not a runtime condition callers should recover
		// from.
		panic("ebpf: kestrelynxebpfKlEvent has no fixed binary size")
	}
	if len(raw) < klEventSize {
		return Event{}, ErrShortRecord
	}

	var rec kestrelynxebpfKlEvent
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &rec); err != nil {
		return Event{}, fmt.Errorf("ebpf: decode event: %w", err)
	}

	n := int(rec.PathLen)
	if n > len(rec.Path) {
		n = len(rec.Path)
	}
	// PathLen is meant to already exclude any trailing NUL (the C side
	// subtracts it from what bpf_d_path/bpf_probe_read_kernel_str report),
	// but a ring buffer record is untrusted input regardless of source: cut
	// at the first NUL within the claimed length too, so a wrong or
	// corrupted PathLen cannot hand a NUL-embedded string to a caller that
	// treats Path as a plain filesystem path (e.g. for index lookups or
	// opening it).
	if i := bytes.IndexByte(rec.Path[:n], 0); i >= 0 {
		n = i
	}

	return Event{
		Kind:             EventKind(rec.Kind),
		CgroupID:         rec.CgroupId,
		MountNamespaceID: rec.MntNsId,
		UserNamespaceID:  rec.UserNsId,
		TGID:             rec.Tgid,
		StartBoottimeNs:  rec.StartBoottimeNs,
		CapEffective:     rec.CapEffective,
		Dev:              rec.Dev,
		Ino:              rec.Ino,
		RootDev:          rec.RootDev,
		RootIno:          rec.RootIno,
		KtimeNs:          rec.KtimeNs,
		EUID:             rec.Euid,
		Prot:             rec.Prot,
		PathTruncated:    rec.PathTruncated != 0,
		Path:             string(rec.Path[:n]),
	}, nil
}
