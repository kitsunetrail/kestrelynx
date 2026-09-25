package ebpf

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"
)

func TestDecodeEventRoundTrip(t *testing.T) {
	want := kestrelynxebpfKlEvent{
		CgroupId:        1,
		MntNsId:         2,
		UserNsId:        3,
		Tgid:            4,
		StartBoottimeNs: 5,
		CapEffective:    0x1FFFFFFFFF,
		Dev:             6,
		Ino:             7,
		KtimeNs:         8,
		Euid:            1000,
		Prot:            0x4,
		Kind:            uint8(EventExecOpen),
		PathTruncated:   0,
		PathLen:         uint16(len("/usr/bin/example")),
	}
	copy(want.Path[:], "/usr/bin/example")

	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, want); err != nil {
		t.Fatalf("binary.Write: %v", err)
	}

	got, err := DecodeEvent(buf.Bytes())
	if err != nil {
		t.Fatalf("DecodeEvent: %v", err)
	}

	switch {
	case got.Kind != EventExecOpen:
		t.Errorf("Kind = %v, want %v", got.Kind, EventExecOpen)
	case got.CgroupID != want.CgroupId:
		t.Errorf("CgroupID = %d, want %d", got.CgroupID, want.CgroupId)
	case got.MountNamespaceID != want.MntNsId:
		t.Errorf("MountNamespaceID = %d, want %d", got.MountNamespaceID, want.MntNsId)
	case got.UserNamespaceID != want.UserNsId:
		t.Errorf("UserNamespaceID = %d, want %d", got.UserNamespaceID, want.UserNsId)
	case got.TGID != want.Tgid:
		t.Errorf("TGID = %d, want %d", got.TGID, want.Tgid)
	case got.StartBoottimeNs != want.StartBoottimeNs:
		t.Errorf("StartBoottimeNs = %d, want %d", got.StartBoottimeNs, want.StartBoottimeNs)
	case got.CapEffective != want.CapEffective:
		t.Errorf("CapEffective = %#x, want %#x", got.CapEffective, want.CapEffective)
	case got.Dev != want.Dev:
		t.Errorf("Dev = %d, want %d", got.Dev, want.Dev)
	case got.Ino != want.Ino:
		t.Errorf("Ino = %d, want %d", got.Ino, want.Ino)
	case got.KtimeNs != want.KtimeNs:
		t.Errorf("KtimeNs = %d, want %d", got.KtimeNs, want.KtimeNs)
	case got.EUID != want.Euid:
		t.Errorf("EUID = %d, want %d", got.EUID, want.Euid)
	case got.Prot != want.Prot:
		t.Errorf("Prot = %#x, want %#x", got.Prot, want.Prot)
	case got.PathTruncated:
		t.Error("PathTruncated = true, want false")
	case got.Path != "/usr/bin/example":
		t.Errorf("Path = %q, want %q", got.Path, "/usr/bin/example")
	}
}

// TestDecodeEventTrimsEmbeddedNUL guards against the wire contract this
// package actually receives from bpf_d_path and bpf_probe_read_kernel_str:
// both report a length that counts the trailing NUL they write into the
// buffer, so a wire PathLen that (by a bug in the C source, or a future one)
// counts that NUL must still decode to a path with no trailing \x00 rather
// than propagating it into Event.Path, where a caller comparing it against
// a package index or opening it as a filesystem path would silently fail.
func TestDecodeEventTrimsEmbeddedNUL(t *testing.T) {
	const path = "/usr/bin/example"
	want := kestrelynxebpfKlEvent{
		Kind: uint8(EventFileOpen),
		// One past the last path byte: what PathLen would be if it still
		// counted the NUL byte at want.Path[len(path)], matching the shape
		// bpf_d_path's own return value has before the C source's -1.
		PathLen: uint16(len(path) + 1),
	}
	copy(want.Path[:], path)
	// want.Path[len(path)] is already 0 from the struct's zero value; this
	// spells out that the record actually being decoded has a real NUL
	// byte within the range PathLen claims, not just implicitly.
	want.Path[len(path)] = 0

	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, want); err != nil {
		t.Fatalf("binary.Write: %v", err)
	}

	got, err := DecodeEvent(buf.Bytes())
	if err != nil {
		t.Fatalf("DecodeEvent: %v", err)
	}
	if got.Path != path {
		t.Errorf("Path = %q, want %q", got.Path, path)
	}
	if len(got.Path) > 0 && got.Path[len(got.Path)-1] == 0 {
		t.Errorf("Path = %q ends with a NUL byte", got.Path)
	}
}

func TestDecodeEventTruncatedPath(t *testing.T) {
	want := kestrelynxebpfKlEvent{
		Kind:          uint8(EventFileOpen),
		PathTruncated: 1,
		PathLen:       0,
	}
	copy(want.Path[:], "irrelevant, PathLen is 0")

	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, want); err != nil {
		t.Fatalf("binary.Write: %v", err)
	}

	got, err := DecodeEvent(buf.Bytes())
	if err != nil {
		t.Fatalf("DecodeEvent: %v", err)
	}
	if !got.PathTruncated {
		t.Error("PathTruncated = false, want true")
	}
	if got.Path != "" {
		t.Errorf("Path = %q, want empty (PathLen was 0)", got.Path)
	}
}

func TestDecodeEventShortRecord(t *testing.T) {
	_, err := DecodeEvent(make([]byte, 4))
	if err != ErrShortRecord {
		t.Fatalf("DecodeEvent(4 bytes) error = %v, want ErrShortRecord", err)
	}
}

func TestDecodeEventPathLenBeyondBuffer(t *testing.T) {
	// A PathLen larger than the fixed path buffer should never come from
	// this package's own BPF programs (the kernel side clamps it), but
	// DecodeEvent treats the ring buffer as untrusted input regardless of
	// source, so a corrupt PathLen must not read past the array.
	want := kestrelynxebpfKlEvent{
		Kind:    uint8(EventFileOpen),
		PathLen: 65535,
	}
	copy(want.Path[:], "short")

	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, want); err != nil {
		t.Fatalf("binary.Write: %v", err)
	}

	got, err := DecodeEvent(buf.Bytes())
	if err != nil {
		t.Fatalf("DecodeEvent: %v", err)
	}
	if len(got.Path) > len(want.Path) {
		t.Fatalf("Path length %d exceeds the wire buffer size %d", len(got.Path), len(want.Path))
	}
}

// TestEventKindMatchesBPFSource greps bpf/kestrelynx.c for its KL_EVENT_*
// #define values and checks they match the EventKind constants in
// events.go byte for byte. The two are hand-mirrored (the C side has no
// exported enum bpf2go could generate a Go type from), so this test is what
// actually keeps them in sync across an edit to either file.
func TestEventKindMatchesBPFSource(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("bpf", "kestrelynx.c"))
	if err != nil {
		t.Fatalf("reading bpf/kestrelynx.c: %v", err)
	}

	want := map[string]EventKind{
		"KL_EVENT_EXEC_SUCCESS": EventExecSuccess,
		"KL_EVENT_EXEC_OPEN":    EventExecOpen,
		"KL_EVENT_MMAP_SUCCESS": EventMmapSuccess,
		"KL_EVENT_FILE_OPEN":    EventFileOpen,
		"KL_EVENT_CGROUP_MKDIR": EventCgroupMkdir,
		"KL_EVENT_MMAP_OPEN":    EventMmapOpen,
	}

	define := regexp.MustCompile(`(?m)^#define\s+(KL_EVENT_\w+)\s+(\d+)\s*$`)
	matches := define.FindAllStringSubmatch(string(src), -1)
	if len(matches) == 0 {
		t.Fatal("found no #define KL_EVENT_* lines in bpf/kestrelynx.c; did its naming change?")
	}

	seen := map[string]bool{}
	for _, m := range matches {
		name, value := m[1], m[2]
		seen[name] = true

		wantKind, ok := want[name]
		if !ok {
			t.Errorf("bpf/kestrelynx.c defines %s, which events.go's EventKind constants do not mirror", name)
			continue
		}
		if value != strconv.Itoa(int(wantKind)) {
			t.Errorf("%s = %s in bpf/kestrelynx.c, but events.go's %v = %d", name, value, wantKind, uint8(wantKind))
		}
	}

	for name := range want {
		if !seen[name] {
			t.Errorf("events.go mirrors %s, but bpf/kestrelynx.c no longer defines it", name)
		}
	}
}
