package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

// containerIDRE matches a 64-character hexadecimal container identifier,
// which is how a container's own control group directory is named whatever
// naming scheme the surrounding hierarchy uses.
var containerIDRE = regexp.MustCompile(`([0-9a-f]{64})`)

// containerIDOf extracts the container a control group directory belongs
// to from its name.
//
// The conventional layout puts each container in a scope named after it
// under a system slice, but a deployment can ask for a different parent,
// and a workload can create groups of its own below the container's. So
// the name is matched for the identifier itself rather than the whole
// conventional path being required, and the hierarchy is walked upward for
// the nearest match rather than one fixed depth being assumed.
func containerIDOf(name string) string {
	switch {
	case strings.HasPrefix(name, "docker-") && strings.HasSuffix(name, ".scope"):
		if m := containerIDRE.FindStringSubmatch(name); m != nil {
			return m[1]
		}
	case len(name) == 64:
		if m := containerIDRE.FindStringSubmatch(name); m != nil && m[1] == name {
			return m[1]
		}
	}
	return ""
}

// cgroupIDByHandle asks the kernel for the identifier it reports for a
// control group directory, through the directory's file handle.
//
// This exists because the table's whole premise — that a control group's
// identifier equals its directory's inode number — is a premise. Where the
// two disagree, the handle is the authority: it is the same value the
// kernel hands a tracing program, and the inode number is not.
func cgroupIDByHandle(dir string) (uint64, error) {
	// struct file_handle: handle_bytes (u32), handle_type (i32), then the
	// handle itself. A control group handle is 8 bytes holding the
	// identifier.
	var buf [24]byte
	const headerLen = 8
	putUint32(buf[0:4], uint32(len(buf)-headerLen))

	pathBytes, err := syscall.BytePtrFromString(dir)
	if err != nil {
		return 0, err
	}
	trap, known := nameToHandleAtSyscall[runtime.GOARCH]
	if !known {
		return 0, fmt.Errorf("name_to_handle_at: no system call number is recorded for %s, so the kernel's own identifier for a control group cannot be read here", runtime.GOARCH)
	}
	var mountID int32
	_, _, errno := syscall.Syscall6(trap,
		uintptr(atFDCWDValue), uintptr(unsafe.Pointer(pathBytes)),
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&mountID)), 0, 0)
	if errno != 0 {
		return 0, fmt.Errorf("name_to_handle_at %s: %w", dir, errno)
	}
	size := getUint32(buf[0:4])
	if size < 8 {
		return 0, fmt.Errorf("name_to_handle_at %s: handle is %d bytes, too short to hold an identifier", dir, size)
	}
	return getUint64(buf[headerLen : headerLen+8]), nil
}

// nameToHandleAtSyscall is the system call number for name_to_handle_at,
// per architecture. The standard library does not carry the constant, and
// an architecture missing from this table gets an explicit error rather
// than a guessed number: calling the wrong system call would not fail, it
// would do something else.
var nameToHandleAtSyscall = map[string]uintptr{
	"amd64": 303, "386": 341, "arm": 370, "arm64": 264,
	"riscv64": 264, "loong64": 264, "ppc64": 345, "ppc64le": 345, "s390x": 335,
}

// atFDCWDValue is the "relative to the current directory" descriptor,
// as an unsigned word. The paths passed here are absolute, so it is never
// actually used as a starting point.
const atFDCWDValue = ^uintptr(0) - 99

func putUint32(b []byte, v uint32) {
	b[0], b[1], b[2], b[3] = byte(v), byte(v>>8), byte(v>>16), byte(v>>24)
}

func getUint32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

func getUint64(b []byte) uint64 {
	var v uint64
	for i := 7; i >= 0; i-- {
		v = v<<8 | uint64(b[i])
	}
	return v
}

// buildCgroupTable walks a control group hierarchy and records, for every
// group in it, which container it belongs to and what identifier the
// kernel reports for it.
func buildCgroupTable(root string) CgroupTable {
	now := time.Now().UTC()
	table := CgroupTable{GeneratedAt: now, Root: root, Snapshots: 1, UpdatedAt: []time.Time{now}, Calibration: "unchecked"}

	agree, disagree := 0, 0
	var walk func(dir string, container string, depth int)
	walk = func(dir, container string, depth int) {
		entries, err := os.ReadDir(dir)
		if err != nil {
			table.Errors = append(table.Errors, fmt.Sprintf("%s: %v", dir, err))
			return
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			child := path.Join(dir, e.Name())
			childContainer, childDepth := container, depth+1
			if id := containerIDOf(e.Name()); id != "" {
				childContainer, childDepth = id, 0
			}
			entry := CgroupEntry{
				Path: child, ContainerID: childContainer, Depth: childDepth,
				FirstSeen: now, LastSeen: now, Generation: 1, IDAgreement: "unchecked",
			}
			if fi, serr := os.Stat(child); serr == nil {
				if st, ok := fi.Sys().(*syscall.Stat_t); ok {
					entry.Inode = st.Ino
					entry.CgroupID = st.Ino
				}
			}
			if handle, herr := cgroupIDByHandle(child); herr == nil {
				entry.HandleID = handle
				if entry.Inode == handle {
					entry.IDAgreement = "agree"
					agree++
				} else {
					entry.IDAgreement = "disagree"
					disagree++
					// The handle is what a tracing program reports, so it
					// is the identifier the table has to key on.
					entry.CgroupID = handle
				}
			} else {
				entry.HandleErr = herr.Error()
			}
			table.Entries = append(table.Entries, entry)
			walk(child, childContainer, childDepth)
		}
	}
	walk(root, "", -1)

	switch {
	case disagree > 0:
		table.Calibration = "disagree"
	case agree > 0:
		table.Calibration = "agree"
	}
	sortCgroupEntries(table.Entries)
	return table
}

func sortCgroupEntries(entries []CgroupEntry) {
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Path != entries[j].Path {
			return entries[i].Path < entries[j].Path
		}
		return entries[i].Generation < entries[j].Generation
	})
}

// mergeCgroupTable folds a new snapshot into an existing table.
//
// An entry whose path is still backed by the same control group has its
// last-seen time extended. One whose path now holds a different group —
// which is what a container restart produces — closes the old entry at the
// moment the change was found and opens a new generation beside it, so an
// event that arrived while the old group existed still resolves to the
// container that existed then. An entry whose path is gone is closed and
// kept: it is the only record of what that identifier meant.
func mergeCgroupTable(existing, fresh CgroupTable) CgroupTable {
	out := existing
	out.GeneratedAt = fresh.GeneratedAt
	out.Root = fresh.Root
	out.Snapshots = existing.Snapshots + 1
	out.UpdatedAt = append(append([]time.Time{}, existing.UpdatedAt...), fresh.GeneratedAt)
	out.Calibration = fresh.Calibration
	out.Errors = append(append([]string{}, existing.Errors...), fresh.Errors...)

	live := map[string]int{} // path -> index of the open entry for it
	for i := range out.Entries {
		if out.Entries[i].ExpiredAt.IsZero() {
			live[out.Entries[i].Path] = i
		}
	}
	seen := map[string]bool{}
	maxGen := map[string]int{}
	for _, e := range out.Entries {
		if e.Generation > maxGen[e.Path] {
			maxGen[e.Path] = e.Generation
		}
	}
	for _, e := range fresh.Entries {
		seen[e.Path] = true
		if i, ok := live[e.Path]; ok {
			if out.Entries[i].CgroupID == e.CgroupID {
				out.Entries[i].LastSeen = fresh.GeneratedAt
				out.Entries[i].ContainerID = e.ContainerID
				out.Entries[i].Depth = e.Depth
				continue
			}
			out.Entries[i].ExpiredAt = fresh.GeneratedAt
		}
		e.Generation = maxGen[e.Path] + 1
		maxGen[e.Path] = e.Generation
		out.Entries = append(out.Entries, e)
	}
	for i := range out.Entries {
		if out.Entries[i].ExpiredAt.IsZero() && !seen[out.Entries[i].Path] {
			out.Entries[i].ExpiredAt = fresh.GeneratedAt
		}
	}
	sortCgroupEntries(out.Entries)
	return out
}

// cgroupLookup answers, for an identifier reported with an event, which
// container the event belongs to.
type cgroupLookup struct {
	byID map[uint64][]CgroupEntry
}

func newCgroupLookup(table CgroupTable) *cgroupLookup {
	l := &cgroupLookup{byID: map[uint64][]CgroupEntry{}}
	for _, e := range table.Entries {
		l.byID[e.CgroupID] = append(l.byID[e.CgroupID], e)
	}
	return l
}

// lookup resolves one identifier at one instant. An identifier the table
// does not know about resolves to nothing, and is reported as
// unattributed: it is not the host's merely because the table has no entry
// for it.
func (l *cgroupLookup) lookup(id uint64, at time.Time) (containerID string, depth int, ok bool) {
	if l == nil {
		return "", 0, false
	}
	var best *CgroupEntry
	for i := range l.byID[id] {
		e := l.byID[id][i]
		if at.Before(e.FirstSeen) {
			continue
		}
		if !e.ExpiredAt.IsZero() && at.After(e.ExpiredAt) {
			continue
		}
		if best == nil || e.FirstSeen.After(best.FirstSeen) {
			cp := e
			best = &cp
		}
	}
	if best == nil {
		// The identifier is known but only outside this instant's validity
		// window, or not known at all. Either way the event cannot be
		// attributed, and the weaker fallback — taking whichever entry
		// ever had this identifier — is not applied: a container that was
		// replaced must not inherit its predecessor's events.
		return "", 0, false
	}
	if best.ContainerID == "" {
		return "", best.Depth, false
	}
	return best.ContainerID, best.Depth, true
}

func readCgroupTable(path string) (CgroupTable, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return CgroupTable{}, fmt.Errorf("read control group table: %w", err)
	}
	var t CgroupTable
	if err := json.Unmarshal(data, &t); err != nil {
		return CgroupTable{}, fmt.Errorf("parse control group table: %w", err)
	}
	return t, nil
}
