// Package sensor is the Sensor's observer: the process that walks the
// host's /proc, resolves container generations, samples running processes
// and their listening sockets, indexes each container's OS package database
// (through a separately-sandboxed parser process), and writes the resulting
// evidence file the main body reads. This file holds the pieces of the
// observer's startup sequence that `kestrelynx sensor` (the real, resident
// observer) and `kestrelynx sensor --probe` (the deployment/permission
// verification tool) both need to perform identically: raising the
// transient capabilities a file capability grants at exec, resolving this
// process's own cgroup identity, classifying the outcome of loading and
// attaching eBPF, and spawning a parser child over a fresh socketpair. Every
// function here is a pure or narrowly side-effecting building block; neither
// the daemon loop nor the probe tool's own report assembly lives here.
package sensor

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"golang.org/x/sys/unix"

	"github.com/kitsunetrail/kestrelynx/internal/evidence"
	"github.com/kitsunetrail/kestrelynx/internal/sensor/parser"
	"github.com/kitsunetrail/kestrelynx/internal/sensor/sandbox"
)

// CapState is one transient capability's story at startup: whether the file
// capability's permitted set actually held it when this process started,
// and whether raising it effective succeeded.
type CapState struct {
	PermittedAtStart bool
	RaisedEffective  bool
	Err              error
}

// TransientCapabilities is the four capabilities a real observer's file
// capability grants and raises effective at startup, in the order the
// startup sequence raises them: CAP_SYS_PTRACE and CAP_DAC_READ_SEARCH stay
// effective for the observer's whole life; CAP_BPF and CAP_PERFMON are
// dropped again once eBPF has been loaded and attached (or has failed to).
var TransientCapabilities = []struct {
	Name string
	Num  uintptr
}{
	{"CAP_SYS_PTRACE", unix.CAP_SYS_PTRACE},
	{"CAP_DAC_READ_SEARCH", unix.CAP_DAC_READ_SEARCH},
	{"CAP_BPF", unix.CAP_BPF},
	{"CAP_PERFMON", unix.CAP_PERFMON},
}

// RaiseTransientCapabilities reads this process's own capability set (to
// record whether each capability was actually present in the file
// capability's permitted set at exec) and then raises every capability in
// TransientCapabilities to effective, one at a time — so a single missing
// capability never keeps the others from being raised and reported
// individually. The returned map always has exactly one entry per name in
// TransientCapabilities. statusErr is ReadTaskStatuses' own error reading
// this process's starting capability set, if any — every PermittedAtStart in
// the returned map defaults to false when that happens (this function still
// proceeds to raise every capability regardless), and it is returned rather
// than silently dropped so a caller that reports warnings (the probe tool)
// can surface it the same way it always has.
func RaiseTransientCapabilities() (out map[string]*CapState, statusErr error) {
	out = make(map[string]*CapState, len(TransientCapabilities))
	var permittedAtStart uint64
	statuses, statusErr := sandbox.ReadTaskStatuses(os.Getpid())
	if statusErr == nil && len(statuses) > 0 {
		permittedAtStart = statuses[0].CapPermitted
	}
	for _, c := range TransientCapabilities {
		cs := &CapState{PermittedAtStart: permittedAtStart&(1<<c.Num) != 0}
		if err := sandbox.RaiseEffective(c.Num); err != nil {
			cs.Err = err
		} else {
			cs.RaisedEffective = true
		}
		out[c.Name] = cs
	}
	return out, statusErr
}

// CgroupInfo is this process's own cgroup v2 identity, as OwnCgroupInfo
// resolves it.
type CgroupInfo struct {
	CgroupV2 bool
	Path     string
	KernfsID uint64
	Err      error
}

// OwnCgroupInfo determines this process's own cgroup v2 path and the kernfs
// (directory inode) ID that identifies it — the same ID
// bpf_get_current_cgroup_id() returns for a process in that cgroup — by
// reading /proc/self/cgroup and stat'ing the corresponding directory under
// /sys/fs/cgroup (host-visible when the Sensor container runs with
// `cgroup: host`, and simply the host's own tree otherwise). The returned
// uint64 is the same value as CgroupInfo.KernfsID, for a caller (ebpf.Load)
// that wants just the number.
func OwnCgroupInfo() (CgroupInfo, uint64, error) {
	var stfs unix.Statfs_t
	if err := unix.Statfs("/sys/fs/cgroup", &stfs); err != nil {
		err = fmt.Errorf("statfs /sys/fs/cgroup: %w", err)
		return CgroupInfo{Err: err}, 0, err
	}
	if int64(stfs.Type) != int64(unix.CGROUP2_SUPER_MAGIC) {
		err := fmt.Errorf("cgroup_v1: /sys/fs/cgroup is not cgroup2 (statfs type %#x)", stfs.Type)
		return CgroupInfo{CgroupV2: false, Err: err}, 0, err
	}
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		err = fmt.Errorf("read /proc/self/cgroup: %w", err)
		return CgroupInfo{CgroupV2: true, Err: err}, 0, err
	}
	line := trimNewline(string(data))
	rel, ok := cutPrefix(line, "0::")
	if !ok {
		err := fmt.Errorf("unexpected /proc/self/cgroup content (not a single cgroup-v2 line): %q", line)
		return CgroupInfo{CgroupV2: true, Err: err}, 0, err
	}
	ino, err := StatCgroupDirInode(rel)
	if err != nil {
		return CgroupInfo{CgroupV2: true, Path: rel, Err: err}, 0, err
	}
	return CgroupInfo{CgroupV2: true, Path: rel, KernfsID: ino}, ino, nil
}

// StatCgroupDirInode stats /sys/fs/cgroup/<relPath> and returns its inode
// number, freshly, every time it is called.
func StatCgroupDirInode(relPath string) (uint64, error) {
	full := filepath.Join("/sys/fs/cgroup", relPath)
	var st unix.Stat_t
	if err := unix.Stat(full, &st); err != nil {
		return 0, fmt.Errorf("stat %s: %w", full, err)
	}
	return st.Ino, nil
}

func trimNewline(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}

func cutPrefix(s, prefix string) (string, bool) {
	if len(s) < len(prefix) || s[:len(prefix)] != prefix {
		return s, false
	}
	return s[len(prefix):], true
}

// ClassifyEBPFStatus turns the individual failure points of an eBPF
// load/attach attempt into the (status, reason) vocabulary
// evidence.EventsInfo uses: cgErr is OwnCgroupInfo's own error (checked
// first — cgroup_v1 gets its own reason, any other cgroup failure explains
// why Load was never attempted with a real ID), then whether BTF was
// readable, then whether both CAP_BPF and CAP_PERFMON actually raised
// effective, then loadErr itself. Shared between the probe tool and the
// daemon so the two never drift apart on what counts as which reason.
func ClassifyEBPFStatus(cgErr error, btfReadable, capBPFRaised, capPERFMONRaised bool, loadErr error) (evidence.EventsStatus, evidence.EventsReason) {
	switch {
	case cgErr != nil && hasPrefix(cgErr.Error(), "cgroup_v1:"):
		return evidence.EventsUnavailable, evidence.EventsReasonCgroupV1
	case cgErr != nil:
		return evidence.EventsUnavailable, evidence.EventsReasonAttachFailed
	case !btfReadable:
		return evidence.EventsUnavailable, evidence.EventsReasonBTFMissing
	case !capBPFRaised || !capPERFMONRaised:
		return evidence.EventsUnavailable, evidence.EventsReasonPermission
	case loadErr != nil:
		return evidence.EventsUnavailable, evidence.EventsReasonAttachFailed
	default:
		return evidence.EventsOK, evidence.EventsReasonNone
	}
}

func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

// PlainParserBinary returns the path to the parser's own executable: the
// same source and build as the calling process, but never a file that
// carries the observer's file capability. In the deployed image, the
// observer runs as /usr/local/bin/kestrelynx-sensor (the setcap copy) and
// the parser must instead exec /usr/local/bin/kestrelynx (the plain copy in
// the same directory, with no security.capability xattr at all) — spawning
// the parser from the setcap'd binary would give it every transient
// capability in its own permitted set purely from the file it exec'd, even
// though those bits would stay out of its effective set until something
// raised them. Outside that image (e.g. a local, non-setcap build under
// test), this process's own executable has no capability either way, so it
// is used as-is.
func PlainParserBinary() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	dir, base := filepath.Split(exe)
	if base == "kestrelynx-sensor" {
		return filepath.Join(dir, "kestrelynx"), nil
	}
	return exe, nil
}

// SpawnParserChild starts a fresh copy of PlainParserBinary as
// `kestrelynx sensor <parserArgs...>` over a SOCK_SEQPACKET socketpair —
// exactly the arrangement the startup sequence's step 6 calls for — and
// waits for the child's self-check Report before returning. The returned
// sockFD is this process's end of the socketpair, left open for the caller
// to keep issuing requests on for as long as this Sensor session runs (or,
// for the probe tool's one-shot use, to simply let process exit reclaim);
// SpawnParserChild itself never closes it.
func SpawnParserChild(parserArgs ...string) (pid int, sockFD int, report parser.Report, err error) {
	exe, err := PlainParserBinary()
	if err != nil {
		return 0, -1, parser.Report{}, fmt.Errorf("locate plain (capability-less) executable: %w", err)
	}
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return 0, -1, parser.Report{}, fmt.Errorf("socketpair: %w", err)
	}
	parentFD := fds[0]
	childFile := os.NewFile(uintptr(fds[1]), "sensor-parser-sock")

	args := append([]string{"sensor"}, parserArgs...)
	cmd := exec.Command(exe, args...)
	cmd.ExtraFiles = []*os.File{childFile}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		unix.Close(parentFD)
		childFile.Close()
		return 0, -1, parser.Report{}, fmt.Errorf("start parser child: %w", err)
	}
	childFile.Close()

	report, rerr := parser.ReadReport(parentFD)
	if rerr != nil {
		return cmd.Process.Pid, parentFD, parser.Report{}, fmt.Errorf("read parser report: %w", rerr)
	}
	return cmd.Process.Pid, parentFD, report, nil
}
