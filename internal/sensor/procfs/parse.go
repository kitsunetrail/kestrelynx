package procfs

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"
)

// deletedSuffix is appended by the kernel to a symlink target or maps
// pathname when the underlying file has been unlinked (man 5 proc_pid_exe,
// proc_pid_maps).
const deletedSuffix = " (deleted)"

// SplitDeleted strips a trailing " (deleted)" marker and reports whether it
// was present.
func SplitDeleted(path string) (string, bool) {
	if strings.HasSuffix(path, deletedSuffix) {
		return strings.TrimSuffix(path, deletedSuffix), true
	}
	return path, false
}

// MapEntry is one file-backed executable mapping from /proc/<pid>/maps.
type MapEntry struct {
	Path    string
	Dev     string // "MM:mm" hex, as the kernel prints it
	Inode   uint64
	Perms   string
	Deleted bool
}

// mapsLineRE matches one /proc/<pid>/maps record:
//
//	address           perms offset   dev   inode      pathname
//	7f2b3a000000-...  r-xp  00000000 08:01 131099     /usr/sbin/nginx
//
// pathname is optional (anonymous mappings have none) and may itself contain
// spaces, so it is captured as the remainder of the line rather than as a
// whitespace-delimited field.
var mapsLineRE = regexp.MustCompile(`^\S+\s+(\S+)\s+\S+\s+(\S+)\s+(\S+)\s*(.*)$`)

// ParseMapsLine parses one line of /proc/<pid>/maps and reports the file
// mapping it describes, if any. Only executable mappings backed by an
// absolute path are collected; anonymous mappings, non-executable mappings,
// and pseudo-paths ("[heap]", "[stack]", "[vdso]", …) are not.
func ParseMapsLine(line string) (MapEntry, bool) {
	m := mapsLineRE.FindStringSubmatch(line)
	if m == nil {
		return MapEntry{}, false
	}
	perms, dev, inodeField, pathname := m[1], m[2], m[3], strings.TrimSpace(m[4])
	if len(perms) < 3 || perms[2] != 'x' {
		return MapEntry{}, false
	}
	if !strings.HasPrefix(pathname, "/") {
		return MapEntry{}, false
	}
	if inodeField == "0" {
		// Anonymous or unbacked mapping (e.g. a shared anonymous mapping
		// that happens to carry a synthetic pathname); man 5 proc_pid_maps
		// documents inode 0 for such mappings.
		return MapEntry{}, false
	}
	inode, err := strconv.ParseUint(inodeField, 10, 64)
	if err != nil {
		return MapEntry{}, false
	}
	path, deleted := SplitDeleted(pathname)
	return MapEntry{Path: path, Dev: dev, Inode: inode, Perms: perms, Deleted: deleted}, true
}

// ParseMapsStream reads an entire /proc/<pid>/maps stream and returns the
// deduplicated set of file-backed executable mappings, keyed by (path, dev,
// inode).
//
// Truncated is set once more than MaxMapsLines *raw* lines have been read
// off r, counted before ParseMapsLine's filtering and before the (path,
// dev, inode) dedup — not once MaxMapsLines qualifying entries have been
// collected. A mapping's owning process fully controls how many lines its
// own maps file has (anonymous mappings, non-executable mappings, and
// repeated mappings of the same file all add lines without ever adding an
// entry), so counting only the entries that survive filtering would let a
// process with an arbitrarily large number of disqualified lines be read to
// completion, and consume unbounded time and memory doing it, without ever
// tripping the limit meant to bound exactly that.
func ParseMapsStream(r io.Reader) (entries []MapEntry, truncated bool, err error) {
	seen := map[[3]string]bool{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	lines := 0
	for sc.Scan() {
		lines++
		if lines > MaxMapsLines {
			// The rest of the file is left unread: whatever mappings it
			// still held are neither confirmed nor denied, so the caller
			// must not treat this generation's absence of a package from
			// entries as "not observed" — only as unresolved, since the
			// unread remainder could have held the missing evidence.
			truncated = true
			break
		}
		e, ok := ParseMapsLine(sc.Text())
		if !ok {
			continue
		}
		key := [3]string{e.Path, e.Dev, fmt.Sprint(e.Inode)}
		if seen[key] {
			continue
		}
		seen[key] = true
		entries = append(entries, e)
	}
	if serr := sc.Err(); serr != nil {
		return entries, truncated, serr
	}
	return entries, truncated, nil
}

// ParseStatus extracts the effective UID (2nd field of the "Uid:" line) and
// the raw "CapEff:" hex string from the contents of /proc/<pid>/status.
func ParseStatus(data []byte) (effectiveUID int, capEff string, err error) {
	var uidField string
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "Uid:"):
			fields := strings.Fields(line)
			// "Uid:" real effective saved filesystem
			if len(fields) < 3 {
				return 0, "", fmt.Errorf("procfs: status: malformed Uid line %q", line)
			}
			uidField = fields[2]
		case strings.HasPrefix(line, "CapEff:"):
			fields := strings.Fields(line)
			if len(fields) < 2 {
				return 0, "", fmt.Errorf("procfs: status: malformed CapEff line %q", line)
			}
			capEff = fields[1]
		}
	}
	if err := sc.Err(); err != nil {
		return 0, "", err
	}
	if uidField == "" || capEff == "" {
		return 0, "", fmt.Errorf("procfs: status: missing Uid or CapEff line")
	}
	uid, err := strconv.Atoi(uidField)
	if err != nil {
		return 0, "", fmt.Errorf("procfs: status: malformed effective uid %q: %w", uidField, err)
	}
	return uid, capEff, nil
}

// NetTCPListen is one LISTEN-state row parsed from /proc/<pid>/net/tcp or
// tcp6.
type NetTCPListen struct {
	LocalAddr string
	LocalPort int
	Inode     uint64
}

// netTCPListenState is the "st" column value for TCP_LISTEN
// (include/net/tcp_states.h via man 5 proc_net_tcp: state 0A is LISTEN).
const netTCPListenState = "0A"

// ParseNetTCPLine parses one data row (not the header) of
// /proc/<pid>/net/tcp{,6} and returns the local address/port/inode when the
// row is in LISTEN state. The local_address field is "<hex addr>:<hex
// port>", little-endian per 32-bit word for the address.
func ParseNetTCPLine(line string) (NetTCPListen, bool) {
	f := strings.Fields(line)
	// sl local_address rem_address st tx:rx tr:tm retrnsmt uid timeout inode ...
	if len(f) < 10 {
		return NetTCPListen{}, false
	}
	if f[3] != netTCPListenState {
		return NetTCPListen{}, false
	}
	addrPort := strings.SplitN(f[1], ":", 2)
	if len(addrPort) != 2 {
		return NetTCPListen{}, false
	}
	addr, ok := decodeHexAddr(addrPort[0])
	if !ok {
		return NetTCPListen{}, false
	}
	port, err := strconv.ParseUint(addrPort[1], 16, 32)
	if err != nil {
		return NetTCPListen{}, false
	}
	inode, err := strconv.ParseUint(f[9], 10, 64)
	if err != nil {
		return NetTCPListen{}, false
	}
	return NetTCPListen{LocalAddr: addr, LocalPort: int(port), Inode: inode}, true
}

// decodeHexAddr decodes the per-32-bit-word hex address format used by
// /proc/net/tcp (8 hex chars = IPv4) and /proc/net/tcp6 (32 hex chars =
// IPv6). Each 4-byte word is stored in the kernel's native in-memory byte
// order (the kernel writes the raw in_addr/in6_addr word, not a
// byte-swapped wire form), so decoding uses the host's own native
// endianness (binary.NativeEndian, Go 1.21+) rather than a hardcoded byte
// order.
func decodeHexAddr(hexAddr string) (string, bool) {
	raw, err := hex.DecodeString(hexAddr)
	if err != nil || (len(raw) != 4 && len(raw) != 16) {
		return "", false
	}
	ip := make(net.IP, len(raw))
	for word := 0; word < len(raw); word += 4 {
		// Reinterpret this word's bytes as a native-endian machine integer
		// (recovering the __be32/in6_addr word the kernel actually holds),
		// then write it out in network byte order, which is what an IP
		// address's octets are in.
		binary.BigEndian.PutUint32(ip[word:word+4], binary.NativeEndian.Uint32(raw[word:word+4]))
	}
	return ip.String(), true
}

// ParseStarttime extracts field 22 (starttime) from the raw contents of
// /proc/<pid>/stat, used to detect PID reuse across samples (man 5
// proc_pid_stat). The comm field (2nd, parenthesized) can itself contain
// spaces or parentheses, so parsing starts after the *last* ")" rather than
// naively splitting on whitespace.
func ParseStarttime(content string) (int64, error) {
	line := strings.TrimRight(content, "\n")
	closeParen := strings.LastIndexByte(line, ')')
	if closeParen < 0 {
		return 0, fmt.Errorf("procfs: stat: no comm field in %q", line)
	}
	fields := strings.Fields(line[closeParen+1:])
	// After the comm field: fields[0] is state (3rd overall), so starttime
	// (22nd overall) is fields[22-3] = fields[19].
	const starttimeIndex = 19
	if len(fields) <= starttimeIndex {
		return 0, fmt.Errorf("procfs: stat: too few fields after comm (%d)", len(fields))
	}
	st, err := strconv.ParseInt(fields[starttimeIndex], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("procfs: stat: malformed starttime %q: %w", fields[starttimeIndex], err)
	}
	return st, nil
}

// ParseState extracts field 3 (state) from the raw contents of
// /proc/<pid>/stat, the same way ParseStarttime extracts field 22 — parsing
// starts after the comm field's *last* ")" for the same reason. The
// returned byte is one of proc_pid_stat(5)'s own single-character process
// state codes ('R' running, 'S' sleeping, 'D' uninterruptible sleep, 'Z'
// zombie, 'X'/'x' dead, among others) — used to tell a zombie or already-
// reaped process apart from one that is genuinely still running, which
// Starttime alone cannot: a zombie's own stat entry still reports its
// original starttime unchanged (proc_pid_stat(5)) until its parent actually
// reaps it, so a starttime match alone is not proof a process is still
// alive in any sense that matters to a caller treating it as still running.
func ParseState(content string) (byte, error) {
	line := strings.TrimRight(content, "\n")
	closeParen := strings.LastIndexByte(line, ')')
	if closeParen < 0 {
		return 0, fmt.Errorf("procfs: stat: no comm field in %q", line)
	}
	fields := strings.Fields(line[closeParen+1:])
	// After the comm field: fields[0] is state (3rd overall).
	const stateIndex = 0
	if len(fields) <= stateIndex || len(fields[stateIndex]) != 1 {
		return 0, fmt.Errorf("procfs: stat: malformed state field in %q", line)
	}
	return fields[stateIndex][0], nil
}

// ParsePPID extracts field 4 (ppid) from the raw contents of
// /proc/<pid>/stat, the same way ParseStarttime extracts field 22 — parsing
// starts after the comm field's *last* ")" for the same reason. Used to find
// a container generation's init process: the process in that container's
// cgroup whose parent is not (man 5 proc_pid_stat).
func ParsePPID(content string) (int, error) {
	line := strings.TrimRight(content, "\n")
	closeParen := strings.LastIndexByte(line, ')')
	if closeParen < 0 {
		return 0, fmt.Errorf("procfs: stat: no comm field in %q", line)
	}
	fields := strings.Fields(line[closeParen+1:])
	// After the comm field: fields[0] is state (3rd overall), fields[1] is
	// ppid (4th overall).
	const ppidIndex = 1
	if len(fields) <= ppidIndex {
		return 0, fmt.Errorf("procfs: stat: too few fields after comm (%d)", len(fields))
	}
	ppid, err := strconv.Atoi(fields[ppidIndex])
	if err != nil {
		return 0, fmt.Errorf("procfs: stat: malformed ppid %q: %w", fields[ppidIndex], err)
	}
	return ppid, nil
}
