package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// deletedSuffix is appended by the kernel to a symlink target or maps
// pathname when the underlying file has been unlinked (man 5 proc_pid_exe,
// proc_pid_maps).
const deletedSuffix = " (deleted)"

// splitDeleted strips a trailing " (deleted)" marker and reports whether it
// was present.
func splitDeleted(path string) (string, bool) {
	if strings.HasSuffix(path, deletedSuffix) {
		return strings.TrimSuffix(path, deletedSuffix), true
	}
	return path, false
}

// readExe resolves /proc/<pid>/exe and reports the (possibly deleted) target
// path. err is the raw readlink error, surfaced to the caller so EACCES/ESRCH
// can be recorded distinctly rather than folded into "not found".
func readExe(pid int) (path string, deleted bool, err error) {
	target, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return "", false, err
	}
	path, deleted = splitDeleted(target)
	return path, deleted, nil
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

// parseMapsLine parses one line of /proc/<pid>/maps and reports the file
// mapping it describes, if any. Only executable mappings backed by an
// absolute path are collected; anonymous mappings, non-executable mappings,
// and pseudo-paths ("[heap]", "[stack]", "[vdso]", …) are not.
func parseMapsLine(line string) (MapEntry, bool) {
	m := mapsLineRE.FindStringSubmatch(line)
	if m == nil {
		return MapEntry{}, false
	}
	perms, dev, inode, pathname := m[1], m[2], m[3], strings.TrimSpace(m[4])
	if len(perms) < 3 || perms[2] != 'x' {
		return MapEntry{}, false
	}
	if !strings.HasPrefix(pathname, "/") {
		return MapEntry{}, false
	}
	if inode == "0" {
		// Anonymous or unbacked mapping (e.g. a shared anonymous mapping
		// that happens to carry a synthetic pathname); man 5 proc_pid_maps
		// documents inode 0 for such mappings.
		return MapEntry{}, false
	}
	path, deleted := splitDeleted(pathname)
	return MapEntry{Path: path, Dev: dev, Inode: inode, Perms: perms, Deleted: deleted}, true
}

// readMaps reads /proc/<pid>/maps and returns the deduplicated set of
// file-backed executable mappings, keyed by (path, dev, inode).
func readMaps(pid int) ([]MapEntry, error) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	seen := map[[3]string]bool{}
	var out []MapEntry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		e, ok := parseMapsLine(sc.Text())
		if !ok {
			continue
		}
		key := [3]string{e.Path, e.Dev, e.Inode}
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, e)
	}
	if err := sc.Err(); err != nil {
		return out, err
	}
	return out, nil
}

// parseStatus extracts the effective UID (2nd field of the "Uid:" line) and
// the raw "CapEff:" hex string from the contents of /proc/<pid>/status.
func parseStatus(data []byte) (effectiveUID, capEff string, err error) {
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "Uid:"):
			fields := strings.Fields(line)
			// "Uid:" real effective saved filesystem
			if len(fields) < 3 {
				return effectiveUID, capEff, fmt.Errorf("status: malformed Uid line %q", line)
			}
			effectiveUID = fields[2]
		case strings.HasPrefix(line, "CapEff:"):
			fields := strings.Fields(line)
			if len(fields) < 2 {
				return effectiveUID, capEff, fmt.Errorf("status: malformed CapEff line %q", line)
			}
			capEff = fields[1]
		}
	}
	if err := sc.Err(); err != nil {
		return effectiveUID, capEff, err
	}
	if effectiveUID == "" || capEff == "" {
		return effectiveUID, capEff, fmt.Errorf("status: missing Uid or CapEff line")
	}
	return effectiveUID, capEff, nil
}

func readStatus(pid int) (effectiveUID, capEff string, err error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return "", "", err
	}
	return parseStatus(data)
}

// netTCPListen is one LISTEN-state row parsed from /proc/<pid>/net/tcp or
// tcp6.
type netTCPListen struct {
	LocalAddr string
	LocalPort int
	Inode     string
}

// netTCPListenState is the "st" column value for TCP_LISTEN
// (include/net/tcp_states.h via man 5 proc_net_tcp: state 0A is LISTEN).
const netTCPListenState = "0A"

// parseNetTCPLine parses one data row (not the header) of
// /proc/<pid>/net/tcp{,6} and returns the local address/port/inode when the
// row is in LISTEN state. The local_address field is "<hex addr>:<hex
// port>", little-endian per 32-bit word for the address.
func parseNetTCPLine(line string) (netTCPListen, bool) {
	f := strings.Fields(line)
	// sl local_address rem_address st tx:rx tr:tm retrnsmt uid timeout inode ...
	if len(f) < 10 {
		return netTCPListen{}, false
	}
	if f[3] != netTCPListenState {
		return netTCPListen{}, false
	}
	addrPort := strings.SplitN(f[1], ":", 2)
	if len(addrPort) != 2 {
		return netTCPListen{}, false
	}
	addr, ok := decodeHexAddr(addrPort[0])
	if !ok {
		return netTCPListen{}, false
	}
	port, err := strconv.ParseUint(addrPort[1], 16, 32)
	if err != nil {
		return netTCPListen{}, false
	}
	return netTCPListen{LocalAddr: addr, LocalPort: int(port), Inode: f[9]}, true
}

// decodeHexAddr decodes the per-32-bit-word hex address format used by
// /proc/net/tcp (8 hex chars = IPv4) and /proc/net/tcp6 (32 hex chars =
// IPv6). Each 4-byte word is stored in the kernel's native in-memory byte
// order (the kernel writes the raw in_addr/in6_addr word, not a
// byte-swapped wire form), so decoding uses the host's own native
// endianness (binary.NativeEndian, Go 1.21+) rather than a hardcoded
// byte order; the actual host architecture this ran on is recorded
// alongside the data (Window.HostArch) so a result decoded under a
// different-endian host is identifiable.
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

// readNetTCPListens reads one /proc/<pid>/net/tcp or tcp6 file and returns
// its LISTEN rows.
func readNetTCPListens(path string) ([]netTCPListen, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []netTCPListen
	sc := bufio.NewScanner(f)
	first := true
	for sc.Scan() {
		if first {
			first = false
			continue // header row
		}
		if l, ok := parseNetTCPLine(sc.Text()); ok {
			out = append(out, l)
		}
	}
	if err := sc.Err(); err != nil {
		return out, err
	}
	return out, nil
}

// socketInodeRE matches the readlink target of a socket file descriptor
// (man 5 proc_pid_fd: "socket:[<inode>]").
var socketInodeRE = regexp.MustCompile(`^socket:\[(\d+)\]$`)

// cgroupContainsID reports whether /proc/<pid>/cgroup's contents mention the
// given container ID (or its short 12-character form) — corroboration that
// a Docker-API-reported PID actually belongs to that container. It is
// evidence only, never the primary PID source.
func cgroupContainsID(data []byte, containerID string) (matched bool) {
	if containerID == "" {
		return false
	}
	short := containerID
	if len(short) > 12 {
		short = short[:12]
	}
	text := string(data)
	return strings.Contains(text, containerID) || strings.Contains(text, short)
}

func readCgroup(pid int) ([]byte, error) {
	return os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
}

// readStarttime returns field 22 (starttime, in clock ticks since boot) of
// /proc/<pid>/stat, used to detect PID reuse across samples (man 5
// proc_pid_stat). The comm field (2nd, parenthesized) can itself contain
// spaces or parentheses, so parsing starts after the *last* ")" rather than
// naively splitting on whitespace.
func readStarttime(pid int) (string, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return "", err
	}
	return parseStarttime(string(data))
}

// parseStarttime extracts field 22 (starttime) from the raw contents of
// /proc/<pid>/stat, pure and separated from the file read so it can be
// tested against a hand-built line.
func parseStarttime(content string) (string, error) {
	line := strings.TrimRight(content, "\n")
	close := strings.LastIndexByte(line, ')')
	if close < 0 {
		return "", fmt.Errorf("stat: no comm field in %q", line)
	}
	fields := strings.Fields(line[close+1:])
	// After the comm field: fields[0] is state (3rd overall), so starttime
	// (22nd overall) is fields[22-3] = fields[19].
	const starttimeIndex = 19
	if len(fields) <= starttimeIndex {
		return "", fmt.Errorf("stat: too few fields after comm (%d)", len(fields))
	}
	return fields[starttimeIndex], nil
}

// readNSLink reads the readlink target of /proc/<pid>/ns/<kind> (e.g.
// "net:[4026531840]"), one of the per-PID namespace identifiers used to
// detect a namespace change across samples (man 7 namespaces).
func readNSLink(pid int, kind string) (string, error) {
	return os.Readlink(fmt.Sprintf("/proc/%d/ns/%s", pid, kind))
}

// readUIDMap reads the raw contents of /proc/<pid>/uid_map (man 7
// user_namespaces): recorded so a userns-remap environment is visible in
// the observation rather than silently assumed away. An empty/absent
// mapping (the ordinary non-remapped case) reads back as a single line
// mapping the full UID range 1:1 ("0 0 4294967295" on most kernels), which
// this function returns verbatim rather than interpreting.
func readUIDMap(pid int) (string, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/uid_map", pid))
	if err != nil {
		return "", err
	}
	return strings.TrimRight(string(data), "\n"), nil
}
