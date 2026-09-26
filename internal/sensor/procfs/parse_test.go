package procfs

import (
	"strings"
	"testing"
)

func TestSplitDeleted(t *testing.T) {
	tests := []struct {
		in      string
		wantOut string
		wantDel bool
	}{
		{"/usr/sbin/nginx", "/usr/sbin/nginx", false},
		{"/usr/lib/libssl.so.3 (deleted)", "/usr/lib/libssl.so.3", true},
	}
	for _, tt := range tests {
		out, del := SplitDeleted(tt.in)
		if out != tt.wantOut || del != tt.wantDel {
			t.Errorf("SplitDeleted(%q) = (%q, %v), want (%q, %v)", tt.in, out, del, tt.wantOut, tt.wantDel)
		}
	}
}

func TestParseMapsLine(t *testing.T) {
	tests := []struct {
		name string
		line string
		ok   bool
		want MapEntry
	}{
		{
			name: "executable file-backed mapping",
			// Real record: experiments/runtime-discovery out/13-root-...
			// case13 collect JSON, dash's own exe mapping (VERIFIED).
			line: "7f2b3a000000-7f2b3a021000 r-xp 00000000 08:30 971799                     /usr/bin/dash",
			ok:   true,
			want: MapEntry{Path: "/usr/bin/dash", Dev: "08:30", Inode: 971799, Perms: "r-xp"},
		},
		{
			name: "deleted executable mapping",
			line: "7f2b3a000000-7f2b3a021000 r-xp 00000000 08:01 131099                     /usr/lib/x86_64-linux-gnu/libssl.so.3 (deleted)",
			ok:   true,
			want: MapEntry{Path: "/usr/lib/x86_64-linux-gnu/libssl.so.3", Dev: "08:01", Inode: 131099, Perms: "r-xp", Deleted: true},
		},
		{
			name: "non-executable mapping is excluded",
			line: "7f2b3a000000-7f2b3a021000 r--p 00000000 08:01 131099                     /usr/sbin/nginx",
			ok:   false,
		},
		{
			name: "anonymous mapping (no path) is excluded",
			line: "7f2b3a000000-7f2b3a021000 rwxp 00000000 00:00 0",
			ok:   false,
		},
		{
			name: "pseudo-path is excluded",
			line: "7ffde0000000-7ffde0021000 r-xp 00000000 00:00 0                          [vdso]",
			ok:   false,
		},
		{
			name: "heap pseudo-path is excluded",
			line: "00e5d000-00e7e000 rwxp 00000000 00:00 0                          [heap]",
			ok:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := ParseMapsLine(tt.line)
			if ok != tt.ok {
				t.Fatalf("ParseMapsLine(%q) ok = %v, want %v", tt.line, ok, tt.ok)
			}
			if !ok {
				return
			}
			if got != tt.want {
				t.Errorf("ParseMapsLine(%q) = %+v, want %+v", tt.line, got, tt.want)
			}
		})
	}
}

func TestParseStatus(t *testing.T) {
	data := []byte(`Name:	nginx
Umask:	0022
State:	S (sleeping)
Uid:	0	0	0	0
Gid:	0	0	0	0
CapInh:	0000000000000000
CapPrm:	0000003fffffffff
CapEff:	0000003fffffffff
CapBnd:	0000003fffffffff
Seccomp:	0
`)
	uid, capEff, err := ParseStatus(data)
	if err != nil {
		t.Fatalf("ParseStatus: %v", err)
	}
	if uid != 0 {
		t.Errorf("effective uid = %d, want 0", uid)
	}
	if capEff != "0000003fffffffff" {
		t.Errorf("CapEff = %q, want %q", capEff, "0000003fffffffff")
	}
}

func TestParseStatusNonRoot(t *testing.T) {
	data := []byte("Uid:\t101\t101\t101\t101\nCapEff:\t0000000000000000\n")
	uid, capEff, err := ParseStatus(data)
	if err != nil {
		t.Fatalf("ParseStatus: %v", err)
	}
	if uid != 101 {
		t.Errorf("effective uid = %d, want 101", uid)
	}
	if capEff != "0000000000000000" {
		t.Errorf("CapEff = %q, want %q", capEff, "0000000000000000")
	}
}

func TestParseStatusMissingFields(t *testing.T) {
	if _, _, err := ParseStatus([]byte("Name:\tfoo\n")); err == nil {
		t.Fatal("expected error for status data missing Uid/CapEff")
	}
}

func TestParseNetTCPLine(t *testing.T) {
	header := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode"
	if _, ok := ParseNetTCPLine(header); ok {
		t.Error("header line must not parse as a listen row")
	}

	tests := []struct {
		name     string
		line     string
		ok       bool
		wantAddr string
		wantPort int
		wantIno  uint64
	}{
		{
			name:     "IPv4 listen on all interfaces",
			line:     "   0: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 27587 1 0000000000000000 100 0 0 10 0",
			ok:       true,
			wantAddr: "0.0.0.0",
			wantPort: 8080,
			wantIno:  27587,
		},
		{
			name:     "IPv4 listen on loopback",
			line:     "   1: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 27588 1 0000000000000000 100 0 0 10 0",
			ok:       true,
			wantAddr: "127.0.0.1",
			wantPort: 8080,
			wantIno:  27588,
		},
		{
			name: "non-listen state is excluded",
			line: "   2: 0100007F:1F90 0100007F:CB2E 01 00000000:00000000 00:00000000 00000000     0        0 27589 1 0000000000000000 20 4 30 10 -1",
			ok:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := ParseNetTCPLine(tt.line)
			if ok != tt.ok {
				t.Fatalf("ParseNetTCPLine ok = %v, want %v", ok, tt.ok)
			}
			if !ok {
				return
			}
			if got.LocalAddr != tt.wantAddr || got.LocalPort != tt.wantPort || got.Inode != tt.wantIno {
				t.Errorf("ParseNetTCPLine = %+v, want addr=%s port=%d inode=%d", got, tt.wantAddr, tt.wantPort, tt.wantIno)
			}
		})
	}
}

func TestParseNetTCPLineIPv6(t *testing.T) {
	// "::" (all-zero) listening on port 80: 32 zero hex chars.
	line := "   0: 00000000000000000000000000000000:0050 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 9999 1 0000000000000000 100 0 0 10 0"
	got, ok := ParseNetTCPLine(line)
	if !ok {
		t.Fatal("expected IPv6 listen row to parse")
	}
	if got.LocalAddr != "::" {
		t.Errorf("LocalAddr = %q, want \"::\"", got.LocalAddr)
	}
	if got.LocalPort != 80 {
		t.Errorf("LocalPort = %d, want 80", got.LocalPort)
	}
}

// TestParseNetTCPLineIPv4MappedIPv6 covers a dual-stack listener: a socket
// bound to an IPv4-mapped IPv6 address appears in /proc/<pid>/net/tcp6, not
// tcp, and its 16-byte address must decode back to the IPv4 address it maps.
// The hex form is the kernel's four native-endian 32-bit words, so
// ::ffff:127.0.0.1 is written "0000000000000000FFFF00000100007F".
func TestParseNetTCPLineIPv4MappedIPv6(t *testing.T) {
	line := "   1: 0000000000000000FFFF00000100007F:1F90 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 9998 1 0000000000000000 100 0 0 10 0"
	got, ok := ParseNetTCPLine(line)
	if !ok {
		t.Fatal("expected IPv4-mapped IPv6 listen row to parse")
	}
	if got.LocalAddr != "127.0.0.1" {
		t.Errorf("LocalAddr = %q, want \"127.0.0.1\" (the IPv4 address the mapped form names)", got.LocalAddr)
	}
	if got.LocalPort != 8080 {
		t.Errorf("LocalPort = %d, want 8080", got.LocalPort)
	}
}

func TestParseStarttime(t *testing.T) {
	// 20 post-comm fields (state..starttime); starttime (index 19, field 22
	// overall) is "123456". The comm field itself contains a space and a
	// nested "(" to exercise "split after the *last* )" rather than the
	// first.
	postComm := make([]string, 20)
	for i := range postComm {
		postComm[i] = "0"
	}
	// Field 3 overall (the first post-comm field) is the process state: a
	// single letter such as "S" or "R", never a number.
	postComm[0] = "S"
	postComm[19] = "123456"
	line := "4242 (some (nested) name) " + joinFields(postComm)

	got, err := ParseStarttime(line)
	if err != nil {
		t.Fatalf("ParseStarttime: %v", err)
	}
	if got != 123456 {
		t.Errorf("ParseStarttime = %d, want 123456", got)
	}
}

func joinFields(fields []string) string {
	out := ""
	for i, f := range fields {
		if i > 0 {
			out += " "
		}
		out += f
	}
	return out
}

func TestParseStarttimeMalformed(t *testing.T) {
	if _, err := ParseStarttime("no comm field here"); err == nil {
		t.Fatal("expected error for a line with no comm field")
	}
	if _, err := ParseStarttime("4242 (short) S 0 0"); err == nil {
		t.Fatal("expected error for too few post-comm fields")
	}
}

func TestParsePPID(t *testing.T) {
	postComm := make([]string, 20)
	for i := range postComm {
		postComm[i] = "0"
	}
	postComm[0] = "S"
	postComm[1] = "777" // ppid
	line := "4242 (some (nested) name) " + joinFields(postComm)

	got, err := ParsePPID(line)
	if err != nil {
		t.Fatalf("ParsePPID: %v", err)
	}
	if got != 777 {
		t.Errorf("ParsePPID = %d, want 777", got)
	}
}

func TestParsePPIDMalformed(t *testing.T) {
	if _, err := ParsePPID("no comm field here"); err == nil {
		t.Fatal("expected error for a line with no comm field")
	}
	if _, err := ParsePPID("4242 (short) S"); err == nil {
		t.Fatal("expected error for too few post-comm fields")
	}
}

// anonMapLine is one line that never produces a MapEntry (no path, inode
// 0): the shape of line ParseMapsStream must still count toward
// MaxMapsLines even though it never contributes an entry.
const anonMapLine = "00000000-00001000 rwxp 00000000 00:00 0"

// execMapLine is one line that does produce a MapEntry.
const execMapLine = "7f2b3a000000-7f2b3a021000 r-xp 00000000 08:01 131099                     /usr/sbin/nginx"

func TestParseMapsStream_TruncatesOnRawLineCount_DisqualifiedLines(t *testing.T) {
	// MaxMapsLines+1 lines that individually never parse into a MapEntry
	// (anonymous mappings). Counting qualifying entries (the old behavior)
	// would never truncate this, since len(entries) stays 0 throughout;
	// counting raw lines must still catch it.
	lines := make([]string, MaxMapsLines+1)
	for i := range lines {
		lines[i] = anonMapLine
	}
	r := strings.NewReader(strings.Join(lines, "\n") + "\n")

	entries, truncated, err := ParseMapsStream(r)
	if err != nil {
		t.Fatalf("ParseMapsStream: %v", err)
	}
	if !truncated {
		t.Error("truncated = false, want true: more than MaxMapsLines raw lines were read")
	}
	if len(entries) != 0 {
		t.Errorf("entries = %v, want none (every line was an anonymous mapping)", entries)
	}
}

func TestParseMapsStream_TruncatesOnRawLineCount_DuplicateLines(t *testing.T) {
	// MaxMapsLines+1 repeats of the *same* file-backed mapping. Dedup
	// collapses them to a single entry, but the raw line count — checked
	// before dedup — must still trip the limit.
	lines := make([]string, MaxMapsLines+1)
	for i := range lines {
		lines[i] = execMapLine
	}
	r := strings.NewReader(strings.Join(lines, "\n") + "\n")

	entries, truncated, err := ParseMapsStream(r)
	if err != nil {
		t.Fatalf("ParseMapsStream: %v", err)
	}
	if !truncated {
		t.Error("truncated = false, want true: more than MaxMapsLines raw lines were read, even though they all dedup to one entry")
	}
	if len(entries) != 1 {
		t.Errorf("entries = %v, want exactly one deduplicated entry", entries)
	}
}

func TestParseMapsStream_NotTruncatedUnderLimit(t *testing.T) {
	r := strings.NewReader(anonMapLine + "\n" + execMapLine + "\n")
	entries, truncated, err := ParseMapsStream(r)
	if err != nil {
		t.Fatalf("ParseMapsStream: %v", err)
	}
	if truncated {
		t.Error("truncated = true, want false: well under MaxMapsLines")
	}
	if len(entries) != 1 {
		t.Errorf("entries = %v, want exactly one", entries)
	}
}
