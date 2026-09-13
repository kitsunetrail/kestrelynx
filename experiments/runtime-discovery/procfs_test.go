package main

import "testing"

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
		out, del := splitDeleted(tt.in)
		if out != tt.wantOut || del != tt.wantDel {
			t.Errorf("splitDeleted(%q) = (%q, %v), want (%q, %v)", tt.in, out, del, tt.wantOut, tt.wantDel)
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
			line: "7f2b3a000000-7f2b3a021000 r-xp 00000000 08:01 131099                     /usr/sbin/nginx",
			ok:   true,
			want: MapEntry{Path: "/usr/sbin/nginx", Dev: "08:01", Inode: "131099", Perms: "r-xp"},
		},
		{
			name: "deleted executable mapping",
			line: "7f2b3a000000-7f2b3a021000 r-xp 00000000 08:01 131099                     /usr/lib/x86_64-linux-gnu/libssl.so.3 (deleted)",
			ok:   true,
			want: MapEntry{Path: "/usr/lib/x86_64-linux-gnu/libssl.so.3", Dev: "08:01", Inode: "131099", Perms: "r-xp", Deleted: true},
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
			got, ok := parseMapsLine(tt.line)
			if ok != tt.ok {
				t.Fatalf("parseMapsLine(%q) ok = %v, want %v", tt.line, ok, tt.ok)
			}
			if !ok {
				return
			}
			if got != tt.want {
				t.Errorf("parseMapsLine(%q) = %+v, want %+v", tt.line, got, tt.want)
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
	uid, capEff, err := parseStatus(data)
	if err != nil {
		t.Fatalf("parseStatus: %v", err)
	}
	if uid != "0" {
		t.Errorf("effective uid = %q, want %q", uid, "0")
	}
	if capEff != "0000003fffffffff" {
		t.Errorf("CapEff = %q, want %q", capEff, "0000003fffffffff")
	}
}

func TestParseStatusNonRoot(t *testing.T) {
	data := []byte("Uid:\t101\t101\t101\t101\nCapEff:\t0000000000000000\n")
	uid, capEff, err := parseStatus(data)
	if err != nil {
		t.Fatalf("parseStatus: %v", err)
	}
	if uid != "101" {
		t.Errorf("effective uid = %q, want %q", uid, "101")
	}
	if capEff != "0000000000000000" {
		t.Errorf("CapEff = %q, want %q", capEff, "0000000000000000")
	}
}

func TestParseStatusMissingFields(t *testing.T) {
	if _, _, err := parseStatus([]byte("Name:\tfoo\n")); err == nil {
		t.Fatal("expected error for status data missing Uid/CapEff")
	}
}

func TestParseNetTCPLine(t *testing.T) {
	header := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode"
	if _, ok := parseNetTCPLine(header); ok {
		t.Error("header line must not parse as a listen row")
	}

	tests := []struct {
		name     string
		line     string
		ok       bool
		wantAddr string
		wantPort int
		wantIno  string
	}{
		{
			name:     "IPv4 listen on all interfaces",
			line:     "   0: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 27587 1 0000000000000000 100 0 0 10 0",
			ok:       true,
			wantAddr: "0.0.0.0",
			wantPort: 8080,
			wantIno:  "27587",
		},
		{
			name:     "IPv4 listen on loopback",
			line:     "   1: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 27588 1 0000000000000000 100 0 0 10 0",
			ok:       true,
			wantAddr: "127.0.0.1",
			wantPort: 8080,
			wantIno:  "27588",
		},
		{
			name: "non-listen state is excluded",
			line: "   2: 0100007F:1F90 0100007F:CB2E 01 00000000:00000000 00:00000000 00000000     0        0 27589 1 0000000000000000 20 4 30 10 -1",
			ok:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := parseNetTCPLine(tt.line)
			if ok != tt.ok {
				t.Fatalf("parseNetTCPLine ok = %v, want %v", ok, tt.ok)
			}
			if !ok {
				return
			}
			if got.LocalAddr != tt.wantAddr || got.LocalPort != tt.wantPort || got.Inode != tt.wantIno {
				t.Errorf("parseNetTCPLine = %+v, want addr=%s port=%d inode=%s", got, tt.wantAddr, tt.wantPort, tt.wantIno)
			}
		})
	}
}

func TestParseNetTCPLineIPv6(t *testing.T) {
	// "::" (all-zero) listening on port 80: 32 zero hex chars.
	line := "   0: 00000000000000000000000000000000:0050 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 9999 1 0000000000000000 100 0 0 10 0"
	got, ok := parseNetTCPLine(line)
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
// tcp, and its 16-byte address must decode back to the IPv4 address it
// maps. The hex form is the kernel's four native-endian 32-bit words, so
// ::ffff:127.0.0.1 is written "0000000000000000FFFF00000100007F".
func TestParseNetTCPLineIPv4MappedIPv6(t *testing.T) {
	line := "   1: 0000000000000000FFFF00000100007F:1F90 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 9998 1 0000000000000000 100 0 0 10 0"
	got, ok := parseNetTCPLine(line)
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
	// 20 post-comm fields (state..starttime); starttime (index 19,
	// field 22 overall) is "123456". The comm field itself contains a
	// space and a nested "(" to exercise "split after the *last* )"
	// rather than the first.
	postComm := make([]string, 20)
	for i := range postComm {
		postComm[i] = "0"
	}
	// Field 3 overall (the first post-comm field) is the process state: a
	// single letter such as "S" or "R", never a number.
	postComm[0] = "S"
	postComm[19] = "123456"
	line := "4242 (some (nested) name) " + joinFields(postComm)

	got, err := parseStarttime(line)
	if err != nil {
		t.Fatalf("parseStarttime: %v", err)
	}
	if got != "123456" {
		t.Errorf("parseStarttime = %q, want %q", got, "123456")
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
	if _, err := parseStarttime("no comm field here"); err == nil {
		t.Fatal("expected error for a line with no comm field")
	}
	if _, err := parseStarttime("4242 (short) S 0 0"); err == nil {
		t.Fatal("expected error for too few post-comm fields")
	}
}

func TestCgroupContainsID(t *testing.T) {
	full := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	data := []byte("0::/system.slice/docker-" + full + ".scope\n")
	if !cgroupContainsID(data, full) {
		t.Error("expected full container id to match")
	}
	if !cgroupContainsID(data, full[:12]) {
		t.Error("expected short (12-char) container id to match")
	}
	if cgroupContainsID(data, "0000000000000000000000000000000000000000000000000000000000000000") {
		t.Error("unrelated container id must not match")
	}
	if cgroupContainsID(data, "") {
		t.Error("empty container id must never match")
	}
}
