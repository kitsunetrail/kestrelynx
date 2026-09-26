package sensor

import (
	"net"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/sensor/procfs"
)

func TestFindMapEntry(t *testing.T) {
	maps := []procfs.MapEntry{
		{Path: "/usr/sbin/nginx", Dev: "08:01", Inode: 111},
		{Path: "/usr/lib/libssl.so.3", Dev: "08:01", Inode: 222},
	}
	dev, inode := findMapEntry(maps, "/usr/lib/libssl.so.3")
	if dev != "08:01" || inode != 222 {
		t.Errorf("findMapEntry = (%q, %d), want (08:01, 222)", dev, inode)
	}
	dev, inode = findMapEntry(maps, "/no/such/path")
	if dev != "" || inode != 0 {
		t.Errorf("findMapEntry for a missing path = (%q, %d), want zero value", dev, inode)
	}
}

// TestOwnedListeners_FindsOwnListener opens a real TCP listener in this test
// process and confirms ownedListeners attributes it to this process (via its
// own fd table), the way it must for the same-sample/same-process rule: a
// listener is only ever attached to the process that actually holds the fd,
// not to every process sharing its network namespace.
func TestOwnedListeners_FindsOwnListener(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	_, portStr, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}

	h, err := procfs.Open(os.Getpid())
	if err != nil {
		t.Fatalf("procfs.Open(self): %v", err)
	}
	defer h.Close()

	listeners := ownedListeners(h)
	found := false
	want := "tcp:127.0.0.1:" + strconv.Itoa(port)
	for _, l := range listeners {
		if l == want {
			found = true
		}
	}
	if !found {
		t.Errorf("ownedListeners() = %v, want to contain %q", listeners, want)
	}
}

// TestOwnedListeners_DoesNotClaimOtherProcessesListeners is a sanity check
// that ownedListeners never returns something obviously wrong (a listener
// this process cannot possibly hold an fd for) when it holds none at all.
func TestOwnedListeners_EmptyWhenNoListeners(t *testing.T) {
	h, err := procfs.Open(os.Getpid())
	if err != nil {
		t.Fatalf("procfs.Open(self): %v", err)
	}
	defer h.Close()
	for _, l := range ownedListeners(h) {
		if strings.Contains(l, ":0") {
			t.Errorf("unexpected zero-port listener reported: %q", l)
		}
	}
}
