package sensor

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/kitsunetrail/kestrelynx/internal/evidence"
	"github.com/kitsunetrail/kestrelynx/internal/sensor/parser"
)

// This file exercises the whole observer<->parser OS-package-database
// protocol (dbOp, buildContainerIndex, lookupPaths, forgetIndex, dbHandler)
// end to end, against a real, separately-exec'd parser process — the same
// pattern internal/sensor/parser's own tests use, and for the same reason
// (parser.Run's LockDown step requires a freshly-exec'd process; see
// testdata/parserhelper/main.go).

var (
	helperBinOnce sync.Once
	helperBinPath string
	helperBinErr  error
)

func buildParserHelper(t *testing.T) string {
	t.Helper()
	helperBinOnce.Do(func() {
		outDir, err := os.MkdirTemp("", "kl-sensor-helper-*")
		if err != nil {
			helperBinErr = err
			return
		}
		out := filepath.Join(outDir, "parserhelper")
		cmd := exec.Command("go", "build", "-o", out, "./testdata/parserhelper")
		// CGO_ENABLED=0, matching the Dockerfile's own build of the real
		// binary: internal/sensor pulls in enough of the tree (ebpf, procfs,
		// exec) that a cgo build can end up linking in the cgo-based net
		// resolver, whose background threads exist outside the Go runtime's
		// own bookkeeping — exactly what breaks
		// syscall.AllThreadsSyscall6 (used by sandbox.SetNoNewPrivsAll,
		// which parser.LockDown calls). A pure Go build never hits that.
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			helperBinErr = fmt.Errorf("%w\n%s", err, stderr.String())
			return
		}
		helperBinPath = out
	})
	if helperBinErr != nil {
		t.Fatalf("build testdata/parserhelper: %v", helperBinErr)
	}
	return helperBinPath
}

// spawnTestParser starts a real parserhelper child over a fresh socketpair
// and returns the observer-side fd, ready for
// buildContainerIndex/lookupPaths/forgetIndex/fetchLedger — exactly the
// same single, unshared fd the dbworker goroutine would own in production
// (these tests call the dbclient.go functions directly, single-threaded,
// the same way runDBWorker does). The caller must call the returned
// cleanup once done, which closes the fd and waits for the child to exit
// (it exits on its own once the fd closes, per parser.Run's EOF handling).
func spawnTestParser(t *testing.T) (sockFD int, cleanup func()) {
	t.Helper()
	exe := buildParserHelper(t)

	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	childFile := os.NewFile(uintptr(fds[1]), "child-sock")
	cmd := exec.Command(exe)
	cmd.ExtraFiles = []*os.File{childFile}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start parserhelper: %v", err)
	}
	childFile.Close()

	if _, err := parser.ReadReport(fds[0]); err != nil {
		t.Fatalf("read parser report: %v", err)
	}

	return fds[0], func() {
		unix.Close(fds[0])
		cmd.Wait()
	}
}

// noDeadline is a build deadline far enough in the future that the soft cap
// never trips in a test.
func noDeadline() time.Time { return time.Now().Add(time.Hour) }

const testDpkgStatus = `Package: libssl3
Status: install ok installed
Version: 3.0.15-1~deb12u1
Architecture: amd64

Package: zlib1g
Status: install ok installed
Version: 1:1.2.13.dfsg-1
Architecture: amd64
`

const testLibsslList = "/.\n/usr/lib/x86_64-linux-gnu/libssl.so.3\n"
const testZlibList = "/.\n/usr/lib/x86_64-linux-gnu/libz.so.1\n"

// pipeWith returns a read-only *os.File whose content is data, for use as
// an indexFile's fd — a stand-in for what rootfs.Reader.OpenFile would
// return from a real container's filesystem.
func pipeWith(t *testing.T, data string) *os.File {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	go func() {
		w.WriteString(data)
		w.Close()
	}()
	return r
}

func TestDBProtocol_DpkgBuildAndLookup(t *testing.T) {
	sockFD, cleanup := spawnTestParser(t)
	defer cleanup()

	gen := "test-gen-dpkg"
	files := []indexFile{
		{Role: roleStatus, Name: "status", File: pipeWith(t, testDpkgStatus)},
		{Role: roleList, Name: "libssl3.list", File: pipeWith(t, testLibsslList)},
		{Role: roleList, Name: "zlib1g.list", File: pipeWith(t, testZlibList)},
	}
	_, _, _, _, err := buildContainerIndex(sockFD, gen, evidence.DBKindDpkg, files, noDeadline())
	if err != nil {
		t.Fatalf("buildContainerIndex: %v", err)
	}
	ledger, err := fetchLedger(sockFD, gen, noDeadline())
	if err != nil {
		t.Fatalf("fetchLedger: %v", err)
	}
	if len(ledger) != 2 {
		t.Fatalf("ledger = %+v, want 2 entries", ledger)
	}

	owners, err := lookupPaths(sockFD, gen, []string{
		"/usr/lib/x86_64-linux-gnu/libssl.so.3",
		"/usr/lib/x86_64-linux-gnu/libz.so.1",
		"/no/such/path",
	})
	if err != nil {
		t.Fatalf("lookupPaths: %v", err)
	}
	if o := owners["/usr/lib/x86_64-linux-gnu/libssl.so.3"]; len(o.owners) != 1 || o.owners[0].Name != "libssl3" || o.owners[0].Version != "3.0.15-1~deb12u1" {
		t.Errorf("libssl.so.3 owners = %+v", o)
	}
	if o := owners["/usr/lib/x86_64-linux-gnu/libz.so.1"]; len(o.owners) != 1 || o.owners[0].Name != "zlib1g" {
		t.Errorf("libz.so.1 owners = %+v", o)
	}
	if o, ok := owners["/no/such/path"]; !ok || len(o.owners) != 0 {
		t.Errorf("/no/such/path owners = %+v, ok=%v, want present with zero owners", o, ok)
	}

	if err := forgetIndex(sockFD, gen); err != nil {
		t.Fatalf("forgetIndex: %v", err)
	}
	owners2, err := lookupPaths(sockFD, gen, []string{"/usr/lib/x86_64-linux-gnu/libssl.so.3"})
	if err != nil {
		t.Fatalf("lookupPaths after forget: %v", err)
	}
	if o := owners2["/usr/lib/x86_64-linux-gnu/libssl.so.3"]; len(o.owners) != 0 {
		t.Errorf("owners after forget = %+v, want none (index forgotten)", o)
	}
}

func TestDBProtocol_AmbiguousOwnership(t *testing.T) {
	sockFD, cleanup := spawnTestParser(t)
	defer cleanup()

	// Two packages' .list files both claim the same path — dpkg genuinely
	// allows this (e.g. libc-bin's /usr/bin/ld.so symlink and the loader it
	// points at), which is exactly the case dbOpLookup must report as more
	// than one owner rather than picking one arbitrarily.
	const sharedPath = "/usr/lib/x86_64-linux-gnu/shared-thing"
	files := []indexFile{
		{Role: roleStatus, Name: "status", File: pipeWith(t, testDpkgStatus)},
		{Role: roleList, Name: "libssl3.list", File: pipeWith(t, "/.\n"+sharedPath+"\n")},
		{Role: roleList, Name: "zlib1g.list", File: pipeWith(t, "/.\n"+sharedPath+"\n")},
	}
	gen := "test-gen-ambiguous"
	if _, _, _, _, err := buildContainerIndex(sockFD, gen, evidence.DBKindDpkg, files, noDeadline()); err != nil {
		t.Fatalf("buildContainerIndex: %v", err)
	}
	owners, err := lookupPaths(sockFD, gen, []string{sharedPath})
	if err != nil {
		t.Fatalf("lookupPaths: %v", err)
	}
	if len(owners[sharedPath].owners) != 2 {
		t.Fatalf("owners = %+v, want 2 (ambiguous)", owners[sharedPath])
	}
}

// TestDBProtocol_OwnersTruncatedPastMaxOwnersPerPath covers dbHandler's own
// maxOwnersPerPath cap (32): a path 33 distinct packages all claim must
// come back with exactly maxOwnersPerPath owners and OwnersTruncated set —
// never silently reported as a complete, if merely ambiguous, owner list,
// since a caller that missed the 33rd owner would misjudge this path every
// bit as badly as one that missed the only owner entirely.
func TestDBProtocol_OwnersTruncatedPastMaxOwnersPerPath(t *testing.T) {
	sockFD, cleanup := spawnTestParser(t)
	defer cleanup()

	const sharedPath = "/usr/lib/x86_64-linux-gnu/shared-thing"
	const ownerCount = maxOwnersPerPath + 1

	files := []indexFile{{Role: roleStatus, Name: "status", File: pipeWith(t, testDpkgStatus)}}
	for i := 0; i < ownerCount; i++ {
		name := fmt.Sprintf("owner%d", i)
		files = append(files, indexFile{Role: roleList, Name: name + ".list", File: pipeWith(t, "/.\n"+sharedPath+"\n")})
	}
	gen := "test-gen-owners-truncated"
	if _, _, _, _, err := buildContainerIndex(sockFD, gen, evidence.DBKindDpkg, files, noDeadline()); err != nil {
		t.Fatalf("buildContainerIndex: %v", err)
	}

	owners, err := lookupPaths(sockFD, gen, []string{sharedPath})
	if err != nil {
		t.Fatalf("lookupPaths: %v", err)
	}
	got, ok := owners[sharedPath]
	if !ok {
		t.Fatalf("owners[%s] missing entirely, want a truncated-but-present answer", sharedPath)
	}
	if len(got.owners) != maxOwnersPerPath {
		t.Errorf("len(owners) = %d, want exactly %d (the cap, not %d)", len(got.owners), maxOwnersPerPath, ownerCount)
	}
	if !got.truncated {
		t.Errorf("truncated = false, want true — %d owners exceeds the %d cap", ownerCount, maxOwnersPerPath)
	}
}

func TestDBProtocol_Apk(t *testing.T) {
	sockFD, cleanup := spawnTestParser(t)
	defer cleanup()

	const apkInstalled = "P:musl\n" +
		"V:1.2.4-r2\n" +
		"A:x86_64\n" +
		"F:lib\n" +
		"R:libc.musl-x86_64.so.1\n" +
		"\n"
	files := []indexFile{{Role: roleInstalled, Name: "installed", File: pipeWith(t, apkInstalled)}}
	gen := "test-gen-apk"
	_, _, _, _, err := buildContainerIndex(sockFD, gen, evidence.DBKindApk, files, noDeadline())
	if err != nil {
		t.Fatalf("buildContainerIndex: %v", err)
	}
	ledger, err := fetchLedger(sockFD, gen, noDeadline())
	if err != nil {
		t.Fatalf("fetchLedger: %v", err)
	}
	if len(ledger) != 1 || ledger[0].Name != "musl" {
		t.Fatalf("ledger = %+v", ledger)
	}
	owners, err := lookupPaths(sockFD, gen, []string{"/lib/libc.musl-x86_64.so.1"})
	if err != nil {
		t.Fatalf("lookupPaths: %v", err)
	}
	if o := owners["/lib/libc.musl-x86_64.so.1"]; len(o.owners) != 1 || o.owners[0].Name != "musl" || o.owners[0].Version != "1.2.4-r2" {
		t.Errorf("owners = %+v", o)
	}
}

func TestDBProtocol_Distroless(t *testing.T) {
	sockFD, cleanup := spawnTestParser(t)
	defer cleanup()

	const control = "Package: libssl3\nVersion: 3.0.15-1~deb12u1\nArchitecture: amd64\n"
	const md5sums = "abc123  usr/lib/x86_64-linux-gnu/libssl.so.3\n"
	files := []indexFile{
		{Role: roleControl, Name: "libssl3", File: pipeWith(t, control)},
		{Role: roleMD5Sums, Name: "libssl3.md5sums", File: pipeWith(t, md5sums)},
	}
	gen := "test-gen-distroless"
	_, _, _, _, err := buildContainerIndex(sockFD, gen, evidence.DBKindDistroless, files, noDeadline())
	if err != nil {
		t.Fatalf("buildContainerIndex: %v", err)
	}
	ledger, err := fetchLedger(sockFD, gen, noDeadline())
	if err != nil {
		t.Fatalf("fetchLedger: %v", err)
	}
	if len(ledger) != 1 || ledger[0].Name != "libssl3" {
		t.Fatalf("ledger = %+v", ledger)
	}
	owners, err := lookupPaths(sockFD, gen, []string{"/usr/lib/x86_64-linux-gnu/libssl.so.3"})
	if err != nil {
		t.Fatalf("lookupPaths: %v", err)
	}
	if o := owners["/usr/lib/x86_64-linux-gnu/libssl.so.3"]; len(o.owners) != 1 || o.owners[0].Name != "libssl3" {
		t.Errorf("owners = %+v", o)
	}
}

func TestDBProtocol_ChunkedLookupAcrossManyPaths(t *testing.T) {
	sockFD, cleanup := spawnTestParser(t)
	defer cleanup()

	gen := "test-gen-chunked"
	files := []indexFile{
		{Role: roleStatus, Name: "status", File: pipeWith(t, testDpkgStatus)},
		{Role: roleList, Name: "libssl3.list", File: pipeWith(t, testLibsslList)},
	}
	if _, _, _, _, err := buildContainerIndex(sockFD, gen, evidence.DBKindDpkg, files, noDeadline()); err != nil {
		t.Fatalf("buildContainerIndex: %v", err)
	}

	// Enough distinct paths that lookupPaths must issue more than one
	// dbOpLookup request under maxWireRequestBytes.
	var paths []string
	for i := 0; i < 500; i++ {
		paths = append(paths, fmt.Sprintf("/some/long/synthetic/path/number/%d/that/takes/up/real/space", i))
	}
	paths = append(paths, "/usr/lib/x86_64-linux-gnu/libssl.so.3")

	owners, err := lookupPaths(sockFD, gen, paths)
	if err != nil {
		t.Fatalf("lookupPaths: %v", err)
	}
	if len(owners) != len(paths) {
		t.Fatalf("got %d results, want %d (one per input path)", len(owners), len(paths))
	}
	if o := owners["/usr/lib/x86_64-linux-gnu/libssl.so.3"]; len(o.owners) != 1 || o.owners[0].Name != "libssl3" {
		t.Errorf("owners = %+v", o)
	}
}
