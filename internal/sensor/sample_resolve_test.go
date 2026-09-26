package sensor

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/kitsunetrail/kestrelynx/internal/evidence"
)

func statPath(t *testing.T, path string) (dev string, ino uint64) {
	t.Helper()
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return formatDevForCompare(st.Dev), st.Ino
}

func TestResolveCandidates_LiveFileWithMatchingIdentityIsVerified(t *testing.T) {
	r, dir := openTestRoot(t)
	defer r.Close()
	writeTestFile(t, dir, "usr/bin/app", "binary")
	dev, ino := statPath(t, filepath.Join(dir, "usr/bin/app"))

	candidates := map[string][]sampleCandidate{
		"/usr/bin/app": {{kind: evidence.KindExe, dev: dev, inode: ino}},
	}
	res := resolveCandidatesWithRoot(r, candidates)
	if res.incomplete {
		t.Errorf("incomplete = true, want false")
	}
	if len(res.verified) != 1 || res.verified[0] != "/usr/bin/app" {
		t.Errorf("verified = %v, want [/usr/bin/app]", res.verified)
	}
	if len(res.replaced) != 0 {
		t.Errorf("replaced = %v, want none", res.replaced)
	}
}

func TestResolveCandidates_NoRecordedIdentityTrustsPresence(t *testing.T) {
	r, dir := openTestRoot(t)
	defer r.Close()
	writeTestFile(t, dir, "usr/bin/app", "binary")

	candidates := map[string][]sampleCandidate{
		"/usr/bin/app": {{kind: evidence.KindExe}}, // no dev/inode recorded
	}
	res := resolveCandidatesWithRoot(r, candidates)
	if len(res.verified) != 1 {
		t.Errorf("verified = %v, want [/usr/bin/app] (presence alone, no calibration data to contradict it)", res.verified)
	}
}

func TestResolveCandidates_DeletedIsReplacedNotIncomplete(t *testing.T) {
	r, _ := openTestRoot(t)
	defer r.Close()

	candidates := map[string][]sampleCandidate{
		"/usr/bin/gone": {{kind: evidence.KindExe, dev: "08:01", inode: 111, deleted: true}},
	}
	res := resolveCandidatesWithRoot(r, candidates)
	if res.incomplete {
		t.Errorf("incomplete = true, want false — a deleted candidate's identity is known, not unresolvable")
	}
	if len(res.replaced) != 1 || res.replaced[0] != "/usr/bin/gone" {
		t.Errorf("replaced = %v, want [/usr/bin/gone]", res.replaced)
	}
}

func TestResolveCandidates_MixedDeletedTreatsWholePathAsReplaced(t *testing.T) {
	r, dir := openTestRoot(t)
	defer r.Close()
	writeTestFile(t, dir, "usr/bin/app", "binary")
	dev, ino := statPath(t, filepath.Join(dir, "usr/bin/app"))

	candidates := map[string][]sampleCandidate{
		"/usr/bin/app": {
			{kind: evidence.KindExe, dev: dev, inode: ino, deleted: false},
			{kind: evidence.KindMappedLibrary, dev: dev, inode: ino, deleted: true},
		},
	}
	res := resolveCandidatesWithRoot(r, candidates)
	if len(res.replaced) != 1 {
		t.Errorf("replaced = %v, want the path treated as replaced when any contributor says deleted", res.replaced)
	}
	if len(res.verified) != 0 {
		t.Errorf("verified = %v, want none", res.verified)
	}
}

func TestResolveCandidates_MissingPathIsIncomplete(t *testing.T) {
	r, _ := openTestRoot(t)
	defer r.Close()

	candidates := map[string][]sampleCandidate{
		"/usr/bin/nope": {{kind: evidence.KindExe, dev: "08:01", inode: 111}},
	}
	res := resolveCandidatesWithRoot(r, candidates)
	if !res.incomplete {
		t.Errorf("incomplete = false, want true — the candidate's own file could not be found at all (open failed, not a deleted marker)")
	}
	if len(res.verified) != 0 || len(res.replaced) != 0 {
		t.Errorf("verified=%v replaced=%v, want both empty", res.verified, res.replaced)
	}
}

func TestResolveCandidates_CalibrationMismatchIsReplaced(t *testing.T) {
	r, dir := openTestRoot(t)
	defer r.Close()
	writeTestFile(t, dir, "usr/bin/app", "new content, different inode than recorded")

	candidates := map[string][]sampleCandidate{
		// A dev/inode that does not match the file currently at this path —
		// as if the file were replaced in place after maps recorded the old
		// identity.
		"/usr/bin/app": {{kind: evidence.KindExe, dev: "ff:ff", inode: 999999}},
	}
	res := resolveCandidatesWithRoot(r, candidates)
	if len(res.replaced) != 1 {
		t.Errorf("replaced = %v, want the path recognized as replaced via calibration mismatch", res.replaced)
	}
	if res.incomplete {
		t.Errorf("incomplete = true, want false — this is a known replacement, not an unresolvable candidate")
	}
}

func TestResolveCandidates_DisallowedFilesystemIsIncomplete(t *testing.T) {
	// A FIFO is refused by rootfs.OpenFile (ErrNotRegularFile), which this
	// package cannot distinguish from "we don't know what happened" any
	// more confidently than a resolve failure — both fall to incomplete.
	r, dir := openTestRoot(t)
	defer r.Close()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	fifoPath := filepath.Join(dir, "fifo")
	if err := unix.Mkfifo(fifoPath, 0o644); err != nil {
		t.Skipf("mkfifo not available in this environment: %v", err)
	}

	candidates := map[string][]sampleCandidate{
		"/fifo": {{kind: evidence.KindExe, dev: "08:01", inode: 111}},
	}
	res := resolveCandidatesWithRoot(r, candidates)
	if !res.incomplete {
		t.Errorf("incomplete = false, want true for a non-regular-file candidate")
	}
}

func TestDetectMergedUsrDirs_ConfirmsRealSymlink(t *testing.T) {
	r, dir := openTestRoot(t)
	defer r.Close()
	if err := os.MkdirAll(filepath.Join(dir, "usr", "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("usr/bin", filepath.Join(dir, "bin")); err != nil {
		t.Fatal(err)
	}

	merged := detectMergedUsrDirs(r)
	if !merged["/bin/"] {
		t.Errorf("merged[/bin/] = false, want true (real symlink to usr/bin)")
	}
	if merged["/sbin/"] {
		t.Errorf("merged[/sbin/] = true, want false (no such directory at all)")
	}
}

func TestDetectMergedUsrDirs_DoesNotAssumeFromNonMergedLayout(t *testing.T) {
	r, dir := openTestRoot(t)
	defer r.Close()
	if err := os.MkdirAll(filepath.Join(dir, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "usr", "bin"), 0o755); err != nil {
		t.Fatal(err)
	}

	merged := detectMergedUsrDirs(r)
	if merged["/bin/"] {
		t.Errorf("merged[/bin/] = true, want false — /bin and /usr/bin are two distinct real directories here")
	}
}

func TestUsrmergeAlias_OnlyAppliesToConfirmedPairs(t *testing.T) {
	merged := map[string]bool{"/bin/": true}
	if alias, ok := usrmergeAlias("/bin/sleep", merged); !ok || alias != "/usr/bin/sleep" {
		t.Errorf("usrmergeAlias(/bin/sleep) = (%q, %v), want (/usr/bin/sleep, true)", alias, ok)
	}
	if alias, ok := usrmergeAlias("/sbin/init", merged); ok {
		t.Errorf("usrmergeAlias(/sbin/init) = (%q, true), want ok=false — /sbin was never confirmed merged", alias)
	}
}
