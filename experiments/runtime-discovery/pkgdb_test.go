package main

import (
	"os"
	"path/filepath"
	"testing"
)

// writeFile is a small test helper that creates path (and its parent dirs)
// with the given content.
func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// lookupOne is a small test helper for the common case of an unambiguous
// (single-owner) path lookup, mirroring the pre-multiple_owners lookup
// signature so existing test expectations read the same way.
func lookupOne(idx *pkgIndex, path string) (kind, pkg, ver string, ok bool) {
	owners, found := idx.lookup(path)
	if !found || len(owners) != 1 {
		return "", "", "", false
	}
	return owners[0][0], owners[0][1], idx.versionOf(owners[0][0], owners[0][1]), true
}

func TestReadLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nginx.list")
	// Hand-written fixture matching the format of this development
	// machine's real /var/lib/dpkg/info/*.list files (one absolute path per
	// line, files and directories both, "/." as the first line).
	writeFile(t, path, "/.\n/usr\n/usr/sbin\n/usr/sbin/nginx\n/usr/share/doc/nginx\n")

	got, err := readLines(path, nil)
	if err != nil {
		t.Fatalf("readLines: %v", err)
	}
	want := []string{"/.", "/usr", "/usr/sbin", "/usr/sbin/nginx", "/usr/share/doc/nginx"}
	if len(got) != len(want) {
		t.Fatalf("readLines = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("readLines[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestReadDpkgControlEntries(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "status")
	// Hand-written fixture matching dpkg's RFC822-like stanza format
	// (man 5 deb-control shape, as used by /var/lib/dpkg/status), including
	// a multiarch package's Architecture line.
	writeFile(t, path, `Package: nginx
Status: install ok installed
Priority: optional
Architecture: amd64
Version: 1.27.0-1~bookworm
Description: small, powerful, scalable web/proxy server
 Nginx ("engine X") is a high-performance web and reverse proxy server.

Package: libssl3
Status: install ok installed
Architecture: amd64
Multi-Arch: same
Version: 3.0.13-1~deb12u1
`)
	entries, err := readDpkgControlEntries(path, nil)
	if err != nil {
		t.Fatalf("readDpkgControlEntries: %v", err)
	}
	versions := map[string]string{}
	archs := map[string]string{}
	for _, e := range entries {
		versions[e.Package] = e.Version
		archs[e.Package] = e.Architecture
	}
	if got, want := versions["nginx"], "1.27.0-1~bookworm"; got != want {
		t.Errorf("nginx version = %q, want %q", got, want)
	}
	if got, want := versions["libssl3"], "3.0.13-1~deb12u1"; got != want {
		t.Errorf("libssl3 version = %q, want %q", got, want)
	}
	if got, want := archs["libssl3"], "amd64"; got != want {
		t.Errorf("libssl3 architecture = %q, want %q", got, want)
	}
	if got, want := archs["nginx"], "amd64"; got != want {
		t.Errorf("nginx architecture = %q, want %q", got, want)
	}
}

func TestBuildPkgIndexDpkgMultiArch(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "var/lib/dpkg/info/libc6:amd64.list"), "/.\n/usr/lib/x86_64-linux-gnu/libc.so.6\n")
	writeFile(t, filepath.Join(root, "var/lib/dpkg/status"), "Package: libc6\nStatus: install ok installed\nArchitecture: amd64\nVersion: 2.36-9\n")

	idx, info, _, err := buildPkgIndexFromRoot(root, "mv1")
	if err != nil {
		t.Fatalf("buildPkgIndexFromRoot: %v", err)
	}
	if info.DBKind != dpkgKind {
		t.Fatalf("DBKind = %q, want %q", info.DBKind, dpkgKind)
	}
	kind, pkg, ver, ok := lookupOne(idx, "/usr/lib/x86_64-linux-gnu/libc.so.6")
	if !ok {
		t.Fatal("expected path to resolve")
	}
	if kind != dpkgKind || pkg != "libc6" || ver != "2.36-9" {
		t.Errorf("lookup = (%s, %s, %s), want (dpkg, libc6, 2.36-9)", kind, pkg, ver)
	}
}

func TestBuildPkgIndexDpkgPriorityOverApk(t *testing.T) {
	// A rootfs with both a dpkg info dir and an apk database present must
	// use dpkg only (the package-database priority order is dpkg, then
	// distroless, then apk; never merged).
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "var/lib/dpkg/info/nginx.list"), "/usr/sbin/nginx\n")
	writeFile(t, filepath.Join(root, "var/lib/dpkg/status"), "Package: nginx\nVersion: 1.27.0-1\n")
	writeFile(t, filepath.Join(root, "lib/apk/db/installed"), "P:musl\nV:1.2.4-r2\nF:lib\nR:ld-musl-x86_64.so.1\n")

	idx, info, _, err := buildPkgIndexFromRoot(root, "mv1")
	if err != nil {
		t.Fatalf("buildPkgIndexFromRoot: %v", err)
	}
	if info.DBKind != dpkgKind {
		t.Errorf("DBKind = %q, want %q (dpkg takes priority)", info.DBKind, dpkgKind)
	}
	if _, _, _, ok := lookupOne(idx, "/lib/ld-musl-x86_64.so.1"); ok {
		t.Error("apk entries must not be merged in when dpkg is the selected database")
	}
}

func TestBuildPkgIndexDistrolessStatusD(t *testing.T) {
	root := t.TempDir()
	// Hand-written fixture matching distroless's documented status.d
	// layout: <package> (a normal dpkg control stanza) and
	// <package>.md5sums ("<md5>  <relative-path>" per line, relative to "/").
	writeFile(t, filepath.Join(root, "var/lib/dpkg/status.d/libc6"), "Package: libc6\nStatus: install ok installed\nVersion: 2.36-9\n")
	writeFile(t, filepath.Join(root, "var/lib/dpkg/status.d/libc6.md5sums"),
		"d41d8cd98f00b204e9800998ecf8427e  usr/lib/x86_64-linux-gnu/libc.so.6\n")
	// A package with metadata but no file list: no_file_list.
	writeFile(t, filepath.Join(root, "var/lib/dpkg/status.d/base-files"), "Package: base-files\nStatus: install ok installed\nVersion: 12\n")

	idx, info, ledger, err := buildPkgIndexFromRoot(root, "mv1")
	if err != nil {
		t.Fatalf("buildPkgIndexFromRoot: %v", err)
	}
	if info.DBKind != dpkgStatusDKind {
		t.Fatalf("DBKind = %q, want %q", info.DBKind, dpkgStatusDKind)
	}
	kind, pkg, ver, ok := lookupOne(idx, "/usr/lib/x86_64-linux-gnu/libc.so.6")
	if !ok || kind != dpkgStatusDKind || pkg != "libc6" || ver != "2.36-9" {
		t.Errorf("lookup = (%v, %s, %s, %s), want (true, dpkg-status.d, libc6, 2.36-9)", ok, kind, pkg, ver)
	}
	fileListPresent := map[string]bool{}
	for _, e := range ledger {
		fileListPresent[e.Name] = e.FileListPresent
	}
	if !fileListPresent["libc6"] {
		t.Error("libc6: FileListPresent = false, want true (has a .md5sums)")
	}
	if fileListPresent["base-files"] {
		t.Error("base-files: FileListPresent = true, want false (no .md5sums)")
	}
}

func TestBuildPkgIndexApk(t *testing.T) {
	root := t.TempDir()
	// Hand-written fixture approximating apk-tools' installed database
	// format: stanzas separated by blank lines, "P:"/"V:" naming the
	// package, "F:" setting the current directory for subsequent "R:" file
	// entries (path = "/" + F + "/" + R), "Z:" a "Q1" + base64(SHA-1)
	// checksum (28 base64 characters after "Q1"; the parser does not
	// interpret Z, but the value must still look like apk's real format).
	//
	// musl-fixturepkg is a synthetic package invented purely to exercise
	// the generic F:/R: path-reconstruction parser; it is not modeled on
	// any real package's file layout.
	writeFile(t, filepath.Join(root, "lib/apk/db/installed"), `P:musl
V:1.2.4-r2
A:x86_64
F:lib
R:ld-musl-x86_64.so.1
Z:Q1wL5PltcT+E9TiI9hXlAOV9cit/E=

P:musl-fixturepkg
V:1.0.0-r0
A:x86_64
F:usr/local/bin
R:fixture-binary
Z:Q1mMLS456RBqu9cIDcKaWwUSTISRs=
`)
	idx, info, _, err := buildPkgIndexFromRoot(root, "mv1")
	if err != nil {
		t.Fatalf("buildPkgIndexFromRoot: %v", err)
	}
	if info.DBKind != apkKind {
		t.Fatalf("DBKind = %q, want %q", info.DBKind, apkKind)
	}
	kind, pkg, ver, ok := lookupOne(idx, "/lib/ld-musl-x86_64.so.1")
	if !ok || kind != apkKind || pkg != "musl" || ver != "1.2.4-r2" {
		t.Errorf("musl lookup = (%v, %s, %s, %s), want (true, apk, musl, 1.2.4-r2)", ok, kind, pkg, ver)
	}
	if _, _, _, ok := lookupOne(idx, "/usr/local/bin/fixture-binary"); !ok {
		t.Error("expected fixture-binary's own apk-declared path to resolve")
	}
}

// TestBuildPkgIndexApkUnownedPath models the real official redis:*-alpine
// image: its redis-server binary is produced by a source build (make
// install) rather than installed via apk, so no apk package owns
// /usr/local/bin/redis-server even though the apk database itself is
// present and readable.
func TestBuildPkgIndexApkUnownedPath(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "lib/apk/db/installed"), `P:musl
V:1.2.4-r2
A:x86_64
F:lib
R:ld-musl-x86_64.so.1
Z:Q1wL5PltcT+E9TiI9hXlAOV9cit/E=
`)
	idx, _, _, err := buildPkgIndexFromRoot(root, "mv1")
	if err != nil {
		t.Fatalf("buildPkgIndexFromRoot: %v", err)
	}
	if _, _, _, ok := lookupOne(idx, "/usr/local/bin/redis-server"); ok {
		t.Error("redis-server must not resolve: the real redis:*-alpine image builds it from source, outside apk")
	}
	if _, _, _, ok := lookupOne(idx, "/lib/ld-musl-x86_64.so.1"); !ok {
		t.Error("musl must still resolve: an unowned path elsewhere must not break resolution of genuinely owned paths")
	}
}

func TestBuildPkgIndexApkRecordBoundary(t *testing.T) {
	// F: must never survive past a blank-line record boundary: a package
	// whose own F: names the root directory must not inherit the previous
	// package's directory. apk always writes an F: line before the R:
	// lines it applies to, so the second record declares an empty F: (the
	// root) rather than omitting it.
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "lib/apk/db/installed"), `P:pkg-a
V:1.0.0-r0
F:opt/a
R:file-a

P:pkg-b
V:1.0.0-r0
F:
R:file-b
`)
	idx, _, _, err := buildPkgIndexFromRoot(root, "mv1")
	if err != nil {
		t.Fatalf("buildPkgIndexFromRoot: %v", err)
	}
	if _, _, _, ok := lookupOne(idx, "/file-b"); !ok {
		t.Error("expected pkg-b's file-b at root-relative path /file-b (no inherited F:)")
	}
	if _, _, _, ok := lookupOne(idx, "/opt/a/file-b"); ok {
		t.Error("pkg-b must not inherit pkg-a's F: directory across the record boundary")
	}
}

// TestBuildPkgIndexApkMissingFileDirective is the malformed-input case: an
// R: line with no F: line before it in its own record has no directory to
// be relative to. apk-tools itself treats that as a format error, so the
// parser must report it rather than invent a root-directory placement that
// would then be looked up as a real owned path.
func TestBuildPkgIndexApkMissingFileDirective(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "lib/apk/db/installed"), `P:pkg-a
V:1.0.0-r0
F:opt/a
R:file-a

P:pkg-b
V:1.0.0-r0
R:file-b
`)
	idx, _, ledger, err := buildPkgIndexFromRoot(root, "mv1")
	if err == nil {
		t.Error("expected a parse error for an R: line with no preceding F: in its record")
	}
	if _, _, _, ok := lookupOne(idx, "/file-b"); ok {
		t.Error("a malformed R: entry must not be indexed as a root-directory file")
	}
	if _, _, _, ok := lookupOne(idx, "/opt/a/file-a"); !ok {
		t.Error("the well-formed record must still be indexed")
	}
	for _, e := range ledger {
		if e.Name == "pkg-b" && e.FileListPresent {
			t.Error("pkg-b: FileListPresent = true, want false (its only R: line was unusable)")
		}
	}
}

// TestBuildPkgIndexFileListCompleteness records the difference between a
// database that can say "nothing owns this path" and one that cannot. When
// every package has a file list, a lookup miss is genuinely unowned; when
// some package's list is missing, the same miss might be that package's
// file, and the index says so.
func TestBuildPkgIndexFileListCompleteness(t *testing.T) {
	complete := t.TempDir()
	writeFile(t, filepath.Join(complete, "var/lib/dpkg/status.d/libc6"), "Package: libc6\nVersion: 2.36-9\n")
	writeFile(t, filepath.Join(complete, "var/lib/dpkg/status.d/libc6.md5sums"),
		"d41d8cd98f00b204e9800998ecf8427e  usr/lib/x86_64-linux-gnu/libc.so.6\n")
	idx, info, _, err := buildPkgIndexFromRoot(complete, "mv1")
	if err != nil {
		t.Fatalf("buildPkgIndexFromRoot: %v", err)
	}
	if !idx.fileListComplete || !info.FileListComplete {
		t.Error("a database where every package has a file list must report FileListComplete")
	}

	partial := t.TempDir()
	writeFile(t, filepath.Join(partial, "var/lib/dpkg/status.d/libc6"), "Package: libc6\nVersion: 2.36-9\n")
	writeFile(t, filepath.Join(partial, "var/lib/dpkg/status.d/libc6.md5sums"),
		"d41d8cd98f00b204e9800998ecf8427e  usr/lib/x86_64-linux-gnu/libc.so.6\n")
	writeFile(t, filepath.Join(partial, "var/lib/dpkg/status.d/base-files"), "Package: base-files\nVersion: 12\n")
	idx, info, _, err = buildPkgIndexFromRoot(partial, "mv1")
	if err != nil {
		t.Fatalf("buildPkgIndexFromRoot: %v", err)
	}
	if idx.fileListComplete || info.FileListComplete {
		t.Error("a database with a package whose file list is missing must not report FileListComplete")
	}
}

func TestBuildPkgIndexNoDatabase(t *testing.T) {
	root := t.TempDir() // empty: neither dpkg, distroless, nor apk present
	idx, info, _, err := buildPkgIndexFromRoot(root, "mv1")
	if err != nil {
		t.Fatalf("buildPkgIndexFromRoot: %v", err)
	}
	if info.DBKind != noDBKind {
		t.Errorf("DBKind = %q, want %q", info.DBKind, noDBKind)
	}
	if _, _, _, ok := lookupOne(idx, "/usr/local/bin/anything"); ok {
		t.Error("empty index must not resolve any path")
	}
}

// TestBuildPkgIndexSymlinkAndTargetAreOneOwner models what a real shared
// library package looks like: libsqlite3-0's own file list names both the
// versioned object and the SONAME symlink pointing at it. Normalizing that
// symlink to its target lands both entries on the same resolved path, and
// a naive index would then report two owners for it. They are one package
// claiming one file twice, so the path must resolve to a single owner —
// otherwise every shared library in the image comes back multiple_owners
// and confirms nothing.
func TestBuildPkgIndexSymlinkAndTargetAreOneOwner(t *testing.T) {
	root := t.TempDir()
	libDir := filepath.Join(root, "usr/lib/x86_64-linux-gnu")
	writeFile(t, filepath.Join(libDir, "libsqlite3.so.0.8.6"), "\x7fELF fixture\n")
	if err := os.Symlink("libsqlite3.so.0.8.6", filepath.Join(libDir, "libsqlite3.so.0")); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(root, "var/lib/dpkg/info/libsqlite3-0:amd64.list"),
		"/.\n/usr/lib/x86_64-linux-gnu/libsqlite3.so.0.8.6\n/usr/lib/x86_64-linux-gnu/libsqlite3.so.0\n")
	writeFile(t, filepath.Join(root, "var/lib/dpkg/status"),
		"Package: libsqlite3-0\nStatus: install ok installed\nArchitecture: amd64\nVersion: 3.40.1-2\n")

	idx, _, _, err := buildPkgIndexFromRoot(root, "mv1")
	if err != nil {
		t.Fatalf("buildPkgIndexFromRoot: %v", err)
	}

	resolved := "/usr/lib/x86_64-linux-gnu/libsqlite3.so.0.8.6"
	owners, ok := idx.lookup(resolved)
	if !ok {
		t.Fatalf("%s did not resolve to any owner", resolved)
	}
	if len(owners) != 1 {
		t.Fatalf("owners of %s = %v, want exactly one (the symlink and its target are the same package)", resolved, owners)
	}
	kind, pkg, ver, ok := lookupOne(idx, resolved)
	if !ok || kind != dpkgKind || pkg != "libsqlite3-0" || ver != "3.40.1-2" {
		t.Errorf("lookup = (%v, %s, %s, %s), want (true, dpkg, libsqlite3-0, 3.40.1-2)", ok, kind, pkg, ver)
	}
}

// TestBuildPkgIndexGenuineMultipleOwners is the other side of the same
// rule: two different packages claiming one path really are ambiguous, and
// deduplicating owners must not collapse that away.
func TestBuildPkgIndexGenuineMultipleOwners(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "var/lib/dpkg/info/pkg-a.list"), "/usr/share/contested-file\n")
	writeFile(t, filepath.Join(root, "var/lib/dpkg/info/pkg-b.list"), "/usr/share/contested-file\n")
	writeFile(t, filepath.Join(root, "var/lib/dpkg/status"),
		"Package: pkg-a\nArchitecture: amd64\nVersion: 1\n\nPackage: pkg-b\nArchitecture: amd64\nVersion: 2\n")

	idx, _, _, err := buildPkgIndexFromRoot(root, "mv1")
	if err != nil {
		t.Fatalf("buildPkgIndexFromRoot: %v", err)
	}
	owners, ok := idx.lookup("/usr/share/contested-file")
	if !ok || len(owners) != 2 {
		t.Fatalf("owners = %v (ok=%v), want two distinct packages", owners, ok)
	}
}

// mergedUsrLoaderRoot builds the rootfs shape a merged-/usr Debian image
// actually has around the dynamic loader, which is where ownership
// resolution is hardest:
//
//	/lib                       -> usr/lib                     (top-level alias)
//	/lib64                     -> usr/lib64                   (top-level alias)
//	/usr/lib64/ld-linux-*.so.2 -> ../lib/x86_64-linux-gnu/...  (cross-directory)
//	/usr/bin/ld.so             -> ../lib64/ld-linux-*.so.2     (a third hop)
//
// with the loader itself a regular file under /usr/lib/x86_64-linux-gnu.
// Three packages are involved, exactly as on a real system: libc6 owns the
// loader and lists it twice (through /lib and through /lib64), libc-bin
// owns only the /usr/bin/ld.so symlink, and base-files owns the top-level
// directory aliases.
func mergedUsrLoaderRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	const loader = "usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"

	writeFile(t, filepath.Join(root, loader), "\x7fELF loader fixture\n")
	writeFile(t, filepath.Join(root, "usr/lib/x86_64-linux-gnu/libc.so.6"), "\x7fELF libc fixture\n")
	if err := os.MkdirAll(filepath.Join(root, "usr/lib64"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "usr/bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, link := range []struct{ target, path string }{
		{"usr/lib", "lib"},
		{"usr/lib64", "lib64"},
		{"../lib/x86_64-linux-gnu/ld-linux-x86-64.so.2", "usr/lib64/ld-linux-x86-64.so.2"},
		{"../lib64/ld-linux-x86-64.so.2", "usr/bin/ld.so"},
	} {
		if err := os.Symlink(link.target, filepath.Join(root, link.path)); err != nil {
			t.Fatal(err)
		}
	}

	writeFile(t, filepath.Join(root, "var/lib/dpkg/info/libc6:amd64.list"),
		"/.\n/lib/x86_64-linux-gnu/libc.so.6\n/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2\n/lib64/ld-linux-x86-64.so.2\n")
	writeFile(t, filepath.Join(root, "var/lib/dpkg/info/libc-bin.list"),
		"/.\n/usr/bin/ld.so\n")
	writeFile(t, filepath.Join(root, "var/lib/dpkg/info/base-files.list"),
		"/.\n/lib\n/lib64\n")
	writeFile(t, filepath.Join(root, "var/lib/dpkg/status"),
		"Package: libc6\nStatus: install ok installed\nArchitecture: amd64\nVersion: 2.36-9+deb12u10\n\n"+
			"Package: libc-bin\nStatus: install ok installed\nArchitecture: amd64\nVersion: 2.36-9+deb12u10\n\n"+
			"Package: base-files\nStatus: install ok installed\nArchitecture: amd64\nVersion: 12.4+deb12u11\n")
	return root
}

// TestBuildPkgIndexMergedUsrLoaderHasOneOwner is the case a real nginx:1.27
// run got wrong: every process mapped the dynamic loader, and every sample
// reported multiple_owners for it while the seven other mapped libraries
// resolved correctly.
//
// The cause is the third symlink above. libc-bin owns /usr/bin/ld.so, a
// symlink that eventually reaches the loader; following that last hop while
// normalizing the database registered libc-bin as an owner of libc6's file,
// so two packages claimed it. Only the loader was affected because it is
// the only mapped file with a symlink alias owned by a *different* package.
func TestBuildPkgIndexMergedUsrLoaderHasOneOwner(t *testing.T) {
	root := mergedUsrLoaderRoot(t)
	idx, _, _, err := buildPkgIndexFromRoot(root, "mv1")
	if err != nil {
		t.Fatalf("buildPkgIndexFromRoot: %v", err)
	}

	// The path as the kernel reports it in /proc/<pid>/maps: the file the
	// mapping is backed by, never a symlink to it.
	const observed = "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"
	owners, ok := idx.lookup(observed)
	if !ok {
		t.Fatalf("%s did not resolve to any owner", observed)
	}
	if len(owners) != 1 {
		t.Fatalf("owners of %s = %v, want exactly one (libc6): a package owning a symlink to a file does not own the file", observed, owners)
	}
	kind, pkg, ver, ok := lookupOne(idx, observed)
	if !ok || kind != dpkgKind || pkg != "libc6" || ver != "2.36-9+deb12u10" {
		t.Errorf("lookup = (%v, %s, %s, %s), want (true, dpkg, libc6, 2.36-9+deb12u10)", ok, kind, pkg, ver)
	}

	// The other mapped library of the same package, reached through the
	// /lib alias, must still resolve — the directory half of the
	// normalization is what makes both sides agree and has to keep working.
	if _, pkg, _, ok := lookupOne(idx, "/usr/lib/x86_64-linux-gnu/libc.so.6"); !ok || pkg != "libc6" {
		t.Errorf("libc.so.6 = (%v, %s), want (true, libc6)", ok, pkg)
	}

	// libc-bin still owns the symlink it actually ships, under the
	// directory-normalized form of its own path.
	if _, pkg, _, ok := lookupOne(idx, "/usr/bin/ld.so"); !ok || pkg != "libc-bin" {
		t.Errorf("/usr/bin/ld.so = (%v, %s), want (true, libc-bin): the symlink itself is libc-bin's file", ok, pkg)
	}
}

// TestResolvePathRecordMergedUsrLoaderIsOwned carries the same rootfs
// through the collector's own path classification, which is where the
// wrong answer was actually observed: ownership must come back "owned"
// with the package and version filled in, not "multiple_owners" with both
// fields empty.
func TestResolvePathRecordMergedUsrLoaderIsOwned(t *testing.T) {
	root := mergedUsrLoaderRoot(t)
	idx, info, _, err := buildPkgIndexFromRoot(root, "mv1")
	if err != nil {
		t.Fatalf("buildPkgIndexFromRoot: %v", err)
	}
	cache := &containerPkgCache{idx: idx, info: info}

	got := resolvePathRecord("s0", ProcessGeneration{PID: 1, Starttime: "1"}, root, "maps",
		"/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2", "08:01", "131099", false, cache)
	if got.Ownership != OwnershipOwned {
		t.Fatalf("ownership = %q, want owned", got.Ownership)
	}
	if got.Package != "libc6" || got.DBVersion != "2.36-9+deb12u10" {
		t.Errorf("package/version = %q/%q, want libc6/2.36-9+deb12u10", got.Package, got.DBVersion)
	}
}

// redisAlpineRoot reproduces the part of a real redis:7-alpine database
// that decides ownership of the server binary. Two things matter and both
// are taken from the running image:
//
//   - redis-server lives at /usr/local/bin/redis-server because the
//     official image builds it from source, so no apk package owns it.
//   - the image carries .redis-rundeps, a virtual package `apk add
//     --virtual` created to bundle the runtime dependencies. It is a
//     normal record in the installed database — P/V/A and a dependency
//     list — with no F: or R: lines, because it installs no files.
func redisAlpineRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "lib/apk/db/installed"), `C:Q1eVYCqNRTHXNwYHCJ7ZLLQnrpSkg=
P:musl
V:1.2.5-r11
A:x86_64
T:the musl c library (libc) implementation
o:musl
t:1755530000
F:lib
R:ld-musl-x86_64.so.1
Z:Q1wL5PltcT+E9TiI9hXlAOV9cit/E=

C:Q1LFSgZ5MPaBpzOZQMM7fZAhWO1xY=
P:libcrypto3
V:3.3.7-r0
A:x86_64
T:Crypto library from openssl
o:openssl
t:1755530000
F:usr/lib
R:libcrypto.so.3
Z:Q1mMLS456RBqu9cIDcKaWwUSTISRs=

C:Q1cKmJW0cHUwZ8xQCvFhJ4kJQ3RnA=
P:libssl3
V:3.3.7-r0
A:x86_64
T:SSL shared libraries
o:openssl
t:1755530000
F:usr/lib
R:libssl.so.3
Z:Q1wL5PltcT+E9TiI9hXlAOV9cit/E=

C:Q1pTLF7B1YPmJTJKm8nO0aWXd9pFQ=
P:.redis-rundeps
V:20260818.165646
A:noarch
T:virtual meta package
o:.redis-rundeps
t:1755530000
D:so:libc.musl-x86_64.so.1 so:libssl.so.3
`)
	// The paths the two real packages own, so a lookup miss below is a
	// genuine miss rather than an empty index.
	writeFile(t, filepath.Join(root, "lib/ld-musl-x86_64.so.1"), "\x7fELF musl fixture\n")
	writeFile(t, filepath.Join(root, "usr/lib/libcrypto.so.3"), "\x7fELF libcrypto fixture\n")
	writeFile(t, filepath.Join(root, "usr/lib/libssl.so.3"), "\x7fELF libssl fixture\n")
	writeFile(t, filepath.Join(root, "usr/local/bin/redis-server"), "\x7fELF redis fixture\n")
	return root
}

// TestBuildPkgIndexApkVirtualPackageKeepsFileListComplete is case 2: a
// virtual package has no files, and that must not be read as "this
// database cannot report file lists". Treating it as a missing list made
// the whole database incomplete, and every unowned path in the image —
// including the source-built redis-server the case exists to observe —
// came back no_file_list instead of unowned.
func TestBuildPkgIndexApkVirtualPackageKeepsFileListComplete(t *testing.T) {
	root := redisAlpineRoot(t)
	idx, info, ledger, err := buildPkgIndexFromRoot(root, "mv1")
	if err != nil {
		t.Fatalf("buildPkgIndexFromRoot: %v", err)
	}
	if info.DBKind != apkKind {
		t.Fatalf("DBKind = %q, want %q", info.DBKind, apkKind)
	}
	if !info.FileListComplete || !idx.fileListComplete {
		t.Error("FileListComplete = false: a package that installs no files has a complete, empty list")
	}

	byName := map[string]LedgerEntry{}
	for _, e := range ledger {
		byName[e.Name] = e
	}
	virtual, ok := byName[".redis-rundeps"]
	if !ok {
		t.Fatalf("ledger = %v, want an entry for the virtual package", ledger)
	}
	if !virtual.FileListPresent {
		t.Error(".redis-rundeps: FileListPresent = false, want true (its list is known and empty)")
	}
	if virtual.FileCount != 0 {
		t.Errorf(".redis-rundeps: FileCount = %d, want 0", virtual.FileCount)
	}
	if got := byName["musl"]; !got.FileListPresent || got.FileCount != 1 {
		t.Errorf("musl: FileListPresent=%v FileCount=%d, want true/1", got.FileListPresent, got.FileCount)
	}
}

// TestResolvePathRecordRedisServerIsUnowned carries the same database
// through the collector's own classification, against the exact path the
// real run misclassified. redis-server is built from source and owned by
// nothing, which is a finding the case is designed to produce — "the
// collector does not attribute an unowned executable to some package" —
// and no_file_list would have hidden it behind a database limitation that
// does not exist.
func TestResolvePathRecordRedisServerIsUnowned(t *testing.T) {
	root := redisAlpineRoot(t)
	idx, info, _, err := buildPkgIndexFromRoot(root, "mv1")
	if err != nil {
		t.Fatalf("buildPkgIndexFromRoot: %v", err)
	}
	cache := &containerPkgCache{idx: idx, info: info}
	gen := ProcessGeneration{PID: 1, Starttime: "1"}

	// The four distinct paths the real run observed, with the ownership
	// each one should have had.
	want := []struct {
		path      string
		ownership Ownership
		pkg       string
		version   string
	}{
		{"/lib/ld-musl-x86_64.so.1", OwnershipOwned, "musl", "1.2.5-r11"},
		{"/usr/lib/libcrypto.so.3", OwnershipOwned, "libcrypto3", "3.3.7-r0"},
		{"/usr/lib/libssl.so.3", OwnershipOwned, "libssl3", "3.3.7-r0"},
		{"/usr/local/bin/redis-server", OwnershipUnowned, "", ""},
	}
	for _, tt := range want {
		got := resolvePathRecord("s0", gen, root, "maps", tt.path, "08:01", "131099", false, cache)
		if got.Ownership != tt.ownership || got.Package != tt.pkg || got.DBVersion != tt.version {
			t.Errorf("%s = (%q, %q, %q), want (%q, %q, %q)",
				tt.path, got.Ownership, got.Package, got.DBVersion, tt.ownership, tt.pkg, tt.version)
		}
	}
}

// TestBuildPkgIndexDistrolessMissingMd5sumsIsIncomplete keeps the other
// side of the distinction: distroless has no record of a package's files
// beyond its .md5sums, so an absent one genuinely leaves the database
// unable to answer, and a lookup miss there is not evidence of non-
// ownership.
func TestBuildPkgIndexDistrolessMissingMd5sumsIsIncomplete(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "var/lib/dpkg/status.d/libc6"), "Package: libc6\nVersion: 2.36-9\n")
	writeFile(t, filepath.Join(root, "var/lib/dpkg/status.d/libc6.md5sums"),
		"d41d8cd98f00b204e9800998ecf8427e  usr/lib/x86_64-linux-gnu/libc.so.6\n")
	writeFile(t, filepath.Join(root, "var/lib/dpkg/status.d/base-files"), "Package: base-files\nVersion: 12\n")

	_, info, ledger, err := buildPkgIndexFromRoot(root, "mv1")
	if err != nil {
		t.Fatalf("buildPkgIndexFromRoot: %v", err)
	}
	if info.FileListComplete {
		t.Error("FileListComplete = true, want false: base-files has no .md5sums, so its files are unknown")
	}
	for _, e := range ledger {
		if e.Name == "base-files" && e.FileListPresent {
			t.Error("base-files: FileListPresent = true, want false (absent .md5sums, not an empty one)")
		}
	}
}
