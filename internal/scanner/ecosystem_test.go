package scanner

import (
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/inventory"
)

// The fixtures this file reads are real Trivy 0.71.2 output
// (`trivy image --format json --scanners vuln`), trimmed to keep every
// Vulnerability for the package each fixture exists to demonstrate plus a
// few others for shape variety, with the unparsed top-level Packages field
// removed — nothing was hand-authored or edited. scripts/gen_scanner_
// ecosystem_fixtures.py reproduces all six from scratch (base image pulls
// plus the two Dockerfiles and the Go build below) and applies the same
// trim; it is the source of truth for how these files were produced.
//
//   - real_alpine_3.19.json: docker.io/library/alpine:3.19
//     (sha256:6baf43584bcb78f2e5847d1de515f23499913ac9f12bdf834811a3145eb11ca1)
//   - real_debian_12-slim.json: docker.io/library/debian:12-slim
//     (sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251)
//   - real_python_3.9.1-slim_langpkg.json: docker.io/library/python:3.9.1-slim
//     (sha256:bf3ec573c0ae0d0c619c3f3e0e9490878432bf7a5c63a643b6c39c9878b51191)
//   - real_node_lodash_nodepkg.json: a locally built image, FROM
//     node:20-slim, with `npm install lodash@4.17.19 --no-save
//     --no-package-lock` run under /app (node_modules present, no lockfile,
//     so Trivy's node-pkg analyzer — not npm — reports it); lodash's own
//     Vulnerabilities are kept, not just the base image's bundled npm deps
//   - real_jar_commons-collections.json: a locally built image, FROM
//     eclipse-temurin:17-jdk-jammy, with commons-collections-3.2.1.jar
//     (fetched from Maven Central) added under /app
//   - real_gobinary_golang-x-text.json: a locally built image, FROM scratch,
//     containing a Go binary built locally against golang.org/x/text@v0.3.6
//     (chosen over the fixture's original github.com/gorilla/mux@v1.8.0
//     because that module carries no known CVE in Trivy's database, so a
//     trim kept only the Go standard library's own findings and none of the
//     third-party gobinary dependency's; golang.org/x/text has real ones)
func TestParseReport_RealEcosystems(t *testing.T) {
	cases := []struct {
		fixture   string
		vulnID    string
		pkgName   string
		ecosystem inventory.Ecosystem
		class     PkgClass
		target    string
		pkgPath   string
	}{
		{
			fixture: "real_alpine_3.19.json", vulnID: "CVE-2024-58251", pkgName: "busybox",
			ecosystem: inventory.EcosystemAlpine, class: ClassOS,
			target: "alpine:3.19 (alpine 3.19.9)", pkgPath: "",
		},
		{
			fixture: "real_debian_12-slim.json", vulnID: "CVE-2011-3374", pkgName: "apt",
			ecosystem: inventory.EcosystemDebian, class: ClassOS,
			target: "debian:12-slim (debian 12.15)", pkgPath: "",
		},
		{
			fixture: "real_python_3.9.1-slim_langpkg.json", vulnID: "CVE-2021-3572", pkgName: "pip",
			ecosystem: inventory.EcosystemPythonPkg, class: ClassLang,
			target: "Python", pkgPath: "usr/local/lib/python3.9/site-packages/pip-21.0.1.dist-info/METADATA",
		},
		{
			fixture: "real_node_lodash_nodepkg.json", vulnID: "CVE-2021-23337", pkgName: "lodash",
			ecosystem: inventory.EcosystemNodePkg, class: ClassLang,
			target: "Node.js", pkgPath: "app/node_modules/lodash/package.json",
		},
		{
			fixture: "real_jar_commons-collections.json", vulnID: "CVE-2015-7501", pkgName: "commons-collections:commons-collections",
			ecosystem: inventory.EcosystemJar, class: ClassLang,
			target: "Java", pkgPath: "app/commons-collections-3.2.1.jar",
		},
		{
			fixture: "real_gobinary_golang-x-text.json", vulnID: "CVE-2021-38561", pkgName: "golang.org/x/text",
			ecosystem: inventory.EcosystemGoBinary, class: ClassLang,
			target: "usr/local/bin/gofixture", pkgPath: "",
		},
	}

	for _, c := range cases {
		t.Run(c.fixture, func(t *testing.T) {
			scan, err := ParseReport(loadFixture(t, c.fixture))
			if err != nil {
				t.Fatalf("ParseReport: %v", err)
			}
			f := findByVuln(t, scan, c.vulnID)
			if f.Package != c.pkgName {
				t.Errorf("Package = %q, want %q", f.Package, c.pkgName)
			}
			if f.Class != c.class {
				t.Errorf("Class = %q, want %q", f.Class, c.class)
			}
			if f.Target != c.target {
				t.Errorf("Target = %q, want %q", f.Target, c.target)
			}
			if f.PkgPath != c.pkgPath {
				t.Errorf("PkgPath = %q, want %q", f.PkgPath, c.pkgPath)
			}
			ref := f.PackageRef()
			if ref.Ecosystem != c.ecosystem {
				t.Errorf("PackageRef().Ecosystem = %q, want %q", ref.Ecosystem, c.ecosystem)
			}
			if ref.Class != c.class {
				t.Errorf("PackageRef().Class = %q, want %q", ref.Class, c.class)
			}
			if ref.Name != c.pkgName {
				t.Errorf("PackageRef().Name = %q, want %q", ref.Name, c.pkgName)
			}
			if ref.Version != f.InstalledVer {
				t.Errorf("PackageRef().Version = %q, want Finding.InstalledVer %q", ref.Version, f.InstalledVer)
			}
		})
	}
}

// TestParseReport_UnmappedEcosystemType pins the allowlist boundary: a
// Result.Type Trivy has never been recorded emitting (or a future one this
// allowlist doesn't yet know) must parse to EcosystemUnknown, not be trusted
// verbatim or dropped.
func TestParseReport_UnmappedEcosystemType(t *testing.T) {
	if got := inventory.ParseEcosystem("some-future-analyzer"); got != inventory.EcosystemUnknown {
		t.Errorf("ParseEcosystem(unmapped) = %q, want EcosystemUnknown", got)
	}
}
