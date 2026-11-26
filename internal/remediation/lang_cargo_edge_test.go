package remediation

import (
	"errors"
	"strings"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/github"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

// A crate is the one the lock lists only when the version is the same text:
// build metadata is not ignored when a finding is matched.
func TestLanguagePlan_CargoVersionsMatchExactly(t *testing.T) {
	lock := cargoLockText(4, ownBlock("app", "0.1.0", "tokio"), cratesBlock("tokio", "1.18.0+vendor.2", cksumA))
	manifest := cargoFixture(t, "exp2.Cargo.toml")
	manifest = strings.Replace(manifest, "exp2", "app", 1)

	gh := newFakeGitHub()
	cargoRepo(gh, "ex/app", "svc", map[string]string{"Cargo.toml": manifest, "Cargo.lock": lock})
	it := cargoItem(t, cargoPlan(t, gh, langInput("shop", "api", rustFinding("CVE-1", typeCargo, "app/Cargo.lock", "tokio", "1.18.0+vendor.1", "1.18.4"))))
	if p := it.Packages[0]; p.Action != ActionManual || p.Reason != ReasonNotFoundInSource {
		t.Errorf("lockfile finding of another build: %+v", p)
	}
	// The same text is a match.
	gh = newFakeGitHub()
	cargoRepo(gh, "ex/app", "svc", map[string]string{"Cargo.toml": manifest, "Cargo.lock": lock})
	it = cargoItem(t, cargoPlan(t, gh, langInput("shop", "api", rustFinding("CVE-1", typeCargo, "app/Cargo.lock", "tokio", "1.18.0+vendor.2", "1.18.4"))))
	if p := it.Packages[0]; p.Action != ActionUpdate {
		t.Errorf("same build: %+v", p)
	}
	// A binary's crate of another build is not what the lock leads to.
	in := langInput("shop", "api", rustFinding("CVE-1", typeRustBinary, "usr/local/bin/app", "tokio", "1.18.0+vendor.1", "1.18.4"))
	in.Scan.Packages = []scanner.ResultPackages{rustBinaryPackages("usr/local/bin/app", "app", "0.1.0", "tokio", "1.18.0+vendor.1")}
	it = cargoItem(t, cargoPlan(t, gh, in))
	if it.Reason != ReasonRustBinaryNotFromSource || !strings.Contains(it.Detail, "tokio@1.18.0+vendor.1 is built in but Cargo.lock does not list it") {
		t.Errorf("binary of another build: %s (%s)", it.Reason, it.Detail)
	}
	// Nor is a root of another build a member.
	in = langInput("shop", "api", rustFinding("CVE-1", typeRustBinary, "usr/local/bin/app", "tokio", "1.18.0+vendor.2", "1.18.4"))
	in.Scan.Packages = []scanner.ResultPackages{rustBinaryPackages("usr/local/bin/app", "app", "0.1.0+other", "tokio", "1.18.0+vendor.2")}
	if items := cargoPlan(t, gh, in); len(items) != 0 {
		t.Errorf("root of another build: %+v", items)
	}
}

func TestLanguagePlan_CargoLockAndManifestMustAgree(t *testing.T) {
	tok := rustFinding("CVE-1", typeCargo, "app/Cargo.lock", "tokio", "1.18.0", "1.18.4")
	manifest := "[package]\nname = \"app\"\nversion = \"0.1.0\"\n[dependencies]\ntokio = \"1\"\n"
	for name, c := range map[string]struct{ lock, want string }{
		"a member the lock lacks":                     {cargoLockText(4, ownBlock("other", "0.1.0", "tokio"), cratesBlock("tokio", "1.18.0", cksumA)), "does not list the package app 0.1.0"},
		"a member at another version":                 {cargoLockText(4, ownBlock("app", "0.2.0", "tokio"), cratesBlock("tokio", "1.18.0", cksumA)), "does not list the package app 0.1.0"},
		"an entry without a source that is no member": {cargoLockText(4, ownBlock("app", "0.1.0", "tokio"), ownBlock("ghost", "1.0.0"), cratesBlock("tokio", "1.18.0", cksumA)), "ghost 1.0.0 without a source"},
		"a member also on crates.io":                  {cargoLockText(4, ownBlock("app", "0.1.0", "tokio"), cratesBlock("app", "0.1.0", cksumB), cratesBlock("tokio", "1.18.0", cksumA)), "both a package of the workspace and a crate of crates.io named app 0.1.0"},
	} {
		gh := newFakeGitHub()
		cargoRepo(gh, "ex/app", "svc", map[string]string{"Cargo.toml": manifest, "Cargo.lock": c.lock})
		it := cargoItem(t, cargoPlan(t, gh, langInput("shop", "api", tok)))
		if it.Category != CategoryManual || it.Reason != ReasonDependencyFileUnusable || !strings.Contains(it.Detail, c.want) || it.Packages[0].Action != ActionManual {
			t.Errorf("%s: %s %s (%s)", name, it.Category, it.Reason, it.Detail)
		}
	}
	// The member and a crate of crates.io of one name, whichever finding.
	gh := newFakeGitHub()
	cargoRepo(gh, "ex/app", "svc", map[string]string{"Cargo.toml": manifest, "Cargo.lock": cargoLockText(4, ownBlock("app", "0.1.0", "tokio"), cratesBlock("app", "0.1.0", cksumB), cratesBlock("tokio", "1.18.0", cksumA))})
	it := cargoItem(t, cargoPlan(t, gh, langInput("shop", "api", tok)))
	if it.Reason != ReasonDependencyFileUnusable {
		t.Errorf("a finding of an unrelated crate: %s", it.Reason)
	}
}

func TestLanguagePlan_CargoDotCargoAndKinds(t *testing.T) {
	tok := rustFinding("CVE-1", typeCargo, "app/Cargo.lock", "tokio", "1.18.0", tokioFixes)
	for name, c := range map[string]struct {
		dir, entry string // the directory listed and the entry put in it
		typ        github.EntryType
		reason     Reason
		want       string
	}{
		".cargo symlink in the unit":      {"svc", ".cargo", github.EntrySymlink, ReasonUnsupportedSource, "svc/.cargo is a symlink"},
		".cargo submodule in the unit":    {"svc", ".cargo", github.EntrySubmodule, ReasonUnsupportedSource, "submodule"},
		".cargo symlink above":            {".", ".cargo", github.EntrySymlink, ReasonUnsupportedSource, ".cargo is a symlink"},
		"rust-toolchain is a directory":   {"svc", "rust-toolchain", github.EntryDir, ReasonDependencyFileUnusable, "svc/rust-toolchain is a dir"},
		"rust-toolchain.toml is a link":   {".", "rust-toolchain.toml", github.EntrySymlink, ReasonDependencyFileUnusable, "rust-toolchain.toml is a symlink"},
		"an ancestor Cargo.toml is a dir": {".", "Cargo.toml", github.EntryDir, ReasonDependencyFileUnusable, "Cargo.toml is a dir"},
	} {
		gh := newFakeGitHub()
		exp2Repo(t, gh)
		gh.putEntry("ex/app", c.dir, github.Entry{Name: c.entry, Type: c.typ})
		it := cargoItem(t, cargoPlan(t, gh, langInput("shop", "api", tok)))
		if it.Category != CategoryManual || it.Reason != c.reason || !strings.Contains(it.Detail, c.want) {
			t.Errorf("%s: %s %s (%s)", name, it.Category, it.Reason, it.Detail)
		}
	}
	// A configuration of any kind, a directory too, stops the unit.
	gh := newFakeGitHub()
	exp2Repo(t, gh)
	gh.putEntry("ex/app", "svc", github.Entry{Name: ".cargo", Type: github.EntryDir})
	gh.putEntry("ex/app", "svc/.cargo", github.Entry{Name: "config", Type: github.EntryDir})
	it := cargoItem(t, cargoPlan(t, gh, langInput("shop", "api", tok)))
	if it.Reason != ReasonUnsupportedSource || !strings.Contains(it.Detail, "svc/.cargo/config exists") {
		t.Errorf("config directory: %s (%s)", it.Reason, it.Detail)
	}
}

// Other ecosystems' items come first, and their reads before Cargo's.
func TestLanguagePlan_CargoComesAfterOtherEcosystems(t *testing.T) {
	gh := newFakeGitHub()
	npmRepo(gh, "ex/app", "svc")
	exp2Repo(t, gh)
	npmFinding := finding("CVE-N", "ignored", "1", "2", scanner.SeverityHigh)
	npmFinding.Class, npmFinding.Type, npmFinding.Target = "lang-pkgs", typeNodePkg, "app/package.json"
	npmFinding.Package, npmFinding.InstalledVer, npmFinding.FixedVer = "minimist", "1.2.5", "1.2.6"
	in := langInput("shop", "api", npmFinding, rustFinding("CVE-R", typeCargo, "app/Cargo.lock", "tokio", "1.18.0", tokioFixes))
	items := cargoPlan(t, gh, in)
	if len(items) != 2 || items[0].Manager != ManagerNpm || items[1].Manager != ManagerCargo {
		t.Fatalf("items = %+v", items)
	}
	first := func(prefix string) int {
		for i, c := range gh.calls {
			if strings.HasPrefix(c, prefix) {
				return i
			}
		}
		return -1
	}
	if a, b := first("read:ex/app/svc/package-lock.json"), first("read:ex/app/svc/Cargo.toml"); a < 0 || b < 0 || a > b {
		t.Errorf("reads: npm at %d, Cargo at %d: %v", a, b, gh.calls)
	}
}

// A scan that lists one binary's packages twice cannot be compared, whichever
// list comes first.
func TestLanguagePlan_CargoDuplicateBinaryTarget(t *testing.T) {
	good := rustBinaryPackages("usr/local/bin/app", "exp2", "0.1.0", "once_cell", "1.21.4", "pin-project-lite", "0.2.18", "tokio", "1.18.0")
	other := rustBinaryPackages("usr/local/bin/app", "tool", "1.0.0", "tokio", "1.18.0")
	for name, lists := range map[string][]scanner.ResultPackages{"member first": {good, other}, "other first": {other, good}} {
		gh := newFakeGitHub()
		exp2Repo(t, gh)
		in := langInput("shop", "api", tokioApp("CVE-1"))
		in.Scan.Packages = lists
		it := cargoItem(t, cargoPlan(t, gh, in))
		if it.Category != CategoryManual || it.Reason != ReasonRustBinaryNotFromSource || !strings.Contains(it.Detail, "more than once") {
			t.Errorf("%s: %s %s (%s)", name, it.Category, it.Reason, it.Detail)
		}
	}
}

func TestLanguagePlan_CargoWorkspaceChecks(t *testing.T) {
	tok := rustFinding("CVE-1", typeCargo, "app/Cargo.lock", "tokio", "1.18.0", tokioFixes)
	app := "[package]\nname = \"app\"\nversion = \"0.1.0\"\n[dependencies]\ntokio = \"1\"\n"
	lock := cargoLockText(4, ownBlock("app", "0.1.0", "tokio"), cratesBlock("tokio", "1.18.0", cksumA))
	for name, c := range map[string]struct {
		files  map[string]string
		reason Reason
		want   string
	}{
		"a pattern that matches nothing": {map[string]string{"Cargo.toml": "[workspace]\nmembers = [\"app\", \"missing/*\"]\n", "app/Cargo.toml": app, "Cargo.lock": lock}, ReasonDependencyFilesNotFound, "matches nothing"},
		"two members of one name": {map[string]string{"Cargo.toml": "[workspace]\nmembers = [\"a\", \"b\"]\n",
			"a/Cargo.toml": "[package]\nname = \"p\"\nversion = \"1.0.0\"\n", "b/Cargo.toml": "[package]\nname = \"p\"\nversion = \"2.0.0\"\n", "Cargo.lock": lock}, ReasonWorkspaceUnsupported, "both a package named p"},
		"default-members that is no member": {map[string]string{"Cargo.toml": "[workspace]\nmembers = [\"app\"]\ndefault-members = [\"missing\"]\n", "app/Cargo.toml": app, "Cargo.lock": lock}, ReasonWorkspaceUnsupported, "default-members"},
		"default-members with a pattern":    {map[string]string{"Cargo.toml": "[workspace]\nmembers = [\"app\"]\ndefault-members = [\"a*\"]\n", "app/Cargo.toml": app, "Cargo.lock": lock}, ReasonWorkspaceUnsupported, "default-members"},
	} {
		gh := newFakeGitHub()
		cargoRepo(gh, "ex/app", "svc", c.files)
		it := cargoItem(t, cargoPlan(t, gh, langInput("shop", "api", tok)))
		if it.Category != CategoryManual || it.Reason != c.reason || !strings.Contains(it.Detail, c.want) {
			t.Errorf("%s: %s %s (%s)", name, it.Category, it.Reason, it.Detail)
		}
	}
	// A default member that is a member is fine.
	gh := newFakeGitHub()
	cargoRepo(gh, "ex/app", "svc", map[string]string{"Cargo.toml": "[workspace]\nmembers = [\"app\"]\ndefault-members = [\"app\"]\n", "app/Cargo.toml": app, "Cargo.lock": lock})
	if it := cargoItem(t, cargoPlan(t, gh, langInput("shop", "api", tok))); it.Category != CategoryDependencyUpdateCandidate {
		t.Errorf("item = %s (%s)", it.Reason, it.Detail)
	}
	// The package that makes the requirement is named, not only its file.
	gh = newFakeGitHub()
	cargoRepo(gh, "ex/app", "svc", map[string]string{"Cargo.toml": "[workspace]\nmembers = [\"services/api\"]\n",
		"services/api/Cargo.toml": "[package]\nname = \"gateway\"\n[dependencies]\ntokio = \"=1.18.0\"\n",
		"Cargo.lock":              cargoLockText(4, ownBlock("gateway", "0.0.0", "tokio"), cratesBlock("tokio", "1.18.0", cksumA))})
	it := cargoItem(t, cargoPlan(t, gh, langInput("shop", "api", tok)))
	if d := it.Packages[0].Detail; d != `svc/services/api/Cargo.toml (package gateway) requires tokio "=1.18.0", which does not allow 1.18.4` {
		t.Errorf("detail = %s", d)
	}
}

func TestCargoNumbersAndWildcards(t *testing.T) {
	big := "1.2.18446744073709551616"
	if _, ok := parseCargoVersion(big); ok {
		t.Error("a patch number over 64 bits was accepted")
	}
	if _, ok := parseCargoVersion("1.2.18446744073709551615"); !ok {
		t.Error("the largest 64-bit number was refused")
	}
	if _, reason, _ := cargoTarget("1.2.3", []CVERef{{VulnID: "A", FixedVers: []string{big}}}); reason != ReasonUnparsableVersion {
		t.Errorf("fix over 64 bits: %s", reason)
	}
	if _, reason, _ := cargoTarget(big, []CVERef{{VulnID: "A", FixedVers: []string{"2.0.0"}}}); reason != ReasonUnparsableVersion {
		t.Errorf("installed over 64 bits: %s", reason)
	}
	if _, err := parseCargoLock([]byte(cargoLockText(4, cratesBlock("t", big, cksumA)))); err == nil {
		t.Error("a lock version over 64 bits was accepted")
	}
	if _, err := parseCargoManifest("Cargo.toml", []byte("[package]\nname = \"a\"\nversion = \""+big+"\"\n")); err == nil {
		t.Error("a package version over 64 bits was accepted")
	}
	if _, err := parseCargoIndex([]byte(indexLine("t", big, "")), "t"); err == nil {
		t.Error("an index version over 64 bits was accepted")
	}
	v, _ := parseSemver("1.2.4")
	for _, req := range []string{"*, >=1", ">=1, *", "x, <2", "*,*", "^99999999999999999999", "1.99999999999999999999.*"} {
		if _, ev := cargoReqAllows(req, v); ev {
			t.Errorf("%q was evaluated", req)
		}
	}
	for _, req := range []string{"*", "1.*, <2", ">=1, <2"} {
		if ok, ev := cargoReqAllows(req, v); !ev || !ok {
			t.Errorf("%q = %v, %v", req, ok, ev)
		}
	}
}

func TestParseCargoIndex_SchemaAndBuildMetadata(t *testing.T) {
	for name, line := range map[string]string{
		"schema 3":    indexLine("t", "1.0.0", `,"v":3`),
		"schema 0":    indexLine("t", "1.0.0", `,"v":0`),
		"schema text": indexLine("t", "1.0.0", `,"v":"2"`),
	} {
		if _, err := parseCargoIndex([]byte(line), "t"); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
	for name, line := range map[string]string{"no schema": indexLine("t", "1.0.0", ""), "schema 1": indexLine("t", "1.0.0", `,"v":1`), "schema 2": indexLine("t", "1.0.0", `,"v":2`)} {
		if _, err := parseCargoIndex([]byte(line), "t"); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Two builds of one version are one release; the text is kept as it is.
	if _, err := parseCargoIndex([]byte(indexLine("t", "1.2.3+a", "")+"\n"+indexLine("t", "1.2.3+b", "")), "t"); err == nil {
		t.Error("two builds of one version were accepted")
	}
	rs, err := parseCargoIndex([]byte(indexLine("t", "1.2.3+a", "")), "t")
	if err != nil || rs[0].Version != "1.2.3+a" {
		t.Errorf("%v %+v", err, rs)
	}
	// Lines are processed in turn, and there are not more than the limit.
	if _, err := parseCargoIndex([]byte(strings.Repeat("\n", maxCargoIndexLines+1)), "t"); err == nil || !strings.Contains(err.Error(), "more than") {
		t.Errorf("many lines: %v", err)
	}
}

func TestLanguagePlan_CargoExcludeNamesTheManifest(t *testing.T) {
	// An exclude entry that names the Cargo.toml of a path dependency keeps it
	// out of the workspace as Cargo does, and such a path dependency is not
	// handled.
	app := "[package]\nname = \"app\"\nversion = \"0.1.0\"\n[dependencies]\nhelper = { path = \"helper\" }\ntokio = \"1\"\n[workspace]\nexclude = [\"helper/Cargo.toml\"]\n"
	gh := newFakeGitHub()
	cargoRepo(gh, "ex/app", "svc", map[string]string{
		"Cargo.toml":        app,
		"helper/Cargo.toml": "[package]\nname = \"helper\"\nversion = \"0.2.0\"\n",
		"Cargo.lock":        cargoLockText(4, ownBlock("app", "0.1.0", "helper", "tokio"), ownBlock("helper", "0.2.0"), cratesBlock("tokio", "1.18.0", cksumA)),
	})
	tok := rustFinding("CVE-1", typeCargo, "app/Cargo.lock", "tokio", "1.18.0", tokioFixes)
	it := cargoItem(t, cargoPlan(t, gh, langInput("shop", "api", tok)))
	if it.Category != CategoryManual || it.Reason != ReasonWorkspaceUnsupported || !strings.Contains(it.Detail, "excluded directory") {
		t.Errorf("item = %s %s (%s)", it.Category, it.Reason, it.Detail)
	}
}

func TestParseCargoManifest_VirtualWithPackageTables(t *testing.T) {
	for _, tb := range []string{"dependencies", "dev-dependencies", "features", "lib"} {
		data := "[workspace]\nmembers = [\"app\"]\n[" + tb + "]\n"
		_, err := parseCargoManifest("Cargo.toml", []byte(data))
		var ue *UnsupportedError
		if !errors.As(err, &ue) || ue.Reason != ReasonCargoManifestUnsupported {
			t.Errorf("%s: %v", tb, err)
		}
	}
	if _, err := parseCargoManifest("Cargo.toml", []byte("[workspace]\nmembers = [\"app\"]\n[profile.release]\nlto = true\n")); err != nil {
		t.Errorf("a virtual manifest with a profile: %v", err)
	}
}

func TestCargoReqAllows_CargoParserLimits(t *testing.T) {
	v, _ := parseSemver("1.18.4")
	for _, req := range []string{"*.*", "*.*.*", "x.1", "*.2.3"} {
		if _, ev := cargoReqAllows(req, v); ev {
			t.Errorf("%q was evaluated", req)
		}
	}
	many := strings.TrimSuffix(strings.Repeat(">=1, ", 33), ", ")
	if _, ev := cargoReqAllows(many, v); ev {
		t.Error("33 comparators were evaluated")
	}
	if ok, ev := cargoReqAllows(strings.TrimSuffix(strings.Repeat(">=1, ", 32), ", "), v); !ok || !ev {
		t.Error("32 comparators were not evaluated")
	}
}

func TestParseCargoIndex_KeysAreExact(t *testing.T) {
	for name, line := range map[string]string{
		"a key in another case":        indexLine("t", "1.0.0", `,"YANKED":false`),
		"a key given twice":            strings.Replace(indexLine("t", "1.0.0", ""), `"yanked":false`, `"yanked":true,"yanked":false`, 1),
		"a null schema version":        indexLine("t", "1.0.0", `,"v":null`),
		"a dependency key in a case":   strings.Replace(indexLine("t", "1.0.0", ""), `"deps":[]`, `"deps":[{"name":"a","req":"^1","Req":"*"}]`, 1),
		"a dependency key given twice": strings.Replace(indexLine("t", "1.0.0", ""), `"deps":[]`, `"deps":[{"name":"a","req":"^1","req":"*"}]`, 1),
	} {
		if _, err := parseCargoIndex([]byte(line), "t"); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
}

func TestLanguagePlan_CargoExcludeTakesInTheRoot(t *testing.T) {
	tok := rustFinding("CVE-1", typeCargo, "app/Cargo.lock", "tokio", "1.18.0", tokioFixes)
	for _, c := range []struct{ dir, ex string }{{"svc", `"Cargo.toml"`}, {"svc", `"."`}, {".", `"Cargo.toml"`}, {".", `"."`}} {
		ex := c.ex
		gh := newFakeGitHub()
		mapping := []DependencyMapping{depMapping("compose/shop/api", "ex/app", c.dir)}
		cargoRepo(gh, "ex/app", c.dir, map[string]string{
			"Cargo.toml": "[package]\nname = \"app\"\nversion = \"0.1.0\"\n[dependencies]\ntokio = \"1\"\n[workspace]\nexclude = [" + ex + "]\n",
			"Cargo.lock": cargoLockText(4, ownBlock("app", "0.1.0", "tokio"), cratesBlock("tokio", "1.18.0", cksumA)),
		})
		it := cargoItem(t, langPlan(t, gh, mapping, nil, langInput("shop", "api", tok)).LanguageItems)
		if it.Category != CategoryManual || it.Reason != ReasonWorkspaceUnsupported || !strings.Contains(it.Detail, "root's own Cargo.toml") {
			t.Errorf("%s exclude %s: %s %s (%s)", c.dir, ex, it.Category, it.Reason, it.Detail)
		}
	}
}

func TestCargoReqAllows_OnlyTheASCIISpaceIsBlank(t *testing.T) {
	v, _ := parseSemver("1.18.4")
	for _, req := range []string{">=\t1.18.0", "\t>=1.18.0", ">=1.18.0,\t<2", ">=1.18.0\n"} {
		if _, ev := cargoReqAllows(req, v); ev {
			t.Errorf("%q was evaluated", req)
		}
	}
	if ok, ev := cargoReqAllows(" >= 1.18.0 , < 2 ", v); !ok || !ev {
		t.Error("spaces were refused")
	}
}
