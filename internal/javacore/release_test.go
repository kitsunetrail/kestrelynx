package javacore

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/imagefs"
)

func releaseFixture(t testing.TB, name string) []byte {
	t.Helper()
	return readFixture(t, "release/"+name+".release")
}

func TestParseRelease(t *testing.T) {
	r, err := ParseRelease(releaseFixture(t, "temurin21"))
	if err != nil {
		t.Fatal(err)
	}
	if r.Implementor != "Eclipse Adoptium" || r.JavaVersion != "21.0.13.1" || !r.HasModules || r.Modules[0] != "java.base" {
		t.Errorf("parsed %+v", r)
	}
	r, err = ParseRelease([]byte("# c\nUNKNOWN=\"x\"\nnot an assignment\nJAVA_VERSION=\"1\"\nJAVA_VERSION=\"2\"\nMODULES=\"\"\n"))
	if err != nil || r.JavaVersion != "2" || !r.HasModules || len(r.Modules) != 0 {
		t.Errorf("tolerant parse = %+v, %v", r, err)
	}
	r, _ = ParseRelease([]byte("JAVA_VERSION=\"21\"\n"))
	if r.HasModules {
		t.Error("HasModules without a MODULES line")
	}
	if _, err := ParseRelease(make([]byte, maxReleaseSize+1)); err == nil {
		t.Error("oversize content accepted")
	}
	long := "JAVA_VERSION=\"" + strings.Repeat("9", maxReleaseLine) + "\"\nIMPLEMENTOR=\"X\"\n"
	r, err = ParseRelease([]byte(long))
	if err != nil || r.JavaVersion != "" || r.Implementor != "X" {
		t.Errorf("long line = %+v, %v", r, err)
	}
}

func TestClassify_Fixtures(t *testing.T) {
	tests := []struct {
		fixture, dir string
		vendor       Vendor
		ok           bool
		version      string
	}{
		{"temurin21", "/opt/java/openjdk", VendorTemurin, true, "21.0.13.1"},
		{"temurin8", "/opt/java/openjdk", VendorTemurin, true, "8u512"},
		{"oracle-openjdk27", "/usr/share/elasticsearch/jdk", VendorOracleOpenJDK, true, "27.0.1.1"},
		{"jenkins-jlink21", "/opt/java/openjdk", VendorUnknown, true, "21.0.13"},
		{"jlink-java-base", "/opt/jre", VendorUnknown, true, "21.0.13.1"},
		{"oracle-jdk25", "/usr/lib/jvm/jdk-25", "", false, ""},
		{"corretto8", "/usr/lib/jvm/java-1.8.0-amazon-corretto.x86_64", "", false, ""},
		{"corretto8", "/opt/jdk", "", false, ""},
		{"corretto21", "/usr/lib/jvm/java-21-amazon-corretto.x86_64", "", false, ""},
		{"zulu21", "/usr/lib/jvm/zulu21-ca-amd64", "", false, ""},
		{"semeru21", "/opt/java/openjdk", "", false, ""},
		{"redhat21", "/usr/lib/jvm/java-21-openjdk", "", false, ""},
		{"debian21", "/usr/lib/jvm/java-21-openjdk-amd64", "", false, ""},
		{"microsoft21", "/usr/lib/jvm/msopenjdk-21-amd64", "", false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.fixture+tt.dir, func(t *testing.T) {
			r, err := ParseRelease(releaseFixture(t, tt.fixture))
			if err != nil {
				t.Fatal(err)
			}
			vendor, ok, reason := Classify(tt.dir, r)
			if vendor != tt.vendor || ok != tt.ok || reason == "" {
				t.Errorf("Classify = %q, %v, %q", vendor, ok, reason)
			}
			chk := fixtureSnapshot(t).CheckRelease(tt.dir, releaseFixture(t, tt.fixture), allSeverities)
			if chk.Checked != tt.ok || chk.Version != tt.version || chk.Reason == "" {
				t.Errorf("CheckRelease = checked %v, version %q, reason %q", chk.Checked, chk.Version, chk.Reason)
			}
			if !tt.ok && (len(chk.Advisories) != 0 || len(chk.Suppressed) != 0) {
				t.Errorf("unchecked JDK has results: %+v", chk)
			}
		})
	}
}

func TestClassify_DirectoryNames(t *testing.T) {
	r := Release{JavaVersion: "21.0.13.1"}
	for dir, want := range map[string]bool{
		"/usr/lib/jvm/zulu-custom":     false,
		"/opt/Corretto/jdk":            false,
		"/opt/semeru/bin/../jdk":       false,
		"/usr/lib/jvm/OpenJ9-21":       false,
		"/opt/jre":                     true,
		"/opt/java/openjdk":            true,
		"/usr/share/elasticsearch/jdk": true,
		"/usr/lib/jvm/java-21-openjdk": true,
		"":                             true,
		"/opt/bellsoft-jre/../plain":   true, // cleaned away
	} {
		if _, ok, _ := Classify(dir, r); ok != want {
			t.Errorf("Classify(%q) ok = %v, want %v", dir, ok, want)
		}
	}
}

func TestClassify_Rules(t *testing.T) {
	tests := []struct {
		name    string
		r       Release
		vendor  Vendor
		ok      bool
		version string
	}{
		{"commercial first", Release{Implementor: "Eclipse Adoptium", BuildType: "commercial", JavaVersion: "21.0.1"}, "", false, ""},
		{"oracle open source element", Release{Implementor: "Oracle Corporation", Source: ".:git:aa open:git:bb", JavaVersion: "21"}, "", false, ""},
		{"oracle lts", Release{Implementor: "Oracle Corporation", JavaRuntimeVersion: "21.0.1+1-LTS", JavaVersion: "21.0.1"}, "", false, ""},
		{"oracle openjdk", Release{Implementor: "Oracle Corporation", JavaRuntimeVersion: "27+4-22", JavaVersion: "27"}, VendorOracleOpenJDK, true, "27"},
		{"ea", Release{Implementor: "Eclipse Adoptium", JavaRuntimeVersion: "27-ea+3-1", JavaVersion: "27"}, "", false, ""},
		{"internal", Release{JavaRuntimeVersion: "27-internal-adhoc", JavaVersion: "27"}, "", false, ""},
		{"no implementor series 8", Release{JavaVersion: "1.8.0_512"}, "", false, ""},
		{"temurin 8", Release{Implementor: "Eclipse Adoptium", JavaVersion: "1.8.0_512"}, VendorTemurin, true, "8u512"},
		{"six parts", Release{Implementor: "Eclipse Adoptium", JavaVersion: "21.0.13.1.2.3"}, VendorTemurin, true, "21.0.13.1.2.3"},
		{"seven parts", Release{Implementor: "Eclipse Adoptium", JavaVersion: "21.0.13.1.2.3.4"}, "", false, ""},
		{"leading zero", Release{Implementor: "Eclipse Adoptium", JavaVersion: "21.00.1"}, "", false, ""},
		{"first below 9", Release{Implementor: "Eclipse Adoptium", JavaVersion: "8.0.1"}, "", false, ""},
		{"series 9", Release{Implementor: "Eclipse Adoptium", JavaVersion: "9.0.4"}, VendorTemurin, true, "9.0.4"},
		{"1.7 form", Release{Implementor: "Eclipse Adoptium", JavaVersion: "1.7.0_80"}, "", false, ""},
		{"8u form is not JAVA_VERSION", Release{Implementor: "Eclipse Adoptium", JavaVersion: "8u512"}, "", false, ""},
		{"1.8.0 zero update", Release{Implementor: "Eclipse Adoptium", JavaVersion: "1.8.0_0"}, "", false, ""},
		{"empty version", Release{Implementor: "Eclipse Adoptium"}, "", false, ""},
		{"huge component", Release{Implementor: "Eclipse Adoptium", JavaVersion: "21.0.9999999999"}, "", false, ""},
		{"other implementor", Release{Implementor: "Alpine", JavaVersion: "21.0.1"}, "", false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vendor, v, ok, reason := classify("/opt/jdk", tt.r)
			if vendor != tt.vendor || ok != tt.ok || reason == "" {
				t.Fatalf("classify = %q, %v, %q", vendor, ok, reason)
			}
			if ok && v.String() != tt.version {
				t.Errorf("version = %s, want %s", v, tt.version)
			}
		})
	}
}

func withVersion(t testing.TB, fixture, from, to string) []byte {
	t.Helper()
	s := string(releaseFixture(t, fixture))
	if !strings.Contains(s, "JAVA_VERSION=\""+from+"\"") {
		t.Fatalf("%s has no %q", fixture, from)
	}
	return []byte(strings.Replace(s, "JAVA_VERSION=\""+from+"\"", "JAVA_VERSION=\""+to+"\"", 1))
}

func TestCheckRelease_JlinkSuppressesVendorFixedCVE(t *testing.T) {
	sn := fixtureSnapshot(t)
	jenkins := sn.CheckRelease("/opt/java/openjdk", releaseFixture(t, "jenkins-jlink21"), allSeverities)
	if _, ok := find(jenkins.Advisories, "CVE-2026-114820"); ok {
		t.Error("the jlink JDK reports CVE-2026-114820")
	}
	if !reflect.DeepEqual(jenkins.Suppressed, []string{"CVE-2026-114820"}) {
		t.Errorf("Suppressed = %v", jenkins.Suppressed)
	}
	if len(jenkins.Advisories) == 0 {
		t.Error("the jlink JDK has no other advisories")
	}

	oracle := append([]byte("IMPLEMENTOR=\"Oracle Corporation\"\n"), releaseFixture(t, "jenkins-jlink21")...)
	got := sn.CheckRelease("/opt/java/openjdk", oracle, allSeverities)
	if got.Vendor != VendorOracleOpenJDK {
		t.Fatalf("vendor = %q", got.Vendor)
	}
	adv, ok := find(got.Advisories, "CVE-2026-114820")
	if !ok {
		t.Fatal("Oracle OpenJDK does not report CVE-2026-114820")
	}
	if len(got.Suppressed) != 0 {
		t.Errorf("Suppressed = %v", got.Suppressed)
	}
	if adv.FixedVer == "" || adv.FixedVer == "21.0.13" {
		t.Errorf("FixedVer = %q, want the first Temurin release above the ceiling", adv.FixedVer)
	}
}

func TestCheckRelease_SuppressedFollowsSeverity(t *testing.T) {
	sn := fixtureSnapshot(t)
	got := sn.CheckRelease("/opt/jre", releaseFixture(t, "jenkins-jlink21"), allSeverities)
	if len(got.Suppressed) != 1 {
		t.Fatalf("Suppressed = %v", got.Suppressed)
	}
	sev := ""
	for _, a := range sn.Match(VendorOracleOpenJDK, mustVersion(t, "21.0.13")) {
		if a.VulnID == "CVE-2026-114820" {
			sev = a.Severity
		}
	}
	other := "LOW"
	if sev == "LOW" {
		other = "HIGH"
	}
	if got := sn.CheckRelease("/opt/jre", releaseFixture(t, "jenkins-jlink21"), []string{other}); len(got.Suppressed) != 0 {
		t.Errorf("Suppressed with only %s = %v", other, got.Suppressed)
	}
	if got := sn.CheckRelease("/opt/jre", releaseFixture(t, "jenkins-jlink21"), []string{" " + strings.ToLower(sev)}); len(got.Suppressed) != 1 {
		t.Errorf("Suppressed with %s = %v", sev, got.Suppressed)
	}
}

func TestCheckRelease_ModulesDropOnlyKnownComponents(t *testing.T) {
	sn := fixtureSnapshot(t)
	// 21.0.12 is affected by CVEs of many components.
	content := withVersion(t, "jlink-java-base", "21.0.13.1", "21.0.12")
	got := sn.CheckRelease("/opt/jre", content, allSeverities)
	if !got.Checked || got.Version != "21.0.12" {
		t.Fatalf("check = %+v", got)
	}
	res := sn.match(VendorUnknown, mustVersion(t, "21.0.12"))
	dropped := map[string]bool{}
	for _, id := range got.ModuleDropped {
		dropped[id] = true
	}
	var twoD, jgss bool
	for _, a := range res.advisories {
		comp := res.components[a.VulnID]
		_, mapped := moduleOf(comp)
		if mapped != dropped[a.VulnID] {
			t.Errorf("%s (%s): mapped %v, dropped %v", a.VulnID, comp, mapped, dropped[a.VulnID])
		}
		if _, kept := find(got.Advisories, a.VulnID); kept == dropped[a.VulnID] {
			t.Errorf("%s (%s) is both kept and dropped or neither", a.VulnID, comp)
		}
		twoD = twoD || (strings.HasPrefix(comp, "client-libs/2d") && dropped[a.VulnID])
		jgss = jgss || (comp == "security-libs/org.ietf.jgss" && dropped[a.VulnID])
	}
	if !jgss {
		t.Error("no org.ietf.jgss CVE was dropped")
	}
	// The recorded advisories have client-libs/2d CVEs only for older builds.
	old := sn.CheckRelease("/opt/jre", withVersion(t, "jlink-java-base", "21.0.13.1", "21.0.1"), allSeverities)
	res = sn.match(VendorUnknown, mustVersion(t, "21.0.1"))
	for _, a := range res.advisories {
		if strings.HasPrefix(res.components[a.VulnID], "client-libs/2d") {
			if !contains(old.ModuleDropped, a.VulnID) {
				t.Errorf("%s (client-libs/2d) not dropped", a.VulnID)
			}
			twoD = true
		}
	}
	if !twoD {
		t.Fatal("the fixtures have no client-libs/2d CVE for the versions tried")
	}
	for _, id := range []string{"CVE-2026-114938", "CVE-2026-61308"} { // hotspot, core-libs/java.net
		if _, ok := find(got.Advisories, id); !ok {
			t.Errorf("%s was dropped", id)
		}
	}
	if len(got.Suppressed) != 0 {
		t.Errorf("module drops are reported as suppressed: %v", got.Suppressed)
	}
}

func TestCheckRelease_ModulesPresentKeepsEverythingElse(t *testing.T) {
	sn := fixtureSnapshot(t)
	// A release with the full module list drops nothing.
	got := sn.CheckRelease("/opt/jre", releaseFixture(t, "jenkins-jlink21"), allSeverities)
	if len(got.ModuleDropped) != 0 {
		t.Errorf("ModuleDropped = %v", got.ModuleDropped)
	}
	// Without a MODULES line nothing is dropped either.
	noMods := "JAVA_VERSION=\"21.0.12\"\n"
	if got := sn.CheckRelease("/opt/jre", []byte(noMods), allSeverities); len(got.ModuleDropped) != 0 {
		t.Errorf("ModuleDropped = %v", got.ModuleDropped)
	}
	// An empty MODULES line drops every CVE of a known module.
	if got := sn.CheckRelease("/opt/jre", []byte(noMods+"MODULES=\"\"\n"), allSeverities); len(got.ModuleDropped) == 0 {
		t.Error("an empty MODULES drops nothing")
	}
}

func TestModuleOf(t *testing.T) {
	for comp, want := range map[string]string{
		"client-libs/2d":                 "java.desktop",
		"client-libs/java.awt":           "java.desktop",
		"xml/jaxp":                       "java.xml",
		"security-libs/org.ietf.jgss":    "java.security.jgss",
		"security-libs/javax.xml.crypto": "java.xml.crypto",
		"core-libs/javax.naming":         "java.naming",
		"core-libs/javax.script":         "java.scripting",
		"core-libs/java.rmi":             "java.rmi",
		"core-libs/java.sql":             "java.sql",
		"core-svc/java.lang.management":  "java.management",
		"tools/javadoc(tool)":            "jdk.javadoc",
		"tools/jlink":                    "jdk.jlink",
		"tools/jshell":                   "jdk.jshell",
		"core-libs/java.net":             "",
		"hotspot/compiler":               "",
		"core-svc":                       "",
		"client-libs":                    "",
		"xml/jaxp/extra":                 "",
	} {
		got, ok := moduleOf(comp)
		if got != want || ok != (want != "") {
			t.Errorf("moduleOf(%q) = %q, %v", comp, got, ok)
		}
	}
}

func TestCheckRelease_TemurinMatchesStageOne(t *testing.T) {
	sn := fixtureSnapshot(t)
	for _, tt := range []struct{ fixture, from, to string }{
		{"temurin21", "21.0.13.1", "21.0.13.1"},
		{"temurin21", "21.0.13.1", "21.0.12"},
		{"temurin21", "21.0.13.1", "21.0.10"},
		{"temurin8", "1.8.0_512", "1.8.0_512"},
		{"temurin8", "1.8.0_512", "1.8.0_400"},
	} {
		got := sn.CheckRelease("/opt/java/openjdk", withVersion(t, tt.fixture, tt.from, tt.to), allSeverities)
		if got.Vendor != VendorTemurin {
			t.Fatalf("%s %s: vendor %q", tt.fixture, tt.to, got.Vendor)
		}
		// The temurin fixtures carry a full module list that has every
		// module of the JDK, so nothing is dropped.
		if len(got.ModuleDropped) != 0 && tt.fixture == "temurin21" {
			t.Errorf("%s: ModuleDropped %v", tt.to, got.ModuleDropped)
		}
		v, _ := parseJavaVersion(tt.to)
		want := sn.Match(VendorTemurin, v)
		if len(got.Advisories) != len(want) && tt.fixture == "temurin8" {
			t.Errorf("%s: %d advisories, stage one %d", tt.to, len(got.Advisories), len(want))
		}
		if tt.fixture == "temurin21" {
			kept := map[string]bool{}
			for _, a := range got.Advisories {
				kept[a.VulnID] = true
			}
			for _, a := range want {
				if !kept[a.VulnID] && !contains(got.ModuleDropped, a.VulnID) {
					t.Errorf("%s: %s missing", tt.to, a.VulnID)
				}
				if a2, ok := find(got.Advisories, a.VulnID); ok && a2 != a {
					t.Errorf("%s: %s = %+v, stage one %+v", tt.to, a.VulnID, a2, a)
				}
			}
		} else if !reflect.DeepEqual(got.Advisories, want) {
			t.Errorf("%s: advisories differ from stage one", tt.to)
		}
		if len(got.Suppressed) != 0 {
			t.Errorf("%s: Suppressed %v", tt.to, got.Suppressed)
		}
	}
	// With the module filter out of the way the results are identical.
	content := []byte("IMPLEMENTOR=\"Eclipse Adoptium\"\nJAVA_VERSION=\"21.0.12\"\n")
	got := sn.CheckRelease("/opt/java/openjdk", content, allSeverities)
	if want := sn.Match(VendorTemurin, mustVersion(t, "21.0.12")); !reflect.DeepEqual(got.Advisories, want) {
		t.Errorf("Temurin 21.0.12 differs from stage one: %v vs %v", ids(got.Advisories), ids(want))
	}
}

func TestMatch_OracleOpenJDKHasNoExceptions(t *testing.T) {
	sn := fixtureSnapshot(t)
	v := mustVersion(t, "21.0.13")
	if _, ok := find(sn.Match(VendorTemurin, v), "CVE-2026-114820"); ok {
		t.Error("Temurin 21.0.13 reports the exception CVE")
	}
	for _, vendor := range []Vendor{VendorOracleOpenJDK, VendorUnknown} {
		_, ok := find(sn.Match(vendor, v), "CVE-2026-114820")
		if vendor == VendorOracleOpenJDK && !ok {
			t.Error("Oracle OpenJDK 21.0.13 does not report the CVE")
		}
		if vendor == VendorUnknown && ok {
			t.Error("a vendor-less JDK reports the CVE the vendor exception splits")
		}
	}
}

func TestCheckRelease_UncheckedLineAndBadContent(t *testing.T) {
	sn := fixtureSnapshot(t)
	if got := sn.CheckRelease("/opt/jdk", make([]byte, maxReleaseSize+1), allSeverities); got.Checked {
		t.Error("oversize content checked")
	}
	if got := sn.CheckRelease("/opt/jdk", nil, allSeverities); got.Checked || got.Reason == "" {
		t.Errorf("empty content = %+v", got)
	}
}

// A MODULES list cut at the bound is not the whole set: no CVE is dropped as
// belonging to a module that is "absent" from it.
func TestCheckRelease_TruncatedModulesDropNothing(t *testing.T) {
	sn := fixtureSnapshot(t)
	base := "JAVA_VERSION=\"21.0.12\"\n"
	var fillers []string
	for i := 0; i < maxReleaseModules; i++ {
		fillers = append(fillers, fmt.Sprintf("x.m%d", i))
	}
	// The modules that matter come after the bound.
	long := base + "MODULES=\"" + strings.Join(fillers, " ") + " java.desktop java.xml java.naming\"\n"
	rel, err := ParseRelease([]byte(long))
	if err != nil || !rel.ModulesTruncated || len(rel.Modules) != maxReleaseModules {
		t.Fatalf("release: truncated %v, %d modules, %v", rel.ModulesTruncated, len(rel.Modules), err)
	}
	if got := sn.CheckRelease("/opt/jre", []byte(long), allSeverities); len(got.ModuleDropped) != 0 {
		t.Errorf("ModuleDropped = %v for a truncated list", got.ModuleDropped)
	}
	// The same list kept whole does drop (the control).
	short := base + "MODULES=\"" + strings.Join(fillers[:10], " ") + "\"\n"
	if got := sn.CheckRelease("/opt/jre", []byte(short), allSeverities); len(got.ModuleDropped) == 0 {
		t.Error("a short list drops nothing")
	}
}

// The version the image reader detects a JDK by is the one the check reads:
// the last assignment wins in both.
func TestParseRelease_DuplicateJavaVersionLastWins(t *testing.T) {
	content := "JAVA_VERSION=\"1.8.0_402\"\nJAVA_VERSION=\"21.0.13\"\n"
	r, _ := ParseRelease([]byte(content))
	got, _ := imagefs.ReleaseValue(content, "JAVA_VERSION")
	if r.JavaVersion != "21.0.13" || got != r.JavaVersion {
		t.Errorf("ParseRelease %q, ReleaseValue %q", r.JavaVersion, got)
	}
}
