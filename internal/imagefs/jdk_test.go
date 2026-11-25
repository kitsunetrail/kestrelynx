package imagefs

import (
	"errors"
	"strings"
	"testing"
)

func jdkFiles(dirName, release string, extra ...fe) []fe {
	out := []fe{
		file(dirName+"/release", release),
		file(dirName+"/lib/modules", "image"),
		file(dirName+"/bin/java", "elf"),
		file(dirName+"/lib/server/libjvm.so", "so"),
	}
	return append(out, extra...)
}

func TestFindJDKsZuluWithSymlinks(t *testing.T) {
	base := []fe{file("etc/os-release", "ID=ubuntu")}
	jdk := append(jdkFiles("usr/lib/jvm/zulu21-ca-amd64", releaseZulu21),
		sym("usr/lib/jvm/zulu21", "zulu21-ca-amd64"),
		dir("etc/alternatives"),
		sym("etc/alternatives/java", "/usr/lib/jvm/zulu21/bin/java"),
		sym("usr/bin/java", "/etc/alternatives/java"),
	)
	v := overlayOf(t, base, jdk)
	jdks, err := v.FindJDKs()
	if err != nil || len(jdks) != 1 {
		t.Fatalf("jdks %+v err %v", jdks, err)
	}
	j := jdks[0]
	if j.Dir != "usr/lib/jvm/zulu21-ca-amd64" || j.Release != releaseZulu21 {
		t.Errorf("dir %q", j.Dir)
	}
	if len(j.Executables) != 1 || !j.Executables[0].Known || j.Executables[0].Path != "usr/lib/jvm/zulu21-ca-amd64/bin/java" {
		t.Errorf("executables %+v", j.Executables)
	}
	if j.MixedLayers || j.LayerDiffID != v.layers[1] {
		t.Errorf("layer %q mixed=%v, want %q", j.LayerDiffID, j.MixedLayers, v.layers[1])
	}
	// JAVA_HOME can be resolved by the caller.
	r, err := v.ResolvePath("/usr/lib/jvm/zulu21")
	if err != nil || r.Path != j.Dir {
		t.Errorf("JAVA_HOME resolves to %+v %v", r, err)
	}
}

func TestFindJDKsCorretto8(t *testing.T) {
	v := overlayOf(t, []fe{
		file("usr/lib/jvm/java-1.8.0-amazon-corretto.x86_64/release", releaseCorretto8),
		file("usr/lib/jvm/java-1.8.0-amazon-corretto.x86_64/jre/lib/rt.jar", "jar"),
		file("usr/lib/jvm/java-1.8.0-amazon-corretto.x86_64/bin/java", "elf"),
		file("usr/lib/jvm/java-1.8.0-amazon-corretto.x86_64/jre/bin/java", "elf"),
		file("usr/lib/jvm/java-1.8.0-amazon-corretto.x86_64/jre/lib/amd64/server/libjvm.so", "so"),
	})
	jdks, err := v.FindJDKs()
	if err != nil || len(jdks) != 1 {
		t.Fatalf("%+v %v", jdks, err)
	}
	if got := len(jdks[0].Executables); got != 2 {
		t.Errorf("executables %+v, want bin/java and jre/bin/java", jdks[0].Executables)
	}
	if jdks[0].MixedLayers || jdks[0].LayerDiffID == "" {
		t.Errorf("layer %+v", jdks[0])
	}
}

func TestFindJDKsConditions(t *testing.T) {
	cases := map[string][]fe{
		"no modules or rt.jar":     {file("j/release", releaseTemurin21), file("j/bin/java", "x")},
		"no JAVA_VERSION":          {file("j/release", "IMPLEMENTOR=\"x\"\n"), file("j/lib/modules", "m")},
		"release is a symlink":     {file("real/release", releaseTemurin21), sym("j/release", "/real/release"), file("j/lib/modules", "m")},
		"modules is a directory":   {file("j/release", releaseTemurin21), dir("j/lib/modules")},
		"release over 16 KiB":      {file("j/release", releaseTemurin21+"#"+strings.Repeat("x", 16<<10)), file("j/lib/modules", "m")},
		"release is a directory":   {dir("j/release"), file("j/lib/modules", "m")},
		"lib/modules in another d": {file("j/release", releaseTemurin21), file("k/lib/modules", "m")},
	}
	for name, entries := range cases {
		jdks, err := overlayOf(t, entries).FindJDKs()
		if err != nil || len(jdks) != 0 {
			t.Errorf("%s: %+v %v", name, jdks, err)
		}
	}
	// A JAVA_VERSION line must be a line of its own.
	jdks, _ := overlayOf(t, []fe{file("j/release", "X_JAVA_VERSION=\"1\"\n"), file("j/lib/modules", "m")}).FindJDKs()
	if len(jdks) != 0 {
		t.Errorf("X_JAVA_VERSION counted")
	}
}

func TestFindJDKsTwoJDKsAndOverwrittenRelease(t *testing.T) {
	v := overlayOf(t,
		append(jdkFiles("opt/a", releaseTemurin21), jdkFiles("opt/b", releaseTemurin21)...),
		[]fe{file("opt/b/release", strings.Repeat("z", 16<<10+1))}, // not a release any more
	)
	jdks, err := v.FindJDKs()
	if err != nil || len(jdks) != 1 || jdks[0].Dir != "opt/a" {
		t.Fatalf("%+v %v", jdks, err)
	}
}

func TestFindJDKsLayerOfTheJDK(t *testing.T) {
	// Same layer for everything: that layer. Written over in a later layer: mixed.
	v := overlayOf(t, []fe{file("x", "1")}, jdkFiles("opt/j", releaseTemurin21), []fe{file("y", "1")})
	jdks, _ := v.FindJDKs()
	if len(jdks) != 1 || jdks[0].MixedLayers || jdks[0].LayerDiffID != v.layers[1] {
		t.Errorf("one layer: %+v want %s", jdks, v.layers[1])
	}
	for name, patch := range map[string]fe{
		"release rewritten":  file("opt/j/release", releaseTemurin21),
		"modules rewritten":  file("opt/j/lib/modules", "other"),
		"launcher rewritten": file("opt/j/bin/java", "other"),
		"libjvm rewritten":   file("opt/j/lib/server/libjvm.so", "other"),
	} {
		v := overlayOf(t, jdkFiles("opt/j", releaseTemurin21), []fe{patch})
		jdks, _ := v.FindJDKs()
		if len(jdks) != 1 || !jdks[0].MixedLayers || jdks[0].LayerDiffID != "" {
			t.Errorf("%s: %+v, want mixed layers", name, jdks)
		}
	}
}

func TestFindJDKsExecutablePaths(t *testing.T) {
	// bin/java as an alternatives chain, and as a broken link, and a loop.
	for name, tc := range map[string]struct {
		extra []fe
		known bool
		path  string
	}{
		"alternatives chain": {[]fe{dir("etc/alternatives"), sym("opt/j/bin/java", "/etc/alternatives/java"), sym("etc/alternatives/java", "/opt/real/bin/java"), file("opt/real/bin/java", "elf")}, true, "opt/real/bin/java"},
		"dangling":           {[]fe{sym("opt/j/bin/java", "/nowhere/java")}, false, ""},
		"loop":               {[]fe{sym("opt/j/bin/java", "java")}, false, ""},
		"escape":             {[]fe{sym("opt/j/bin/java", "../../../../x")}, false, ""},
	} {
		entries := []fe{file("opt/j/release", releaseTemurin21), file("opt/j/lib/modules", "m")}
		entries = append(entries, tc.extra...)
		jdks, err := overlayOf(t, entries).FindJDKs()
		if err != nil || len(jdks) != 1 || len(jdks[0].Executables) != 1 {
			t.Fatalf("%s: %+v %v", name, jdks, err)
		}
		e := jdks[0].Executables[0]
		if e.Known != tc.known || e.Path != tc.path || e.Declared != "opt/j/bin/java" {
			t.Errorf("%s: %+v", name, e)
		}
	}
}

func TestFindJDKsHardlinkedRelease(t *testing.T) {
	good := overlayOf(t, []fe{
		file("opt/j/release", releaseTemurin21), hard("opt/k/release", "opt/j/release"),
		file("opt/j/lib/modules", "m"), file("opt/k/lib/modules", "m"),
	})
	jdks, err := good.FindJDKs()
	if err != nil || len(jdks) != 2 || jdks[1].Release != releaseTemurin21 {
		t.Errorf("readable hardlink: %+v %v", jdks, err)
	}
	bad := overlayOf(t, []fe{
		file("opt/j/other", releaseTemurin21), hard("opt/j/release", "opt/j/other"), file("opt/j/lib/modules", "m"),
	})
	if _, err := bad.FindJDKs(); !errors.Is(err, ErrReleaseUnreadable) {
		t.Errorf("unreadable hardlink: %v", err)
	}
	// An unreadable release that is not in a JDK is not an error.
	other := overlayOf(t, []fe{file("srv/x", "1"), hard("srv/release", "srv/x")})
	if jdks, err := other.FindJDKs(); err != nil || len(jdks) != 0 {
		t.Errorf("unrelated: %+v %v", jdks, err)
	}
}

func TestFindJDKsJavaHomeLinkReplacedByDirectory(t *testing.T) {
	// A symlink to the JDK that a later layer turns into an empty directory
	// must not make the JDK appear at the link's place.
	v := overlayOf(t,
		jdkFiles("opt/j", releaseTemurin21),
		[]fe{sym("opt/java", "j")},
		[]fe{dir("opt/java")},
	)
	jdks, err := v.FindJDKs()
	if err != nil || len(jdks) != 1 || jdks[0].Dir != "opt/j" {
		t.Fatalf("%+v %v", jdks, err)
	}
	if r, err := v.ResolvePath("opt/java"); err != nil || r.Path != "opt/java" || r.Type != TypeDir {
		t.Errorf("opt/java: %+v %v", r, err)
	}
}

// The module image that counts is the one of the release's series.
func TestFindJDKsSeriesMarkers(t *testing.T) {
	cases := map[string]struct {
		release string
		files   []fe
		found   bool
	}{
		"21 with lib/modules":             {releaseTemurin21, []fe{file("j/lib/modules", "m")}, true},
		"21 with only an old rt.jar":      {releaseTemurin21, []fe{file("j/lib/rt.jar", "jar")}, false},
		"21 with only jre/lib/rt.jar":     {releaseTemurin21, []fe{file("j/jre/lib/rt.jar", "jar")}, false},
		"8 with lib/rt.jar":               {releaseCorretto8, []fe{file("j/lib/rt.jar", "jar")}, true},
		"8 with jre/lib/rt.jar":           {releaseCorretto8, []fe{file("j/jre/lib/rt.jar", "jar")}, true},
		"8 with only lib/modules":         {releaseCorretto8, []fe{file("j/lib/modules", "m")}, false},
		"8 with both":                     {releaseCorretto8, []fe{file("j/lib/modules", "m"), file("j/lib/rt.jar", "jar")}, true},
		"21 with both":                    {releaseTemurin21, []fe{file("j/lib/modules", "m"), file("j/lib/rt.jar", "jar")}, true},
		"11 by a bare major":              {"JAVA_VERSION=\"11\"\n", []fe{file("j/lib/modules", "m")}, true},
		"11 with only rt.jar":             {"JAVA_VERSION=\"11\"\n", []fe{file("j/lib/rt.jar", "jar")}, false},
		"9 early access with lib/modules": {"JAVA_VERSION=\"9-ea\"\n", []fe{file("j/lib/modules", "m")}, true},
	}
	for name, tc := range cases {
		entries := append([]fe{file("j/release", tc.release)}, tc.files...)
		jdks, err := overlayOf(t, entries).FindJDKs()
		if err != nil || (len(jdks) == 1) != tc.found || len(jdks) > 1 {
			t.Errorf("%s: %+v %v, want found=%v", name, jdks, err, tc.found)
		}
	}
}

// The file that is the marker of the series is the one whose layer counts.
func TestFindJDKsLayerUsesTheAdoptedMarker(t *testing.T) {
	for name, tc := range map[string]struct {
		release string
		first   []fe
		patch   fe
		mixed   bool
	}{
		"8: lib/modules rewritten does not matter": {releaseCorretto8, []fe{file("j/release", releaseCorretto8), file("j/lib/modules", "m"), file("j/lib/rt.jar", "jar")}, file("j/lib/modules", "x"), false},
		"8: rt.jar rewritten":                      {releaseCorretto8, []fe{file("j/release", releaseCorretto8), file("j/lib/modules", "m"), file("j/lib/rt.jar", "jar")}, file("j/lib/rt.jar", "x"), true},
		"21: rt.jar rewritten does not matter":     {releaseTemurin21, []fe{file("j/release", releaseTemurin21), file("j/lib/modules", "m"), file("j/lib/rt.jar", "jar")}, file("j/lib/rt.jar", "x"), false},
		"21: modules rewritten":                    {releaseTemurin21, []fe{file("j/release", releaseTemurin21), file("j/lib/modules", "m"), file("j/lib/rt.jar", "jar")}, file("j/lib/modules", "x"), true},
	} {
		jdks, err := overlayOf(t, tc.first, []fe{tc.patch}).FindJDKs()
		if err != nil || len(jdks) != 1 || jdks[0].MixedLayers != tc.mixed {
			t.Errorf("%s: %+v %v, want mixed=%v", name, jdks, err, tc.mixed)
		}
	}
}

// A link and what it points to are both written by some layer; a layer that
// replaces only the target makes the JDK's layer mixed.
func TestFindJDKsLayerOfLinkTargets(t *testing.T) {
	base := []fe{
		file("opt/j/release", releaseTemurin21), file("opt/j/lib/modules", "m"),
		sym("opt/j/bin/java", "/opt/real/bin/java"), file("opt/real/bin/java", "elf"),
		sym("opt/j/lib/server/libjvm.so", "/opt/real/libjvm.so"), file("opt/real/libjvm.so", "so"),
	}
	jdks, err := overlayOf(t, base).FindJDKs()
	if err != nil || len(jdks) != 1 || jdks[0].MixedLayers || jdks[0].LayerDiffID == "" {
		t.Fatalf("one layer: %+v %v", jdks, err)
	}
	for name, patch := range map[string]fe{
		"launcher target replaced": file("opt/real/bin/java", "other"),
		"libjvm target replaced":   file("opt/real/libjvm.so", "other"),
	} {
		jdks, err := overlayOf(t, base, []fe{patch}).FindJDKs()
		if err != nil || len(jdks) != 1 || !jdks[0].MixedLayers || jdks[0].LayerDiffID != "" {
			t.Errorf("%s: %+v %v, want mixed layers", name, jdks, err)
		}
	}
	// A link that cannot be resolved leaves the layer undetermined.
	dangling := []fe{file("opt/j/release", releaseTemurin21), file("opt/j/lib/modules", "m"), sym("opt/j/bin/java", "/nowhere/java")}
	jdks, _ = overlayOf(t, dangling).FindJDKs()
	if len(jdks) != 1 || !jdks[0].MixedLayers || jdks[0].LayerDiffID != "" {
		t.Errorf("dangling launcher: %+v", jdks)
	}
}

// With JAVA_VERSION assigned twice the last one decides the series, as when
// the release is checked against advisories.
func TestFindJDKsDuplicateJavaVersionLastWins(t *testing.T) {
	eightThen21 := "JAVA_VERSION=\"1.8.0_402\"\nJAVA_VERSION=\"21.0.13\"\n"
	twentyOneThen8 := "JAVA_VERSION=\"21.0.13\"\nJAVA_VERSION=\"1.8.0_402\"\n"
	jdks, err := overlayOf(t, []fe{file("j/release", eightThen21), file("j/lib/modules", "m")}).FindJDKs()
	if err != nil || len(jdks) != 1 {
		t.Errorf("8 then 21 with lib/modules: %+v %v", jdks, err)
	}
	jdks, _ = overlayOf(t, []fe{file("j/release", eightThen21), file("j/lib/rt.jar", "jar")}).FindJDKs()
	if len(jdks) != 0 {
		t.Errorf("8 then 21 with only rt.jar: %+v", jdks)
	}
	jdks, _ = overlayOf(t, []fe{file("j/release", twentyOneThen8), file("j/lib/rt.jar", "jar")}).FindJDKs()
	if len(jdks) != 1 {
		t.Errorf("21 then 8 with rt.jar: %+v", jdks)
	}
	jdks, _ = overlayOf(t, []fe{file("j/release", twentyOneThen8), file("j/lib/modules", "m")}).FindJDKs()
	if len(jdks) != 0 {
		t.Errorf("21 then 8 with only lib/modules: %+v", jdks)
	}
}
