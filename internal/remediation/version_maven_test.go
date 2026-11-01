package remediation

import (
	"sort"
	"strings"
	"testing"
)

// The expected results are those of Maven's ComparableVersion, which
// go-mvn-version (used by Trivy) agrees with.
var mavenCompareVectors = []struct {
	a, b string
	want int
}{
	// pairs checked against go-mvn-version
	{"2.13.4.2", "2.13.4", 1},
	{"32.0.0-android", "30.0-jre", 1},
	{"32.0.0-android", "32.0.0-jre", -1},
	{"33.7.2", "33.7.2-jre", -1},
	{"5.2.24.RELEASE", "5.3.20", -1},
	{"5.2.24.RELEASE", "5.2.24", 0},
	{"11.0.0-M11", "11.0.0", -1},
	{"11.0.0-M11", "10.1.16", 1},
	{"4.1.71.Final", "4.1.68.Final", 1},
	{"4.1.68.Final", "4.1.68", 0},
	{"9999.0-empty-to-avoid-conflict-with-guava", "1.0", 1},
	{"1.0-SNAPSHOT", "1.0", -1},
	{"1.0-rc1", "1.0", -1},
	{"2.12.7.1", "2.13.3", -1},
	// pairs checked against Maven's ComparableVersion
	{"30.0-jre", "32.0.0-jre", -1},
	{"32.0.0-jre", "32.0.0-android", 1},
	{"32.0.0-android", "33.7.2", -1},
	{"33.7.2", "33.7.2-jre", -1},
	{"33.7.2-jre", "5.2.24.RELEASE", 1},
	{"5.2.24.RELEASE", "5.2.24", 0},
	{"5.2.24", "5.3.20", -1},
	{"5.3.20", "11.0.0-M11", -1},
	{"11.0.0-M11", "11.0.0", -1},
	{"11.0.0", "10.1.16", 1},
	{"10.1.16", "4.1.68", 1},
	{"4.1.68", "4.1.68.Final", 0},
	{"4.1.68.Final", "1.0-SNAPSHOT", 1},
	{"1.0-SNAPSHOT", "1.0-rc1", 1},
	{"1.0-rc1", "1.0", -1},
	{"1.0", "2.13.4", -1},
	{"2.13.4", "2.13.4.2", -1},
	// qualifier order and aliases
	{"1.0-alpha1", "1.0-beta1", -1},
	{"1.0-beta1", "1.0-milestone1", -1},
	{"1.0-milestone1", "1.0-rc1", -1},
	{"1.0-rc1", "1.0-snapshot", -1},
	{"1.0-snapshot", "1.0", -1},
	{"1.0", "1.0-sp1", -1},
	{"1.0-a1", "1.0-alpha-1", 0},
	{"1.0-b2", "1.0-beta-2", 0},
	{"1.0-m3", "1.0-milestone-3", 0},
	{"1.0-cr1", "1.0-rc1", 0},
	{"1.0-ga", "1.0", 0},
	{"1.0-final", "1.0", 0},
	{"1.0-release", "1.0", 0},
	{"1.0.0", "1", 0},
	{"1.0-foo", "1.0", 1},
	{"1.0-foo", "1.0-sp1", 1},
	{"1.0-abc", "1.0-abd", -1},
	{"1.0.1", "1.0-1", 1},
	{"1.0.0.X1", "1.0.0-X2", -1},
	{"1-1", "1.1", -1},
	{"1.0.0000000000000000000000001", "1.0.1", 0},
	{"1.10", "1.9", 1},
	{"01.1", "1.1", 0},
}

func TestMavenVersionVectors(t *testing.T) {
	for _, v := range mavenCompareVectors {
		got, ok := compareVersions(schemeMaven, v.a, v.b)
		if !ok {
			t.Errorf("%q vs %q: does not parse", v.a, v.b)
			continue
		}
		if got != v.want {
			t.Errorf("%q vs %q = %d, want %d", v.a, v.b, got, v.want)
		}
		back, _ := compareVersions(schemeMaven, v.b, v.a)
		if back != -v.want {
			t.Errorf("%q vs %q = %d, want %d (reverse)", v.b, v.a, back, -v.want)
		}
	}
}

func TestMavenVersionParse(t *testing.T) {
	for _, s := range []string{"1", "1.0", "x", "1.0-SNAPSHOT", "11.0.0-M11", "5.2.24.RELEASE", "a.b.c", "1..2", "-1", "1-", "ä1"} {
		if _, ok := parseVersion(schemeMaven, s); !ok {
			t.Errorf("%q should parse", s)
		}
	}
	for _, s := range []string{"", " ", "1 0", "1.0\n", "1\t", "1\x00", "\xff", strings.Repeat("1", 129)} {
		if _, ok := parseVersion(schemeMaven, s); ok {
			t.Errorf("%q should not parse", s)
		}
	}
	if _, ok := parseVersion(schemeMaven, strings.Repeat("1", 128)); !ok {
		t.Error("128 bytes should parse")
	}
	if c, ok := compareVersions(schemeMaven, "1.0", ""); ok || c != 0 {
		t.Error("an empty version must not compare")
	}
}

// Real FixedVersion strings Trivy reports for Java packages.
var mavenFixedTokens = []string{
	"11.0.0-M11", "11.0.0-M12", "11.0.0-M17", "11.0.0-M21", "11.0.0-M5",
	"32.0.0-android", "4.1.108.Final", "4.1.115.Final", "4.1.118.Final",
	"4.1.125.Final", "4.1.129.Final", "4.1.132.Final", "4.1.133.Final",
	"4.1.135.Final", "4.1.136.Final", "4.1.137.Final", "4.1.71.Final",
	"4.1.77.Final", "4.1.94.Final", "4.2.10.Final", "4.2.13.Final",
	"4.2.15.Final", "4.2.16.Final", "4.2.17.Final", "4.2.5.Final",
	"4.2.8.Final", "5.2.23.RELEASE", "5.2.24.RELEASE",
	"1.3.12", "1.4.12", "1.2.13", "1.5.19", "10.1.14", "9.0.81", "8.5.94",
	"10.1.16", "9.0.83", "11.0.10", "33.7.2", "33.7.2-jre", "2.13.4.2",
}

func TestMavenFixedTokensOrderIsConsistent(t *testing.T) {
	cmp := func(a, b string) int {
		c, ok := compareVersions(schemeMaven, a, b)
		if !ok {
			t.Fatalf("%q or %q does not parse", a, b)
		}
		return c
	}
	for _, a := range mavenFixedTokens {
		if cmp(a, a) != 0 {
			t.Errorf("%q is not equal to itself", a)
		}
		for _, b := range mavenFixedTokens {
			if cmp(a, b) != -cmp(b, a) {
				t.Errorf("%q vs %q is not antisymmetric", a, b)
			}
			for _, c := range mavenFixedTokens {
				if cmp(a, b) <= 0 && cmp(b, c) <= 0 && cmp(a, c) > 0 {
					t.Errorf("not transitive: %q <= %q <= %q but %q > %q", a, b, c, a, c)
				}
			}
		}
	}
	// A sort in either input order gives the same result.
	fwd := append([]string(nil), mavenFixedTokens...)
	rev := make([]string, len(fwd))
	for i, s := range fwd {
		rev[len(fwd)-1-i] = s
	}
	less := func(s []string) func(i, j int) bool {
		return func(i, j int) bool { return cmp(s[i], s[j]) < 0 }
	}
	sort.SliceStable(fwd, less(fwd))
	sort.SliceStable(rev, less(rev))
	for i := range fwd {
		if cmp(fwd[i], rev[i]) != 0 {
			t.Errorf("sort position %d differs: %q vs %q", i, fwd[i], rev[i])
		}
	}
	if fwd[0] != "1.2.13" || fwd[len(fwd)-1] != "33.7.2-jre" {
		t.Errorf("unexpected ends: %q ... %q", fwd[0], fwd[len(fwd)-1])
	}
}

func TestMavenIsPrerelease(t *testing.T) {
	for s, want := range map[string]bool{
		"11.0.0-M11":     true,
		"1.0-rc1":        true,
		"1.0-RC1":        true,
		"1.0-cr1":        true,
		"1.0-SNAPSHOT":   true,
		"1.0-alpha":      true,
		"1.0-beta-2":     true,
		"1.0-milestone1": true,
		"1.0-a1":         true,
		"1.0-b1":         true,
		"2.0.0.Beta1":    true,
		"5.2.24.RELEASE": false,
		"4.1.68.Final":   false,
		"32.0.0-jre":     false,
		"32.0.0-android": false,
		"2.13.4.2":       false,
		"1.0":            false,
		"1.0-sp1":        false,
		"1.0-ga":         false,
		"":               false,
	} {
		if got := mavenIsPrerelease(s); got != want {
			t.Errorf("mavenIsPrerelease(%q) = %v, want %v", s, got, want)
		}
	}
}

func TestMavenMajor(t *testing.T) {
	for s, want := range map[string]string{
		"10.1.16": "10", "5.2.24.RELEASE": "5", "007.1": "7", "0.9": "0", "11.0.0-M11": "11", "2": "2",
	} {
		got, ok := mavenMajor(s)
		if !ok || got != want {
			t.Errorf("mavenMajor(%q) = %q, %v; want %q", s, got, ok, want)
		}
	}
	for _, s := range []string{"", "v1.0", "abc", "-1", ".1"} {
		if got, ok := mavenMajor(s); ok {
			t.Errorf("mavenMajor(%q) = %q, want not ok", s, got)
		}
	}
}

func TestMavenFlavor(t *testing.T) {
	for s, want := range map[string]string{
		"31.1-jre":       "jre",
		"32.0.0-android": "android",
		"32.0.0-JRE":     "jre",
		"4.1.68.Final":   "",
		"1.0-rc1":        "",
		"2.13.4.2":       "",
		"1.0":            "",
		"1.0-SNAPSHOT":   "",
		"1.0-alpha":      "",
		"1.0-final":      "",
		"1.0-sp":         "",
		"1.0-jre1":       "",
		"1.0-":           "",
		"-jre":           "",
	} {
		if got := mavenFlavor(s); got != want {
			t.Errorf("mavenFlavor(%q) = %q, want %q", s, got, want)
		}
	}
}
