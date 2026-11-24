package javacore

import "testing"

func TestParseVersion(t *testing.T) {
	good := map[string]string{
		"21.0.13.1":  "21.0.13.1",
		"27":         "27",
		"27.0.1.0.2": "27.0.1.0.2",
		"11.0.2":     "11.0.2",
		"8u512":      "8u512",
		"7u211":      "7u211",
		"9.0.4":      "9.0.4",
	}
	for in, want := range good {
		v, ok := parseVersion(in)
		if !ok {
			t.Errorf("parseVersion(%q) failed", in)
			continue
		}
		if v.String() != want {
			t.Errorf("parseVersion(%q).String() = %q", in, v.String())
		}
	}
	for _, in := range []string{
		"", "8", "8.0.512", "1.8.0_512", "21.0.13.1.1.1.1", "21.00.1", "21.0.", ".21", "21..1", "v21", "21.0.13+9",
		"8u", "8u0", "8u0512", "6u45", "9u1", "21.0.1234567890", "21-ea", "-21", "21.0.13 ",
	} {
		if v, ok := parseVersion(in); ok {
			t.Errorf("parseVersion(%q) = %v, want failure", in, v)
		}
	}
}

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
		ok   bool
	}{
		{"21.0.13", "21.0.13.0", 0, true},
		{"21.0.13.0.3", "21.0.13.1", -1, true},
		{"21.0.13.1", "21.0.13.0.3", 1, true},
		{"21.0.13.0.2", "21.0.13.0.3", -1, true},
		{"27", "27.0.1", -1, true},
		{"27.0.10", "27.0.9", 1, true},
		{"8u512", "8u514", -1, true},
		{"8u514", "8u514", 0, true},
		{"11.0.8", "8u512", 0, false},
		{"21.0.13", "25.0.1", 0, false},
	}
	for _, c := range cases {
		got, ok := mustVersion(t, c.a).compare(mustVersion(t, c.b))
		if got != c.want || ok != c.ok {
			t.Errorf("compare(%s, %s) = %d, %v; want %d, %v", c.a, c.b, got, ok, c.want, c.ok)
		}
	}
	if mustVersion(t, "21.0.13").atMost(mustVersion(t, "25.0.1")) {
		t.Error("versions of different lines are not ordered")
	}
}

func TestParseReleaseVersion(t *testing.T) {
	good := map[string]string{
		"21.0.13.1+2-LTS": "21.0.13.1",
		"21.0.13+9-LTS":   "21.0.13",
		"27.0.1.0":        "27.0.1.0",
		"27+35":           "27",
		"26.0.2.1+1":      "26.0.2.1",
		"1.8.0_514-b01":   "8u514",
		"11.0.33+9":       "11.0.33",
	}
	for in, want := range good {
		v, ok := parseReleaseVersion(in)
		if !ok || v.String() != want {
			t.Errorf("parseReleaseVersion(%q) = %v, %v; want %s", in, v, ok, want)
		}
	}
	for _, in := range []string{"", "jdk-21", "21.0.13+x", "1.8.0_514", "1.7.0_80-b15", "17.0.1+12-LTS-extra!", "ea"} {
		if v, ok := parseReleaseVersion(in); ok {
			t.Errorf("parseReleaseVersion(%q) = %v, want failure", in, v)
		}
	}
}

func TestDetectVersion(t *testing.T) {
	accept := map[string]string{
		"jdk-21.0.13.1+2":     "21.0.13.1",
		"jdk-27+35":           "27",
		"jdk-27.0.1.0.2+1":    "27.0.1.0.2",
		"jdk-11.0.33+9":       "11.0.33",
		"jdk-9.0.4+11":        "9.0.4",
		"jdk8u512-b09":        "8u512",
		"jdk-17.0.21.1+0":     "17.0.21.1",
		"jdk-21.0.13.1.0.0+1": "21.0.13.1.0.0",
	}
	for in, want := range accept {
		v, vendor, ok := detectVersion([]string{"JAVA_VERSION=" + in})
		if !ok || v.String() != want || vendor != VendorTemurin {
			t.Errorf("detectVersion(%q) = %v, %q, %v; want %s", in, v, vendor, ok, want)
		}
	}
	// Forms that are not Temurin's, or that name no distribution, or that
	// are not releases.
	for _, in := range []string{
		"21.0.10", "21.0.13.0", "22", "jdk-28-ea+3", "jdk-11.0.11+9_openj9-0.26.0", "1.8.0_512", "8u512",
		"jdk-8.0.512+1", "jdk-08.0+1", "jdk-21.0.13.1.0.0.0+1", "jdk-21.0.13.1", "jdk-21.0.13.1+", "jdk-21.0.013+2",
		"jdk8u0-b09", "jdk8u512", "jdk8u512-b", "jdk-21.0.13.1+2 ", " jdk-21.0.13.1+2", "", "JDK-21.0.13.1+2", "jdk-21.0.13.1+2-LTS",
		"jdk-9999999999.0+1",
	} {
		if v, _, ok := detectVersion([]string{"JAVA_VERSION=" + in}); ok {
			t.Errorf("detectVersion(%q) = %v, want no detection", in, v)
		}
	}
	if _, _, ok := detectVersion([]string{"PATH=/usr/bin", "JAVA_HOME=/opt/java/openjdk"}); ok {
		t.Error("detected a version without JAVA_VERSION")
	}
	// The last occurrence wins, as in a container runtime.
	v, _, ok := detectVersion([]string{"JAVA_VERSION=jdk-21.0.13.1+2", "JAVA_VERSION=jdk-25.0.5+8"})
	if !ok || v.String() != "25.0.5" {
		t.Errorf("repeated variable: %v, %v", v, ok)
	}
	if _, _, ok := detectVersion([]string{"JAVA_VERSION=jdk-21.0.13.1+2", "JAVA_VERSION=21.0.10"}); ok {
		t.Error("the last value is not a Temurin form, so nothing is detected")
	}
}

func TestExecutablePath(t *testing.T) {
	cases := []struct {
		name string
		env  []string
		want string
	}{
		{"absolute", []string{"JAVA_HOME=/opt/java/openjdk"}, "opt/java/openjdk/bin/java"},
		{"trailing slash", []string{"JAVA_HOME=/opt/java/openjdk/"}, "opt/java/openjdk/bin/java"},
		{"unset", []string{"PATH=/bin"}, ""},
		{"empty", []string{"JAVA_HOME="}, ""},
		{"relative", []string{"JAVA_HOME=opt/java/openjdk"}, ""},
		{"dot relative", []string{"JAVA_HOME=./jdk"}, ""},
		{"last wins", []string{"JAVA_HOME=/a", "JAVA_HOME=/b"}, "b/bin/java"},
		{"last is relative", []string{"JAVA_HOME=/a", "JAVA_HOME=b"}, ""},
		{"too long", []string{"JAVA_HOME=/" + string(make([]byte, 0)) + repeat("a", maxHomeLen)}, ""},
	}
	for _, c := range cases {
		if got := executablePath(c.env); got != c.want {
			t.Errorf("%s: executablePath = %q, want %q", c.name, got, c.want)
		}
	}
}

func repeat(s string, n int) string {
	out := make([]byte, 0, len(s)*n)
	for i := 0; i < n; i++ {
		out = append(out, s...)
	}
	return string(out)
}

func TestSeverityOf(t *testing.T) {
	cases := map[int]string{100: "CRITICAL", 90: "CRITICAL", 89: "HIGH", 70: "HIGH", 69: "MEDIUM", 40: "MEDIUM", 39: "LOW", 1: "LOW", 0: "UNKNOWN"}
	for score, want := range cases {
		if got := severityOf(score); got != want {
			t.Errorf("severityOf(%d) = %s, want %s", score, got, want)
		}
	}
}
