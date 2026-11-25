package javacore

import (
	"bytes"
	"errors"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/kitsunetrail/kestrelynx/internal/imagefs"
)

const (
	// maxReleaseSize bounds the content of a release file that is parsed.
	maxReleaseSize = 256 << 10
	// maxReleaseLine bounds one line; a longer one is ignored.
	maxReleaseLine = 64 << 10
	// maxReleaseModules bounds the modules read from MODULES.
	maxReleaseModules = 4096
)

// Release is the content of a JDK's release file that the check uses.
type Release struct {
	JavaVersion        string
	JavaRuntimeVersion string
	Implementor        string
	Source             string
	BuildType          string
	// Modules are the entries of MODULES. HasModules tells an absent line
	// from an empty one.
	Modules    []string
	HasModules bool
	// ModulesTruncated is true when MODULES held more entries than are kept:
	// the list is then not the whole set of modules, and no module is judged
	// absent from it.
	ModulesTruncated bool
}

// ParseRelease reads the KEY="value" lines of a release file. Unknown keys,
// blank lines and lines that are not assignments are ignored; the last
// assignment of a key wins. It fails only on content over the size bound.
func ParseRelease(content []byte) (Release, error) {
	var r Release
	if len(content) > maxReleaseSize {
		return r, errors.New("release file is too large")
	}
	for _, line := range bytes.Split(content, []byte("\n")) {
		if len(line) > maxReleaseLine {
			continue
		}
		s := strings.TrimSpace(string(line))
		key, val, ok := strings.Cut(s, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)
		if len(val) >= 2 && val[0] == '"' && val[len(val)-1] == '"' {
			val = val[1 : len(val)-1]
		}
		switch key {
		case "JAVA_VERSION":
			// Read by the rule the image reader detects a JDK by.
			r.JavaVersion, _ = imagefs.ReleaseValue(string(content), "JAVA_VERSION")
		case "JAVA_RUNTIME_VERSION":
			r.JavaRuntimeVersion = val
		case "IMPLEMENTOR":
			r.Implementor = val
		case "SOURCE":
			r.Source = val
		case "BUILD_TYPE":
			r.BuildType = val
		case "MODULES":
			fields := strings.Fields(val)
			if len(fields) > maxReleaseModules {
				fields = fields[:maxReleaseModules]
				r.ModulesTruncated = true
			} else {
				r.ModulesTruncated = false
			}
			r.Modules, r.HasModules = fields, true
		}
	}
	return r, nil
}

const (
	// VendorOracleOpenJDK is an OpenJDK build by Oracle (not the commercial
	// Oracle JDK), such as the one Elasticsearch bundles.
	VendorOracleOpenJDK Vendor = "oracle-openjdk"
	// VendorUnknown is a JDK whose release file names no vendor, as after
	// jlink.
	VendorUnknown Vendor = "unknown"
)

var (
	javaVersion8Re = regexp.MustCompile(`^1\.8\.0_([1-9][0-9]*)$`)
	// vendorDirNames are the names that a JDK directory of a known
	// distribution carries.
	vendorDirNames = []string{"corretto", "zulu", "sapmachine", "msopenjdk", "microsoft", "liberica", "bellsoft", "semeru", "openj9"}
)

// Classify decides whether the JDK in dir, described by its release file, is
// matched against the OpenJDK advisories and as which vendor. The reason is a
// short English description for the log.
func Classify(dir string, r Release) (Vendor, bool, string) {
	v, _, ok, reason := classify(dir, r)
	return v, ok, reason
}

func classify(dir string, r Release) (Vendor, version, bool, string) {
	vendor, ok, reason := classifyVendor(dir, r)
	if !ok {
		return "", version{}, false, reason
	}
	if strings.Contains(r.JavaRuntimeVersion, "-ea") || strings.Contains(r.JavaRuntimeVersion, "-internal") {
		return "", version{}, false, "early-access or internal build"
	}
	v, ok := parseJavaVersion(r.JavaVersion)
	if !ok {
		return "", version{}, false, "unreadable JAVA_VERSION"
	}
	if vendor == VendorUnknown && v.legacy {
		return "", version{}, false, "no IMPLEMENTOR and series " + fmt.Sprint(v.series())
	}
	return vendor, v, true, reason
}

func classifyVendor(dir string, r Release) (Vendor, bool, string) {
	impl := strings.TrimSpace(r.Implementor)
	switch {
	case strings.EqualFold(strings.TrimSpace(r.BuildType), "commercial"):
		return "", false, "commercial build"
	case impl == "Eclipse Adoptium":
		return VendorTemurin, true, "Eclipse Adoptium"
	case impl == "Oracle Corporation":
		if strings.Contains(r.JavaRuntimeVersion, "-LTS") || sourceHasOpen(r.Source) {
			return "", false, "Oracle JDK commercial build"
		}
		return VendorOracleOpenJDK, true, "Oracle OpenJDK build"
	case impl == "":
		if hasVendorName(dir) {
			return "", false, "no IMPLEMENTOR and the directory names a distribution"
		}
		// The series is checked by the caller once the version is parsed.
		return VendorUnknown, true, "no IMPLEMENTOR"
	}
	return "", false, "IMPLEMENTOR " + sanitize(impl)
}

// sourceHasOpen reports whether SOURCE has an element starting with "open:".
func sourceHasOpen(source string) bool {
	for _, f := range strings.Fields(source) {
		if strings.HasPrefix(f, "open:") {
			return true
		}
	}
	return false
}

func hasVendorName(dir string) bool {
	low := strings.ToLower(dir)
	for _, el := range strings.Split(path.Clean(low), "/") {
		for _, n := range vendorDirNames {
			if strings.Contains(el, n) {
				return true
			}
		}
	}
	return false
}

// sanitize makes a release value safe and short for a log line.
func sanitize(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	if len(s) > 64 {
		s = s[:64]
	}
	return s
}

// parseJavaVersion reads JAVA_VERSION: the dotted number of series 9 and
// later, or 1.8.0_<update> as 8u<update>.
func parseJavaVersion(s string) (version, bool) {
	if m := javaVersion8Re.FindStringSubmatch(s); m != nil {
		return parseVersion("8u" + m[1])
	}
	v, ok := parseVersion(s)
	if !ok || v.legacy {
		return version{}, false
	}
	return v, true
}

// moduleOf is the module an advisory component belongs to, when that is
// certain. Components that may belong to java.base are not listed.
func moduleOf(component string) (string, bool) {
	if strings.HasPrefix(component, "client-libs/") {
		return "java.desktop", true
	}
	m, ok := componentModules[component]
	return m, ok
}

var componentModules = map[string]string{
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
}

// ReleaseCheck is the outcome of checking one JDK by its release file.
type ReleaseCheck struct {
	// Checked is false when the JDK is not matched; Reason says why.
	Checked bool
	Reason  string
	Vendor  Vendor
	Version string
	// Unchecked is true when the advisories cannot be matched for the
	// version's line.
	Unchecked bool
	// Advisories are the matched CVEs of the wanted severities.
	Advisories []Advisory
	// Suppressed are CVEs left out because the vendor fixed them in a
	// version the upstream rules cannot tell (VendorUnknown only).
	Suppressed []string
	// ModuleDropped are CVEs left out because their module is not in the
	// release file's MODULES.
	ModuleDropped []string
}

// CheckRelease classifies the JDK in dir by its release file content and
// matches it. Only advisories and suppressed CVEs of the given severities
// are returned.
func (sn *Snapshot) CheckRelease(dir string, content []byte, severities []string) ReleaseCheck {
	rel, err := ParseRelease(content)
	if err != nil {
		return ReleaseCheck{Reason: err.Error()}
	}
	vendor, v, ok, reason := classify(dir, rel)
	if !ok {
		return ReleaseCheck{Reason: reason}
	}
	out := ReleaseCheck{Checked: true, Reason: reason, Vendor: vendor, Version: v.String()}
	if sn.Unchecked(v.series()) {
		out.Unchecked = true
		return out
	}
	want := make(map[string]bool, len(severities))
	for _, s := range severities {
		want[strings.ToUpper(strings.TrimSpace(s))] = true
	}
	var modules map[string]bool
	if rel.HasModules && !rel.ModulesTruncated && !v.legacy {
		modules = make(map[string]bool, len(rel.Modules))
		for _, m := range rel.Modules {
			modules[m] = true
		}
	}
	res := sn.match(vendor, v)
	for _, a := range res.advisories {
		if !want[a.Severity] {
			continue
		}
		if modules != nil {
			if m, ok := moduleOf(res.components[a.VulnID]); ok && !modules[m] {
				out.ModuleDropped = append(out.ModuleDropped, a.VulnID)
				continue
			}
		}
		out.Advisories = append(out.Advisories, a)
	}
	for cve, sev := range res.suppressed {
		if want[sev] {
			out.Suppressed = append(out.Suppressed, cve)
		}
	}
	sort.Strings(out.Suppressed)
	sort.Strings(out.ModuleDropped)
	return out
}
