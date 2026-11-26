package worker

import (
	"regexp"
	"strings"
)

// The id of a runtime says what the runtime is: the language and its series,
// and for Gradle the exact version and the JDK. The rows of a runtime table
// and the runtime of a job are both read with this one grammar, so the main
// process and the program in the work container agree on what an id means
// without sharing a table.
//
//	node<major>                  node24
//	python3.<minor>              python3.13
//	golang1.<minor>              golang1.26
//	rust1.<minor>                rust1.100
//	gradle<version>-jdk<major>   gradle9.8.2-jdk21
var (
	nodeIDRe   = regexp.MustCompile(`^node([1-9][0-9]{0,2})$`)
	pythonIDRe = regexp.MustCompile(`^python(3\.(?:0|[1-9][0-9]?))$`)
	golangIDRe = regexp.MustCompile(`^golang(1\.(?:0|[1-9][0-9]{0,2}))$`)
	rustIDRe   = regexp.MustCompile(`^rust(1\.(?:0|[1-9][0-9]{0,2}))$`)
)

// RuntimeFromID reads the kind, the series and, for Gradle, the version and
// the JDK out of the id of a runtime. The row it returns carries only those:
// it says what the runtime is, not which image a table pins for it. ok is
// false for an id that is not one of a runtime.
func RuntimeFromID(id string) (RuntimeSpec, bool) {
	if len(id) > 64 {
		return RuntimeSpec{}, false
	}
	if m := nodeIDRe.FindStringSubmatch(id); m != nil {
		return RuntimeSpec{ID: id, Kind: KindNode, Series: m[1]}, true
	}
	if m := pythonIDRe.FindStringSubmatch(id); m != nil {
		return RuntimeSpec{ID: id, Kind: KindPython, Series: m[1]}, true
	}
	if m := golangIDRe.FindStringSubmatch(id); m != nil {
		return RuntimeSpec{ID: id, Kind: KindGolang, Series: m[1]}, true
	}
	if m := rustIDRe.FindStringSubmatch(id); m != nil {
		return RuntimeSpec{ID: id, Kind: KindRust, Series: m[1]}, true
	}
	if rest, ok := strings.CutPrefix(id, "gradle"); ok {
		version, jdk, ok := strings.Cut(rest, "-jdk")
		if !ok || !ValidGradleVersion(version) || !jdkRe.MatchString(jdk) {
			return RuntimeSpec{}, false
		}
		series, _, _ := strings.Cut(version, ".")
		return RuntimeSpec{ID: id, Kind: KindGradle, Series: series, Version: version, JDK: jdk}, true
	}
	return RuntimeSpec{}, false
}
