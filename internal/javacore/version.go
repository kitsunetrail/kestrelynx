package javacore

import (
	"regexp"
	"strconv"
	"strings"
)

// version is a JDK version. Versions from 9 on are the dotted numbers of
// JEP 322 (21.0.13.1 has the components 21, 0, 13, 1); series 7 and 8 use the
// update form 8u512, kept as the components 8 and 512 with legacy set.
type version struct {
	parts  []int
	legacy bool
}

const (
	// maxVersionDigits bounds one version component so it always fits an int.
	maxVersionDigits = 9
	// maxVersionParts is the most components a JEP 322 version has here.
	maxVersionParts = 6
)

var (
	jepVersionRe    = regexp.MustCompile(`^(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*))*$`)
	legacyVersionRe = regexp.MustCompile(`^([78])u([1-9][0-9]*)$`)
)

// parseVersion parses a JEP 322 version of series 9 or later, or the update
// form of series 7 and 8.
func parseVersion(s string) (version, bool) {
	if m := legacyVersionRe.FindStringSubmatch(s); m != nil {
		series, _ := strconv.Atoi(m[1])
		if len(m[2]) > maxVersionDigits {
			return version{}, false
		}
		update, err := strconv.Atoi(m[2])
		if err != nil {
			return version{}, false
		}
		return version{parts: []int{series, update}, legacy: true}, true
	}
	if !jepVersionRe.MatchString(s) {
		return version{}, false
	}
	fields := strings.Split(s, ".")
	if len(fields) > maxVersionParts {
		return version{}, false
	}
	parts := make([]int, len(fields))
	for i, f := range fields {
		if len(f) > maxVersionDigits {
			return version{}, false
		}
		n, err := strconv.Atoi(f)
		if err != nil {
			return version{}, false
		}
		parts[i] = n
	}
	if parts[0] < 9 {
		return version{}, false
	}
	return version{parts: parts}, true
}

// series is the release line of the version: 8 for 8u512, 21 for 21.0.13.1.
func (v version) series() int { return v.parts[0] }

func (v version) String() string {
	if v.legacy {
		return strconv.Itoa(v.parts[0]) + "u" + strconv.Itoa(v.parts[1])
	}
	fields := make([]string, len(v.parts))
	for i, p := range v.parts {
		fields[i] = strconv.Itoa(p)
	}
	return strings.Join(fields, ".")
}

// compare returns -1, 0 or 1 as v is below, equal to or above o. Components
// are compared as numbers from the left and a missing one counts as 0, so
// 21.0.13 equals 21.0.13.0 and 21.0.13.0.3 is below 21.0.13.1. ok is false
// for versions of different series or forms, which are not ordered.
func (v version) compare(o version) (c int, ok bool) {
	if v.legacy != o.legacy || v.parts[0] != o.parts[0] {
		return 0, false
	}
	n := max(len(v.parts), len(o.parts))
	for i := 0; i < n; i++ {
		a, b := 0, 0
		if i < len(v.parts) {
			a = v.parts[i]
		}
		if i < len(o.parts) {
			b = o.parts[i]
		}
		switch {
		case a < b:
			return -1, true
		case a > b:
			return 1, true
		}
	}
	return 0, true
}

// atMost reports whether v is in the same series as o and not above it.
func (v version) atMost(o version) bool {
	c, ok := v.compare(o)
	return ok && c <= 0
}
