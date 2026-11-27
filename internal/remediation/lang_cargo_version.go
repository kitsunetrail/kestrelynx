package remediation

import (
	"fmt"
	"strconv"
	"strings"
)

// ReasonCargoFixInOtherSeries: every fix of a crate is in a series the version
// in use is not compatible with (another major version, or for 0.x another
// minor version), which an update of Cargo.lock does not move to.
const ReasonCargoFixInOtherSeries Reason = "cargo_fix_in_other_series"

// parseCargoVersion reads a version as Cargo does: a semantic version whose
// major, minor and patch numbers each fit in 64 bits.
func parseCargoVersion(s string) (semver, bool) {
	v, ok := parseSemver(s)
	if !ok {
		return semver{}, false
	}
	for _, n := range []string{v.major, v.minor, v.patch} {
		if _, err := strconv.ParseUint(n, 10, 64); err != nil {
			return semver{}, false
		}
	}
	return v, true
}

// cargoSeries names the series of releases a version is compatible with, by
// the rule of Cargo's default (caret) requirement: from 1.0 on the major
// version, below it the minor version, and below 0.1 the version itself.
// A pre-release is in the series of the release it precedes, and build
// metadata is not part of a version's identity.
func cargoSeries(v semver) string {
	switch {
	case v.major != "0":
		return v.major
	case v.minor != "0":
		return "0." + v.minor
	}
	return "0.0." + v.patch
}

// cargoCompatible reports whether two versions are in the same series.
func cargoCompatible(a, b semver) bool { return cargoSeries(a) == cargoSeries(b) }

// cargoTarget picks the version selection starts from: for each
// vulnerability the lowest reported fix above the installed version that is
// compatible with it (see cargoSeries), then the highest of those over the
// vulnerabilities. A vulnerability whose fixes above the installed version are
// all of other series is not reached by changing the lockfile and goes to a
// person, with those fixes named. A version that does not parse anywhere on
// the way does too.
func cargoTarget(installed string, cves []CVERef) (string, Reason, string) {
	inst, ok := parseCargoVersion(installed)
	if !ok {
		return "", ReasonUnparsableVersion, fmt.Sprintf("the installed version %q is not a version", installed)
	}
	var best semver
	bestStr := ""
	for _, c := range cves {
		var low semver
		lowStr := ""
		var other []string
		for _, alt := range c.FixedVers {
			for _, one := range splitFixed(alt) {
				v, ok := parseCargoVersion(one)
				if !ok {
					return "", ReasonUnparsableVersion, fmt.Sprintf("%s reports the fixed version %q, which is not a version", c.VulnID, one)
				}
				if v.compare(inst) <= 0 {
					continue
				}
				if !cargoCompatible(inst, v) {
					if !containsString(other, one) {
						other = append(other, one)
					}
					continue
				}
				if lowStr == "" || v.compare(low) < 0 {
					low, lowStr = v, one
				}
			}
		}
		if lowStr == "" {
			if len(other) > 0 {
				return "", ReasonCargoFixInOtherSeries, fmt.Sprintf("%s is fixed in %s only, which is not in the series of %s that a lockfile update stays in", c.VulnID, strings.Join(other, ", "), installed)
			}
			return "", ReasonNoFixedVersion, fmt.Sprintf("%s reports no fixed version above %s", c.VulnID, installed)
		}
		if bestStr == "" || low.compare(best) > 0 {
			best, bestStr = low, lowStr
		}
	}
	if bestStr == "" {
		return "", ReasonNoFixedVersion, "no vulnerability to fix"
	}
	return bestStr, "", ""
}
