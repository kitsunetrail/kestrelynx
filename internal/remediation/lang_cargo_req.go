package remediation

import (
	"regexp"
	"strconv"
	"strings"
)

// maxCargoReqClauses is the most comparators Cargo reads in one requirement.
const maxCargoReqClauses = 32

// Cargo takes only the ASCII space as blank in a requirement.
//
// cargoClauseRE is the shape of one comparator of a Cargo version
// requirement: an optional operator and a version of one to three numeric
// parts, any of which may be a wildcard. A pre-release or build suffix does
// not match, so such a requirement is not evaluated.
var cargoClauseRE = regexp.MustCompile(`^(\^|~|=|>=|<=|>|<)? *([0-9]+|[*xX])(\.([0-9]+|[*xX]))?(\.([0-9]+|[*xX]))?$`)

// cargoReqAllows reports whether the release version v satisfies the version
// requirement of a Cargo.toml dependency. evaluable is false when the answer
// cannot be given: the requirement is not in the grammar below, has a
// pre-release or build part, or v is itself a pre-release (which a
// requirement admits only under extra rules).
//
// A requirement is comparators separated by commas, all of which must hold.
// A comparator without an operator is a caret requirement. The operators are
// ^, ~, =, >, >=, < and <=; a version may be partial ("1", "1.2"), and a
// part may be a wildcard ("*", "1.*", "1.2.*"), which takes no operator.
func cargoReqAllows(req string, v semver) (ok, evaluable bool) {
	if v.isPrerelease() {
		return false, false
	}
	req = strings.Trim(req, " ")
	if req == "" || len(req) > maxSpecifierBytes {
		return false, false
	}
	clauses := strings.Split(req, ",")
	if len(clauses) > maxCargoReqClauses {
		return false, false
	}
	ok = true
	for _, clause := range clauses {
		clause = strings.Trim(clause, " ")
		m := cargoClauseRE.FindStringSubmatch(clause)
		if m == nil {
			return false, false
		}
		// A lone wildcard stands alone, a wildcard major part is the whole
		// version, and every number fits in 64 bits.
		if len(clauses) > 1 && (clause == "*" || clause == "x" || clause == "X") {
			return false, false
		}
		if strings.Trim(m[2], "*xX") == "" && m[3] != "" {
			return false, false
		}
		for _, n := range []string{m[2], m[4], m[6]} {
			if n != "" && strings.Trim(n, "*xX") != "" {
				if _, err := strconv.ParseUint(n, 10, 64); err != nil {
					return false, false
				}
			}
		}
		op := m[1]
		wild := strings.ContainsAny(clause[len(op):], "*xX")
		if wild && op != "" {
			return false, false
		}
		if op == "" && !wild {
			op = "^"
		}
		version := strings.Trim(clause[len(m[1]):], " ")
		preds, valid := comparatorPredicates(op + version)
		if !valid {
			return false, false
		}
		for _, p := range preds {
			if !p.holds(v) {
				ok = false
			}
		}
	}
	return ok, true
}
