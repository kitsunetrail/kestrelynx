package scanner

import (
	"context"
	"sort"
	"strings"
)

// SeveritySource states the severity of vulnerabilities by ID, for the ones
// Trivy reports without a severity. It returns only the IDs it has a
// severity for, as LOW, MEDIUM, HIGH or CRITICAL, and gives the same answer
// to every scan of a cycle.
type SeveritySource interface {
	Severities(ctx context.Context, ids []string) map[string]string
}

// unscoredSetting is what analysis settings carry when Unscored is set: the
// same report yields different findings with and without it.
const unscoredSetting = ";unknown-severity=cve-record"

// settingsSuffix is unscoredSetting when t fills in severities, else "".
func (t Trivy) settingsSuffix() string {
	if t.Unscored == nil {
		return ""
	}
	return unscoredSetting
}

// scanSeverity is the value passed to --severity: the configured severities
// and, when t fills in severities, UNKNOWN on top, so that Trivy reports the
// findings whose severity is still to be looked up.
func (t Trivy) scanSeverity() string {
	s := t.severity()
	if t.Unscored == nil {
		return s
	}
	for _, e := range normalizeSeverities(strings.Split(s, ",")) {
		if e == string(SeverityUnknown) {
			return s
		}
	}
	return s + "," + string(SeverityUnknown)
}

// fillUnscored gives every UNKNOWN finding the severity t.Unscored states for
// its ID, and then leaves out the findings that were UNKNOWN and are not of a
// configured severity: the ones nothing was stated for when UNKNOWN is not
// configured, and the ones whose stated severity is not. Findings Trivy gave a
// severity are returned as they are. Without t.Unscored it returns findings
// unchanged.
func (t Trivy) fillUnscored(ctx context.Context, findings []Finding) []Finding {
	if t.Unscored == nil {
		return findings
	}
	seen := map[string]bool{}
	var ids []string
	for _, f := range findings {
		if f.Severity == SeverityUnknown && !seen[f.VulnID] {
			seen[f.VulnID] = true
			ids = append(ids, f.VulnID)
		}
	}
	if len(ids) == 0 {
		return findings
	}
	sort.Strings(ids)
	stated := t.Unscored.Severities(ctx, ids)
	configured := map[string]bool{}
	for _, s := range normalizeSeverities(strings.Split(t.severity(), ",")) {
		configured[s] = true
	}
	out := make([]Finding, 0, len(findings))
	for _, f := range findings {
		if f.Severity == SeverityUnknown {
			if s := stated[f.VulnID]; s != "" {
				f.Severity = Severity(s)
			}
			if !configured[string(f.Severity)] {
				continue
			}
		}
		out = append(out, f)
	}
	return out
}
