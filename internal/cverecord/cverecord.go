// Package cverecord reads the severity a CVE record states: the score of the
// organization that published the CVE (its CNA) or, when it gave none, of an
// organization that added one to the record afterwards (an ADP, such as
// CISA). The scanner uses it for the vulnerabilities Trivy reports without a
// severity, which is how a CVE looks between its publication and its NVD
// score.
package cverecord

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// DefaultBaseURL is where the CVE records are read from: the cves directory
// of the CVE list repository.
const DefaultBaseURL = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/"

// idRe is a CVE ID; the groups are the year and the number.
var idRe = regexp.MustCompile(`^CVE-([0-9]{4})-([0-9]{4,8})$`)

// ValidID reports whether id is a CVE ID. Anything else (a distribution's
// temporary ID, a GHSA ID) has no CVE record.
func ValidID(id string) bool { return idRe.MatchString(id) }

// RecordURL is the address of the record of id under base, in the layout of
// the CVE list repository: <base><year>/<number/1000>xxx/<id>.json. It reports
// false when id is not a CVE ID.
func RecordURL(base, id string) (string, bool) {
	m := idRe.FindStringSubmatch(id)
	if m == nil {
		return "", false
	}
	if !strings.HasSuffix(base, "/") {
		base += "/"
	}
	n, _ := strconv.Atoi(m[2])
	return base + m[1] + "/" + strconv.Itoa(n/1000) + "xxx/" + id + ".json", true
}

// Metric is one entry of a metrics list of a CVE record.
type Metric struct {
	V4  *Score `json:"cvssV4_0"`
	V31 *Score `json:"cvssV3_1"`
	V30 *Score `json:"cvssV3_0"`
}

// Score is the part of a CVSS score in use.
type Score struct {
	BaseSeverity string `json:"baseSeverity"`
}

// SeverityOf is the severity the metrics state, upper case: the CNA's, else
// that of the first ADP list that has one, else "". Within a list CVSS 4.0
// is preferred, then 3.1, then 3.0. Any value a score carries counts.
func SeverityOf(cna []Metric, adp ...[]Metric) string {
	return severityOf(func(string) bool { return true }, cna, adp)
}

// severityOf is SeverityOf over the values accept takes: one it does not take
// is passed over like a metric without a score.
func severityOf(accept func(string) bool, cna []Metric, adp [][]Metric) string {
	if s := firstSeverity(cna, accept); s != "" {
		return s
	}
	for _, metrics := range adp {
		if s := firstSeverity(metrics, accept); s != "" {
			return s
		}
	}
	return ""
}

// firstSeverity is the severity of the first metric that carries an accepted
// one, preferring CVSS 4.0, then 3.1, then 3.0 across the list.
func firstSeverity(metrics []Metric, accept func(string) bool) string {
	for _, get := range []func(Metric) *Score{
		func(m Metric) *Score { return m.V4 },
		func(m Metric) *Score { return m.V31 },
		func(m Metric) *Score { return m.V30 },
	} {
		for _, m := range metrics {
			if sc := get(m); sc != nil {
				if s := strings.ToUpper(strings.TrimSpace(sc.BaseSeverity)); s != "" && accept(s) {
					return s
				}
			}
		}
	}
	return ""
}

// record is the part of a CVE record the severity is read from.
type record struct {
	CVEMetadata struct {
		CVEID string `json:"cveId"`
		State string `json:"state"`
	} `json:"cveMetadata"`
	Containers struct {
		CNA struct {
			Metrics []Metric `json:"metrics"`
		} `json:"cna"`
		ADP []struct {
			Metrics []Metric `json:"metrics"`
		} `json:"adp"`
	} `json:"containers"`
}

// levels are the severities a record may state. A score of NONE, or any other
// value, counts as no score: the next one in the order of SeverityOf is taken.
var levels = map[string]bool{"LOW": true, "MEDIUM": true, "HIGH": true, "CRITICAL": true}

// severityOfRecord reads the severity out of the record of id. It is "" when
// the record states none or the CVE is not published (a rejected CVE keeps
// its record). A document that is not the record of id is an error.
func severityOfRecord(id string, data []byte) (string, error) {
	var r record
	if err := json.Unmarshal(data, &r); err != nil {
		return "", fmt.Errorf("parse the record of %s: %w", id, err)
	}
	if r.CVEMetadata.CVEID != id {
		return "", fmt.Errorf("the record is of %q, not of %s", r.CVEMetadata.CVEID, id)
	}
	if r.CVEMetadata.State != "PUBLISHED" {
		return "", nil
	}
	adp := make([][]Metric, 0, len(r.Containers.ADP))
	for _, a := range r.Containers.ADP {
		adp = append(adp, a.Metrics)
	}
	return severityOf(func(s string) bool { return levels[s] }, r.Containers.CNA.Metrics, adp), nil
}
