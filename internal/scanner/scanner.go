// Package scanner runs Trivy against container images and converts its JSON
// output into StackWatch's neutral Finding/ImageScan types.
//
// The neutral types deliberately hide Trivy's schema so that downstream
// packages (analyze, notify) never import Trivy-shaped data, and so a
// different scanner could be substituted later. See docs/TRIVY_OUTPUT.md for
// the validated field mapping this code depends on.
package scanner

import (
	"encoding/json"
	"fmt"
)

// PkgClass distinguishes OS packages (distro versioning, not semver) from
// language packages (semver). This drives whether analyze applies a semver
// breaking-change judgement. See docs/ARCHITECTURE.md ADR-005.
type PkgClass string

const (
	ClassOS   PkgClass = "os"
	ClassLang PkgClass = "lang"
)

// Status mirrors Trivy's vulnerability status and is the primary axis for
// triage (more meaningful than "has a fixed version"). See docs/TRIVY_OUTPUT.md §5.
type Status string

const (
	StatusFixed    Status = "fixed"
	StatusAffected Status = "affected"
	StatusWontFix  Status = "will_not_fix"
)

// Severity is restricted in practice to HIGH/CRITICAL because StackWatch asks
// Trivy to filter, but the raw string is preserved as-is.
type Severity string

const (
	SeverityHigh     Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"
)

// Finding is one vulnerability in one package of one image.
type Finding struct {
	Image        string
	Class        PkgClass
	Package      string
	InstalledVer string
	FixedVer     string // empty unless Status == fixed
	Status       Status
	Severity     Severity
	VulnID       string
	URL          string
	Title        string // short human-readable summary of the vulnerability, if Trivy supplied one
}

// ImageScan is the result of scanning a single image. Err is non-nil when the
// scan itself failed (e.g. image could not be pulled); callers should surface
// it rather than dropping it.
type ImageScan struct {
	Image    string
	OSFamily string
	OSEOSL   bool // base OS is end-of-life: no more security updates
	Findings []Finding
	Err      error
}

// trivyReport is the subset of Trivy's JSON schema (SchemaVersion 2) that
// StackWatch depends on. Fields we don't use are intentionally omitted.
type trivyReport struct {
	ArtifactName string `json:"ArtifactName"`
	Metadata     struct {
		OS struct {
			Family string `json:"Family"`
			EOSL   bool   `json:"EOSL"`
		} `json:"OS"`
	} `json:"Metadata"`
	Results []struct {
		Class           string `json:"Class"`
		Vulnerabilities []struct {
			VulnerabilityID  string `json:"VulnerabilityID"`
			PkgName          string `json:"PkgName"`
			InstalledVersion string `json:"InstalledVersion"`
			FixedVersion     string `json:"FixedVersion"`
			Status           string `json:"Status"`
			Severity         string `json:"Severity"`
			PrimaryURL       string `json:"PrimaryURL"`
			Title            string `json:"Title"`
		} `json:"Vulnerabilities"`
	} `json:"Results"`
}

// ParseReport converts one Trivy JSON report into an ImageScan. It is pure and
// fully testable, kept separate from CLI execution so parsing can be verified
// against recorded fixtures.
func ParseReport(data []byte) (ImageScan, error) {
	var r trivyReport
	if err := json.Unmarshal(data, &r); err != nil {
		return ImageScan{}, fmt.Errorf("parse trivy report: %w", err)
	}

	scan := ImageScan{
		Image:    r.ArtifactName,
		OSFamily: r.Metadata.OS.Family,
		OSEOSL:   r.Metadata.OS.EOSL,
	}

	for _, res := range r.Results {
		class := classOf(res.Class)
		for _, v := range res.Vulnerabilities {
			scan.Findings = append(scan.Findings, Finding{
				Image:        r.ArtifactName,
				Class:        class,
				Package:      v.PkgName,
				InstalledVer: v.InstalledVersion,
				FixedVer:     v.FixedVersion,
				Status:       Status(v.Status),
				Severity:     Severity(v.Severity),
				VulnID:       v.VulnerabilityID,
				URL:          v.PrimaryURL,
				Title:        v.Title,
			})
		}
	}

	return scan, nil
}

// classOf maps Trivy's Result.Class to our PkgClass. Trivy uses "os-pkgs" for
// distro packages and "lang-pkgs" for language dependencies; anything else is
// treated as a language package (the conservative choice, since OS handling
// suppresses semver and we'd rather not wrongly suppress it).
func classOf(trivyClass string) PkgClass {
	if trivyClass == "os-pkgs" {
		return ClassOS
	}
	return ClassLang
}
