package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return data
}

func TestParseReport_ImageMetadata(t *testing.T) {
	scan, err := ParseReport(loadFixture(t, "sample.json"))
	if err != nil {
		t.Fatalf("ParseReport: %v", err)
	}
	if scan.Image != "demo:1.0" {
		t.Errorf("Image = %q, want demo:1.0", scan.Image)
	}
	if scan.OSFamily != "debian" {
		t.Errorf("OSFamily = %q, want debian", scan.OSFamily)
	}
	if !scan.OSEOSL {
		t.Errorf("OSEOSL = false, want true (debian 10.8 is EOL)")
	}
}

func TestParseReport_FindingCount(t *testing.T) {
	scan, err := ParseReport(loadFixture(t, "sample.json"))
	if err != nil {
		t.Fatalf("ParseReport: %v", err)
	}
	// 3 os-pkgs + 2 lang-pkgs; the empty result contributes nothing.
	if got := len(scan.Findings); got != 5 {
		t.Fatalf("len(Findings) = %d, want 5", got)
	}
}

// findByVuln returns the finding with the given CVE id, failing if absent.
func findByVuln(t *testing.T, scan ImageScan, id string) Finding {
	t.Helper()
	for _, f := range scan.Findings {
		if f.VulnID == id {
			return f
		}
	}
	t.Fatalf("finding %s not found", id)
	return Finding{}
}

func TestParseReport_OSFindingFields(t *testing.T) {
	scan, _ := ParseReport(loadFixture(t, "sample.json"))
	f := findByVuln(t, scan, "CVE-OS-FIXED")

	if f.Class != ClassOS {
		t.Errorf("Class = %q, want %q", f.Class, ClassOS)
	}
	if f.Package != "libc-bin" {
		t.Errorf("Package = %q, want libc-bin", f.Package)
	}
	if f.InstalledVer != "2.28-10" || f.FixedVer != "2.28-10+deb10u2" {
		t.Errorf("versions = %q -> %q, want 2.28-10 -> 2.28-10+deb10u2", f.InstalledVer, f.FixedVer)
	}
	if f.Status != StatusFixed {
		t.Errorf("Status = %q, want %q", f.Status, StatusFixed)
	}
	if f.Severity != SeverityCritical {
		t.Errorf("Severity = %q, want %q", f.Severity, SeverityCritical)
	}
	if f.Image != "demo:1.0" {
		t.Errorf("Image = %q, want demo:1.0", f.Image)
	}
	if f.URL != "https://example.test/CVE-OS-FIXED" {
		t.Errorf("URL = %q", f.URL)
	}
	if f.Title != "glibc: example title for CVE-OS-FIXED" {
		t.Errorf("Title = %q", f.Title)
	}
}

// A Trivy entry with no Title field must parse as an empty string, not fail
// or leave a stale value from a previous entry.
func TestParseReport_MissingTitleIsEmpty(t *testing.T) {
	scan, _ := ParseReport(loadFixture(t, "sample.json"))
	f := findByVuln(t, scan, "CVE-OS-WONTFIX")
	if f.Title != "" {
		t.Errorf("Title = %q, want empty (fixture has no Title field)", f.Title)
	}
}

func TestParseReport_LangClassMapping(t *testing.T) {
	scan, _ := ParseReport(loadFixture(t, "sample.json"))
	f := findByVuln(t, scan, "CVE-LANG-MAJOR")
	if f.Class != ClassLang {
		t.Errorf("Class = %q, want %q (lang-pkgs)", f.Class, ClassLang)
	}
}

func TestParseReport_StatusMapping(t *testing.T) {
	scan, _ := ParseReport(loadFixture(t, "sample.json"))
	cases := map[string]Status{
		"CVE-OS-FIXED":    StatusFixed,
		"CVE-OS-WONTFIX":  StatusWontFix,
		"CVE-OS-AFFECTED": StatusAffected,
	}
	for id, want := range cases {
		if got := findByVuln(t, scan, id).Status; got != want {
			t.Errorf("%s Status = %q, want %q", id, got, want)
		}
	}
}

// The real Trivy output must parse without error and yield sane data.
// Guards against schema drift in the fields we depend on.
func TestParseReport_RealOutput(t *testing.T) {
	scan, err := ParseReport(loadFixture(t, "real_python_3.9.1-slim.json"))
	if err != nil {
		t.Fatalf("ParseReport(real): %v", err)
	}
	if scan.Image != "python:3.9.1-slim" {
		t.Errorf("Image = %q", scan.Image)
	}
	if !scan.OSEOSL {
		t.Errorf("OSEOSL = false, want true")
	}
	if len(scan.Findings) < 100 {
		t.Errorf("len(Findings) = %d, want >=100", len(scan.Findings))
	}
	// Every finding must carry the core fields we rely on downstream.
	var sawOS, sawLang, sawFixed, sawTitle bool
	for _, f := range scan.Findings {
		if f.VulnID == "" || f.Package == "" || f.Severity == "" {
			t.Fatalf("incomplete finding: %+v", f)
		}
		switch f.Class {
		case ClassOS:
			sawOS = true
		case ClassLang:
			sawLang = true
		}
		if f.Status == StatusFixed {
			sawFixed = true
		}
		if f.Title != "" {
			sawTitle = true
		}
	}
	if !sawOS || !sawLang || !sawFixed || !sawTitle {
		t.Errorf("coverage: os=%v lang=%v fixed=%v title=%v", sawOS, sawLang, sawFixed, sawTitle)
	}
}
