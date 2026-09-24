package scanner

import "testing"

// status_all.json is synthetic: Trivy 0.71.2 scans recorded so far never
// emitted end_of_life, under_investigation, not_affected or a missing Status
// key, so their shape is reproduced by hand (a Red Hat UBI image, where the
// vendor data can produce those values) to pin how each is parsed. Every one
// of Trivy's eight values appears, plus a missing key and a value Trivy does
// not define.
func TestParseReport_EveryTrivyStatus(t *testing.T) {
	scan, err := ParseReport(loadFixture(t, "status_all.json"))
	if err != nil {
		t.Fatalf("ParseReport: %v", err)
	}
	cases := map[string]Status{
		"CVE-2032-0001": StatusFixed,
		"CVE-2032-0002": StatusAffected,
		"CVE-2032-0003": StatusFixDeferred,
		"CVE-2032-0004": StatusUnderInvestigation,
		"CVE-2032-0005": StatusUnknown, // Status key absent
		"CVE-2032-0006": StatusUnknown,
		"CVE-2032-0007": Status("future_status"), // kept verbatim
		"CVE-2032-0008": StatusEndOfLife,
		"CVE-2032-0009": StatusEndOfLife,
		"CVE-2032-0010": StatusWontFix,
		"CVE-2032-0011": StatusNotAffected,
	}
	if len(scan.Findings) != len(cases) {
		t.Fatalf("len(Findings) = %d, want %d: the parser must not drop any status", len(scan.Findings), len(cases))
	}
	for id, want := range cases {
		if got := findByVuln(t, scan, id).Status; got != want {
			t.Errorf("%s Status = %q, want %q", id, got, want)
		}
	}
}

// real_debian12_status_mix.json is a real Trivy 0.71.2 scan of nginx:1.27
// (Debian 12.11), cut down by hand to curl's fix_deferred, affected and
// fixed findings plus one will_not_fix finding on zlib1g.
func TestParseReport_RealDebianStatusMix(t *testing.T) {
	scan, err := ParseReport(loadFixture(t, "real_debian12_status_mix.json"))
	if err != nil {
		t.Fatalf("ParseReport: %v", err)
	}
	cases := map[string]Status{
		"CVE-2026-12064": StatusFixDeferred,
		"CVE-2026-8286":  StatusFixDeferred,
		"CVE-2026-6276":  StatusAffected,
		"CVE-2026-5773":  StatusFixed,
		"CVE-2023-45853": StatusWontFix,
	}
	if len(scan.Findings) != len(cases) {
		t.Fatalf("len(Findings) = %d, want %d", len(scan.Findings), len(cases))
	}
	for id, want := range cases {
		if got := findByVuln(t, scan, id).Status; got != want {
			t.Errorf("%s Status = %q, want %q", id, got, want)
		}
	}
	if f := findByVuln(t, scan, "CVE-2026-12064"); f.Package != "curl" || f.FixedVer != "" || f.Class != ClassOS {
		t.Errorf("fix_deferred finding = %+v, want curl, no fixed version, os class", f)
	}
}
