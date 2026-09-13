package main

import (
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

// syntheticTrivyReport is a small, hand-written Trivy JSON report exercising
// a duplicate Finding, a package whose name resolves in the observation but
// at a different installed version, and a package that is never referenced
// by any observed process at all.
const syntheticTrivyReport = `{
  "SchemaVersion": 2,
  "ArtifactName": "kl-integration-test:1",
  "Metadata": {
    "OS": { "Family": "debian", "Name": "12.5", "EOSL": false },
    "ImageID": "sha256:1e60f61e927ad57a35d95a00a5c8f740915938c2fc0295482cdae2288ef54732"
  },
  "Results": [
    {
      "Class": "os-pkgs",
      "Type": "debian",
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2030-0001",
          "PkgName": "libssl3",
          "InstalledVersion": "3.0.13-1",
          "FixedVersion": "3.0.14-1",
          "Status": "fixed",
          "Severity": "HIGH",
          "Title": "duplicated Finding, first occurrence"
        },
        {
          "VulnerabilityID": "CVE-2030-0001",
          "PkgName": "libssl3",
          "InstalledVersion": "3.0.13-1",
          "FixedVersion": "3.0.14-1",
          "Status": "fixed",
          "Severity": "HIGH",
          "Title": "duplicated Finding, second occurrence (same PkgName/InstalledVersion/VulnerabilityID)"
        },
        {
          "VulnerabilityID": "CVE-2030-0002",
          "PkgName": "libssl3",
          "InstalledVersion": "3.0.13-1",
          "FixedVersion": "3.0.14-1",
          "Status": "fixed",
          "Severity": "CRITICAL",
          "Title": "distinct CVE, same package and version"
        },
        {
          "VulnerabilityID": "CVE-2030-0003",
          "PkgName": "gzip",
          "InstalledVersion": "1.12-1",
          "FixedVersion": "1.12-1.1",
          "Status": "fixed",
          "Severity": "HIGH",
          "Title": "never referenced by any observed process"
        }
      ]
    }
  ]
}`

func TestParseReportGroupAndVerdictIntegration(t *testing.T) {
	scan, err := scanner.ParseReport([]byte(syntheticTrivyReport))
	if err != nil {
		t.Fatalf("ParseReport: %v", err)
	}
	if len(scan.Findings) != 4 {
		t.Fatalf("ParseReport returned %d raw findings, want 4 (including the intentional duplicate)", len(scan.Findings))
	}

	groups := groupFindings(scan.Findings)
	if len(groups) != 2 {
		t.Fatalf("groupFindings returned %d groups, want 2 (libssl3, gzip)", len(groups))
	}

	var libssl3, gzip *pkgGroup
	for i := range groups {
		switch groups[i].key.Package {
		case "libssl3":
			libssl3 = &groups[i]
		case "gzip":
			gzip = &groups[i]
		}
	}
	if libssl3 == nil || gzip == nil {
		t.Fatalf("groupFindings groups = %+v, want both libssl3 and gzip present", groups)
	}
	if len(libssl3.vulns) != 2 {
		t.Errorf("libssl3 Finding-unit count = %d, want 2 (CVE-2030-0001 deduplicated, CVE-2030-0002 distinct)", len(libssl3.vulns))
	}
	if len(gzip.vulns) != 1 {
		t.Errorf("gzip Finding-unit count = %d, want 1", len(gzip.vulns))
	}

	rec := &ContainerRecord{
		Window:            Window{Samples: []SampleTiming{{SampleID: "s0"}}},
		CollectionResults: []CollectionResult{{SampleID: "s0", ProcObserve: "ok", PkgdbRead: "ok", Valid: true}},
		Processes:         []ProcessRecord{{SampleID: "s0", Generation: ProcessGeneration{PID: 1}, Exe: "/usr/sbin/nginx"}},
		PathResolution: []PathResolutionRecord{
			{SampleID: "s0", Generation: ProcessGeneration{PID: 1}, Path: "/usr/sbin/nginx", Resolved: "/usr/sbin/nginx", Ownership: OwnershipOwned, DBKind: dpkgKind, Package: "nginx", DBVersion: "1.27.0-1"},
			{SampleID: "s0", Generation: ProcessGeneration{PID: 1}, Path: "/usr/lib/x86_64-linux-gnu/libssl.so.3", Resolved: "/usr/lib/x86_64-linux-gnu/libssl.so.3", Ownership: OwnershipOwned, DBKind: dpkgKind, Package: "libssl3", DBVersion: "3.0.15-2"},
		},
		PackageLedger: []LedgerEntry{
			{Name: "nginx", Version: "1.27.0-1", FileListPresent: true},
			{Name: "libssl3", Version: "3.0.15-2", FileListPresent: true},
			{Name: "gzip", Version: "1.12-1", FileListPresent: true},
		},
		PkgDBs: []PkgDBGenerationInfo{{DBKind: dpkgKind}},
	}
	wv := computeWindowValidity(rec)

	libssl3Verdict := assignVerdict(*libssl3, rec, Case{}, "observed", wv)
	if libssl3Verdict.Verdict == VerdictConfirmed {
		t.Errorf("libssl3 verdict = confirmed, want not confirmed: the observed version (3.0.15-2) does not match Trivy's InstalledVersion (3.0.13-1)")
	}
	if len(libssl3Verdict.VersionMismatchPaths) != 1 || libssl3Verdict.VersionMismatchPaths[0] != "/usr/lib/x86_64-linux-gnu/libssl.so.3" {
		t.Errorf("libssl3 VersionMismatchPaths = %v, want [/usr/lib/x86_64-linux-gnu/libssl.so.3]", libssl3Verdict.VersionMismatchPaths)
	}

	gzipVerdict := assignVerdict(*gzip, rec, Case{}, "observed", wv)
	if gzipVerdict.Verdict != VerdictUnobserved || gzipVerdict.Factor != factorNoObserved {
		t.Errorf("gzip verdict = (%s, %s), want (unobserved, no_observation)", gzipVerdict.Verdict, gzipVerdict.Factor)
	}

	packages := []PackageVerdict{libssl3Verdict, gzipVerdict}
	overall, _, _, _, _, _, _ := aggregate(packages)
	if overall.FindingDenominator != 3 {
		t.Errorf("overall Finding-unit denominator = %d, want 3 (deduplicated)", overall.FindingDenominator)
	}
	if overall.FindingConfirmed != 0 {
		t.Errorf("overall Finding-unit confirmed = %d, want 0 (version mismatch and no_observation both fail to confirm)", overall.FindingConfirmed)
	}
}

// TestInspectFailedContainerStaysInThePopulation covers the first rule of
// the decision table at its sharpest: a container the Docker API could not
// inspect at all produces no samples, and every Finding of its image must
// come back not_determined. Refusing such a record instead would drop the
// whole image from the denominator, which is the bias the rule exists to
// prevent — a run that cannot observe would report a better confirmation
// rate than one that can.
func TestInspectFailedContainerStaysInThePopulation(t *testing.T) {
	scan, err := scanner.ParseReport([]byte(syntheticTrivyReport))
	if err != nil {
		t.Fatalf("ParseReport: %v", err)
	}
	rec := ContainerRecord{
		Subject:      Subject{Runtime: "docker", Docker: DockerSubject{ContainerID: "c9"}},
		RunKey:       RunKey{CaseVariant: "INSPECT-FAIL", Permission: "none", Interval: 30, Window: 300, Replicate: 1},
		InspectError: "GET /containers/c9/json: status 500 Internal Server Error",
	}
	wv := computeWindowValidity(&rec)
	if state := observationState(&rec, wv); state != "observation_failed" {
		t.Fatalf("observationState = %q, want observation_failed", state)
	}

	groups := groupFindings(scan.Findings)
	packages := make([]PackageVerdict, 0, len(groups))
	for _, g := range groups {
		pv := assignVerdict(g, &rec, Case{}, "observation_failed", wv)
		if pv.Verdict != VerdictNotDetermined {
			t.Errorf("%s: verdict = %q, want not_determined", pv.Package, pv.Verdict)
		}
		if pv.Factor == "" {
			t.Errorf("%s: a not_determined verdict must name the failure that caused it", pv.Package)
		}
		packages = append(packages, pv)
	}
	overall, _, _, _, _, _, _ := aggregate(packages)
	if overall.FindingDenominator != 3 {
		t.Errorf("Finding denominator = %d, want 3: an unobservable container keeps its image's Findings in the population", overall.FindingDenominator)
	}
	if overall.FindingObservationFailed != 3 {
		t.Errorf("observation_failed Findings = %d, want 3", overall.FindingObservationFailed)
	}
	if overall.ConditionalRate != -1 {
		t.Errorf("conditional rate = %v, want N/A: the conditional denominator is empty here", overall.ConditionalRate)
	}
}
