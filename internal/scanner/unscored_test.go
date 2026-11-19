package scanner

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

// fakeSeverities is a SeveritySource that records what it was asked.
type fakeSeverities struct {
	stated map[string]string
	asked  [][]string
}

func (f *fakeSeverities) Severities(_ context.Context, ids []string) map[string]string {
	f.asked = append(f.asked, append([]string(nil), ids...))
	out := map[string]string{}
	for _, id := range ids {
		if s := f.stated[id]; s != "" {
			out[id] = s
		}
	}
	return out
}

func TestScanSeverity(t *testing.T) {
	src := &fakeSeverities{}
	cases := []struct {
		configured []string
		src        SeveritySource
		want       string
	}{
		{nil, nil, "HIGH,CRITICAL"},
		{nil, src, "HIGH,CRITICAL,UNKNOWN"},
		{[]string{"MEDIUM", "HIGH", "CRITICAL"}, src, "MEDIUM,HIGH,CRITICAL,UNKNOWN"},
		{[]string{"unknown", "HIGH"}, src, "unknown,HIGH"},
		{[]string{"HIGH,UNKNOWN"}, src, "HIGH,UNKNOWN"},
		{[]string{"UNKNOWN", "HIGH"}, nil, "UNKNOWN,HIGH"},
	}
	for _, tc := range cases {
		tr := Trivy{Severity: tc.configured}
		if tc.src != nil {
			tr.Unscored = tc.src
		}
		if got := tr.scanSeverity(); got != tc.want {
			t.Errorf("scanSeverity(%v, source %v) = %q, want %q", tc.configured, tc.src != nil, got, tc.want)
		}
	}
}

func ids(findings []Finding) []string {
	var out []string
	for _, f := range findings {
		out = append(out, f.VulnID+"/"+f.Package+"="+string(f.Severity))
	}
	return out
}

func TestFillUnscored(t *testing.T) {
	findings := []Finding{
		{VulnID: "CVE-2026-123007", Package: "nginx", Severity: "UNKNOWN"},
		{VulnID: "CVE-2026-123007", Package: "nginx-module-njs", Severity: "UNKNOWN"},
		{VulnID: "CVE-2026-121757", Package: "libc6", Severity: "UNKNOWN"},
		{VulnID: "CVE-2026-91094", Package: "dpkg", Severity: "UNKNOWN"},
		{VulnID: "TEMP-0000000-A338F9", Package: "tar", Severity: "UNKNOWN"},
		{VulnID: "CVE-2026-15176", Package: "nginx", Severity: "HIGH"},
		// Trivy's own severity stands, whatever the source would say.
		{VulnID: "CVE-2026-0002", Package: "zlib", Severity: "CRITICAL"},
	}
	stated := map[string]string{
		"CVE-2026-123007": "CRITICAL",
		"CVE-2026-121757": "MEDIUM",
		"CVE-2026-0002":   "LOW",
	}

	t.Run("without a source nothing changes", func(t *testing.T) {
		got := Trivy{}.fillUnscored(context.Background(), findings)
		if !reflect.DeepEqual(got, findings) {
			t.Errorf("findings changed: %v", ids(got))
		}
	})
	t.Run("high and critical", func(t *testing.T) {
		src := &fakeSeverities{stated: stated}
		got := Trivy{Unscored: src}.fillUnscored(context.Background(), findings)
		want := []string{
			"CVE-2026-123007/nginx=CRITICAL",
			"CVE-2026-123007/nginx-module-njs=CRITICAL",
			"CVE-2026-15176/nginx=HIGH",
			"CVE-2026-0002/zlib=CRITICAL",
		}
		if !reflect.DeepEqual(ids(got), want) {
			t.Errorf("findings = %v, want %v", ids(got), want)
		}
		// Asked once, for the UNKNOWN findings' IDs only, each once.
		wantAsked := [][]string{{"CVE-2026-121757", "CVE-2026-123007", "CVE-2026-91094", "TEMP-0000000-A338F9"}}
		if !reflect.DeepEqual(src.asked, wantAsked) {
			t.Errorf("asked = %v, want %v", src.asked, wantAsked)
		}
		// The input is not modified.
		if findings[0].Severity != "UNKNOWN" {
			t.Error("the input findings were modified")
		}
	})
	t.Run("medium configured", func(t *testing.T) {
		tr := Trivy{Severity: []string{"MEDIUM", "HIGH", "CRITICAL"}, Unscored: &fakeSeverities{stated: stated}}
		got := ids(tr.fillUnscored(context.Background(), findings))
		if len(got) != 5 || got[2] != "CVE-2026-121757/libc6=MEDIUM" {
			t.Errorf("findings = %v", got)
		}
	})
	t.Run("unknown configured keeps what nothing was stated for", func(t *testing.T) {
		tr := Trivy{Severity: []string{"UNKNOWN", "HIGH", "CRITICAL"}, Unscored: &fakeSeverities{stated: stated}}
		got := ids(tr.fillUnscored(context.Background(), findings))
		want := []string{
			"CVE-2026-123007/nginx=CRITICAL",
			"CVE-2026-123007/nginx-module-njs=CRITICAL",
			// MEDIUM is stated for CVE-2026-121757 and is not configured.
			"CVE-2026-91094/dpkg=UNKNOWN",
			"TEMP-0000000-A338F9/tar=UNKNOWN",
			"CVE-2026-15176/nginx=HIGH",
			"CVE-2026-0002/zlib=CRITICAL",
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("findings = %v, want %v", got, want)
		}
	})
	t.Run("nothing unknown asks nothing", func(t *testing.T) {
		src := &fakeSeverities{stated: stated}
		in := findings[5:]
		got := Trivy{Unscored: src}.fillUnscored(context.Background(), in)
		if !reflect.DeepEqual(got, in) || len(src.asked) != 0 {
			t.Errorf("findings = %v, asked = %v", ids(got), src.asked)
		}
	})
}

const unscoredReportJSON = `{"ArtifactName":"nginx:1.30-alpine","Trivy":{"Version":"0.71.2"},"Results":[
 {"Target":"nginx:1.30-alpine (alpine 3.24.4)","Class":"os-pkgs","Type":"alpine",
  "Vulnerabilities":[
   {"VulnerabilityID":"CVE-2026-123007","PkgName":"nginx","InstalledVersion":"1.30.6-r1","FixedVersion":"1.30.7-r0","Status":"fixed","Severity":"UNKNOWN"},
   {"VulnerabilityID":"CVE-2026-121757","PkgName":"musl","InstalledVersion":"1.2.6-r3","Status":"affected","Severity":"UNKNOWN"},
   {"VulnerabilityID":"CVE-2026-125350","PkgName":"libxslt","InstalledVersion":"1.1.43-r3","FixedVersion":"1.1.43-r4","Status":"fixed","Severity":"HIGH"}]}]}`

func TestScan_FillsUnscoredSeverity(t *testing.T) {
	argsFile := t.TempDir() + "/args"
	bin := writeFakeTrivy(t, argsFile, unscoredReportJSON, false)
	src := &fakeSeverities{stated: map[string]string{"CVE-2026-123007": "CRITICAL", "CVE-2026-121757": "MEDIUM"}}
	scan := Trivy{BinPath: bin, Unscored: src}.Scan(context.Background(), refTarget("nginx:1.30-alpine"))
	if scan.Err != nil {
		t.Fatal(scan.Err)
	}
	want := []string{"CVE-2026-123007/nginx=CRITICAL", "CVE-2026-125350/libxslt=HIGH"}
	if !reflect.DeepEqual(ids(scan.Findings), want) {
		t.Errorf("findings = %v, want %v", ids(scan.Findings), want)
	}
	args := strings.Split(strings.TrimSpace(read(t, argsFile)), "\n")
	found := false
	for i, a := range args {
		if a == "--severity" && i+1 < len(args) {
			found = args[i+1] == "HIGH,CRITICAL,UNKNOWN"
		}
	}
	if !found {
		t.Errorf("trivy was not asked for UNKNOWN findings: %v", args)
	}

	// Without a source the same report keeps its UNKNOWN findings as Trivy
	// gave them (Trivy itself filters by --severity) and asks for no more.
	scan = Trivy{BinPath: bin}.Scan(context.Background(), refTarget("nginx:1.30-alpine"))
	if len(scan.Findings) != 3 {
		t.Errorf("without a source findings = %v", ids(scan.Findings))
	}
	if args := read(t, argsFile); !strings.Contains(args, "\nHIGH,CRITICAL\n") {
		t.Errorf("without a source the severities passed changed: %q", args)
	}
}

func TestUnscoredIsPartOfTheConditions(t *testing.T) {
	f := newFSFake(t, strings.Replace(unscoredReportJSON, `"ArtifactName":"nginx:1.30-alpine"`, `"ArtifactName":"/x"`, 1))
	cache := t.TempDir()
	writeCache(t, cache)
	ctx := context.Background()
	src := &fakeSeverities{stated: map[string]string{"CVE-2026-123007": "CRITICAL"}}
	plain := Trivy{BinPath: f.bin, CacheDir: cache, SkipDBUpdate: true}
	filling := plain
	filling.Unscored = src

	plainConds, err := plain.PrepareDB(ctx)
	if err != nil {
		t.Fatal(err)
	}
	fillConds, err := filling.PrepareDB(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if plainConds.Equal(fillConds) {
		t.Fatal("conditions with and without the severity source compare as equal")
	}
	if !reflect.DeepEqual(plainConds.Severities, fillConds.Severities) {
		t.Errorf("the configured severities differ: %v and %v", plainConds.Severities, fillConds.Severities)
	}
	if ok, err := filling.VerifyDB(ctx, fillConds); err != nil || !ok {
		t.Errorf("VerifyDB = %v, %v", ok, err)
	}
	if ok, _ := plain.VerifyDB(ctx, fillConds); ok {
		t.Error("a scanner without the source verified conditions prepared with it")
	}

	files := map[string][]byte{"requirements.txt": []byte("a==1\n")}
	// A scanner must not be compared with conditions of the other kind.
	if _, err := plain.ScanFS(ctx, files, fillConds); !errors.Is(err, ErrConditionsDiffer) {
		t.Errorf("fs scan without the source under conditions with it: err = %v", err)
	}
	if _, err := filling.ScanFS(ctx, files, plainConds); !errors.Is(err, ErrConditionsDiffer) {
		t.Errorf("fs scan with the source under conditions without it: err = %v", err)
	}
	res, err := filling.ScanFS(ctx, files, fillConds)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"CVE-2026-123007/nginx=CRITICAL", "CVE-2026-125350/libxslt=HIGH"}
	if !reflect.DeepEqual(ids(res.Report.Findings), want) {
		t.Errorf("fs findings = %v, want %v", ids(res.Report.Findings), want)
	}
	lines := readLog(t, f.log)
	if last := lines[len(lines)-1]; !strings.Contains(last, "--severity HIGH,CRITICAL,UNKNOWN ") {
		t.Errorf("the fs scan was not asked for UNKNOWN findings: %s", last)
	}
	if !strings.HasPrefix(res.Conditions.AnalysisSettings, "fs;") || !strings.HasSuffix(res.Conditions.AnalysisSettings, unscoredSetting) {
		t.Errorf("fs analysis settings = %q", res.Conditions.AnalysisSettings)
	}
}
