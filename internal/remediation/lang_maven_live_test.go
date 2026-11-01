package remediation

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

// TestMavenUpdateLive updates a Spring Boot 2.7.0 project against the real
// Maven Central and a real Trivy: the scans go through the relay, and the
// fixes of Tomcat and Jackson come from overriding the parent's properties.
// It runs only when KESTRELYNX_MAVEN_IT=1 (KESTRELYNX_TRIVY_BIN and
// KESTRELYNX_TRIVY_CACHE as in the other integration tests).
func TestMavenUpdateLive(t *testing.T) {
	if os.Getenv("KESTRELYNX_MAVEN_IT") != "1" {
		t.Skip("set KESTRELYNX_MAVEN_IT=1 to update a pom against Maven Central with a real Trivy")
	}
	home, _ := os.UserHomeDir()
	bin := os.Getenv("KESTRELYNX_TRIVY_BIN")
	if bin == "" {
		bin = filepath.Join(home, ".local", "bin", "trivy")
	}
	cache := os.Getenv("KESTRELYNX_TRIVY_CACHE")
	if cache == "" {
		cache = filepath.Join(home, ".cache", "trivy")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	tr := scanner.Trivy{BinPath: bin, Severity: []string{"HIGH", "CRITICAL"}, CacheDir: cache, SkipDBUpdate: true}
	prepared, err := tr.CurrentConditions(ctx)
	if err != nil {
		t.Fatalf("trivy conditions: %v", err)
	}
	pom := `<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <parent>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-parent</artifactId>
    <version>2.7.0</version>
    <relativePath/>
  </parent>
  <groupId>com.example</groupId>
  <artifactId>demo</artifactId>
  <version>0.0.1-SNAPSHOT</version>
  <dependencies>
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
  </dependencies>
</project>
`
	reg := &MavenClient{}
	// The findings of the original pom, as the plan would have taken them
	// from the running image.
	relay, err := startMavenRelay(reg, newMavenPOMCache(), map[string]string{"com.example:demo": "0.0.1-SNAPSHOT"}, maxMavenRelayRequests)
	if err != nil {
		t.Fatal(err)
	}
	base, err := tr.ScanFSWith(ctx, map[string][]byte{"pom.xml": []byte(pom)}, prepared, scanner.FSOptions{MavenMirror: relay.URL()})
	relay.Close()
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if p := relay.Problems(); len(p) > 0 {
		t.Fatalf("relay problems: %v", p)
	}
	groups := map[string]*findingGroup{}
	for _, f := range base.Report.Findings {
		if f.Type != "pom" || f.FixedVer == "" {
			continue
		}
		if f.Package != "org.apache.tomcat.embed:tomcat-embed-core" && f.Package != "com.fasterxml.jackson.core:jackson-databind" {
			continue
		}
		g := groups[f.Package]
		if g == nil {
			g = &findingGroup{Type: typeJar, Name: f.Package, Installed: f.InstalledVer}
			groups[f.Package] = g
		}
		g.cves = append(g.cves, CVERef{VulnID: f.VulnID, Severity: f.Severity, FixedVers: splitFixed(f.FixedVer)})
	}
	var pkgs []LanguagePackage
	for _, g := range groups {
		target, reason, detail := chooseMavenTarget(g.Installed, g.cves)
		if reason != "" {
			t.Logf("%s %s: %s (%s)", g.Name, g.Installed, reason, detail)
			continue
		}
		p := LanguagePackage{Name: g.Name, Ecosystem: typeJar, Installed: g.Installed, CVEs: g.cves, SelectionLowerBound: target,
			Action: ActionUpdate, Reason: ReasonUpdateCandidateInSource, Relation: RelationTransitive}
		pkgs = append(pkgs, p)
	}
	if len(pkgs) == 0 {
		t.Fatalf("no package to update among %d findings", len(base.Report.Findings))
	}
	src := SourceRecord{Repository: "o/r", BaseBranch: "main", Directory: ".", CommitSHA: testCommit, Origin: OriginConfig, Confidence: ConfidenceAsserted,
		Files: []SourceFile{{Path: "pom.xml", BlobSHA: gitBlobSHA([]byte(pom))}}}
	it := LanguageItem{Key: "deps:o/r@main:.#maven", Workloads: []string{"compose/p/web"}, Manager: ManagerMaven, Source: src, Packages: pkgs}
	classify(&it)
	up, err := NewLangUpdater(LangUpdateConfig{Scanner: tr, Work: &fakeWork{}, PyPI: &fakePyPI{}, Npm: &fakeNpm{}, Maven: reg,
		GitHub: ghFor(map[string]string{"pom.xml": pom}), Prepared: prepared, MaxJobs: 1})
	if err != nil {
		t.Fatal(err)
	}
	plan := &Plan{LanguageItems: []LanguageItem{it}}
	up.Run(ctx, plan)
	got := plan.LanguageItems[0]
	if got.Category != CategoryPRCandidate {
		t.Fatalf("category = %s %s (%s)", got.Category, got.Reason, got.Detail)
	}
	for _, e := range got.Update.Maven.Edits {
		t.Logf("edit: %+v", e)
		if e.Kind != MavenEditPropertyOverride {
			t.Errorf("edit %+v is not an override of the parent's property", e)
		}
	}
	for _, p := range got.Packages {
		t.Logf("%s %s -> %s", p.Name, p.Installed, p.AdoptedVersion)
	}
	t.Logf("resolved %d, remaining %d, introduced %d", got.SourceCheck.Counts[0], got.SourceCheck.Counts[1], got.SourceCheck.Counts[2])
	t.Logf("moves: %+v", got.Update.Maven.Moves)
	t.Logf("pom:\n%s", got.Artifacts[0].Content)
	if !strings.Contains(string(got.Artifacts[0].Content), "<properties>") {
		t.Error("no properties block")
	}
}
