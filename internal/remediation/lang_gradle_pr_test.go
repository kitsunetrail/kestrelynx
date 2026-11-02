package remediation

import (
	"context"
	"strings"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/worker"
)

func gradlePRFixture() langFixture {
	pkg := npmPackage("org.apache.commons:commons-lang3", "3.11", "3.18.0", "CVE-LANG", "svc/gradle.lockfile")
	pkg.Ecosystem = "jar"
	return langFixture{
		manager: ManagerGradle, root: "svc",
		files: map[string]string{
			"svc/gradle.lockfile": gradleLockBase, "svc/build.gradle.kts": "// build\n", "svc/settings.gradle.kts": "// settings\n",
			"svc/gradle/wrapper/gradle-wrapper.properties": wrapper982,
		},
		updated: map[string]string{
			"svc/gradle.lockfile":   strings.Replace(gradleLockBase, "commons-lang3:3.11=", "commons-lang3:3.18.0=", 1),
			"svc/gradle.properties": "commons-lang3.version=3.18.0\n",
		},
		pkgs: []LanguagePackage{pkg},
	}
}

// A Gradle update may write a gradle.properties the plan looked for and did
// not find; any other file it did not read is still refused.
func TestPRStageGradleWritesAPropertiesFileThePlanDidNotFind(t *testing.T) {
	fx := gradlePRFixture()
	h := langHarness(t, fx)
	item := h.langItem(fx)
	item.Source.Absent = []string{"svc/gradle.properties"}
	item.Update.Gradle = &GradleUpdate{Edits: []GradleEditRecord{{File: "svc/gradle.properties", Kind: GradleEditPropertyOverride, Package: "org.apache.commons:commons-lang3", Property: "commons-lang3.version", From: "3.11", To: "3.18.0"}}}
	res := h.run(prLangPlan(item))
	u := onlyUnit(t, res)
	wantStatus(t, u, PRStatusCreated, "")
	pr := h.gh.pulls(testRepo)[0]
	f, err := h.gh.ReadFile(context.Background(), testRepo, pr.HeadSHA, "svc/gradle.properties")
	if err != nil || string(f.Content) != "commons-lang3.version=3.18.0\n" {
		t.Fatalf("gradle.properties on the branch: %q %v", f.Content, err)
	}
	m, err := parsePRMarker(pr.Body)
	if err != nil || m.Lang == nil || m.Lang.Manager != "gradle" || len(m.Changes) != 2 || m.verify(testRepoID) != nil {
		t.Fatalf("marker %+v err %v", m, err)
	}
	for _, want := range []string{"`commons-lang3.version`", "gradle.lockfile", "--write-locks"} {
		if !strings.Contains(pr.Body, want) {
			t.Errorf("the body lacks %q:\n%s", want, pr.Body)
		}
	}

	other := h.langItem(fx)
	other.Update.Gradle = item.Update.Gradle
	h2 := langHarness(t, fx)
	wantStatus(t, onlyUnit(t, h2.run(prLangPlan(other))), PRStatusFailed, ReasonArtifactsUnusable)
}

func TestLanguagePRBody_Gradle(t *testing.T) {
	for _, lang := range []BodyLanguage{BodyEN, BodyJA} {
		in := languageBodyFixture(lang, "<!-- marker -->", true)
		in.Item.Manager = ManagerGradle
		in.LockPath = "svc/gradle.lockfile"
		in.Files = []FileChange{{Path: "svc/gradle.lockfile"}}
		in.Record.Manager = "gradle"
		in.Record.Chain, in.Record.ManifestEdits, in.Record.Tool = nil, nil, nil
		in.Record.Runtime = &RuntimeRecord{ID: "gradle9.8.2-jdk17", Version: "9.8.2", Image: "gradle@sha256:" + strings.Repeat("c", 64)}
		in.Item.Update.Diff = nil
		in.Item.Update.Steps = []UpdateStep{{ID: "update", Op: "gradle.update_locks"}}
		in.Item.Update.Runtime = in.Record.Runtime
		in.Item.Update.Gradle = &GradleUpdate{
			BOM: "org.springframework.boot:spring-boot-dependencies:4.1.2",
			Edits: []GradleEditRecord{
				{File: "svc/build.gradle.kts", Kind: GradleEditDeclaration, Package: "org.apache.commons:commons-text", From: "1.9", To: "1.10.0"},
				{File: "svc/gradle.properties", Kind: GradleEditPropertyOverride, Package: "org.yaml:snakeyaml", Property: "snakeyaml.version", From: "2.6", To: "2.7"},
				{File: "svc/build.gradle.kts", Kind: GradleEditConstraint, Package: "org.apache.commons:commons-lang3", To: "3.18.0"},
				{File: "svc/gradle/libs.versions.toml", Kind: GradleEditCatalogVersion, Package: "org.apache.commons:commons-text", Property: "text", From: "1.9", To: "1.10.0"},
				{File: "svc/gradle/libs.versions.toml", Kind: GradleEditCatalogLibrary, Package: "org.example:lib", From: "1", To: "2"},
				{File: "svc/gradle.properties", Kind: GradleEditProperty, Package: "org.yaml:snakeyaml", Property: "snakeyaml.version", From: "2.6", To: "2.7"},
			},
			Companions: []GradleCompanion{{Key: "snakeyaml.version", Value: "2.7", Packages: []string{"org.yaml:snakeyaml-engine"}}},
			Moves:      []GradleMove{{Name: "org.example:new", To: []string{"1.0"}}, {Name: "org.example:up", From: []string{"1"}, To: []string{"2"}}},
		}
		body, err := buildLanguagePRBody(in)
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{"`snakeyaml.version`", "`2.7`", "`org.yaml:snakeyaml-engine`", "`org.example:new`", "`1.10.0`", "`org.apache.commons:commons-lang3`",
			"`./gradlew dependencies && ./gradlew build`", "--write-locks", "--update-locks", "Maven Central", "`9.8.2`", "gradle.update_locks"} {
			if !strings.Contains(body, want) {
				t.Errorf("%s: the body lacks %q:\n%s", lang, want, body)
			}
		}
		for _, not := range []string{"no record of them", "installs from the lockfile", "Maven update", "Maven の更新", "%!"} {
			if strings.Contains(body, not) {
				t.Errorf("%s: the body says %q:\n%s", lang, not, body)
			}
		}
	}
}

func TestSplitByWorkSendsGradleToTheWorkContainers(t *testing.T) {
	plan := &Plan{LanguageItems: []LanguageItem{{Manager: ManagerNpm}, {Manager: ManagerMaven}, {Manager: ManagerGradle}, {Manager: ManagerGo}}}
	work, alone := SplitByWork(plan, []int{0, 1, 2, 3})
	if len(work) != 3 || work[0] != 0 || work[1] != 2 || work[2] != 3 || len(alone) != 1 || alone[0] != 1 {
		t.Errorf("work %v, alone %v", work, alone)
	}
}

func TestGradleMarkerRecord(t *testing.T) {
	rec := LangRecord{Manager: "gradle", Packages: []LangKeyEntry{{Ecosystem: "jar", Name: "a:b", Adopted: "2"}},
		Remaining: []LangRemaining{{Ecosystem: "jar", Name: "c:d", Reason: ReasonGradleVersionSourceUnsupported}}}
	if err := rec.wellFormed(); err != nil {
		t.Fatal(err)
	}
	rec.Manager = "gradel"
	if rec.wellFormed() == nil {
		t.Error("an unknown manager is well formed")
	}
}

// An update of a Gradle project is made by this program's edits and one
// gradle.update_locks job: the manager is not one of the chain updates, and
// the scanner type of its lockfile is Trivy's gradle.
func TestGradleIsNotAChainUpdateAndHasAScanType(t *testing.T) {
	up, err := NewLangUpdater(withTestTools(t, LangUpdateConfig{Scanner: &fakeFS{}, Work: &fakeWork{}, PyPI: &fakePyPI{}, Npm: &fakeNpm{}, GitHub: ghFor(nil), MaxJobs: 1}))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := up.chainRunners[ManagerGradle]; ok {
		t.Error("Gradle has a chain runner")
	}
	if sourceScanTypes[ManagerGradle] != "gradle" {
		t.Errorf("scan type = %q", sourceScanTypes[ManagerGradle])
	}
}

func TestExpectedOutputsOfAGradleJobAreItsInputs(t *testing.T) {
	job := worker.Job{Manager: worker.ManagerGradle, Inputs: []worker.Input{{Path: "gradle.lockfile"}, {Path: "gradle/libs.versions.toml"}, {Path: "build.gradle"}}}
	got := expectedOutputs(job, worker.OpGradleUpdateLocks)
	if strings.Join(got, ",") != "build.gradle,gradle.lockfile,gradle/libs.versions.toml" {
		t.Errorf("outputs = %v", got)
	}
	if got := expectedOutputs(worker.Job{Manager: worker.ManagerGo}, worker.OpGoGet); strings.Join(got, ",") != "go.mod,go.sum" {
		t.Errorf("go outputs = %v", got)
	}
}

// A manager the update does not know is an error, not the Gradle default.
func TestUpdateRunRefusesUnknownManagers(t *testing.T) {
	f := newGradleFlow(t, gradleFiles())
	f.item.Manager = "nuget"
	it := f.run()
	if it.Category != CategoryFailed || it.Reason != ReasonUpdateInputInvalid {
		t.Errorf("item = %s %s (%s)", it.Category, it.Reason, it.Detail)
	}
}
