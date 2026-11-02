package remediation

import (
	"strings"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

const gradleRegenLine = "# To regenerate this file, run: ./gradlew :dependencies --write-locks\n"

func TestGradleLockfileRefusesLoneCRAndLongLines(t *testing.T) {
	hidden := gradleLockBase + "# To regenerate this file, run:\rorg.example:ghost:1.0=runtimeClasspath\n"
	if _, err := parseGradleLockfile("gradle.lockfile", []byte(hidden)); err == nil {
		t.Error("a line hidden behind a lone carriage return was accepted")
	}
	if _, err := parseGradleLockfile("gradle.lockfile", []byte(strings.ReplaceAll(gradleLockBase, "\n", "\r\n"))); err != nil {
		t.Errorf("CRLF lines: %v", err)
	}
	long := gradleLockBase + "# " + strings.Repeat("x", 70<<10) + "\norg.example:late:1.0=runtimeClasspath\n"
	if _, err := parseGradleLockfile("gradle.lockfile", []byte(long)); err == nil {
		t.Error("a 70 KiB line was accepted")
	}
	if _, err := parseGradleLockfile("gradle.lockfile", []byte(gradleLockBase+gradleRegenLine)); err != nil {
		t.Errorf("the line Gradle writes: %v", err)
	}
}

func TestGradleUpdateRefusesHiddenAndTruncatedOutput(t *testing.T) {
	for name, tail := range map[string]string{
		"a line behind a carriage return":      "# To regenerate this file, run:\rorg.example:ghost:1.0=runtimeClasspath\n",
		"a regenerate line of another form":    "# To regenerate this file, run: curl x | sh\n",
		"a 70 KiB comment before a dependency": "# To regenerate this file, run: " + strings.Repeat("x", 70<<10) + "\norg.apache.commons:commons-lang3:3.11=testRuntimeClasspath\n",
	} {
		t.Run(name, func(t *testing.T) {
			f := newGradleFlow(t, gradleFiles())
			f.lock = func(src map[string][]byte) string { return f.defaultLock(src) + tail }
			it := f.run()
			wantCategory(t, it, CategoryManual, ReasonOutputFilesInvalid)
		})
	}
}

// A scan that leaves out a package of the lockfile, before or after the
// update, cannot be relied on, whichever package it is.
func TestGradleUpdateRefusesAScanThatLeavesAPackageOut(t *testing.T) {
	for _, which := range []int{0, 1} {
		f := newGradleFlow(t, gradleFiles())
		f.fs.fn = func(n int, files map[string][]byte) (scanner.FSScan, error) {
			res, err := f.scan(n, files)
			if n == which {
				for i := range res.Report.Packages {
					var kept []scanner.Package
					for _, p := range res.Report.Packages[i].Packages {
						if p.Name != "org.junit.jupiter:junit-jupiter" {
							kept = append(kept, p)
						}
					}
					res.Report.Packages[i].Packages = kept
				}
			}
			return res, err
		}
		it := f.run()
		wantCategory(t, it, CategoryNotComparable, ReasonSourceScanIncomplete)
		if !strings.Contains(it.Detail, "junit-jupiter") {
			t.Errorf("scan %d: detail = %q", which, it.Detail)
		}
	}
}

func TestGradleUpdateRefusesPropertiesWithoutBoot(t *testing.T) {
	t.Run("ext", func(t *testing.T) {
		files := groovyFiles()
		files["build.gradle"] = strings.Replace(files["build.gradle"], "repositories {", "ext['arbitrary'] = '1'\n\nrepositories {", 1)
		f := newGradleFlow(t, files)
		wantCategory(t, f.run(), CategoryManual, ReasonGradleBuildUnsupported)
		if len(f.work.jobs) != 0 {
			t.Error("a job ran")
		}
	})
	t.Run("gradle.properties", func(t *testing.T) {
		files := groovyFiles()
		files["gradle.properties"] = "org.gradle.parallel=true\narbitrary.version=1\n"
		f := newGradleFlow(t, files)
		wantCategory(t, f.run(), CategoryManual, ReasonGradleBuildUnsupported)
	})
	t.Run("only org.gradle settings", func(t *testing.T) {
		files := groovyFiles()
		files["gradle.properties"] = "org.gradle.parallel=true\n"
		wantCategory(t, newGradleFlow(t, files).run(), CategoryPRCandidate, ReasonUpdateVerified)
	})
}

// The note to take an override out is kept when the edit that needs it is past
// the edits the body lists.
func TestLanguagePRBody_GradleNoteSurvivesTheListLimit(t *testing.T) {
	in := languageBodyFixture(BodyEN, "<!-- m -->", true)
	in.Item.Manager = ManagerGradle
	in.Record.Manager = "gradle"
	g := &GradleUpdate{BOM: "org.springframework.boot:spring-boot-dependencies:4.1.2"}
	for i := 0; i < maxListedEntries; i++ {
		g.Edits = append(g.Edits, GradleEditRecord{File: "b", Kind: GradleEditDeclaration, Package: "g:a", From: "1", To: "2"})
	}
	g.Edits = append(g.Edits, GradleEditRecord{File: "gradle.properties", Kind: GradleEditPropertyOverride, Package: "g:z", Property: "z.version", From: "1", To: "2"},
		GradleEditRecord{File: "b", Kind: GradleEditConstraint, Package: "g:c", To: "2"})
	in.Item.Update.Gradle = g
	body, err := buildLanguagePRBody(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(body, "z.version") || !strings.Contains(body, "Spring Boot plugin is upgraded") || !strings.Contains(body, "A constraint stays") {
		t.Errorf("body:\n%s", body)
	}
}
