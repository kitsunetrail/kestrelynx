package remediation

import (
	"errors"
	"path"
	"reflect"
	"strings"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/github"
)

const springKotlin = `plugins {
	java
	id("org.springframework.boot") version "4.1.2"
	id("io.spring.dependency-management") version "1.1.7"
}

group = "com.example"
version = "0.0.1-SNAPSHOT"
description = "demo"

java {
	toolchain {
		languageVersion = JavaLanguageVersion.of(17)
	}
}

repositories {
	mavenCentral()
}

dependencies {
	implementation("org.springframework.boot:spring-boot-starter-webmvc")
	testImplementation("org.springframework.boot:spring-boot-starter-webmvc-test")
	testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.withType<Test> {
	useJUnitPlatform()
}

dependencyLocking {
	lockAllConfigurations()
	lockMode = LockMode.STRICT
}
`

const groovyJava = `plugins {
	id 'java'
	id 'org.springframework.boot' version '4.1.2'
	id 'io.spring.dependency-management' version '1.1.7'
}

group = 'com.example'
version = '0.0.1-SNAPSHOT'

java {
	toolchain {
		languageVersion = JavaLanguageVersion.of(21)
	}
}

configurations {
	compileOnly {
		extendsFrom annotationProcessor
	}
}

repositories {
	mavenCentral()
}

ext['snakeyaml.version'] = '2.7'
ext.foo = '1.0'

dependencies {
	implementation 'org.apache.commons:commons-text:1.9'
	implementation('com.google.guava:guava')
	testImplementation 'org.junit.jupiter:junit-jupiter:5.10.0'
	constraints {
		implementation 'org.yaml:snakeyaml:2.7'
	}
}

test {
	useJUnitPlatform()
}

dependencyLocking {
	lockAllConfigurations(); lockMode = LockMode.STRICT
}
`

func mustCatalog(t *testing.T, src string) *gradleCatalog {
	t.Helper()
	c, err := parseGradleCatalog("gradle/libs.versions.toml", []byte(src))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

const catalogToml = `[versions]
text = "1.9"
boot = "4.1.2"

[libraries]
commons-text = { module = "org.apache.commons:commons-text", version.ref = "text" }
guava = "com.google.guava:guava:33.0.0-jre"
jackson-core = { group = "com.fasterxml.jackson.core", name = "jackson-core" }

[bundles]
apache = ["commons-text", "guava"]

[plugins]
boot = { id = "org.springframework.boot", version.ref = "boot" }
`

func reasonOf(err error) Reason {
	var ue *UnsupportedError
	if errors.As(err, &ue) {
		return ue.Reason
	}
	return ""
}

func TestGradleLexer(t *testing.T) {
	toks, err := lexGradle([]byte("a = \"x\" // c\n/* b\n */ b('y')\n"), false)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, k := range toks {
		got = append(got, k.text)
	}
	if want := []string{"a", "=", "x", "b", "(", "y", ")"}; !reflect.DeepEqual(got, want) {
		t.Errorf("tokens = %v", got)
	}
	if !toks[3].nl || toks[3].line != 3 {
		t.Errorf("b = %+v, want a line break before it on line 3", toks[3])
	}
	for name, c := range map[string]struct {
		src    string
		kotlin bool
	}{
		"interpolation": {`a = "x$y"`, false},
		"braces":        {`a = "${y}"`, false},
		"single dollar": {`a = 'x$y'`, false},
		"kotlin single": {`a = 'x'`, true},
		"triple":        {`a = """x"""`, true},
		"unclosed":      {`a = "x`, false},
		"comment":       {`/* x`, false},
		"escape":        {`a = "x\n"`, false},
		"foreign":       {"a = \u00e9", false},
		"unbalanced":    {`a(`, false},
		"closing":       {`}`, false},
		"mismatch":      {`a(]`, false},
		"block no head": {`{ a }`, false},
		"deep":          {strings.Repeat("a {", 10) + strings.Repeat("}", 10), false},
	} {
		toks, err := lexGradle([]byte(c.src), c.kotlin)
		if err == nil {
			_, err = readGradleStmts(toks)
		}
		if err == nil {
			t.Errorf("%s: accepted %q", name, c.src)
		}
	}
}

func TestGradleRecognizerAccepts(t *testing.T) {
	cat := mustCatalog(t, catalogToml)
	t.Run("kotlin template", func(t *testing.T) {
		s, err := recognizeGradleScript("build.gradle.kts", []byte(springKotlin), false, nil, "9.8.2")
		if err != nil {
			t.Fatal(err)
		}
		if s.toolchain != 17 || len(s.plugins) != 3 || len(s.decls) != 3 || !s.declared("org.springframework.boot:spring-boot-starter-webmvc") {
			t.Errorf("script = %+v", s)
		}
		if s.plugins[1] != (gradlePluginUse{id: "org.springframework.boot", version: "4.1.2"}) {
			t.Errorf("plugins = %+v", s.plugins)
		}
	})
	t.Run("groovy", func(t *testing.T) {
		s, err := recognizeGradleScript("build.gradle", []byte(groovyJava), false, nil, "9.8.2")
		if err != nil {
			t.Fatal(err)
		}
		if s.toolchain != 21 || len(s.props) != 2 || s.props[0].Name != "snakeyaml.version" || s.props[1].Name != "foo" {
			t.Errorf("script = %+v", s)
		}
		if s.declared("org.yaml:snakeyaml") || !s.declared("com.google.guava:guava") {
			t.Errorf("decls = %+v", s.decls)
		}
	})
	t.Run("catalog references", func(t *testing.T) {
		src := "dependencies {\n implementation(libs.commons.text)\n runtimeOnly(libs.bundles.apache)\n api(libs.jackson.core)\n}\ndependencyLocking { lockAllConfigurations(); lockMode = LockMode.STRICT }\n"
		s, err := recognizeGradleScript("build.gradle.kts", []byte(src), false, cat, "8.14.6")
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, d := range s.decls {
			got = append(got, d.conf+" "+d.name+" "+d.version+" "+d.catalog)
		}
		want := []string{
			"implementation org.apache.commons:commons-text 1.9 commons-text",
			"runtimeOnly org.apache.commons:commons-text 1.9 commons-text",
			"runtimeOnly com.google.guava:guava 33.0.0-jre guava",
			"api com.fasterxml.jackson.core:jackson-core  jackson-core",
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("decls = %q", got)
		}
	})
	t.Run("forms", func(t *testing.T) {
		for name, src := range map[string]string{
			"semicolons":      "plugins { java; id(\"org.springframework.boot\") version \"4.1.2\" }; dependencyLocking { lockMode = LockMode.STRICT; lockAllConfigurations() }",
			"java-library":    "plugins { `java-library`; application }\ndependencyLocking { lockAllConfigurations(); lockMode = LockMode.STRICT }",
			"id java":         "plugins { id(\"java\") }\ndependencyLocking { lockAllConfigurations(); lockMode = LockMode.STRICT }",
			"named test":      "tasks.named<Test>(\"test\") { useJUnitPlatform() }\ndependencyLocking { lockAllConfigurations(); lockMode = LockMode.STRICT }",
			"compatibility":   "java { sourceCompatibility = JavaVersion.VERSION_17; targetCompatibility = JavaVersion.VERSION_17 }\ndependencyLocking { lockAllConfigurations(); lockMode = LockMode.STRICT }",
			"kotlin config":   "configurations { compileOnly { extendsFrom(configurations.annotationProcessor.get()) } }\ndependencyLocking { lockAllConfigurations(); lockMode = LockMode.STRICT }",
			"extra":           "extra[\"snakeyaml.version\"] = \"2.7\"\ndependencyLocking { lockAllConfigurations(); lockMode = LockMode.STRICT }",
			"developmentOnly": "plugins { id(\"org.springframework.boot\") version \"4.1.2\" }\ndependencies { developmentOnly(\"org.springframework.boot:spring-boot-devtools\") }\ndependencyLocking { lockAllConfigurations(); lockMode = LockMode.STRICT }",
		} {
			if _, err := recognizeGradleScript("build.gradle.kts", []byte(src), false, nil, "9.8.2"); err != nil {
				t.Errorf("%s: %v", name, err)
			}
		}
	})
}

func TestGradleRecognizerRefuses(t *testing.T) {
	cat := mustCatalog(t, catalogToml)
	lock := "dependencyLocking { lockAllConfigurations(); lockMode = LockMode.STRICT }\n"
	for name, c := range map[string]struct {
		file, src, gradle string
		want              Reason
	}{
		"no locking":       {"build.gradle.kts", "plugins { java }\n", "9.8.2", ReasonGradleLockingUnenforced},
		"default mode":     {"build.gradle.kts", "dependencyLocking { lockAllConfigurations(); lockMode = LockMode.DEFAULT }\n", "9.8.2", ReasonGradleLockingUnenforced},
		"lenient":          {"build.gradle.kts", "dependencyLocking { lockAllConfigurations(); lockMode = LockMode.LENIENT }\n", "9.8.2", ReasonGradleLockingUnenforced},
		"no lock all":      {"build.gradle.kts", "dependencyLocking { lockMode = LockMode.STRICT }\n", "9.8.2", ReasonGradleLockingUnenforced},
		"no mode":          {"build.gradle.kts", "dependencyLocking { lockAllConfigurations() }\n", "9.8.2", ReasonGradleLockingUnenforced},
		"ignored":          {"build.gradle.kts", "dependencyLocking { lockAllConfigurations(); lockMode = LockMode.STRICT; ignoredDependencies.add(\"a:*\") }\n", "9.8.2", ReasonGradleLockingUnenforced},
		"mode twice":       {"build.gradle.kts", "dependencyLocking { lockAllConfigurations(); lockMode = LockMode.STRICT; lockMode = LockMode.LENIENT }\n", "9.8.2", ReasonGradleLockingUnenforced},
		"locking twice":    {"build.gradle.kts", lock + lock, "9.8.2", ReasonGradleLockingUnenforced},
		"unknown plugin":   {"build.gradle.kts", "plugins { id(\"com.example.x\") version \"1.0\" }\n" + lock, "9.8.2", ReasonGradlePluginUnsupported},
		"boot version":     {"build.gradle.kts", "plugins { id(\"org.springframework.boot\") version \"4.1.1\" }\n" + lock, "9.8.2", ReasonGradlePluginUnsupported},
		"boot gradle":      {"build.gradle.kts", "plugins { id(\"org.springframework.boot\") version \"4.1.2\" }\n" + lock, "8.14.6", ReasonGradlePluginUnsupported},
		"no version":       {"build.gradle.kts", "plugins { id(\"org.springframework.boot\") }\n" + lock, "9.8.2", ReasonGradlePluginUnsupported},
		"alias":            {"build.gradle.kts", "plugins { alias(libs.plugins.boot) }\n" + lock, "9.8.2", ReasonGradlePluginUnsupported},
		"variable ver":     {"build.gradle.kts", "plugins { id(\"org.springframework.boot\") version bootVersion }\n" + lock, "9.8.2", ReasonGradlePluginUnsupported},
		"plugin template":  {"build.gradle.kts", "plugins { id(\"org.springframework.boot\") version \"$v\" }\n" + lock, "9.8.2", ReasonGradleBuildUnsupported},
		"settings plugin":  {"build.gradle.kts", "plugins { id(\"org.gradle.toolchains.foojay-resolver-convention\") version \"1.0.0\" }\n" + lock, "9.8.2", ReasonGradlePluginUnsupported},
		"apply from":       {"build.gradle", "apply from: 'other.gradle'\n" + lock, "9.8.2", ReasonGradleBuildUnsupported},
		"buildscript":      {"build.gradle.kts", "buildscript { repositories { mavenCentral() } }\n" + lock, "9.8.2", ReasonGradleBuildUnsupported},
		"allprojects":      {"build.gradle.kts", "allprojects { }\n" + lock, "9.8.2", ReasonGradleBuildUnsupported},
		"subprojects":      {"build.gradle.kts", "subprojects { }\n" + lock, "9.8.2", ReasonGradleBuildUnsupported},
		"resolution":       {"build.gradle.kts", "configurations.all { resolutionStrategy { force(\"a:b:1\") } }\n" + lock, "9.8.2", ReasonGradleBuildUnsupported},
		"resolution in":    {"build.gradle.kts", "configurations { all { resolutionStrategy { } } }\n" + lock, "9.8.2", ReasonGradleBuildUnsupported},
		"dep management":   {"build.gradle.kts", "dependencyManagement { imports { } }\n" + lock, "9.8.2", ReasonGradleBuildUnsupported},
		"interpolation":    {"build.gradle.kts", "dependencies { implementation(\"a:b:$v\") }\n" + lock, "9.8.2", ReasonGradleBuildUnsupported},
		"interp braces":    {"build.gradle", "dependencies { implementation \"a:b:${v}\" }\n" + lock, "9.8.2", ReasonGradleBuildUnsupported},
		"other repo":       {"build.gradle.kts", "repositories { maven { url = uri(\"https://example.com\") } }\n" + lock, "9.8.2", ReasonGradleBuildUnsupported},
		"google":           {"build.gradle.kts", "repositories { mavenCentral(); google() }\n" + lock, "9.8.2", ReasonGradleBuildUnsupported},
		"other conf":       {"build.gradle.kts", "dependencies { kapt(\"a:b:1\") }\n" + lock, "9.8.2", ReasonGradleBuildUnsupported},
		"developmentOnly":  {"build.gradle.kts", "dependencies { developmentOnly(\"a:b:1\") }\n" + lock, "9.8.2", ReasonGradleBuildUnsupported},
		"platform":         {"build.gradle.kts", "dependencies { implementation(platform(\"a:b:1\")) }\n" + lock, "9.8.2", ReasonGradleBuildUnsupported},
		"classifier":       {"build.gradle.kts", "dependencies { implementation(\"a:b:1:c\") }\n" + lock, "9.8.2", ReasonGradleBuildUnsupported},
		"dynamic":          {"build.gradle.kts", "dependencies { implementation(\"a:b:1.+\") }\n" + lock, "9.8.2", ReasonGradleBuildUnsupported},
		"range":            {"build.gradle.kts", "dependencies { implementation(\"a:b:[1,2)\") }\n" + lock, "9.8.2", ReasonGradleBuildUnsupported},
		"closure":          {"build.gradle.kts", "dependencies { implementation(\"a:b:1\") { isTransitive = false } }\n" + lock, "9.8.2", ReasonGradleBuildUnsupported},
		"unknown alias":    {"build.gradle.kts", "dependencies { implementation(libs.nope) }\n" + lock, "9.8.2", ReasonGradleBuildUnsupported},
		"kotlin no paren":  {"build.gradle.kts", "dependencies { implementation \"a:b:1\" }\n" + lock, "9.8.2", ReasonGradleBuildUnsupported},
		"task":             {"build.gradle.kts", "tasks.withType<Test> { jvmArgs(\"-javaagent:x.jar\") }\n" + lock, "9.8.2", ReasonGradleBuildUnsupported},
		"val":              {"build.gradle.kts", "val x = 1\n" + lock, "9.8.2", ReasonGradleBuildUnsupported},
		"extra variable":   {"build.gradle.kts", "extra[\"a\"] = x\n" + lock, "9.8.2", ReasonGradleBuildUnsupported},
		"toolchain vend":   {"build.gradle.kts", "java { toolchain { languageVersion = JavaLanguageVersion.of(17); vendor = JvmVendorSpec.ADOPTIUM } }\n" + lock, "9.8.2", ReasonGradleBuildUnsupported},
		"settings include": {"settings.gradle", "include 'a'\n", "9.8.2", ReasonGradleBuildUnsupported},
		"include build":    {"settings.gradle.kts", "includeBuild(\"x\")\n", "9.8.2", ReasonGradleBuildUnsupported},
		"settings repo":    {"settings.gradle.kts", "pluginManagement { repositories { maven { } } }\n", "9.8.2", ReasonGradleBuildUnsupported},
		"foojay":           {"settings.gradle.kts", "plugins { id(\"org.gradle.toolchains.foojay-resolver-convention\") version \"1.0.0\" }\n", "9.8.2", ReasonGradlePluginUnsupported},
		"settings dep":     {"settings.gradle.kts", "dependencyResolutionManagement { }\n", "9.8.2", ReasonGradleBuildUnsupported},
	} {
		settings := strings.HasPrefix(c.file, "settings")
		_, err := recognizeGradleScript(c.file, []byte(c.src), settings, cat, c.gradle)
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if got := reasonOf(err); got != c.want {
			t.Errorf("%s: reason = %q (%v), want %q", name, got, err, c.want)
		}
	}
	// A refusal names the file, the line and the statement.
	_, err := recognizeGradleScript("svc/build.gradle.kts", []byte("plugins { java }\n\nval x = 1\n"+lock), false, nil, "9.8.2")
	if d := err.(*UnsupportedError).Detail; !strings.Contains(d, "svc/build.gradle.kts:3") || !strings.Contains(d, "val x = 1") {
		t.Errorf("detail = %q", d)
	}
}

func TestGradleSettingsAccepts(t *testing.T) {
	for file, src := range map[string]string{
		"settings.gradle":     "rootProject.name = 'demo'\n",
		"settings.gradle.kts": "pluginManagement { repositories { gradlePluginPortal(); mavenCentral() } }\nrootProject.name = \"demo\"\n",
	} {
		s, err := recognizeGradleScript(file, []byte(src), true, nil, "9.8.2")
		if err != nil || s.rootName != "demo" {
			t.Errorf("%s: %v %+v", file, err, s)
		}
	}
}

func TestGradleProperties(t *testing.T) {
	ok := "# c\norg.gradle.parallel=true\norg.gradle.caching = false\norg.gradle.daemon:false\norg.gradle.configuration-cache true\n" +
		"org.gradle.jvmargs=-Xmx2g -Xms512m -XX:MaxMetaspaceSize=256m -Dfile.encoding=UTF-8\nsnakeyaml.version=2.7\n"
	got, err := parseGradleProperties("gradle.properties", []byte(ok))
	if err != nil || len(got) != 1 || got[0] != (GradleProperty{Name: "snakeyaml.version", Value: "2.7", File: "gradle.properties"}) {
		t.Fatalf("got %+v, %v", got, err)
	}
	for name, src := range map[string]string{
		"javaagent":    "org.gradle.jvmargs=-javaagent:/x.jar\n",
		"classpath":    "org.gradle.jvmargs=-cp /x\n",
		"other -D":     "org.gradle.jvmargs=-Dx=y\n",
		"unknown key":  "org.gradle.java.home=/x\n",
		"systemProp":   "systemProp.http.proxyHost=x\n",
		"bad bool":     "org.gradle.parallel=yes\n",
		"bool twice":   "org.gradle.parallel=true\norg.gradle.parallel=false\n",
		"continuation": "org.gradle.jvmargs=-Xmx1g \\\n -Xms1g\n",
		"escape":       "org.gradle.jvmargs=\\u0041\n",
		"version bad":  "a.version=$x\n",
		"empty jvm":    "org.gradle.jvmargs=\n",
		"random":       "foo=bar\n",
	} {
		if _, err := parseGradleProperties("gradle.properties", []byte(src)); reasonOf(err) != ReasonGradleBuildUnsupported {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestGradleWrapper(t *testing.T) {
	for src, want := range map[string]string{
		"distributionUrl=https\\://services.gradle.org/distributions/gradle-9.8.2-bin.zip\n":                                                                 "9.8.2",
		"distributionBase=GRADLE_USER_HOME\ndistributionUrl=https\\://services.gradle.org/distributions/gradle-8.14.6-all.zip\nzipStorePath=wrapper/dists\n": "8.14.6",
		"distributionUrl = https\\://services.gradle.org/distributions/gradle-9.0-bin.zip":                                                                   "9.0",
	} {
		if got, err := parseGradleWrapper("w", []byte(src)); err != nil || got != want {
			t.Errorf("%q: %q, %v", src, got, err)
		}
	}
	for name, src := range map[string]string{
		"missing":   "distributionBase=GRADLE_USER_HOME\n",
		"host":      "distributionUrl=https\\://example.com/gradle-9.8.2-bin.zip\n",
		"http":      "distributionUrl=http\\://services.gradle.org/distributions/gradle-9.8.2-bin.zip\n",
		"snapshot":  "distributionUrl=https\\://services.gradle.org/distributions/gradle-9.9-20260101-bin.zip\n",
		"twice":     "distributionUrl=https\\://services.gradle.org/distributions/gradle-9.8.2-bin.zip\ndistributionUrl=https\\://services.gradle.org/distributions/gradle-9.8.2-all.zip\n",
		"unescaped": "distributionUrl=https://services.gradle.org/distributions/gradle-9.8.2-bin.zip\ndistributionSha=\\u0041\n",
	} {
		if _, err := parseGradleWrapper("w", []byte(src)); reasonOf(err) != ReasonUnsupportedSource {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestGradleLockfile(t *testing.T) {
	src := "# This is a Gradle generated file for dependency locking.\n\n" +
		"a.b:c:1.0=compileClasspath,runtimeClasspath\na.b:c:2.0=testRuntimeClasspath\nx:y:3=runtimeClasspath\nempty=annotationProcessor,testAnnotationProcessor\n"
	l, err := parseGradleLockfile("gradle.lockfile", []byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if len(l.entries) != 3 || len(l.byName["a.b:c"]) != 2 || !l.configs["annotationProcessor"] || !l.configs["compileClasspath"] || !reflect.DeepEqual(l.empty, []string{"annotationProcessor", "testAnnotationProcessor"}) {
		t.Errorf("lock = %+v", l)
	}
	if l.entries[0].inRuntime() != true || l.entries[1].inRuntime() != false {
		t.Errorf("inRuntime wrong: %+v", l.entries)
	}
	for name, src := range map[string]string{
		"no equals":   "a:b:1\n",
		"two parts":   "a:b=compileClasspath\n",
		"four parts":  "a:b:1:c=compileClasspath\n",
		"no confs":    "a:b:1=\n",
		"bad conf":    "a:b:1=compile Classpath\n",
		"duplicate":   "a:b:1=compileClasspath\na:b:1=runtimeClasspath\n",
		"two empties": "empty=a\nempty=b\n",
		"space":       "a: b:1=compileClasspath\n",
	} {
		if _, err := parseGradleLockfile("gradle.lockfile", []byte(src)); reasonOf(err) != ReasonUnparsableSource {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestGradleCatalog(t *testing.T) {
	c := mustCatalog(t, catalogToml)
	ls, err := c.expand("commons.text")
	if err != nil || len(ls) != 1 || ls[0].version != "1.9" || ls[0].versionRef != "text" || ls[0].group != "org.apache.commons" {
		t.Errorf("commons.text = %+v, %v", ls, err)
	}
	if ls, err := c.expand("bundles.apache"); err != nil || len(ls) != 2 {
		t.Errorf("bundle = %+v, %v", ls, err)
	}
	if ls, _ := c.expand("jackson.core"); ls[0].version != "" {
		t.Errorf("jackson.core = %+v", ls)
	}
	for _, bad := range []string{"versions.text", "plugins.boot", "nope", "bundles.nope"} {
		if _, err := c.expand(bad); err == nil {
			t.Errorf("expand(%q) succeeded", bad)
		}
	}
	for name, src := range map[string]string{
		"rich version":  "[libraries]\na = { module = \"g:a\", version = { strictly = \"1\" } }\n",
		"range":         "[versions]\nv = \"[1,2)\"\n",
		"number":        "[versions]\nv = 1\n",
		"unknown key":   "[libraries]\na = { module = \"g:a\", version = \"1\", classifier = \"x\" }\n",
		"missing ref":   "[libraries]\na = { module = \"g:a\", version.ref = \"nope\" }\n",
		"metadata":      "[metadata]\nformat.version = \"1.1\"\n",
		"bad bundle":    "[bundles]\nb = [\"nope\"]\n",
		"module both":   "[libraries]\na = { module = \"g:a\", group = \"g\", name = \"a\" }\n",
		"plugin rich":   "[plugins]\np = { id = \"x\", version = { strictly = \"1\" } }\n",
		"library short": "[libraries]\na = \"g:a\"\n",
	} {
		if _, err := parseGradleCatalog("c.toml", []byte(src)); reasonOf(err) != ReasonGradleBuildUnsupported {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := parseGradleCatalog("c.toml", []byte("[versions\n")); reasonOf(err) != ReasonUnparsableSource {
		t.Errorf("syntax error: %v", err)
	}
	c = mustCatalog(t, catalogToml)
	if !c.pluginVersionRefs["boot"] || c.pluginVersionRefs["text"] {
		t.Errorf("pluginVersionRefs = %v", c.pluginVersionRefs)
	}
}

func TestGradlePluginRuleAllows(t *testing.T) {
	r := gradlePluginRule{id: "x", versions: []string{"1.0.0", "1.2.0"}, gradles: []string{"8.14.6", "9.8.2"}}
	for _, c := range []struct {
		v, g string
		want bool
	}{{"1.0.0", "8.14.6", true}, {"1.2.0", "9.8.2", true}, {"1.1.0", "9.8.2", false}, {"1.0.0.0", "9.8.2", false}, {"1.0.0.RELEASE", "9.8.2", false}, {"1.0.0", "9.8.2.0", false}, {"1.0.0", "9.0", false}} {
		if got := r.allows(c.v, c.g); got != c.want {
			t.Errorf("allows(%s, %s) = %v", c.v, c.g, got)
		}
	}
	if (gradlePluginRule{id: "x"}).allows("1.0", "9.0") {
		t.Error("a rule with no versions allows a combination")
	}
	for _, r := range gradlePluginTable {
		if r.id == "org.gradle.toolchains.foojay-resolver-convention" && r.allows("1.0.0", "9.8.2") {
			t.Error("the toolchain resolver is allowed before a combination was checked")
		}
	}
}

func TestGradleLexerCommentsAndLineEnds(t *testing.T) {
	lock := "dependencyLocking { lockAllConfigurations(); lockMode = LockMode.STRICT }"
	hidden := "/* a /* b */ " + lock + " */\n"
	for _, c := range []struct {
		name, file, src string
		want            Reason
	}{
		// In Kotlin the whole of a nested comment is a comment.
		{"kotlin nested comment", "build.gradle.kts", hidden, ReasonGradleLockingUnenforced},
		// In Groovy the first */ ends the comment, and what follows is code.
		{"groovy comment does not nest", "build.gradle", hidden, ReasonGradleBuildUnsupported},
		{"lone CR kotlin", "build.gradle.kts", "// c\rdependencyLocking { lockAllConfigurations(); lockMode = LockMode.LENIENT }\n" + lock, ReasonGradleBuildUnsupported},
		{"lone CR groovy", "build.gradle", "// c\rdependencyLocking { lockMode = LockMode.LENIENT }\n" + lock, ReasonGradleBuildUnsupported},
		{"trailing CR", "build.gradle", lock + "\r", ReasonGradleBuildUnsupported},
	} {
		_, err := recognizeGradleScript(c.file, []byte(c.src), false, nil, "9.8.2")
		if reasonOf(err) != c.want {
			t.Errorf("%s: %v, want %s", c.name, err, c.want)
		}
	}
	// CRLF is a line break.
	crlf := strings.ReplaceAll("plugins {\n\tjava\n}\n// c\n"+lock+"\n", "\n", "\r\n")
	if _, err := recognizeGradleScript("build.gradle.kts", []byte(crlf), false, nil, "9.8.2"); err != nil {
		t.Errorf("CRLF: %v", err)
	}
	if _, err := recognizeGradleScript("build.gradle.kts", []byte("/* open /* nested */ "+lock), false, nil, "9.8.2"); reasonOf(err) != ReasonGradleBuildUnsupported {
		t.Errorf("an unclosed nested comment: %v", err)
	}
}

func TestGradlePropertiesLineEndsAndEscapes(t *testing.T) {
	for name, src := range map[string]string{
		"lone CR":      "# c\rorg.gradle.jvmargs=-javaagent:x\n",
		"trailing CR":  "org.gradle.parallel=true\r",
		"continuation": "org.gradle.parallel=true\\\nfalse\n",
		"escaped key":  "org.gradle.jvm\\u0061rgs=-Xmx1g\n",
		"escaped sep":  "snakeyaml.version=1\\:2\n",
		"version dup":  "a.version=1\na.version=2\n",
		"dup":          "org.gradle.daemon=true\norg.gradle.daemon=true\n",
	} {
		if _, err := parseGradleProperties("gradle.properties", []byte(src)); reasonOf(err) != ReasonGradleBuildUnsupported {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := parseGradleProperties("gradle.properties", []byte("org.gradle.parallel=true\r\nsnakeyaml.version=2.7\r\n")); err != nil {
		t.Errorf("CRLF: %v", err)
	}
	url := "distributionUrl=https\\://services.gradle.org/distributions/gradle-9.8.2-bin.zip"
	for name, src := range map[string]string{
		"lone CR":       "# c\r" + url + "\n",
		"hidden second": url + "\n# c\rdistributionUrl=https\\://example.com/x.zip\n",
		"continuation":  url + "\\\n",
		"duplicate key": "networkTimeout=1\nnetworkTimeout=2\n" + url + "\n",
		"other escape":  url + "\nzipStorePath=a\\=b\n",
	} {
		if _, err := parseGradleWrapper("w", []byte(src)); reasonOf(err) != ReasonUnsupportedSource {
			t.Errorf("%s: %v", name, err)
		}
	}
	if got, err := parseGradleWrapper("w", []byte(url+"\r\n")); err != nil || got != "9.8.2" {
		t.Errorf("CRLF: %q, %v", got, err)
	}
}

func TestGradleCatalogAccessorCollisions(t *testing.T) {
	for name, src := range map[string]string{
		"versions": "[versions]\nset-one = \"1\"\nset_one = \"2\"\n",
		"bundles":  "[libraries]\na = \"g:a:1\"\n[bundles]\nset-one = [\"a\"]\nset_one = [\"a\"]\n",
		"plugins":  "[plugins]\nset-one = \"x.y:1\"\nset_one = \"x.z:1\"\n",
		"libs":     "[libraries]\nset-one = \"g:a:1\"\nset_one = \"g:b:1\"\n",
	} {
		if _, err := parseGradleCatalog("c.toml", []byte(src)); reasonOf(err) != ReasonGradleBuildUnsupported {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestGradleDirectDependsOnConfiguration(t *testing.T) {
	lock, err := parseGradleLockfile("gradle.lockfile", []byte(
		"org.apache.commons:commons-lang3:3.11=compileClasspath,productionRuntimeClasspath,runtimeClasspath\n"+
			"org.apache.commons:commons-lang3:3.12.0=testCompileClasspath,testRuntimeClasspath\n"+
			"org.apache.commons:commons-text:1.9=compileClasspath,productionRuntimeClasspath,runtimeClasspath,testCompileClasspath,testRuntimeClasspath\n"+
			"a:dev:1=runtimeClasspath\na:rt:1=productionRuntimeClasspath,runtimeClasspath,testRuntimeClasspath\na:co:1=compileClasspath\n"+
			"a:ap:1=annotationProcessor,compileClasspath,runtimeClasspath\n"))
	if err != nil {
		t.Fatal(err)
	}
	declared := map[string][]string{
		"org.apache.commons:commons-text":  {"implementation"},
		"org.apache.commons:commons-lang3": {"testImplementation"},
		"a:dev":                            {"developmentOnly"},
		"a:rt":                             {"runtimeOnly"},
		"a:co":                             {"compileOnly"},
		"a:ap":                             {"annotationProcessor"},
	}
	for _, c := range []struct {
		name, ver string
		rel       Relation
		manual    bool
	}{
		{"org.apache.commons:commons-text", "1.9", RelationDirect, false},
		{"org.apache.commons:commons-lang3", "3.11", RelationTransitive, false},
		{"a:rt", "1", RelationDirect, false},
		{"a:co", "1", RelationDirect, false},
		{"a:ap", "1", RelationTransitive, false},
		{"a:dev", "1", "", true},
	} {
		g := &findingGroup{Name: c.name, Type: typeJar, Installed: c.ver, cves: []CVERef{{VulnID: "CVE-1", FixedVers: []string{strings.SplitN(c.ver, ".", 2)[0] + ".99"}}}}
		p := gradleMatch(lock, declared, false, "gradle.lockfile", g)
		if c.manual {
			if p.Action != ActionManual || p.Reason != ReasonGradleBuildUnsupported {
				t.Errorf("%s = %+v", c.name, p)
			}
			continue
		}
		if p.Action != ActionUpdate || p.Relation != c.rel {
			t.Errorf("%s = %s %s (%s), want %s", c.name, p.Action, p.Relation, p.Detail, c.rel)
		}
	}
}

func TestLanguagePlan_GradleScriptTricksRefusedWholeUnit(t *testing.T) {
	kts := func(m map[string]string) string { return m["build.gradle.kts"] }
	lockBlock := "dependencyLocking {\n\tlockAllConfigurations()\n\tlockMode = LockMode.STRICT\n}\n"
	cases := []struct {
		name string
		edit func(map[string]string)
		want Reason
	}{
		{"locking in a nested comment", func(m map[string]string) {
			m["build.gradle.kts"] = strings.Replace(kts(m), lockBlock, "/* x /* y */ "+lockBlock+" */\n", 1)
		}, ReasonGradleLockingUnenforced},
		{"statement behind a lone CR", func(m map[string]string) {
			m["build.gradle.kts"] = strings.Replace(kts(m), lockBlock, "// c\rdependencyLocking { lockMode = LockMode.LENIENT }\n"+lockBlock, 1)
		}, ReasonGradleBuildUnsupported},
		{"plugin version equal by ordering", func(m map[string]string) {
			m["build.gradle.kts"] = strings.Replace(kts(m), "\"4.1.2\"", "\"4.1.2.RELEASE\"", 1)
		}, ReasonGradlePluginUnsupported},
		{"dependency-management version equal by ordering", func(m map[string]string) {
			m["build.gradle.kts"] = strings.Replace(kts(m), "\"1.1.7\"", "\"1.1.7.0\"", 1)
		}, ReasonGradlePluginUnsupported},
		{"agent behind a lone CR in properties", func(m map[string]string) {
			m["gradle.properties"] = "# c\rorg.gradle.jvmargs=-javaagent:x.jar\n"
		}, ReasonGradleBuildUnsupported},
		{"second distributionUrl behind a lone CR", func(m map[string]string) {
			m["gradle/wrapper/gradle-wrapper.properties"] = wrapper982 + "# c\rdistributionUrl=https\\://example.com/x.zip\n"
		}, ReasonUnsupportedSource},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			files := gradleFiles()
			c.edit(files)
			it, ok := gradlePlanItem(t, files)
			if !ok || it.Category != CategoryManual || it.Reason != c.want {
				t.Fatalf("item = %s %s (%s), want manual %s", it.Category, it.Reason, it.Detail, c.want)
			}
			for _, p := range it.Packages {
				if p.Action != ActionManual {
					t.Errorf("package = %+v", p)
				}
			}
		})
	}
}

// gradleRepo puts the files of a Gradle project in dir of ex/app. A path with
// a directory part is put in that directory, which is listed in its parent.
func gradleRepo(gh *fakeGitHub, dir string, files map[string]string) {
	listed := map[string]bool{}
	for p, content := range files {
		d, name := path.Split(p)
		d = strings.TrimSuffix(d, "/")
		at := dir
		if d != "" {
			at = pathIn(dir, d)
		}
		gh.put("ex/app", at, name, content)
		for d != "" && d != "." {
			parent, base := path.Split(d)
			parent = strings.TrimSuffix(parent, "/")
			if !listed[d] {
				listed[d] = true
				in := dir
				if parent != "" {
					in = pathIn(dir, parent)
				}
				gh.putEntry("ex/app", in, github.Entry{Name: base, Type: github.EntryDir, SHA: "d"})
			}
			d = parent
		}
	}
}

const wrapper982 = "distributionBase=GRADLE_USER_HOME\ndistributionUrl=https\\://services.gradle.org/distributions/gradle-9.8.2-bin.zip\n"

const gradleLockBase = `# This is a Gradle generated file for dependency locking.
# Manual edits can break the build and are not advised.
# This file is expected to be part of source control.
org.apache.commons:commons-lang3:3.11=compileClasspath,productionRuntimeClasspath,runtimeClasspath
org.apache.commons:commons-text:1.9=compileClasspath,productionRuntimeClasspath,runtimeClasspath
org.junit.jupiter:junit-jupiter:5.10.0=testCompileClasspath,testRuntimeClasspath
org.springframework.boot:spring-boot-starter-webmvc:4.1.2=compileClasspath,productionRuntimeClasspath,runtimeClasspath
empty=annotationProcessor,testAnnotationProcessor
`

// gradleFiles is a project of the start.spring.io Kotlin template with the
// locking block and a direct dependency on commons-text.
func gradleFiles() map[string]string {
	return map[string]string{
		"gradle.lockfile":                          gradleLockBase,
		"build.gradle.kts":                         strings.Replace(springKotlin, "\timplementation(\"org.springframework.boot:spring-boot-starter-webmvc\")", "\timplementation(\"org.springframework.boot:spring-boot-starter-webmvc\")\n\timplementation(\"org.apache.commons:commons-text:1.9\")", 1),
		"settings.gradle.kts":                      "rootProject.name = \"demo\"\n",
		"gradle/wrapper/gradle-wrapper.properties": wrapper982,
	}
}

func gradleInput() ImageInput {
	return fatJarInput(
		jarFinding("CVE-TEXT", bootLib+"commons-text-1.9.jar", "org.apache.commons:commons-text", "1.9", "1.10.0"),
		jarFinding("CVE-LANG", bootLib+"commons-lang3-3.11.jar", "org.apache.commons:commons-lang3", "3.11", "3.18.0"),
		jarFinding("CVE-JCT", bootLib+"netty-common-4.1.77.Final.jar", "org.jctools:jctools-core", "3.1.0", "3.1.1"),
		jarFinding("CVE-YAML", bootLib+"snakeyaml-1.30.jar", "org.yaml:snakeyaml", "1.30", "1.31"),
		jarFinding("CVE-JUNIT", bootLib+"junit-jupiter-5.10.0.jar", "org.junit.jupiter:junit-jupiter", "5.10.0", "5.10.2"),
		jarFinding("CVE-LOMBOK", bootLib+"lombok-1.18.30.jar", "org.projectlombok:lombok", "1.18.30", "1.18.32"),
	)
}

func gradlePlanItem(t *testing.T, files map[string]string, extra ...func(*fakeGitHub)) (LanguageItem, bool) {
	t.Helper()
	gh := newFakeGitHub()
	gradleRepo(gh, "svc", files)
	for _, f := range extra {
		f(gh)
	}
	plan := langPlan(t, gh, []DependencyMapping{depMapping("compose/shop/api", "ex/app", "svc")}, nil, gradleInput())
	for _, it := range plan.LanguageItems {
		if it.Manager == ManagerGradle || it.Manager == ManagerMaven {
			return it, true
		}
	}
	return LanguageItem{}, false
}

func TestLanguagePlan_GradleCandidate(t *testing.T) {
	it, ok := gradlePlanItem(t, gradleFiles())
	if !ok {
		t.Fatal("no Gradle item")
	}
	if it.Manager != ManagerGradle || it.Category != CategoryDependencyUpdateCandidate || it.Key != "deps:ex/app@main:svc#gradle" {
		t.Fatalf("item = %s %s %s (%s)", it.Key, it.Category, it.Reason, it.Detail)
	}
	if g := it.Gradle; g == nil || g.Version != "9.8.2" || g.Toolchain != 17 || g.BootVersion != "4.1.2" || !g.DependencyManagement {
		t.Errorf("gradle = %+v", g)
	}
	got := pkgsByName(it)
	if p := got["org.apache.commons:commons-text"]; p.Action != ActionUpdate || p.SelectionLowerBound != "1.10.0" || p.Relation != RelationDirect {
		t.Errorf("commons-text = %+v", p)
	}
	if p := got["org.apache.commons:commons-lang3"]; p.Action != ActionUpdate || p.SelectionLowerBound != "3.18.0" || p.Relation != RelationTransitive {
		t.Errorf("commons-lang3 = %+v", p)
	}
	if p := got["org.jctools:jctools-core"]; p.Action != ActionManual || p.Reason != ReasonJarBundled {
		t.Errorf("jctools = %+v", p)
	}
	if p := got["org.yaml:snakeyaml"]; p.Action != ActionManual || p.Reason != ReasonNotFoundInSource {
		t.Errorf("snakeyaml = %+v", p)
	}
	if p := got["org.junit.jupiter:junit-jupiter"]; p.Action != ActionManual || p.Reason != ReasonNotFoundInSource {
		t.Errorf("junit = %+v; a package locked only for tests is not the application's", p)
	}
	var files []string
	for _, f := range it.Source.Files {
		files = append(files, f.Path)
	}
	for _, want := range []string{"svc/gradle.lockfile", "svc/build.gradle.kts", "svc/settings.gradle.kts", "svc/gradle/wrapper/gradle-wrapper.properties"} {
		if !containsString(files, want) {
			t.Errorf("files = %v, want %s", files, want)
		}
	}
	for _, want := range []string{"svc/gradle.properties", "svc/buildSrc", "svc/gradle/dependency-locks", "svc/gradle/libs.versions.toml", "svc/settings.gradle", "svc/build.gradle", "svc/settings-gradle.lockfile", "svc/buildscript-gradle.lockfile"} {
		if !containsString(it.Source.Absent, want) {
			t.Errorf("absent = %v, want %s", it.Source.Absent, want)
		}
	}
	if it.UpdateExecuted || it.PostUpdateCheckExecuted {
		t.Error("a planned Gradle unit is marked as updated")
	}
}

func TestLanguagePlan_GradleCatalogAndProperties(t *testing.T) {
	files := gradleFiles()
	files["build.gradle.kts"] = strings.Replace(springKotlin, "\timplementation(\"org.springframework.boot:spring-boot-starter-webmvc\")", "\timplementation(libs.commons.text)\n\timplementation(\"org.springframework.boot:spring-boot-starter-webmvc\")", 1)
	files["gradle/libs.versions.toml"] = catalogToml
	files["gradle.properties"] = "org.gradle.parallel=true\nsnakeyaml.version=2.7\n"
	it, ok := gradlePlanItem(t, files)
	if !ok || it.Category != CategoryDependencyUpdateCandidate {
		t.Fatalf("item = %+v", it)
	}
	if p := pkgsByName(it)["org.apache.commons:commons-text"]; p.Relation != RelationDirect {
		t.Errorf("commons-text = %+v, want direct through the catalog", p)
	}
	if g := it.Gradle; len(g.Properties) != 1 || g.Properties[0].Name != "snakeyaml.version" {
		t.Errorf("properties = %+v", g.Properties)
	}
	if containsString(it.Source.Absent, "svc/gradle.properties") || containsString(it.Source.Absent, "svc/gradle/libs.versions.toml") {
		t.Errorf("absent = %v", it.Source.Absent)
	}
}

func TestLanguagePlan_GradleGroovy(t *testing.T) {
	files := gradleFiles()
	delete(files, "build.gradle.kts")
	delete(files, "settings.gradle.kts")
	files["build.gradle"] = groovyJava
	files["settings.gradle"] = "rootProject.name = 'demo'\n"
	files["gradle.lockfile"] = strings.Replace(gradleLockBase, "5.10.0=", "5.10.0=", 1)
	it, ok := gradlePlanItem(t, files)
	if !ok || it.Category != CategoryDependencyUpdateCandidate {
		t.Fatalf("item = %+v", it)
	}
	if it.Gradle.Toolchain != 21 || len(it.Gradle.Properties) != 2 {
		t.Errorf("gradle = %+v", it.Gradle)
	}
}

func TestLanguagePlan_GradleUnitRefusals(t *testing.T) {
	withBuild := func(f func(string) string) func(map[string]string) {
		return func(m map[string]string) { m["build.gradle.kts"] = f(m["build.gradle.kts"]) }
	}
	set := func(k, v string) func(map[string]string) { return func(m map[string]string) { m[k] = v } }
	del := func(k string) func(map[string]string) { return func(m map[string]string) { delete(m, k) } }
	repl := func(old, new string) func(map[string]string) {
		return withBuild(func(s string) string {
			if !strings.Contains(s, old) {
				panic("missing " + old)
			}
			return strings.Replace(s, old, new, 1)
		})
	}
	dirEntry := func(name string) func(*fakeGitHub) {
		return func(gh *fakeGitHub) {
			gh.putEntry("ex/app", "svc", github.Entry{Name: name, Type: github.EntryDir, SHA: "d"})
		}
	}
	cases := []struct {
		name  string
		edit  func(map[string]string)
		extra []func(*fakeGitHub)
		want  Reason
	}{
		{"lock mode missing", repl("\tlockMode = LockMode.STRICT\n", ""), nil, ReasonGradleLockingUnenforced},
		{"lock mode default", repl("LockMode.STRICT", "LockMode.DEFAULT"), nil, ReasonGradleLockingUnenforced},
		{"lock mode lenient", repl("LockMode.STRICT", "LockMode.LENIENT"), nil, ReasonGradleLockingUnenforced},
		{"ignored dependencies", repl("\tlockMode = LockMode.STRICT\n", "\tlockMode = LockMode.STRICT\n\tignoredDependencies.add(\"a:b\")\n"), nil, ReasonGradleLockingUnenforced},
		{"no locking block", repl("dependencyLocking {\n\tlockAllConfigurations()\n\tlockMode = LockMode.STRICT\n}\n", ""), nil, ReasonGradleLockingUnenforced},
		{"unknown plugin", repl("id(\"io.spring.dependency-management\") version \"1.1.7\"", "id(\"com.example.x\") version \"1.0\""), nil, ReasonGradlePluginUnsupported},
		{"plugin version", repl("version \"1.1.7\"", "version \"1.1.6\""), nil, ReasonGradlePluginUnsupported},
		{"alias plugin", repl("java\n\tid(\"org.springframework.boot\")", "alias(libs.plugins.boot)\n\tid(\"org.springframework.boot\")"), nil, ReasonGradlePluginUnsupported},
		{"apply from", repl("repositories {", "apply(from = \"x.gradle\")\nrepositories {"), nil, ReasonGradleBuildUnsupported},
		{"buildscript", repl("repositories {", "buildscript { }\nrepositories {"), nil, ReasonGradleBuildUnsupported},
		{"resolution strategy", repl("repositories {", "configurations.all { resolutionStrategy.force(\"a:b:1\") }\nrepositories {"), nil, ReasonGradleBuildUnsupported},
		{"interpolation", repl("\"demo\"", "\"demo-${version}\""), nil, ReasonGradleBuildUnsupported},
		{"gradle 7", set("gradle/wrapper/gradle-wrapper.properties", strings.Replace(wrapper982, "9.8.2", "7.6.4", 1)), nil, ReasonGradleVersionUnsupported},
		{"gradle 10", set("gradle/wrapper/gradle-wrapper.properties", strings.Replace(wrapper982, "9.8.2", "10.0", 1)), nil, ReasonGradleVersionUnsupported},
		{"gradle 8 with boot", set("gradle/wrapper/gradle-wrapper.properties", strings.Replace(wrapper982, "9.8.2", "8.14.6", 1)), nil, ReasonGradlePluginUnsupported},
		{"wrapper url", set("gradle/wrapper/gradle-wrapper.properties", "distributionUrl=https\\://example.com/gradle-9.8.2-bin.zip\n"), nil, ReasonUnsupportedSource},
		{"toolchain 11", repl("of(17)", "of(11)"), nil, ReasonGradleToolchainUnsupported},
		{"toolchain 25 ok", repl("of(17)", "of(25)"), nil, ""},
		{"jvmargs", set("gradle.properties", "org.gradle.jvmargs=-javaagent:/a.jar\n"), nil, ReasonGradleBuildUnsupported},
		{"unknown property", set("gradle.properties", "org.gradle.java.home=/x\n"), nil, ReasonGradleBuildUnsupported},
		{"settings include", set("settings.gradle.kts", "rootProject.name = \"demo\"\ninclude(\"a\")\n"), nil, ReasonGradleBuildUnsupported},
		{"catalog bad", set("gradle/libs.versions.toml", "[versions]\nv = \"[1,2)\"\n"), nil, ReasonGradleBuildUnsupported},
		{"buildSrc", nil, []func(*fakeGitHub){dirEntry("buildSrc")}, ReasonGradleBuildUnsupported},
		{"dependency-locks", set("gradle/dependency-locks/x.lockfile", "a:b:1=compileClasspath\n"), nil, ReasonGradleBuildUnsupported},
		{"both build files", set("build.gradle", "plugins { id 'java' }\n"), nil, ReasonAmbiguousDependencyFile},
		{"both settings files", set("settings.gradle", "rootProject.name = 'x'\n"), nil, ReasonAmbiguousDependencyFile},
		{"no build file", del("build.gradle.kts"), nil, ReasonDependencyFilesNotFound},
		{"no wrapper", del("gradle/wrapper/gradle-wrapper.properties"), nil, ReasonDependencyFilesNotFound},
		{"lockfile without compileClasspath", set("gradle.lockfile", strings.ReplaceAll(gradleLockBase, "compileClasspath,", "")), nil, ReasonGradleLockingUnenforced},
		{"lockfile garbage", set("gradle.lockfile", "# x\nnonsense\n"), nil, ReasonUnparsableSource},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			files := gradleFiles()
			if c.edit != nil {
				c.edit(files)
			}
			it, ok := gradlePlanItem(t, files, c.extra...)
			if !ok {
				t.Fatal("no item")
			}
			if c.want == "" {
				if it.Category != CategoryDependencyUpdateCandidate {
					t.Fatalf("item = %s %s (%s), want a candidate", it.Category, it.Reason, it.Detail)
				}
				return
			}
			if it.Category != CategoryManual || it.Reason != c.want {
				t.Fatalf("item = %s %s (%s), want manual %s", it.Category, it.Reason, it.Detail, c.want)
			}
			for _, p := range it.Packages {
				if p.Action != ActionManual || p.Reason != c.want {
					t.Errorf("package = %+v", p)
				}
			}
		})
	}
}

func TestLanguagePlan_GradleNoLockfileIsManual(t *testing.T) {
	for _, build := range []string{"build.gradle.kts", "build.gradle"} {
		files := gradleFiles()
		files[build] = files["build.gradle.kts"]
		if build == "build.gradle" {
			delete(files, "build.gradle.kts")
		}
		delete(files, "gradle.lockfile")
		it, ok := gradlePlanItem(t, files)
		if !ok || it.Manager != ManagerGradle || it.Category != CategoryManual || it.Reason != ReasonDependencyFilesNotFound {
			t.Fatalf("%s: item = %+v", build, it)
		}
		if !strings.Contains(it.Detail, "gradle.lockfile") || !containsString(it.Source.Absent, "svc/gradle.lockfile") || len(it.Packages) == 0 {
			t.Errorf("%s: detail %q, absent %v, packages %d", build, it.Detail, it.Source.Absent, len(it.Packages))
		}
		for _, p := range it.Packages {
			if p.Action != ActionManual || p.Reason != ReasonDependencyFilesNotFound {
				t.Errorf("package = %+v", p)
			}
		}
	}
	// Without any Gradle file the directory is not a Gradle project.
	files := gradleFiles()
	delete(files, "gradle.lockfile")
	delete(files, "build.gradle.kts")
	if it, ok := gradlePlanItem(t, files); ok {
		t.Fatalf("a directory without a build script or lockfile has an item: %+v", it)
	}
}

func TestLanguagePlan_GradleAndPomIsMaven(t *testing.T) {
	files := gradleFiles()
	files["pom.xml"] = bootPom
	it, ok := gradlePlanItem(t, files)
	if !ok || it.Manager != ManagerMaven {
		t.Fatalf("item = %+v, want the Maven item", it)
	}
}

func TestLanguagePlan_GradleSourceFailure(t *testing.T) {
	for _, c := range []struct {
		file string
		err  error
		cat  Category
		want Reason
	}{
		{"build.gradle.kts", github.ErrForbidden, CategoryFailed, ReasonSourceAccessDenied},
		{"gradle.lockfile", github.ErrBudgetExhausted, CategoryDeferred, ReasonGitHubBudget},
		{"gradle/wrapper/gradle-wrapper.properties", github.ErrNotFound, CategoryFailed, ReasonSourceNotFound},
	} {
		gh := newFakeGitHub()
		gradleRepo(gh, "svc", gradleFiles())
		gh.readErr["ex/app/svc/"+c.file] = c.err
		plan := langPlan(t, gh, []DependencyMapping{depMapping("compose/shop/api", "ex/app", "svc")}, nil, gradleInput())
		var it LanguageItem
		for _, i := range plan.LanguageItems {
			if i.Manager == ManagerGradle {
				it = i
			}
		}
		if it.Category != c.cat || it.Reason != c.want {
			t.Errorf("%s: item = %s %s (%s)", c.file, it.Category, it.Reason, it.Detail)
		}
	}
}

func TestLanguagePlan_GradleManagerBasics(t *testing.T) {
	if ManagerGradle.LockfileName() != "gradle.lockfile" || ManagerGradle.scheme() != schemeMaven {
		t.Error("the Gradle manager is not set up")
	}
	if DependencyManager("nope").LockfileName() != "" {
		t.Error("an unknown manager has a lockfile")
	}
}

func TestLanguagePlan_GradleNoSettingsFileIsManual(t *testing.T) {
	files := gradleFiles()
	delete(files, "settings.gradle.kts")
	it, ok := gradlePlanItem(t, files)
	if !ok || it.Manager != ManagerGradle || it.Category != CategoryManual || it.Reason != ReasonDependencyFilesNotFound {
		t.Fatalf("item = %+v", it)
	}
	if !strings.Contains(it.Detail, "settings file in the directory is required") || len(it.Packages) == 0 {
		t.Errorf("detail %q, packages %d", it.Detail, len(it.Packages))
	}
}

func TestLanguagePlan_GradleAnnotationProcessorReach(t *testing.T) {
	const decl = "\tannotationProcessor(\"org.projectlombok:lombok:1.18.30\")\n"
	const edge = "configurations {\n\tcompileOnly {\n\t\textendsFrom(configurations.annotationProcessor.get())\n\t}\n}\n\n"
	build := func(withEdge bool) string {
		b := strings.Replace(gradleFiles()["build.gradle.kts"], "dependencies {\n", "dependencies {\n"+decl, 1)
		if withEdge {
			b = strings.Replace(b, "repositories {", edge+"repositories {", 1)
		}
		return b
	}
	for _, c := range []struct {
		name  string
		edge  bool
		confs string
		want  Relation
	}{
		{"edge, compile classpath", true, "annotationProcessor,compileClasspath", RelationDirect},
		{"no edge, compile classpath", false, "annotationProcessor,compileClasspath", RelationTransitive},
		{"edge, runtime classpath only", true, "annotationProcessor,runtimeClasspath", RelationTransitive},
	} {
		t.Run(c.name, func(t *testing.T) {
			files := gradleFiles()
			files["build.gradle.kts"] = build(c.edge)
			files["gradle.lockfile"] = gradleLockBase + "org.projectlombok:lombok:1.18.30=" + c.confs + "\n"
			it, ok := gradlePlanItem(t, files)
			if !ok || it.Category != CategoryDependencyUpdateCandidate {
				t.Fatalf("item = %+v", it)
			}
			if p := pkgsByName(it)["org.projectlombok:lombok"]; p.Action != ActionUpdate || p.Relation != c.want {
				t.Errorf("lombok = %s %s (%s), want %s", p.Action, p.Relation, p.Detail, c.want)
			}
		})
	}
	s, err := recognizeGradleScript("build.gradle", []byte(groovyJava), false, nil, "9.8.2")
	if err != nil || !s.compileOnlyExtendsAP {
		t.Errorf("groovy edge: %v %+v", err, s)
	}
	s, err = recognizeGradleScript("build.gradle.kts", []byte(springKotlin), false, nil, "9.8.2")
	if err != nil || s.compileOnlyExtendsAP {
		t.Errorf("no edge: %v %+v", err, s)
	}
}
