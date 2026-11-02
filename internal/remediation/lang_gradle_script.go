package remediation

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Reasons of the Gradle part.
const (
	// ReasonGradleBuildUnsupported: a build script, settings script,
	// gradle.properties or version catalog holds something other than the
	// forms the plan accepts, so what the build does cannot be told from the
	// files alone.
	ReasonGradleBuildUnsupported Reason = "gradle_build_unsupported"
	// ReasonGradleLockingUnenforced: the build is not set to build exactly
	// what gradle.lockfile lists (dependency locking of every configuration
	// in the STRICT mode, with no dependency left out), or the lockfile does
	// not cover the configurations the application is built from.
	ReasonGradleLockingUnenforced Reason = "gradle_locking_unenforced"
	// ReasonGradlePluginUnsupported: the build applies a plugin, or a version
	// of one, that is not among those checked to leave dependency locking and
	// the resolved configurations alone.
	ReasonGradlePluginUnsupported Reason = "gradle_plugin_unsupported"
	// ReasonGradleVersionUnsupported: the Gradle version of the wrapper is
	// not one a build of the update is available for.
	ReasonGradleVersionUnsupported Reason = "gradle_version_unsupported"
	// ReasonGradleToolchainUnsupported: the Java toolchain the build asks for
	// is not one a build of the update is available for.
	ReasonGradleToolchainUnsupported Reason = "gradle_toolchain_unsupported"
)

// gradlePluginRule is a plugin, the plugin versions and the Gradle versions
// that were checked together. A version must equal one in the lists exactly,
// as a string: versions that Maven's ordering treats as equal (4.1.2.RELEASE
// and 4.1.2) are different plugins here. A rule with an empty list allows
// nothing.
type gradlePluginRule struct {
	id string
	// settings: the plugin is applied in the settings script, not the build
	// script.
	settings bool
	versions []string
	gradles  []string
}

// gradlePluginTable lists what may be applied with a version. A combination
// is added only after it has been checked: that the plugin leaves the lock
// mode and the locking of every configuration alone, which configurations it
// adds, what it fetches outside dependency resolution, and that it adds no
// repository.
var gradlePluginTable = []gradlePluginRule{
	{id: gradleBootPlugin, versions: []string{"4.1.2"}, gradles: []string{"9.8.2"}},
	{id: gradleDependencyMgmtPlugin, versions: []string{"1.1.7"}, gradles: []string{"9.8.2"}},
	// No combination of the toolchain resolver has been checked yet, so it is
	// refused whatever its version.
	{id: "org.gradle.toolchains.foojay-resolver-convention", settings: true},
}

// allows reports whether the plugin at version, in a build run by gradle, is
// one of the checked combinations.
func (r gradlePluginRule) allows(version, gradle string) bool {
	return containsString(r.versions, version) && containsString(r.gradles, gradle)
}

// gradleBootPlugin is the id of the Spring Boot plugin.
const gradleBootPlugin = "org.springframework.boot"

// gradleCorePlugins are applied by name without a version.
var gradleCorePlugins = map[string]bool{"java": true, "java-library": true, "application": true}

// gradleConfigurations are the configurations a dependency may be declared
// in; developmentOnly only with the Spring Boot plugin.
var gradleConfigurations = map[string]bool{
	"implementation": true, "api": true, "compileOnly": true, "runtimeOnly": true,
	"testImplementation": true, "testCompileOnly": true, "testRuntimeOnly": true,
	"annotationProcessor": true, "testAnnotationProcessor": true,
}

// gradleRefused are the statements refused by name, with what to say.
var gradleRefused = map[string]string{
	"apply":                          "applying a script or plugin by apply is not handled",
	"buildscript":                    "a buildscript block is not handled",
	"allprojects":                    "allprojects is not handled",
	"subprojects":                    "subprojects is not handled",
	"resolutionStrategy":             "a resolution strategy is not handled",
	"dependencyManagement":           "a dependencyManagement block is not handled",
	"include":                        "a multi-project build is not handled",
	"includeBuild":                   "a composite build is not handled",
	"dependencyResolutionManagement": "dependency resolution management is not handled",
}

var (
	gradleNameRe    = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.\-]*$`)
	gradleVersionRe = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.\-]*$`)
)

// gradleVersionLiteral reports a version a dependency may name: no range, no
// dynamic version.
func gradleVersionLiteral(v string) bool {
	return gradleVersionRe.MatchString(v) && !strings.HasPrefix(v, "latest.")
}

// gradleDecl is one dependency declaration of a build script, with a catalog
// reference expanded.
type gradleDecl struct {
	conf string
	name string // group:artifact
	// version is the version written, "" for none (a BOM or another
	// constraint decides).
	version string
	// catalog is the alias in the version catalog the declaration came from.
	catalog    string
	constraint bool
	line       int
}

// gradlePluginUse is a plugin a script applies.
type gradlePluginUse struct {
	id, version string
}

// gradleScript is what a recognised build or settings script says.
type gradleScript struct {
	plugins []gradlePluginUse
	decls   []gradleDecl
	// props are the properties set by extra or ext.
	props []GradleProperty
	// toolchain is the Java version of the toolchain, 0 when none is declared.
	toolchain int
	rootName  string
	// compileOnlyExtendsAP: configurations { compileOnly { extendsFrom
	// annotationProcessor } } was read, so what is declared in
	// annotationProcessor is also on the compile classpath.
	compileOnlyExtendsAP bool
}

// declared reports whether the script declares a dependency on the package
// (not a constraint).
func (s *gradleScript) declared(name string) bool {
	for _, d := range s.decls {
		if d.name == name && !d.constraint {
			return true
		}
	}
	return false
}

// pluginApplied reports whether the script applies the plugin.
func (s *gradleScript) pluginApplied(id string) bool {
	for _, p := range s.plugins {
		if p.id == id {
			return true
		}
	}
	return false
}

// gradleReader holds the state of reading one script.
type gradleReader struct {
	file     string
	kotlin   bool
	settings bool
	cat      *gradleCatalog
	gradle   string // the Gradle version of the wrapper
	out      gradleScript
	// seen counts the top-level blocks that may appear once.
	seen         map[string]int
	lockBlocks   int
	hasToolchain bool
}

// recognizeGradleScript reads a build script (settings false) or a settings
// script. Every statement must be one of the accepted forms; the first that
// is not ends the reading with an UnsupportedError. For a build script, the
// dependencyLocking block must be present, once, and in the STRICT mode.
func recognizeGradleScript(file string, src []byte, settings bool, cat *gradleCatalog, gradle string) (*gradleScript, error) {
	kotlin := strings.HasSuffix(file, ".kts")
	toks, err := lexGradle(src, kotlin)
	if err != nil {
		return nil, unsupported(ReasonGradleBuildUnsupported, "%s: %v", file, err)
	}
	stmts, err := readGradleStmts(toks)
	if err != nil {
		return nil, unsupported(ReasonGradleBuildUnsupported, "%s: %v", file, err)
	}
	g := &gradleReader{file: file, kotlin: kotlin, settings: settings, cat: cat, gradle: gradle, seen: map[string]int{}}
	for _, s := range stmts {
		var err error
		if settings {
			err = g.settingsStmt(s)
		} else {
			err = g.buildStmt(s)
		}
		if err != nil {
			return nil, err
		}
	}
	if !settings && g.lockBlocks != 1 {
		return nil, unsupported(ReasonGradleLockingUnenforced, "%s has %d dependencyLocking blocks; exactly one that locks every configuration in the STRICT mode is required", file, g.lockBlocks)
	}
	return &g.out, nil
}

func (g *gradleReader) refuse(reason Reason, s gradleStmt, why string) error {
	return unsupported(reason, "%s:%d: %s: %s", g.file, s.line, why, s.text())
}

func (g *gradleReader) unsupportedStmt(s gradleStmt) error {
	name := ""
	if len(s.head) > 0 && s.head[0].kind == gtIdent {
		name = s.head[0].text
	}
	if why, ok := gradleRefused[name]; ok {
		return g.refuse(ReasonGradleBuildUnsupported, s, why)
	}
	if len(s.head) >= 3 && s.head[0].plainIdent("configurations") && s.head[1].isPunct(".") {
		return g.refuse(ReasonGradleBuildUnsupported, s, "changing configurations is not handled")
	}
	return g.refuse(ReasonGradleBuildUnsupported, s, "a statement that is not one of the accepted forms")
}

// shape is the tokens of the head joined by spaces, a string as its content
// in double quotes: the form to compare a statement without variable parts
// with.
func shape(toks []gradleTok) string {
	parts := make([]string, len(toks))
	for i, t := range toks {
		if t.kind == gtString {
			parts[i] = `"` + t.text + `"`
		} else {
			parts[i] = t.text
		}
	}
	return strings.Join(parts, " ")
}

// named reports a statement that is one plain name with a block.
func named(s gradleStmt, name string) bool {
	return len(s.head) == 1 && s.head[0].plainIdent(name) && s.hasBlock
}

// gradleCur reads the head of a statement token by token.
type gradleCur struct {
	t []gradleTok
	i int
}

func (c *gradleCur) done() bool { return c.i >= len(c.t) }

func (c *gradleCur) punct(p string) bool {
	if c.i < len(c.t) && c.t[c.i].isPunct(p) {
		c.i++
		return true
	}
	return false
}

func (c *gradleCur) ident(name string) bool {
	if c.i < len(c.t) && c.t[c.i].plainIdent(name) {
		c.i++
		return true
	}
	return false
}

func (c *gradleCur) name() (string, bool) {
	if c.i < len(c.t) && c.t[c.i].kind == gtIdent {
		c.i++
		return c.t[c.i-1].text, true
	}
	return "", false
}

func (c *gradleCur) str() (string, bool) {
	if c.i < len(c.t) && c.t[c.i].kind == gtString {
		c.i++
		return c.t[c.i-1].text, true
	}
	return "", false
}

func (c *gradleCur) number() (string, bool) {
	if c.i < len(c.t) && c.t[c.i].kind == gtNumber {
		c.i++
		return c.t[c.i-1].text, true
	}
	return "", false
}

// path reads name(.name)*.
func (c *gradleCur) path() (string, bool) {
	n, ok := c.name()
	if !ok {
		return "", false
	}
	parts := []string{n}
	for c.i+1 < len(c.t) && c.t[c.i].isPunct(".") && c.t[c.i+1].kind == gtIdent {
		parts = append(parts, c.t[c.i+1].text)
		c.i += 2
	}
	return strings.Join(parts, "."), true
}

// once counts a block that may appear once.
func (g *gradleReader) once(s gradleStmt, name string) error {
	g.seen[name]++
	if g.seen[name] > 1 {
		return g.refuse(ReasonGradleBuildUnsupported, s, "the block appears more than once")
	}
	return nil
}

// buildStmt checks one top-level statement of a build script.
func (g *gradleReader) buildStmt(s gradleStmt) error {
	if len(s.head) == 0 {
		return g.unsupportedStmt(s)
	}
	switch {
	case named(s, "plugins"):
		if err := g.once(s, "plugins"); err != nil {
			return err
		}
		return g.pluginsBlock(s)
	case named(s, "repositories"):
		return g.eachShape(s.block, "mavenCentral ( )", "only mavenCentral() is accepted as a repository")
	case named(s, "dependencies"):
		return g.dependenciesBlock(s.block, false)
	case named(s, "dependencyLocking"):
		return g.lockingBlock(s)
	case named(s, "java"):
		if err := g.once(s, "java"); err != nil {
			return err
		}
		return g.javaBlock(s)
	case named(s, "configurations"):
		if err := g.once(s, "configurations"); err != nil {
			return err
		}
		return g.configurationsBlock(s)
	case named(s, "application"):
		if err := g.once(s, "application"); err != nil {
			return err
		}
		return g.applicationBlock(s)
	case named(s, "test"), s.hasBlock && (shape(s.head) == "tasks . withType < Test >" || shape(s.head) == "tasks . withType ( Test )" ||
		shape(s.head) == `tasks . named < Test > ( "test" )` || shape(s.head) == `tasks . named ( "test" )`):
		return g.eachShape(s.block, "useJUnitPlatform ( )", "only useJUnitPlatform() is accepted in the test task")
	case s.hasBlock:
		return g.unsupportedStmt(s)
	}
	c := &gradleCur{t: s.head}
	if p, ok := c.path(); ok {
		switch p {
		case "group", "version", "description":
			eq := c.punct("=")
			if _, ok := c.str(); ok && c.done() && (eq || !g.kotlin) {
				return nil
			}
		case "sourceCompatibility", "targetCompatibility":
			if !g.kotlin {
				c.punct("=")
				if g.compatibilityValue(c) && c.done() {
					return nil
				}
			}
		case "extra", "ext":
			return g.extraStmt(s)
		}
		if strings.HasPrefix(p, "ext.") && !g.kotlin {
			return g.extraStmt(s)
		}
	}
	return g.unsupportedStmt(s)
}

// applicationBlock accepts the main class of the application plugin written
// as a literal: mainClass = "app.Main", or mainClass.set("app.Main") in
// Kotlin. The class name only says what the start scripts and the run task
// start; it does not take part in resolving dependencies.
func (g *gradleReader) applicationBlock(s gradleStmt) error {
	if len(s.block) != 1 || s.block[0].hasBlock {
		return g.refuse(ReasonGradleBuildUnsupported, s, "only mainClass is accepted in the application block")
	}
	b := s.block[0]
	c := &gradleCur{t: b.head}
	ok := c.ident("mainClass")
	switch {
	case ok && c.punct("="):
		_, ok = c.str()
	case ok && g.kotlin && c.punct(".") && c.ident("set") && c.punct("("):
		_, ok = c.str()
		ok = ok && c.punct(")")
	default:
		ok = false
	}
	if !ok || !c.done() {
		return g.refuse(ReasonGradleBuildUnsupported, b, "the main class must be mainClass = \"...\" written literally")
	}
	return nil
}

// eachShape accepts a block whose statements are all the given form.
func (g *gradleReader) eachShape(block []gradleStmt, want, why string) error {
	for _, b := range block {
		if b.hasBlock || shape(b.head) != want {
			return g.refuse(ReasonGradleBuildUnsupported, b, why)
		}
	}
	return nil
}

// compatibilityValue reads the value of sourceCompatibility or
// targetCompatibility: a string, a number (1.8 or 17) or JavaVersion.VERSION_n.
func (g *gradleReader) compatibilityValue(c *gradleCur) bool {
	if _, ok := c.str(); ok {
		return true
	}
	if _, ok := c.number(); ok {
		if c.punct(".") {
			_, ok = c.number()
			return ok
		}
		return true
	}
	if c.ident("JavaVersion") && c.punct(".") {
		n, ok := c.name()
		return ok && strings.HasPrefix(n, "VERSION_")
	}
	return false
}

// extraStmt accepts extra["p"] = "v" (Kotlin) and ext["p"] = "v" or
// ext.p = "v" (Groovy), with a literal name and value.
func (g *gradleReader) extraStmt(s gradleStmt) error {
	c := &gradleCur{t: s.head}
	holder := "ext"
	if g.kotlin {
		holder = "extra"
	}
	var name string
	switch {
	case len(s.head) > 1 && s.head[0].plainIdent(holder) && s.head[1].isPunct("["):
		c.i = 2
		n, ok := c.str()
		if !ok || !c.punct("]") {
			return g.unsupportedStmt(s)
		}
		name = n
	case !g.kotlin && len(s.head) > 1 && s.head[0].plainIdent(holder) && s.head[1].isPunct("."):
		c.i = 2
		n, ok := c.name()
		if !ok {
			return g.unsupportedStmt(s)
		}
		name = n
	default:
		return g.unsupportedStmt(s)
	}
	if !c.punct("=") {
		return g.unsupportedStmt(s)
	}
	v, ok := c.str()
	if !ok || !c.done() {
		return g.refuse(ReasonGradleBuildUnsupported, s, "the value of a property must be a string literal")
	}
	if !gradleNameRe.MatchString(name) || !gradleVersionRe.MatchString(v) {
		return g.refuse(ReasonGradleBuildUnsupported, s, "the name or value of a property has a character that is not accepted")
	}
	g.out.props = append(g.out.props, GradleProperty{Name: name, Value: v, File: g.file})
	return nil
}

// pluginsBlock checks the plugins of a build script or settings script
// against the core plugins and the table.
func (g *gradleReader) pluginsBlock(s gradleStmt) error {
	for _, b := range s.block {
		if b.hasBlock || len(b.head) == 0 {
			return g.refuse(ReasonGradleBuildUnsupported, b, "a statement that is not one of the accepted forms")
		}
		c := &gradleCur{t: b.head}
		if c.ident("alias") {
			return g.refuse(ReasonGradlePluginUnsupported, b, "a plugin from a version catalog is not accepted")
		}
		var id, ver string
		haveVer := false
		if c.ident("id") {
			ok := false
			if c.punct("(") {
				id, ok = c.str()
				ok = ok && c.punct(")")
			} else if !g.kotlin {
				id, ok = c.str()
			}
			if !ok {
				return g.refuse(ReasonGradlePluginUnsupported, b, "the plugin id is not a string literal")
			}
		} else if n, ok := c.name(); ok && !g.settings && (len(b.head) == 1) && (g.kotlin || !b.head[0].quoted) {
			id = n
		} else {
			return g.refuse(ReasonGradleBuildUnsupported, b, "a statement that is not one of the accepted forms")
		}
		if c.ident("version") {
			v, ok := c.str()
			if !ok {
				return g.refuse(ReasonGradlePluginUnsupported, b, "the plugin version is not a string literal")
			}
			ver, haveVer = v, true
		}
		if !c.done() {
			return g.refuse(ReasonGradleBuildUnsupported, b, "a statement that is not one of the accepted forms")
		}
		if !haveVer && gradleCorePlugins[id] && !g.settings {
			g.out.plugins = append(g.out.plugins, gradlePluginUse{id: id})
			continue
		}
		var rule *gradlePluginRule
		for i := range gradlePluginTable {
			if r := &gradlePluginTable[i]; r.id == id && r.settings == g.settings {
				rule = r
			}
		}
		if rule == nil || !haveVer || !rule.allows(ver, g.gradle) {
			return g.refuse(ReasonGradlePluginUnsupported, b, fmt.Sprintf("the plugin %s %s is not among the combinations checked with Gradle %s", id, ver, g.gradle))
		}
		g.out.plugins = append(g.out.plugins, gradlePluginUse{id: id, version: ver})
	}
	return nil
}

// dependenciesBlock checks the declarations of a dependencies block, or of
// the constraints block inside it.
func (g *gradleReader) dependenciesBlock(block []gradleStmt, constraint bool) error {
	for _, b := range block {
		if !constraint && named(b, "constraints") {
			if err := g.dependenciesBlock(b.block, true); err != nil {
				return err
			}
			continue
		}
		if b.hasBlock || len(b.head) < 2 {
			return g.refuse(ReasonGradleBuildUnsupported, b, "a declaration that is not one of the accepted forms")
		}
		c := &gradleCur{t: b.head}
		conf, _ := c.name()
		if !gradleConfigurations[conf] && !(conf == "developmentOnly" && g.out.pluginApplied(gradleBootPlugin)) {
			return g.refuse(ReasonGradleBuildUnsupported, b, "a configuration that is not a standard one of the java plugins")
		}
		paren := c.punct("(")
		if !paren && g.kotlin {
			return g.refuse(ReasonGradleBuildUnsupported, b, "a declaration that is not one of the accepted forms")
		}
		decls, err := g.dependencyArg(c, b, conf, constraint)
		if err != nil {
			return err
		}
		if paren && !c.punct(")") || !c.done() {
			return g.refuse(ReasonGradleBuildUnsupported, b, "a declaration that is not one of the accepted forms")
		}
		g.out.decls = append(g.out.decls, decls...)
	}
	return nil
}

// dependencyArg reads the one argument of a declaration: a "group:artifact"
// or "group:artifact:version" string, or a reference to the version catalog.
func (g *gradleReader) dependencyArg(c *gradleCur, b gradleStmt, conf string, constraint bool) ([]gradleDecl, error) {
	if s, ok := c.str(); ok {
		parts := strings.Split(s, ":")
		if len(parts) < 2 || len(parts) > 3 {
			return nil, g.refuse(ReasonGradleBuildUnsupported, b, "a dependency that is not group:artifact or group:artifact:version")
		}
		for _, p := range parts[:2] {
			if !gradleNameRe.MatchString(p) {
				return nil, g.refuse(ReasonGradleBuildUnsupported, b, "a dependency name with a character that is not accepted")
			}
		}
		d := gradleDecl{conf: conf, name: parts[0] + ":" + parts[1], constraint: constraint, line: b.line}
		if len(parts) == 3 {
			if !gradleVersionLiteral(parts[2]) {
				return nil, g.refuse(ReasonGradleBuildUnsupported, b, "a dependency version that is not a literal version")
			}
			d.version = parts[2]
		}
		return []gradleDecl{d}, nil
	}
	ref, ok := c.path()
	if !ok || !strings.HasPrefix(ref, "libs.") {
		return nil, g.refuse(ReasonGradleBuildUnsupported, b, "a dependency that is neither a string nor a reference to the version catalog")
	}
	if g.cat == nil {
		return nil, g.refuse(ReasonGradleBuildUnsupported, b, "a reference to a version catalog the project does not have")
	}
	libs, err := g.cat.expand(strings.TrimPrefix(ref, "libs."))
	if err != nil {
		return nil, g.refuse(ReasonGradleBuildUnsupported, b, err.Error())
	}
	var out []gradleDecl
	for _, l := range libs {
		out = append(out, gradleDecl{conf: conf, name: l.group + ":" + l.artifact, version: l.version, catalog: l.alias, constraint: constraint, line: b.line})
	}
	return out, nil
}

// lockingBlock accepts dependencyLocking { lockAllConfigurations();
// lockMode = LockMode.STRICT }, each statement once and nothing else.
func (g *gradleReader) lockingBlock(s gradleStmt) error {
	g.lockBlocks++
	if g.lockBlocks > 1 {
		return g.refuse(ReasonGradleLockingUnenforced, s, "more than one dependencyLocking block")
	}
	all, strict := 0, 0
	for _, b := range s.block {
		switch {
		case b.hasBlock:
			return g.refuse(ReasonGradleLockingUnenforced, b, "a statement in dependencyLocking that is not accepted")
		case shape(b.head) == "lockAllConfigurations ( )":
			all++
		case shape(b.head) == "lockMode = LockMode . STRICT":
			strict++
		default:
			return g.refuse(ReasonGradleLockingUnenforced, b, "a statement in dependencyLocking that is not accepted, or a lock mode other than STRICT")
		}
	}
	if all != 1 || strict != 1 {
		return g.refuse(ReasonGradleLockingUnenforced, s, "dependencyLocking must lock every configuration and set the STRICT lock mode, each once")
	}
	return nil
}

// javaBlock accepts the Java toolchain and the compatibility levels.
func (g *gradleReader) javaBlock(s gradleStmt) error {
	for _, b := range s.block {
		switch {
		case named(b, "toolchain"):
			if g.hasToolchain || len(b.block) != 1 {
				return g.refuse(ReasonGradleBuildUnsupported, b, "a toolchain block that is not a single languageVersion")
			}
			c := &gradleCur{t: b.block[0].head}
			n := ""
			ok := c.ident("languageVersion") && c.punct("=") && c.ident("JavaLanguageVersion") && c.punct(".") && c.ident("of") && c.punct("(")
			if ok {
				n, ok = c.number()
			}
			if !ok || !c.punct(")") || !c.done() || b.block[0].hasBlock {
				return g.refuse(ReasonGradleBuildUnsupported, b.block[0], "the toolchain must be languageVersion = JavaLanguageVersion.of(N)")
			}
			v, err := strconv.Atoi(n)
			if err != nil || v <= 0 {
				return g.refuse(ReasonGradleBuildUnsupported, b.block[0], "the toolchain version is not a number")
			}
			g.out.toolchain, g.hasToolchain = v, true
		case !b.hasBlock:
			c := &gradleCur{t: b.head}
			if p, ok := c.path(); ok && (p == "sourceCompatibility" || p == "targetCompatibility") && c.punct("=") && g.compatibilityValue(c) && c.done() {
				continue
			}
			return g.refuse(ReasonGradleBuildUnsupported, b, "a statement in java that is not accepted")
		default:
			return g.refuse(ReasonGradleBuildUnsupported, b, "a statement in java that is not accepted")
		}
	}
	return nil
}

// configurationsBlock accepts the one form start.spring.io writes:
// compileOnly extending annotationProcessor.
func (g *gradleReader) configurationsBlock(s gradleStmt) error {
	if len(s.block) != 1 || !named(s.block[0], "compileOnly") || len(s.block[0].block) != 1 || s.block[0].block[0].hasBlock {
		return g.refuse(ReasonGradleBuildUnsupported, s, "only compileOnly extending annotationProcessor is accepted in configurations")
	}
	in := s.block[0].block[0]
	want := "extendsFrom ( configurations . annotationProcessor . get ( ) )"
	if sh := shape(in.head); sh != want && (g.kotlin || sh != "extendsFrom annotationProcessor") {
		return g.refuse(ReasonGradleBuildUnsupported, in, "only compileOnly extending annotationProcessor is accepted in configurations")
	}
	g.out.compileOnlyExtendsAP = true
	return nil
}

// settingsStmt checks one top-level statement of a settings script.
func (g *gradleReader) settingsStmt(s gradleStmt) error {
	switch {
	case named(s, "plugins"):
		if err := g.once(s, "plugins"); err != nil {
			return err
		}
		return g.pluginsBlock(s)
	case named(s, "pluginManagement"):
		if err := g.once(s, "pluginManagement"); err != nil {
			return err
		}
		if len(s.block) != 1 || !named(s.block[0], "repositories") {
			return g.refuse(ReasonGradleBuildUnsupported, s, "only repositories is accepted in pluginManagement")
		}
		for _, b := range s.block[0].block {
			if b.hasBlock || (shape(b.head) != "gradlePluginPortal ( )" && shape(b.head) != "mavenCentral ( )") {
				return g.refuse(ReasonGradleBuildUnsupported, b, "only gradlePluginPortal() and mavenCentral() are accepted as plugin repositories")
			}
		}
		return nil
	case !s.hasBlock:
		c := &gradleCur{t: s.head}
		if p, ok := c.path(); ok && p == "rootProject.name" && c.punct("=") {
			if v, ok := c.str(); ok && c.done() {
				if g.out.rootName != "" {
					return g.refuse(ReasonGradleBuildUnsupported, s, "the root project is named twice")
				}
				g.out.rootName = v
				return nil
			}
		}
	}
	return g.unsupportedStmt(s)
}
