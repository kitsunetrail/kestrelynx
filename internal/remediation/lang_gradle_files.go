package remediation

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// GradleProperty is a property a Gradle project sets that a Spring Boot BOM
// may define a version for: one set in the build script by extra or ext, or a
// key of gradle.properties that ends in ".version". Whether the BOM defines
// the name is not judged here.
type GradleProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	File  string `json:"file"`
}

// GradleRecord is what the plan read of a Gradle project that the later
// stages go on from.
type GradleRecord struct {
	// Version is the Gradle version of the wrapper; Toolchain the Java
	// version of the toolchain the build asks for (21 when it asks for none).
	Version   string `json:"version"`
	Toolchain int    `json:"toolchain"`
	// BootVersion is the version of the Spring Boot plugin, empty when it is
	// not applied; DependencyManagement says the dependency-management
	// plugin is.
	BootVersion          string `json:"boot_version,omitempty"`
	DependencyManagement bool   `json:"dependency_management,omitempty"`
	// Properties are the candidates for an override of a BOM property.
	Properties []GradleProperty `json:"properties,omitempty"`
}

// javaProp is one entry of a Java properties file.
type javaProp struct {
	key, value string
	line       int
}

// parseJavaProperties reads a Java properties file: "key=value",
// "key:value" or "key value" lines and "#" or "!" comments. A carriage return
// that does not end a CRLF line break (Java ends a line at it), a line that
// continues on the next, a duplicate key and any backslash other than before
// one of the characters in escapes are refused.
func parseJavaProperties(data []byte, escapes string) ([]javaProp, error) {
	var out []javaProp
	text := strings.TrimPrefix(string(data), "\xef\xbb\xbf")
	if loneCR(text) {
		return nil, fmt.Errorf("a carriage return that does not end a CRLF line break")
	}
	keys := map[string]bool{}
	for n, raw := range strings.Split(text, "\n") {
		line := n + 1
		raw = strings.TrimSuffix(raw, "\r")
		s := strings.TrimLeft(raw, " \t\f")
		if s == "" || s[0] == '#' || s[0] == '!' {
			continue
		}
		var key, val strings.Builder
		i := 0
		unescape := func(b *strings.Builder) error {
			if i+1 >= len(s) {
				return fmt.Errorf("line %d: a line continues on the next line", line)
			}
			if !strings.ContainsRune(escapes, rune(s[i+1])) {
				return fmt.Errorf("line %d: an escape that is not handled", line)
			}
			b.WriteByte(s[i+1])
			i += 2
			return nil
		}
		for i < len(s) && s[i] != '=' && s[i] != ':' && s[i] != ' ' && s[i] != '\t' && s[i] != '\f' {
			if s[i] == '\\' {
				if err := unescape(&key); err != nil {
					return nil, err
				}
				continue
			}
			key.WriteByte(s[i])
			i++
		}
		for i < len(s) && (s[i] == ' ' || s[i] == '\t' || s[i] == '\f') {
			i++
		}
		if i < len(s) && (s[i] == '=' || s[i] == ':') {
			i++
		}
		for i < len(s) && (s[i] == ' ' || s[i] == '\t' || s[i] == '\f') {
			i++
		}
		for i < len(s) {
			if s[i] == '\\' {
				if err := unescape(&val); err != nil {
					return nil, err
				}
				continue
			}
			val.WriteByte(s[i])
			i++
		}
		if keys[key.String()] {
			return nil, fmt.Errorf("line %d: the key %q is set more than once", line, key.String())
		}
		keys[key.String()] = true
		out = append(out, javaProp{key: key.String(), value: val.String(), line: line})
	}
	return out, nil
}

var (
	gradleMemoryArgRe  = regexp.MustCompile(`^(-Xmx|-Xms|-XX:MaxMetaspaceSize=)[0-9]+[kKmMgG]?$`)
	gradleVersionKeyRe = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.\-]*\.version$`)
)

// gradleBoolKeys are the keys of gradle.properties that take true or false.
var gradleBoolKeys = map[string]bool{
	"org.gradle.parallel": true, "org.gradle.caching": true, "org.gradle.daemon": true, "org.gradle.configuration-cache": true,
}

// parseGradleProperties checks gradle.properties against the keys the plan
// accepts and returns the keys that end in ".version" as candidate properties.
func parseGradleProperties(file string, data []byte) ([]GradleProperty, error) {
	props, err := parseJavaProperties(data, "")
	if err != nil {
		return nil, unsupported(ReasonGradleBuildUnsupported, "%s: %v", file, err)
	}
	var out []GradleProperty
	seen := map[string]bool{}
	for _, p := range props {
		bad := func(why string) error {
			return unsupported(ReasonGradleBuildUnsupported, "%s:%d: %s: %s", file, p.line, why, p.key)
		}
		switch {
		case gradleBoolKeys[p.key]:
			if p.value != "true" && p.value != "false" {
				return nil, bad("the value must be true or false")
			}
		case p.key == "org.gradle.jvmargs":
			args := strings.Fields(p.value)
			if len(args) == 0 {
				return nil, bad("the JVM arguments are empty")
			}
			for _, a := range args {
				if a != "-Dfile.encoding=UTF-8" && !gradleMemoryArgRe.MatchString(a) {
					return nil, bad("a JVM argument that is not accepted: " + a)
				}
			}
		case gradleVersionKeyRe.MatchString(p.key):
			if !gradleVersionRe.MatchString(p.value) {
				return nil, bad("the value of a version property has a character that is not accepted")
			}
			out = append(out, GradleProperty{Name: p.key, Value: p.value, File: file})
			continue
		default:
			return nil, bad("a property that is not accepted")
		}
		if seen[p.key] {
			return nil, bad("the property is set more than once")
		}
		seen[p.key] = true
	}
	return out, nil
}

var gradleDistRe = regexp.MustCompile(`^https://services\.gradle\.org/distributions/gradle-([0-9]+(?:\.[0-9]+){1,2})-(?:bin|all)\.zip$`)

// parseGradleWrapper reads the Gradle version out of
// gradle-wrapper.properties: distributionUrl must be the distribution of a
// release at services.gradle.org.
func parseGradleWrapper(file string, data []byte) (string, error) {
	props, err := parseJavaProperties(data, ":")
	if err != nil {
		return "", unsupported(ReasonUnsupportedSource, "%s: %v", file, err)
	}
	url := ""
	for _, p := range props {
		if p.key != "distributionUrl" {
			continue
		}
		if url != "" {
			return "", unsupported(ReasonUnsupportedSource, "%s sets distributionUrl more than once", file)
		}
		url = p.value
	}
	m := gradleDistRe.FindStringSubmatch(url)
	if m == nil {
		return "", unsupported(ReasonUnsupportedSource, "%s: distributionUrl %q is not the bin or all distribution of a release at services.gradle.org", file, url)
	}
	return m[1], nil
}

// gradleLockEntry is one "group:artifact:version=configurations" line.
type gradleLockEntry struct {
	name, version string
	confs         []string
}

// gradleLock is a gradle.lockfile.
type gradleLock struct {
	entries []gradleLockEntry
	byName  map[string][]int
	// empty are the configurations the "empty=" line lists: locked, and with
	// nothing in them.
	empty []string
	// configs are all configurations the file mentions.
	configs map[string]bool
}

// maxGradleLockLine bounds a line of gradle.lockfile. Trivy reads the file with
// a scanner that stops at a line over 64 KiB without reporting it, which drops
// every line after it from the scan. A line of the file is a coordinate and
// the configurations it is locked in, a few hundred bytes in the largest
// lockfiles seen, so a bound of 8 KiB is far above any real line and well
// below what Trivy stops at.
const maxGradleLockLine = 8 << 10

var gradleConfRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*$`)

// parseGradleLockfile reads gradle.lockfile: "#" comments, lines of
// group:artifact:version=configuration,configuration and one empty=... line.
func parseGradleLockfile(file string, data []byte) (*gradleLock, error) {
	l := &gradleLock{byName: map[string][]int{}, configs: map[string]bool{}}
	bad := func(n int, why string) error {
		return unsupported(ReasonUnparsableSource, "%s:%d: %s", file, n, why)
	}
	confs := func(n int, list string) ([]string, error) {
		if list == "" {
			return nil, nil
		}
		var out []string
		for _, c := range strings.Split(list, ",") {
			if !gradleConfRe.MatchString(c) {
				return nil, bad(n, fmt.Sprintf("%q is not a configuration name", c))
			}
			out = append(out, c)
		}
		return out, nil
	}
	text := strings.TrimPrefix(string(data), "\xef\xbb\xbf")
	// Gradle ends a line at a lone carriage return too, while Trivy and this
	// reader do not, so a line after one would be read by the build and by
	// neither check.
	if loneCR(text) {
		return nil, bad(1, "a carriage return that does not end a CRLF line break")
	}
	seenEmpty := false
	seen := map[string]bool{}
	for i, raw := range strings.Split(text, "\n") {
		n := i + 1
		if len(raw) > maxGradleLockLine {
			return nil, bad(n, fmt.Sprintf("a line of more than %d bytes", maxGradleLockLine))
		}
		line := strings.TrimSuffix(raw, "\r")
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		left, right, ok := strings.Cut(line, "=")
		if !ok {
			return nil, bad(n, "a line that is neither a comment nor key=configurations")
		}
		cs, err := confs(n, right)
		if err != nil {
			return nil, err
		}
		if left == "empty" {
			if seenEmpty {
				return nil, bad(n, "more than one empty= line")
			}
			seenEmpty = true
			l.empty = cs
			for _, c := range cs {
				l.configs[c] = true
			}
			continue
		}
		parts := strings.Split(left, ":")
		if len(parts) != 3 || !gradleNameRe.MatchString(parts[0]) || !gradleNameRe.MatchString(parts[1]) || !gradleVersionRe.MatchString(parts[2]) || len(cs) == 0 {
			return nil, bad(n, "an entry that is not group:artifact:version=configurations")
		}
		if seen[left] {
			return nil, bad(n, "the same entry appears twice")
		}
		seen[left] = true
		e := gradleLockEntry{name: parts[0] + ":" + parts[1], version: parts[2], confs: cs}
		l.byName[e.name] = append(l.byName[e.name], len(l.entries))
		l.entries = append(l.entries, e)
		for _, c := range cs {
			l.configs[c] = true
		}
	}
	return l, nil
}

// gradleRuntimeConfs are the configurations whose dependencies the running
// application is made of.
var gradleRuntimeConfs = []string{"compileClasspath", "runtimeClasspath", "productionRuntimeClasspath"}

// inRuntime reports whether the entry is locked in a configuration of the
// application.
func (e gradleLockEntry) inRuntime() bool {
	for _, c := range e.confs {
		for _, r := range gradleRuntimeConfs {
			if c == r {
				return true
			}
		}
	}
	return false
}

// gradleCatLib is a library of the version catalog, its version resolved.
type gradleCatLib struct {
	alias, group, artifact, version string
	// versionRef is the name in [versions] the version comes from, if any.
	versionRef string
}

// gradleCatalog is gradle/libs.versions.toml.
type gradleCatalog struct {
	versions map[string]string
	libs     map[string]gradleCatLib // by alias in the dotted accessor form
	bundles  map[string][]string     // bundle -> accessor forms of its libraries
	// pluginVersionRefs are the names in [versions] that a plugin refers to.
	pluginVersionRefs map[string]bool
}

var catalogAliasRe = regexp.MustCompile(`^[a-z][A-Za-z0-9_.\-]*$`)

var accessorForm = strings.NewReplacer("-", ".", "_", ".")

// expand gives the libraries a reference such as libs.a.b (without "libs.")
// or libs.bundles.x stands for.
func (c *gradleCatalog) expand(ref string) ([]gradleCatLib, error) {
	if b, ok := strings.CutPrefix(ref, "bundles."); ok {
		keys, found := c.bundles[b]
		if !found {
			return nil, fmt.Errorf("the version catalog has no bundle %q", b)
		}
		out := make([]gradleCatLib, 0, len(keys))
		for _, k := range keys {
			out = append(out, c.libs[k])
		}
		return out, nil
	}
	if strings.HasPrefix(ref, "versions.") || strings.HasPrefix(ref, "plugins.") {
		return nil, fmt.Errorf("a reference to the versions or plugins of the version catalog is not a dependency")
	}
	l, ok := c.libs[ref]
	if !ok {
		return nil, fmt.Errorf("the version catalog has no library %q", ref)
	}
	return []gradleCatLib{l}, nil
}

// parseGradleCatalog reads libs.versions.toml: only literal [versions],
// [libraries], [bundles] and [plugins].
func parseGradleCatalog(file string, data []byte) (*gradleCatalog, error) {
	doc, err := parseTOML(data)
	if err != nil {
		return nil, unsupported(ReasonUnparsableSource, "%s: %v", file, err)
	}
	bad := func(format string, args ...any) error {
		return unsupported(ReasonGradleBuildUnsupported, "%s: %s", file, fmt.Sprintf(format, args...))
	}
	cat := &gradleCatalog{versions: map[string]string{}, libs: map[string]gradleCatLib{}, bundles: map[string][]string{}, pluginVersionRefs: map[string]bool{}}
	section := func(name string) (map[string]any, error) {
		v, ok := doc[name]
		if !ok {
			return nil, nil
		}
		m, ok := v.(map[string]any)
		if !ok {
			return nil, bad("[%s] is not a table", name)
		}
		return m, nil
	}
	for k := range doc {
		if k != "versions" && k != "libraries" && k != "bundles" && k != "plugins" {
			return nil, bad("[%s] is not accepted", k)
		}
	}
	vs, err := section("versions")
	if err != nil {
		return nil, err
	}
	// collide refuses two names of one section that Gradle turns into the
	// same accessor.
	collide := func(section string, seen map[string]string, name string) error {
		k := accessorForm.Replace(name)
		if other, dup := seen[k]; dup {
			return bad("[%s] has %q and %q, which are the same accessor", section, other, name)
		}
		seen[k] = name
		return nil
	}
	seenVersions := map[string]string{}
	for name, v := range vs {
		s, ok := v.(string)
		if !ok || !gradleVersionKeyOK(name) || !gradleVersionLiteral(s) {
			return nil, bad("the version %q is not a literal string", name)
		}
		if err := collide("versions", seenVersions, name); err != nil {
			return nil, err
		}
		cat.versions[name] = s
	}
	// version reads a version field: a literal, or a table of only ref.
	version := func(what string, v any) (lit, ref string, err error) {
		switch t := v.(type) {
		case nil:
			return "", "", nil
		case string:
			if !gradleVersionLiteral(t) {
				return "", "", bad("%s has a version that is not a literal", what)
			}
			return t, "", nil
		case map[string]any:
			r, ok := t["ref"].(string)
			if len(t) != 1 || !ok {
				return "", "", bad("%s has a version other than a literal or a ref", what)
			}
			val, found := cat.versions[r]
			if !found {
				return "", "", bad("%s refers to the version %q, which [versions] does not define", what, r)
			}
			return val, r, nil
		}
		return "", "", bad("%s has a version that is not a literal", what)
	}
	libs, err := section("libraries")
	if err != nil {
		return nil, err
	}
	for alias, v := range libs {
		if !catalogAliasRe.MatchString(alias) {
			return nil, bad("the library alias %q is not accepted", alias)
		}
		var module, ver, ref string
		switch t := v.(type) {
		case string:
			parts := strings.Split(t, ":")
			if len(parts) != 3 {
				return nil, bad("the library %q is not group:artifact:version", alias)
			}
			module, ver = parts[0]+":"+parts[1], parts[2]
			if !gradleVersionLiteral(ver) {
				return nil, bad("the library %q has a version that is not a literal", alias)
			}
		case map[string]any:
			for k := range t {
				if k != "module" && k != "group" && k != "name" && k != "version" {
					return nil, bad("the library %q has the key %q, which is not accepted", alias, k)
				}
			}
			m, hasMod := t["module"].(string)
			g, hasGroup := t["group"].(string)
			n, hasName := t["name"].(string)
			switch {
			case hasMod && !hasGroup && !hasName:
				module = m
			case !hasMod && hasGroup && hasName:
				module = g + ":" + n
			default:
				return nil, bad("the library %q must give module, or group and name", alias)
			}
			lit, r, err := version(fmt.Sprintf("the library %q", alias), t["version"])
			if err != nil {
				return nil, err
			}
			ver, ref = lit, r
		default:
			return nil, bad("the library %q is not a string or a table", alias)
		}
		parts := strings.Split(module, ":")
		if len(parts) != 2 || !gradleNameRe.MatchString(parts[0]) || !gradleNameRe.MatchString(parts[1]) {
			return nil, bad("the library %q has a module that is not group:artifact", alias)
		}
		key := accessorForm.Replace(alias)
		if _, dup := cat.libs[key]; dup {
			return nil, bad("two libraries have the accessor %q", key)
		}
		cat.libs[key] = gradleCatLib{alias: alias, group: parts[0], artifact: parts[1], version: ver, versionRef: ref}
	}
	bundles, err := section("bundles")
	if err != nil {
		return nil, err
	}
	seenBundles := map[string]string{}
	for name, v := range bundles {
		list, ok := v.([]any)
		if !ok || !catalogAliasRe.MatchString(name) {
			return nil, bad("the bundle %q is not a list of library aliases", name)
		}
		var keys []string
		for _, e := range list {
			a, ok := e.(string)
			k := accessorForm.Replace(a)
			if _, found := cat.libs[k]; !ok || !found {
				return nil, bad("the bundle %q lists %v, which is not a library", name, e)
			}
			keys = append(keys, k)
		}
		if err := collide("bundles", seenBundles, name); err != nil {
			return nil, err
		}
		cat.bundles[accessorForm.Replace(name)] = keys
	}
	plugins, err := section("plugins")
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(plugins))
	for name := range plugins {
		names = append(names, name)
	}
	sort.Strings(names)
	seenPlugins := map[string]string{}
	for _, name := range names {
		if err := collide("plugins", seenPlugins, name); err != nil {
			return nil, err
		}
		switch t := plugins[name].(type) {
		case string:
			id, ver, ok := strings.Cut(t, ":")
			if !ok || !gradleNameRe.MatchString(id) || !gradleVersionLiteral(ver) {
				return nil, bad("the plugin %q is not id:version", name)
			}
		case map[string]any:
			for k := range t {
				if k != "id" && k != "version" {
					return nil, bad("the plugin %q has the key %q, which is not accepted", name, k)
				}
			}
			if id, ok := t["id"].(string); !ok || !gradleNameRe.MatchString(id) {
				return nil, bad("the plugin %q has no literal id", name)
			}
			_, ref, err := version(fmt.Sprintf("the plugin %q", name), t["version"])
			if err != nil {
				return nil, err
			}
			if ref != "" {
				cat.pluginVersionRefs[ref] = true
			}
		default:
			return nil, bad("the plugin %q is not a string or a table", name)
		}
	}
	return cat, nil
}

func gradleVersionKeyOK(name string) bool { return gradleNameRe.MatchString(name) }
