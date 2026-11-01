package remediation

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
)

// maxMavenPOMBytes bounds a pom file, read from a repository or from the
// user's project.
const maxMavenPOMBytes = 4 << 20

// maxMavenPOMDepth bounds the nesting of elements in a pom file.
const maxMavenPOMDepth = 100

type mavenParent struct {
	GroupID, ArtifactID, Version string
	RelativePath                 string
	RelativePathSet              bool // the element is present (an empty <relativePath/> counts as set and empty)
}

type mavenDep struct {
	GroupID, ArtifactID, Version, Type, Classifier, Scope string
	Optional                                              string // trimmed text of <optional>, "" when absent
	HasExclusions                                         bool   // at least one <exclusion>
}

// IsImport reports a BOM import: type pom and scope import.
func (d mavenDep) IsImport() bool { return d.Type == "pom" && d.Scope == "import" }

// mavenProfile says which parts of the model a profile changes.
type mavenProfile struct {
	ID                                                                            string
	Dependencies, DependencyManagement, Properties, Parent, Modules, Repositories bool
}

// mavenPOM is the part of a pom file the remediation reads. Only the
// top-level elements of <project> fill the model; what a profile, the build
// or the reporting section holds is not part of it, except that profiles
// report what they change.
type mavenPOM struct {
	GroupID, ArtifactID, Version, Packaging string // as declared, "" when absent
	Parent                                  *mavenParent
	Properties                              map[string]string
	PropertyOrder                           []string
	Modules                                 []string
	Dependencies                            []mavenDep // project <dependencies>
	DependencyManagement                    []mavenDep // <dependencyManagement><dependencies>, imports included, in order
	Profiles                                []mavenProfile
	Repositories                            []string // <repositories><repository><url>
	PluginRepositories                      []string
	Relocation                              bool     // <distributionManagement><relocation> present
	PluginVersionRefs                       []string // every ${name} outside <dependencies>, <dependencyManagement> and <properties> of the project, names only, deduplicated
}

// EffectiveGroupID is the project's own groupId, else the parent's.
func (p *mavenPOM) EffectiveGroupID() string {
	if p.GroupID != "" {
		return p.GroupID
	}
	if p.Parent != nil {
		return p.Parent.GroupID
	}
	return ""
}

// EffectiveVersion is the project's own version, else the parent's.
func (p *mavenPOM) EffectiveVersion() string {
	if p.Version != "" {
		return p.Version
	}
	if p.Parent != nil {
		return p.Parent.Version
	}
	return ""
}

var (
	mavenPropertyRefRE = regexp.MustCompile(`\$\{([^${}]+)\}`)
	mavenWholeRefRE    = regexp.MustCompile(`^\$\{([^${}]+)\}$`)
)

// mavenPropertyRef returns name when s is exactly "${name}" (trimmed), else ok
// is false.
func mavenPropertyRef(s string) (name string, ok bool) {
	m := mavenWholeRefRE.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return "", false
	}
	return m[1], true
}

// mavenPropertyRefs returns every ${name} inside s, in order.
func mavenPropertyRefs(s string) []string {
	var out []string
	for _, m := range mavenPropertyRefRE.FindAllStringSubmatch(s, -1) {
		out = append(out, m[1])
	}
	return out
}

// isMavenVersionRange reports a range spec such as "[1.0,2.0)", "(,1.0]" or
// "[1.0]".
func isMavenVersionRange(s string) bool {
	s = strings.TrimSpace(s)
	if len(s) < 2 {
		return false
	}
	return (s[0] == '[' || s[0] == '(') && (s[len(s)-1] == ']' || s[len(s)-1] == ')')
}

// pomNode is an element of the document with the character data it holds
// directly.
type pomNode struct {
	name     string // local name
	text     string // trimmed character data directly inside the element
	attrs    []string
	children []*pomNode
}

func (n *pomNode) child(name string) *pomNode {
	for _, c := range n.children {
		if c.name == name {
			return c
		}
	}
	return nil
}

func (n *pomNode) childText(name string) string {
	if c := n.child(name); c != nil {
		return c.text
	}
	return ""
}

// elements returns the children named name.
func (n *pomNode) elements(name string) []*pomNode {
	var out []*pomNode
	for _, c := range n.children {
		if c.name == name {
			out = append(out, c)
		}
	}
	return out
}

// hasContent reports an element with at least one child element.
func (n *pomNode) hasContent() bool { return n != nil && len(n.children) > 0 }

// pomCharsetReader serves documents that declare ISO-8859-1 or US-ASCII, which
// older pom files do.
func pomCharsetReader(label string, input io.Reader) (io.Reader, error) {
	switch strings.ToLower(label) {
	case "iso-8859-1", "latin1", "us-ascii", "ascii":
		b, err := io.ReadAll(input)
		if err != nil {
			return nil, err
		}
		rs := make([]rune, len(b))
		for i, c := range b {
			rs[i] = rune(c)
		}
		return strings.NewReader(string(rs)), nil
	}
	return nil, fmt.Errorf("unsupported encoding %q", label)
}

// readPOMTree reads the document into a tree. A DOCTYPE is refused, as are
// documents over the size limit, deeply nested or malformed.
func readPOMTree(data []byte) (*pomNode, error) {
	if len(data) > maxMavenPOMBytes {
		return nil, fmt.Errorf("pom is larger than %d bytes", maxMavenPOMBytes)
	}
	dec := xml.NewDecoder(bytes.NewReader(data))
	dec.CharsetReader = pomCharsetReader
	var root *pomNode
	var stack []*pomNode
	var text []*strings.Builder
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("pom is not well-formed XML: %w", err)
		}
		switch t := tok.(type) {
		case xml.Directive:
			return nil, errors.New("pom has a DOCTYPE, which is refused")
		case xml.StartElement:
			if len(stack) >= maxMavenPOMDepth {
				return nil, errors.New("pom is nested too deeply")
			}
			n := &pomNode{name: t.Name.Local}
			for _, a := range t.Attr {
				n.attrs = append(n.attrs, a.Value)
			}
			if len(stack) == 0 {
				if root != nil {
					return nil, errors.New("pom has more than one root element")
				}
				root = n
			} else {
				p := stack[len(stack)-1]
				p.children = append(p.children, n)
			}
			stack = append(stack, n)
			text = append(text, &strings.Builder{})
		case xml.EndElement:
			n := stack[len(stack)-1]
			n.text = strings.TrimSpace(text[len(text)-1].String())
			stack, text = stack[:len(stack)-1], text[:len(text)-1]
		case xml.CharData:
			if len(stack) > 0 {
				text[len(text)-1].Write(t)
			}
		}
	}
	if root == nil {
		return nil, errors.New("pom has no root element")
	}
	if len(stack) != 0 {
		return nil, errors.New("pom ends inside an element")
	}
	return root, nil
}

func parseMavenDeps(container *pomNode) []mavenDep {
	if container == nil {
		return nil
	}
	var out []mavenDep
	for _, d := range container.elements("dependency") {
		dep := mavenDep{
			GroupID:    d.childText("groupId"),
			ArtifactID: d.childText("artifactId"),
			Version:    d.childText("version"),
			Type:       d.childText("type"),
			Classifier: d.childText("classifier"),
			Scope:      d.childText("scope"),
			Optional:   d.childText("optional"),
		}
		if ex := d.child("exclusions"); ex != nil && len(ex.elements("exclusion")) > 0 {
			dep.HasExclusions = true
		}
		out = append(out, dep)
	}
	return out
}

func parseMavenRepoURLs(container *pomNode, item string) []string {
	if container == nil {
		return nil
	}
	var out []string
	for _, r := range container.elements(item) {
		out = append(out, r.childText("url"))
	}
	return out
}

// collectPOMRefs adds the ${name} references in n and below to refs.
func collectPOMRefs(n *pomNode, seen map[string]bool, refs *[]string) {
	add := func(s string) {
		for _, name := range mavenPropertyRefs(s) {
			if !seen[name] {
				seen[name] = true
				*refs = append(*refs, name)
			}
		}
	}
	add(n.text)
	for _, a := range n.attrs {
		add(a)
	}
	for _, c := range n.children {
		collectPOMRefs(c, seen, refs)
	}
}

// parseMavenPOM reads a pom file. The element names are matched by their
// local part, so documents with and without the POM namespace read alike.
func parseMavenPOM(data []byte) (*mavenPOM, error) {
	root, err := readPOMTree(data)
	if err != nil {
		return nil, err
	}
	if root.name != "project" {
		return nil, fmt.Errorf("pom root element is %q, not project", root.name)
	}
	p := &mavenPOM{
		GroupID:    root.childText("groupId"),
		ArtifactID: root.childText("artifactId"),
		Version:    root.childText("version"),
		Packaging:  root.childText("packaging"),
		Properties: map[string]string{},
	}
	if par := root.child("parent"); par != nil {
		rp := par.child("relativePath")
		p.Parent = &mavenParent{
			GroupID:    par.childText("groupId"),
			ArtifactID: par.childText("artifactId"),
			Version:    par.childText("version"),
		}
		if rp != nil {
			p.Parent.RelativePath, p.Parent.RelativePathSet = rp.text, true
		}
	}
	if props := root.child("properties"); props != nil {
		for _, c := range props.children {
			if _, dup := p.Properties[c.name]; !dup {
				p.PropertyOrder = append(p.PropertyOrder, c.name)
			}
			p.Properties[c.name] = c.text
		}
	}
	if mods := root.child("modules"); mods != nil {
		for _, m := range mods.elements("module") {
			p.Modules = append(p.Modules, m.text)
		}
	}
	p.Dependencies = parseMavenDeps(root.child("dependencies"))
	if dm := root.child("dependencyManagement"); dm != nil {
		p.DependencyManagement = parseMavenDeps(dm.child("dependencies"))
	}
	if profs := root.child("profiles"); profs != nil {
		for _, pr := range profs.elements("profile") {
			mp := mavenProfile{
				ID:           pr.childText("id"),
				Dependencies: pr.child("dependencies").hasContent(),
				Properties:   pr.child("properties").hasContent(),
				Parent:       pr.child("parent") != nil,
				Modules:      pr.child("modules").hasContent(),
				Repositories: pr.child("repositories").hasContent() || pr.child("pluginRepositories").hasContent(),
			}
			if dm := pr.child("dependencyManagement"); dm != nil {
				mp.DependencyManagement = dm.child("dependencies").hasContent()
			}
			p.Profiles = append(p.Profiles, mp)
		}
	}
	p.Repositories = parseMavenRepoURLs(root.child("repositories"), "repository")
	p.PluginRepositories = parseMavenRepoURLs(root.child("pluginRepositories"), "pluginRepository")
	if dm := root.child("distributionManagement"); dm != nil && dm.child("relocation") != nil {
		p.Relocation = true
	}
	seen := map[string]bool{}
	for _, c := range root.children {
		switch c.name {
		case "dependencies", "dependencyManagement", "properties":
			continue
		}
		collectPOMRefs(c, seen, &p.PluginVersionRefs)
	}
	return p, nil
}
