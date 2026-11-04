package remediation

import (
	"bytes"
	"strings"

	"github.com/kitsunetrail/kestrelynx/internal/scanner"
	"github.com/kitsunetrail/kestrelynx/internal/worker"
)

// maxHolders bounds the packages one hint names as bringing a package in.
const maxHolders = 5

// setHolders records on the packages of name what brings it in at a version
// below its target after an update: the packages that depend on it (HeldBy,
// each with the version of name it brings), or, with direct, the project's
// own declaration; conf is the Gradle configuration it was found in.
func (r *updateRun) setHolders(name string, holders []FixHolder, direct bool, conf string) {
	if len(holders) == 0 && !direct {
		return
	}
	for _, k := range r.full.byName[name] {
		r.it.Packages[k].FixHint = &FixHint{HeldBy: append([]FixHolder(nil), holders...), Direct: direct && len(holders) == 0, Configuration: conf}
	}
}

// mavenHolders reads, in the dependency graph of a scan of pom files, the
// packages that depend on name at version: each with its own version. A
// package of the project itself (Trivy's root) is not a dependent; direct
// says one declares it.
func mavenHolders(rep scanner.ImageScan, name, version string) (holders []FixHolder, direct bool) {
	ids := map[string]bool{}
	for _, rp := range rep.Packages {
		if rp.Type != "pom" {
			continue
		}
		for _, p := range rp.Packages {
			if p.Name == name && p.Version == version && p.ID != "" {
				ids[p.ID] = true
			}
		}
	}
	if len(ids) == 0 {
		return nil, false
	}
	seen := map[string]bool{}
	for _, rp := range rep.Packages {
		if rp.Type != "pom" {
			continue
		}
		for _, p := range rp.Packages {
			uses := false
			for _, d := range p.DependsOn {
				uses = uses || ids[d]
			}
			if !uses {
				continue
			}
			if p.Relationship == "root" {
				direct = true
				continue
			}
			k := p.Name + "@" + p.Version
			if seen[k] || len(holders) >= maxHolders {
				continue
			}
			seen[k] = true
			holders = append(holders, FixHolder{Parent: p.Name, ParentVersion: p.Version, Range: version})
		}
	}
	return holders, direct
}

// gradleNode is one line of the dependency tree a Gradle report prints for a
// configuration: its depth, the module (group:artifact), the version asked
// for and the version Gradle resolved it to.
type gradleNode struct {
	depth                   int
	module, asked, resolved string
	constraint              bool
}

// maxGradleTreeLines bounds the lines of a report read, the lines before the
// configuration's tree included, and maxGradleLineBytes the length of a line
// of the tree: a longer one ends it.
const (
	maxGradleTreeLines = 100000
	maxGradleLineBytes = 1024
)

// gradleTree reads the tree the dependencies task printed for conf, nil when
// the report has no such section or is larger than a step returns. A line it
// cannot read ends the tree.
func gradleTree(report []byte, conf string) []gradleNode {
	if len(report) > worker.MaxGradleReportBytes {
		return nil
	}
	var out []gradleNode
	in := false
	rest := report
	for n := 0; len(rest) > 0 && n < maxGradleTreeLines; n++ {
		line := rest
		if i := bytes.IndexByte(rest, '\n'); i >= 0 {
			line, rest = rest[:i], rest[i+1:]
		} else {
			rest = nil
		}
		l := string(line)
		if !in {
			in = l == conf || strings.HasPrefix(l, conf+" - ") || strings.HasPrefix(l, conf+" (")
			continue
		}
		if len(l) > maxGradleLineBytes {
			break
		}
		node, ok := parseGradleTreeLine(l)
		if !ok {
			break
		}
		out = append(out, node)
	}
	if !in {
		return nil
	}
	return out
}

// parseGradleTreeLine reads "|    +--- group:artifact:1.0 -> 1.2 (*)": the
// depth is the number of five-column steps before the "+--- " or "\--- ".
func parseGradleTreeLine(l string) (gradleNode, bool) {
	depth := 0
	for strings.HasPrefix(l, "|    ") || strings.HasPrefix(l, "     ") {
		l = l[5:]
		depth++
	}
	rest, ok := strings.CutPrefix(l, "+--- ")
	if !ok {
		if rest, ok = strings.CutPrefix(l, "\\--- "); !ok {
			return gradleNode{}, false
		}
	}
	n := gradleNode{depth: depth}
	for _, suffix := range []string{" (*)", " (c)", " (n)"} {
		if s, cut := strings.CutSuffix(rest, suffix); cut {
			rest = s
			n.constraint = suffix == " (c)"
		}
	}
	coord, to, moved := strings.Cut(rest, " -> ")
	parts := strings.Split(coord, ":")
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return gradleNode{}, false
	}
	n.module = parts[0] + ":" + parts[1]
	if len(parts) >= 3 {
		n.asked = strings.Join(parts[2:], ":")
	}
	n.resolved = n.asked
	if moved {
		n.resolved = strings.TrimSpace(to)
	}
	return n, true
}

// gradleHolders reads, in the tree of conf, the modules that bring name in at
// version: the parent of each line of it (with the version they ask for), or,
// with direct, the configuration's own declaration of it.
func gradleHolders(report []byte, conf, name, version string) (holders []FixHolder, direct bool) {
	tree := gradleTree(report, conf)
	// The line of each parent counted once, and each module and version.
	parentSeen := map[int]bool{}
	named := map[string]bool{}
	// The index of the last line read at each depth: the parent of a line is
	// the last one read one step up.
	var last []int
	for i, n := range tree {
		if n.depth > len(last) {
			break // a line deeper than its place in the tree: the tree is not read further
		}
		last = append(last[:n.depth], i)
		if n.constraint || n.module != name || n.resolved != version {
			continue
		}
		if n.depth == 0 {
			direct = true
			continue
		}
		pi := last[n.depth-1]
		if parentSeen[pi] {
			continue
		}
		parentSeen[pi] = true
		p := tree[pi]
		if k := p.module + "@" + p.resolved; !named[k] && len(holders) < maxHolders && p.resolved != "" {
			named[k] = true
			holders = append(holders, FixHolder{Parent: p.module, ParentVersion: p.resolved, Range: n.asked})
		}
	}
	return holders, direct
}
