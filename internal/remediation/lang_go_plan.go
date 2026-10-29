package remediation

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

// typeGoBinary is the scanner result type of the modules built into a Go
// binary, and typeGoModule that of a go.mod scanned as a file.
const (
	typeGoBinary = "gobinary"
	typeGoModule = "gomod"
)

// goStdlib is the name Trivy gives the Go standard library a binary was
// built with; its version is the Go release.
const goStdlib = "stdlib"

// goBinary is what a scan says about one Go binary of a running image: its
// main module and the version of every other module built into it.
type goBinary struct {
	roots     []string          // main modules (one for a binary Trivy read whole)
	deps      map[string]string // module path -> version, the root and stdlib left out
	stdlib    string            // the Go release it was built with, "" when not reported
	truncated bool              // the scan's package list was cut short
}

// goBinaryKey identifies a binary of one scan: the scan's place among the
// planner's inputs (an entity key is not enough, since every scan that did
// not confirm its image has the same one) and the binary's path.
func goBinaryKey(input int, target string) string { return strconv.Itoa(input) + "\x00" + target }

// goBinariesOf reads the Go binaries of the scan of input from its package
// lists.
func goBinariesOf(input int, s scanner.ImageScan, into map[string]*goBinary) {
	for _, rp := range s.Packages {
		if rp.Type != typeGoBinary {
			continue
		}
		b := &goBinary{deps: map[string]string{}, truncated: s.PackagesTruncated}
		for _, p := range rp.Packages {
			switch {
			case p.Relationship == "root":
				b.roots = append(b.roots, p.Name)
			case p.Name == goStdlib:
				b.stdlib = p.Version
			default:
				b.deps[p.Name] = p.Version
			}
		}
		into[goBinaryKey(input, rp.Target)] = b
	}
}

// goSelect keeps, of the Go findings of a unit, those of the binaries built
// from the module go.mod declares: a binary whose main module is that
// module. The findings of other binaries (a tool that came with the base
// image, say) are not this source's and are dropped without a trace. This is
// done per running image and binary, before findings are grouped by name and
// version, so that a tool's findings for a module at the same version never
// join the module's own.
//
// With check, the binaries kept must be ones these files can have built:
// every module built into them is required by go.mod at the same version,
// and every module a kept finding names is in the binary's list at the
// finding's version (the standard library and the main module itself
// aside). why is set when one is not, or when a binary cannot be read whole;
// the unit then goes to a person with the kept findings.
func goSelect(fs []srcFinding, bins map[string]*goBinary, gm *goMod, check bool) (kept []srcFinding, why string) {
	required := map[string]string{}
	for _, r := range gm.requires {
		required[r.path] = r.version
	}
	checked := map[*goBinary]bool{}
	note := func(p string) {
		if p != "" && why == "" {
			why = p
		}
	}
	for _, lf := range fs {
		b := bins[goBinaryKey(lf.rank, lf.f.Target)]
		if b == nil || !containsString(b.roots, gm.module) {
			continue
		}
		kept = append(kept, lf)
		if !check {
			continue
		}
		if !checked[b] {
			checked[b] = true
			note(goBinaryProblem(lf.f.Target, b, gm.module, required))
		}
		// A finding of the main module itself is the module's, not one of its
		// dependencies'.
		if lf.f.Package != goStdlib && !containsString(b.roots, lf.f.Package) {
			if v, ok := b.deps[lf.f.Package]; !ok || v != lf.f.InstalledVer {
				note(fmt.Sprintf("%s reports %s %s, which is not in the binary's module list", lf.f.Target, lf.f.Package, lf.f.InstalledVer))
			}
		}
	}
	return kept, why
}

// goBuiltWith is the lowest Go release the binaries built from module were
// built with, whether or not they have findings; "" when one of them did not
// record it.
func goBuiltWith(bins map[string]*goBinary, module string) string {
	var low goRelease
	found := false
	for _, b := range bins {
		if !containsString(b.roots, module) {
			continue
		}
		r, ok := parseGoRelease(strings.TrimPrefix(b.stdlib, "v"))
		if !ok {
			return ""
		}
		if !found || r.compare(low) < 0 {
			low, found = r, true
		}
	}
	if !found {
		return ""
	}
	return low.String()
}

// goSplit separates the standard library groups from the module groups.
func goSplit(groups []*findingGroup) (mods, stdlib []*findingGroup) {
	for _, g := range groups {
		if g.Name == goStdlib {
			stdlib = append(stdlib, g)
		} else {
			mods = append(mods, g)
		}
	}
	return mods, stdlib
}

// goBinaryProblem says why a binary built from the module cannot be matched
// against go.mod, or "".
func goBinaryProblem(target string, b *goBinary, module string, required map[string]string) string {
	switch {
	case b.truncated:
		return fmt.Sprintf("the package list of %s was cut short, so it cannot be compared with go.mod", target)
	case len(b.roots) != 1:
		return fmt.Sprintf("%s names %d main modules (%s)", target, len(b.roots), strings.Join(b.roots, ", "))
	}
	var bad []string
	for mod, ver := range b.deps {
		req, ok := required[mod]
		switch {
		case !ok:
			bad = append(bad, fmt.Sprintf("%s %s is built in but not required", mod, ver))
		case !versionsEqual(schemeGo, req, ver):
			bad = append(bad, fmt.Sprintf("%s is built in at %s, go.mod requires %s", mod, ver, req))
		}
	}
	if len(bad) == 0 {
		return ""
	}
	sort.Strings(bad)
	if len(bad) > 5 {
		bad = append(bad[:5], fmt.Sprintf("and %d more", len(bad)-5))
	}
	return fmt.Sprintf("%s, built from %s, does not match this go.mod: %s", target, module, strings.Join(bad, "; "))
}

// goStdlibPackage is the plan entry of a vulnerability in the Go standard
// library a binary was built with: go.mod does not fix it, building with a
// newer Go does. The detail names the lowest fixed release of the binary's
// own series, or, when that series has none, the lowest fixed release of
// all.
func goStdlibPackage(g *findingGroup) LanguagePackage {
	p := LanguagePackage{Name: g.Name, Ecosystem: g.Type, Installed: g.Installed, CVEs: g.cves, Origins: g.origins}
	at := goStdlibFix(g.Installed, g.cves)
	detail := "building with a newer Go fixes this; go.mod does not"
	if at != "" {
		detail = fmt.Sprintf("building with Go %s or later fixes this; go.mod does not", at)
	}
	manualPackage(&p, ReasonGoStdlib, detail)
	return p
}

// goStdlibFix is the Go release that fixes every vulnerability of a stdlib
// group. A fixed version names the first fixed release of one series (1.25.3
// for 1.25); a series above every series a vulnerability lists has it fixed
// from its first release, and one below the highest listed but not itself
// listed does not have it fixed. The series tried are the installed one and
// each listed series above it, lowest first; the first in which every
// vulnerability is fixed gives the highest of their fixes there. "" when a
// fix does not read as a release or no series fixes them all.
func goStdlibFix(installed string, cves []CVERef) string {
	inst, ok := parseGoRelease(strings.TrimPrefix(installed, "v"))
	if !ok {
		return ""
	}
	type series struct{ major, minor int }
	of := func(r goRelease) series { return series{r.major, r.minor} }
	less := func(a, b series) bool { return a.major < b.major || (a.major == b.major && a.minor < b.minor) }
	fixes := make([]map[series]goRelease, len(cves)) // per vulnerability, the first fixed release of each listed series
	top := make([]series, len(cves))                 // per vulnerability, its highest listed series
	tries := map[series]bool{of(inst): true}
	for i, c := range cves {
		fixes[i] = map[series]goRelease{}
		for _, alt := range c.FixedVers {
			for _, one := range splitFixed(alt) {
				r, ok := parseGoRelease(strings.TrimPrefix(one, "v"))
				if !ok {
					return ""
				}
				s := of(r)
				if cur, ok := fixes[i][s]; !ok || r.compare(cur) < 0 {
					fixes[i][s] = r
				}
				if less(top[i], s) {
					top[i] = s
				}
				if !less(s, of(inst)) {
					tries[s] = true
				}
			}
		}
		if len(fixes[i]) == 0 {
			return ""
		}
	}
	order := make([]series, 0, len(tries))
	for s := range tries {
		order = append(order, s)
	}
	sort.Slice(order, func(i, j int) bool { return less(order[i], order[j]) })
	for _, s := range order {
		var need goRelease
		ok := true
		for i := range cves {
			r, listed := fixes[i][s]
			switch {
			case listed:
			case less(top[i], s):
				r = goRelease{s.major, s.minor, 0}
			default:
				ok = false
			}
			if !ok {
				break
			}
			if r.compare(need) > 0 {
				need = r
			}
		}
		if !ok {
			continue
		}
		if need.compare(inst) <= 0 {
			// Every listed fix of this series is at or below the installed
			// release, which the scan says is affected: the data disagree.
			return ""
		}
		return need.String()
	}
	return ""
}

// goPathMajor is the major version suffix of a module path: "/vN" (N of 2
// or more) at its end, ".vN" of a gopkg.in path, or "" for a path without one.
func goPathMajor(path string) string {
	if strings.HasPrefix(path, "gopkg.in/") {
		i := strings.LastIndex(path, ".v")
		if i < 0 {
			return ""
		}
		return strings.TrimSuffix(path[i:], "-unstable")
	}
	i := strings.LastIndex(path, "/v")
	if i < 0 {
		return ""
	}
	n := path[i+2:]
	if n == "" || n[0] == '0' || n == "1" || strings.Trim(n, "0123456789") != "" {
		return ""
	}
	return path[i:]
}

// goMajorProblem says why a fix cannot be reached by changing only the
// version of the module at path, by the go command's rule: a path with a
// major version suffix takes versions of that major only (gopkg.in's .v1
// also an old v0.0.0 pseudo-version); a path without one takes v0, v1 and,
// from v2, versions without a go.mod of their own (+incompatible). A fix of
// v2 or more on a path without a suffix is taken only when it is marked
// +incompatible or the installed version is: whether the proxy serves it so
// is checked when the update is made.
func goMajorProblem(path, installed, target string) string {
	major := func(v string) (int, bool) {
		sv, ok := parseVersion(schemeGo, v)
		if !ok {
			return 0, false
		}
		n, err := strconv.Atoi(sv.(semver).major)
		return n, err == nil
	}
	m, ok := major(target)
	if !ok {
		return ""
	}
	fits := false
	switch pm := goPathMajor(path); {
	case pm == "":
		fits = m <= 1 || strings.HasSuffix(target, "+incompatible") || strings.HasSuffix(installed, "+incompatible")
	case pm == ".v1" && strings.HasPrefix(strings.TrimPrefix(target, "v"), "0.0.0-"):
		fits = true
	default:
		fits = pm[2:] == strconv.Itoa(m)
	}
	if fits {
		return ""
	}
	return fmt.Sprintf("the fix %s is of another major version than %s, which Go names as another module path than %s", target, installed, path)
}
