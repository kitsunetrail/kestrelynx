package remediation

import (
	"path"
	"sort"
	"strings"

	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

// The language runtimes KestreLynx checks itself (Node.js, CPython and Java) are
// installed by the official images outside any package manager, so Trivy
// attributes their findings to no layer. Their version comes from an
// environment variable of the image config, which makes a base image's
// runtime readable from its registry config alone.

// RuntimeRebuild is what rebuilding on the current base would do to the
// findings of one language runtime of the running image. It is read from the
// base's version, not from a scan of the rebuilt image.
type RuntimeRebuild struct {
	Package string `json:"package"`
	// Installed is the runtime version of the running image and BaseVersion
	// the one the current base carries.
	Installed   string `json:"installed"`
	BaseVersion string `json:"base_version"`
	// Disappearing are the VulnIDs of the running image's findings of this
	// runtime that the base's version does not have, Remaining the ones it
	// still has; both sorted. Findings only the base's version has are not
	// counted.
	Disappearing []string `json:"disappearing,omitempty"`
	Remaining    []string `json:"remaining,omitempty"`
	// Targets are the executable paths of the running image's findings the
	// record covers, sorted. A finding of the same version and CVE at another
	// path, such as a second JDK, is not covered.
	Targets []string `json:"targets,omitempty"`
}

// envDerived reports whether the version of a runtime finding is the one the
// image's environment variables name: findings of Node.js and CPython, the
// environment route of Java, and a JDK read from the image's files that is
// the very runtime the environment names. A JDK that is only another one in
// the image is not.
func envDerived(f scanner.Finding) bool {
	if f.RuntimeSource == scanner.RuntimeSourceRelease {
		return f.RuntimeSameAsEnv
	}
	return true
}

// isRuntimeType reports whether a finding's Type is a language runtime
// KestreLynx checks itself.
func isRuntimeType(t string) bool {
	return inventory.RuntimeVersionEnv(inventory.Ecosystem(t)) != ""
}

// envValue returns the value of the last NAME=value entry of env, as a
// container runtime resolves a repeated variable.
func envValue(env []string, name string) (string, bool) {
	val, found := "", false
	for _, e := range env {
		if v, ok := strings.CutPrefix(e, name+"="); ok {
			val, found = v, true
		}
	}
	return val, found
}

// sameRuntimeLocation reports whether the running image and the base install
// the runtime of ecosystem type t in the same place. A runtime without a
// location variable always does; with one, both images must set it to an
// absolute path and the paths must be equal (unset, empty and relative never
// match), so a runtime reinstalled elsewhere is not taken for the base's.
func sameRuntimeLocation(t string, imageEnv, baseEnv []string) bool {
	name := inventory.RuntimeLocationEnv(inventory.Ecosystem(t))
	if name == "" {
		return true
	}
	iv, iok := envValue(imageEnv, name)
	bv, bok := envValue(baseEnv, name)
	return iok && bok && path.IsAbs(iv) && path.IsAbs(bv) && iv == bv
}

// moveRuntimeFindings moves the runtime findings that could not be placed in a
// layer into the base's group when the running image and the base declare the
// same version of that runtime, installed in the same place. The environment
// variables are the only evidence the runtime came from the base. A finding
// from the JDK files of the image (RuntimeSourceRelease) is placed by its
// layer alone: an overwritten, mixed or unplaced JDK is not moved to the
// base on the strength of the environment variables.
func moveRuntimeFindings(cl *FindingsByLayer, imageEnv, baseEnv []string) {
	var keep []scanner.Finding
	for _, f := range cl.Unknown {
		name := inventory.RuntimeVersionEnv(inventory.Ecosystem(f.Type))
		if name != "" && f.RuntimeSource != scanner.RuntimeSourceRelease {
			iv, iok := envValue(imageEnv, name)
			bv, bok := envValue(baseEnv, name)
			if iok && bok && iv == bv && sameRuntimeLocation(f.Type, imageEnv, baseEnv) {
				cl.Base = append(cl.Base, f)
				continue
			}
		}
		keep = append(keep, f)
	}
	cl.Unknown = keep
}

// baseRuntime is one language runtime found in a base image.
type baseRuntime struct {
	Package  string
	Version  string
	Findings []scanner.Finding
}

// baseRuntimes matches the runtimes of a base image from its config
// environment, without scanning it. A runtime is returned only when its
// advisor could check it: it is not reported unchecked and its package list
// came back. The result is keyed by the runtime's Type.
func (r *run) baseRuntimes(env []string, platform inventory.Platform) map[string]baseRuntime {
	sev := r.p.cfg.Prepared.Severities
	if len(sev) == 0 || len(r.p.cfg.Runtimes) == 0 {
		return nil
	}
	out := map[string]baseRuntime{}
	for _, rt := range r.p.cfg.Runtimes {
		aug := rt.Augment(scanner.ImageScan{ConfigEnv: env, Platform: platform}, sev)
		for _, rp := range aug.Packages {
			if !isRuntimeType(rp.Type) || len(rp.Packages) == 0 {
				continue
			}
			p := rp.Packages[0]
			if containsString(aug.Unchecked, p.Name) {
				continue
			}
			b := baseRuntime{Package: p.Name, Version: p.Version}
			for _, f := range aug.Findings {
				if f.Type == rp.Type {
					b.Findings = append(b.Findings, f)
				}
			}
			out[rp.Type] = b
		}
	}
	return out
}

// runtimeRebuilds compares the runtime findings of the running image with
// those of the current base's runtimes. Only runtimes the running image has
// findings for, and installed in the same place as in the base, are listed,
// ordered by Type.
func (r *run) runtimeRebuilds(in ImageInput, baseEnv []string) []RuntimeRebuild {
	running := map[string][]scanner.Finding{}
	for _, f := range in.Scan.Findings {
		if isRuntimeType(f.Type) && envDerived(f) {
			running[f.Type] = append(running[f.Type], f)
		}
	}
	if len(running) == 0 {
		return nil
	}
	base := r.baseRuntimes(baseEnv, in.Scan.Platform)
	var types []string
	for t := range running {
		if _, ok := base[t]; ok && sameRuntimeLocation(t, in.Scan.ConfigEnv, baseEnv) {
			types = append(types, t)
		}
	}
	sort.Strings(types)
	var out []RuntimeRebuild
	for _, t := range types {
		b := base[t]
		inBase := map[string]bool{}
		for _, f := range b.Findings {
			inBase[f.VulnID] = true
		}
		rr := RuntimeRebuild{Package: b.Package, Installed: running[t][0].InstalledVer, BaseVersion: b.Version}
		seen := map[string]bool{}
		for _, f := range running[t] {
			// The paths only say which findings of the report the record
			// covers; whether a CVE disappears is decided by the CVE alone.
			if !containsString(rr.Targets, f.Target) {
				rr.Targets = append(rr.Targets, f.Target)
			}
			if seen[f.VulnID] {
				continue
			}
			seen[f.VulnID] = true
			if inBase[f.VulnID] {
				rr.Remaining = append(rr.Remaining, f.VulnID)
			} else {
				rr.Disappearing = append(rr.Disappearing, f.VulnID)
			}
		}
		sort.Strings(rr.Disappearing)
		sort.Strings(rr.Remaining)
		sort.Strings(rr.Targets)
		out = append(out, rr)
	}
	return out
}

// mergeRuntimeRebuilds groups the entities' records by (Package, Installed,
// BaseVersion), taking the union of their VulnIDs. A VulnID that one image
// still has is not counted as disappearing.
func mergeRuntimeRebuilds(ents []DockerfileEntity) []RuntimeRebuild {
	type key struct{ pkg, installed, base string }
	type sets struct{ dis, rem, targets map[string]bool }
	groups := map[key]*sets{}
	var keys []key
	for _, e := range ents {
		for _, rr := range e.RebuildRuntimes {
			k := key{rr.Package, rr.Installed, rr.BaseVersion}
			g := groups[k]
			if g == nil {
				g = &sets{dis: map[string]bool{}, rem: map[string]bool{}, targets: map[string]bool{}}
				groups[k] = g
				keys = append(keys, k)
			}
			for _, v := range rr.Disappearing {
				g.dis[v] = true
			}
			for _, v := range rr.Remaining {
				g.rem[v] = true
			}
			for _, v := range rr.Targets {
				g.targets[v] = true
			}
		}
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		if a.pkg != b.pkg {
			return a.pkg < b.pkg
		}
		if a.installed != b.installed {
			return a.installed < b.installed
		}
		return a.base < b.base
	})
	var out []RuntimeRebuild
	for _, k := range keys {
		g := groups[k]
		rr := RuntimeRebuild{Package: k.pkg, Installed: k.installed, BaseVersion: k.base}
		for v := range g.dis {
			if !g.rem[v] {
				rr.Disappearing = append(rr.Disappearing, v)
			}
		}
		for v := range g.rem {
			rr.Remaining = append(rr.Remaining, v)
		}
		for v := range g.targets {
			rr.Targets = append(rr.Targets, v)
		}
		sort.Strings(rr.Disappearing)
		sort.Strings(rr.Remaining)
		sort.Strings(rr.Targets)
		out = append(out, rr)
	}
	return out
}
