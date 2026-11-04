package remediation

import (
	"bytes"
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/kitsunetrail/kestrelynx/internal/worker"
)

// gradleLockHeader are the comment lines Gradle writes at the top of
// gradle.lockfile.
var gradleLockHeader = []string{
	"# This is a Gradle generated file for dependency locking.",
	"# Manual edits can break the build and are not advised.",
	"# This file is expected to be part of source control.",
}

// gradleLockByConf lists, for each configuration, the version of each
// package locked in it. A package locked at two versions in one
// configuration is a lockfile that contradicts itself.
func gradleLockByConf(l *gradleLock) (map[string]map[string]string, error) {
	out := map[string]map[string]string{}
	for _, e := range l.entries {
		for _, c := range e.confs {
			if out[c] == nil {
				out[c] = map[string]string{}
			}
			if v, dup := out[c][e.name]; dup {
				return nil, fmt.Errorf("%s is locked at both %s and %s in %s", e.name, v, e.version, c)
			}
			out[c][e.name] = e.version
		}
	}
	return out, nil
}

// gradleRegenerateRe is the line Gradle writes to say how to make the file
// again, for the root project or a project at a path.
var gradleRegenerateRe = regexp.MustCompile(`^# To regenerate this file, run: \./gradlew ((:[A-Za-z0-9_.-]+)*:)?dependencies --write-locks$`)

// gradleLockComments are the comment lines of a lockfile.
func gradleLockComments(data []byte) []string {
	var out []string
	for _, l := range strings.Split(strings.TrimPrefix(string(data), utf8BOM), "\n") {
		if l = strings.TrimSuffix(l, "\r"); strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return out
}

func sameStringSet(a, b []string) bool {
	x, y := uniqueSorted(a), uniqueSorted(b)
	return strings.Join(x, "\x00") == strings.Join(y, "\x00")
}

// checkGradleOutput judges what the work container returned, which is not
// trusted. Of the files it was given only gradle.lockfile may have changed,
// and the new lockfile must keep the configurations it locks, lose no entry,
// take every target to its release in every configuration it was in, and
// name only packages and versions that have a pom on Maven Central. It
// returns the new lockfile.
func (r *updateRun) checkGradleOutput(ctx context.Context, proj *gradleProject, out *jobOutput, inputs map[string][]byte, releases map[string]string) ([]byte, *updateFailure) {
	invalid := func(format string, args ...any) *updateFailure {
		return manualFailure(ReasonOutputFilesInvalid, format, args...)
	}
	for _, name := range sortedMapKeys(inputs) {
		got, ok := out.finalFile(name)
		if !ok {
			return nil, invalid("the final tree lacks %s", name)
		}
		if name != "gradle.lockfile" && !bytes.Equal(got, inputs[name]) {
			return nil, invalid("the update changed %s, which only the edits of this program may change", name)
		}
	}
	newBytes, _ := out.finalFile("gradle.lockfile")
	nl, err := parseGradleLockfile("gradle.lockfile", newBytes)
	if err != nil {
		return nil, invalid("the updated gradle.lockfile cannot be read: %v", err)
	}
	known := append([]string(nil), gradleLockHeader...)
	known = append(known, gradleLockComments(proj.content[proj.lockPath])...)
	for _, c := range gradleLockComments(newBytes) {
		if !containsString(known, c) && !gradleRegenerateRe.MatchString(c) {
			return nil, invalid("the updated gradle.lockfile has the comment line %q, which is not one Gradle writes", clip(c, 100))
		}
	}
	newBy, err := gradleLockByConf(nl)
	if err != nil {
		return nil, invalid("the updated gradle.lockfile contradicts itself: %v", err)
	}
	oldBy, err := gradleLockByConf(proj.lock)
	if err != nil {
		return nil, manualFailure(ReasonUnparsableSource, "gradle.lockfile contradicts itself: %v", err)
	}

	// The configurations it locks, and the ones it lists as empty.
	if !sameStringSet(trueKeys(proj.lock.configs), trueKeys(nl.configs)) || !sameStringSet(proj.lock.empty, nl.empty) {
		return nil, manualFailure(ReasonGradleLockConfigurationsChanged, "the updated gradle.lockfile locks %s and lists %s as empty; the original locks %s and lists %s",
			strings.Join(uniqueSorted(trueKeys(nl.configs)), ", "), strings.Join(uniqueSorted(nl.empty), ", "),
			strings.Join(uniqueSorted(trueKeys(proj.lock.configs)), ", "), strings.Join(uniqueSorted(proj.lock.empty), ", "))
	}
	// An entry that is gone is not a fix: nothing tells it from a dependency
	// the build still needs.
	var removed []string
	for conf, pkgs := range oldBy {
		for name, v := range pkgs {
			if _, ok := newBy[conf][name]; !ok {
				removed = append(removed, fmt.Sprintf("%s %s from %s", name, v, conf))
			}
		}
	}
	if len(removed) > 0 {
		sort.Strings(removed)
		if len(removed) > 5 {
			removed = append(removed[:5], fmt.Sprintf("and %d more", len(removed)-5))
		}
		return nil, manualFailure(ReasonGradleLockEntryRemoved, "the update took entries out of gradle.lockfile: %s", strings.Join(removed, "; "))
	}

	versionsOf := func(l *gradleLock, name string) []string {
		var out []string
		for _, i := range l.byName[name] {
			out = append(out, l.entries[i].version)
		}
		return uniqueSorted(out)
	}
	r.afterVersions, r.adopted = map[string][]string{}, map[string]string{}
	for _, n := range stringKeys(releases) {
		want := releases[n]
		for conf, pkgs := range oldBy {
			if _, was := pkgs[n]; !was {
				continue
			}
			got := newBy[conf][n]
			if c, ok := compareVersions(schemeMaven, got, want); !ok || c < 0 {
				if report, ok := out.stepFile(stepUpdate, worker.GradleReportName); ok {
					holders, direct := gradleHolders(report, conf, n, got)
					r.setHolders(n, holders, direct, conf)
				}
				return nil, pkgFailure(n, ReasonTargetNotUpdated, "the updated gradle.lockfile has %s at %s in %s, below %s", n, got, conf, want)
			}
		}
		after := versionsOf(nl, n)
		for _, v := range after {
			if lo := r.adopted[n]; lo == "" {
				r.adopted[n] = v
			} else if c, _ := compareVersions(schemeMaven, v, lo); c < 0 {
				r.adopted[n] = v
			}
		}
		r.afterVersions[n] = after
	}

	// Every package and version the update added or changed must be one Maven
	// Central publishes a pom for, and none a snapshot.
	oldPairs := map[string]bool{}
	for _, e := range proj.lock.entries {
		oldPairs[e.name+":"+e.version] = true
	}
	var fresh []gradleLockEntry
	seen := map[string]bool{}
	for _, e := range nl.entries {
		k := e.name + ":" + e.version
		if oldPairs[k] || seen[k] {
			continue
		}
		seen[k] = true
		fresh = append(fresh, e)
	}
	sort.Slice(fresh, func(i, j int) bool {
		return fresh[i].name+":"+fresh[i].version < fresh[j].name+":"+fresh[j].version
	})
	for _, e := range fresh {
		if strings.Contains(strings.ToUpper(e.version), "SNAPSHOT") {
			return nil, manualFailure(ReasonGradleLockVersionUnsupported, "the updated gradle.lockfile locks %s at the snapshot version %s", e.name, e.version)
		}
	}
	for _, e := range fresh {
		g, a := strings.SplitN(e.name, ":", 2)[0], strings.SplitN(e.name, ":", 2)[1]
		if _, fail := r.fetchPOM(ctx, g, a, e.version); fail != nil {
			return nil, fail
		}
	}

	// What moved besides the targets.
	names := map[string]bool{}
	for _, e := range proj.lock.entries {
		names[e.name] = true
	}
	for _, e := range nl.entries {
		names[e.name] = true
	}
	for _, n := range sortedMapKeys(names) {
		if _, target := releases[n]; target {
			continue
		}
		from, to := versionsOf(proj.lock, n), versionsOf(nl, n)
		if strings.Join(from, ",") != strings.Join(to, ",") {
			r.upd.Gradle.Moves = append(r.upd.Gradle.Moves, GradleMove{Name: n, From: from, To: to})
		}
	}
	return newBytes, nil
}

func trueKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
