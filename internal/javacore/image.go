package javacore

import (
	"path"
	"slices"
	"sort"
	"strings"

	"github.com/kitsunetrail/kestrelynx/internal/imagefs"
	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

// augmentImage judges an image whose layers were read (scan.ImageFiles).
//
//   - Read to the end: every JDK found is classified by its release file and
//     the checked ones give findings. The environment variables are not used.
//   - Put off to the next cycle: nothing is reported and the runtime is
//     unchecked, so the earlier findings are kept.
//   - Cannot be read: the environment variables decide, as they do for an
//     image that is not read; without a JDK there, the runtime is unchecked.
func (a *Advisor) augmentImage(scan scanner.ImageScan, severities []string) scanner.RuntimeAugment {
	out := scan.ImageFiles
	switch out.Kind {
	case imagefs.Complete:
		return a.augmentJDKs(scan, out.JDKs, out.JavaHome, severities)
	case imagefs.Deferred:
		a.log().Info("reading the Java runtime of an image is put off to the next cycle",
			"image", scan.Image, "reason", string(out.Reason))
		return scanner.RuntimeAugment{
			Unchecked:       []string{inventory.JavaRuntimePackage},
			UncheckedReason: map[string]string{inventory.JavaRuntimePackage: scanner.ReasonDeferred},
			JavaImage:       &scanner.JavaImageState{Kind: scanner.JavaImageDeferred, Reason: string(out.Reason)},
		}
	}
	// Permanent: the layers cannot be read.
	state := scanner.JavaImageState{Kind: scanner.JavaImagePermanent, Reason: string(out.Reason)}
	if _, _, ok := detectVersion(scan.ConfigEnv); ok {
		a.log().Info("the Java runtime of an image cannot be read from its layers; using its environment variables",
			"image", scan.Image, "reason", string(out.Reason))
		aug := a.augmentEnv(scan, severities)
		state.UsedEnvFallback = true
		aug.JavaImage = &state
		return aug
	}
	a.log().Info("the Java runtime of an image cannot be read from its layers",
		"image", scan.Image, "reason", string(out.Reason))
	return scanner.RuntimeAugment{
		Unchecked:       []string{inventory.JavaRuntimePackage},
		UncheckedReason: map[string]string{inventory.JavaRuntimePackage: scanner.ReasonUnreadable},
		JavaImage:       &state,
	}
}

// jdkRelease is one JDK of the image with what its release file says.
type jdkRelease struct {
	jdk   imagefs.JDK
	check ReleaseCheck
}

// augmentJDKs gives the findings of the JDKs read from an image. home is the
// image's JAVA_HOME resolved inside it (the real directory, no leading slash;
// "" when it names nothing), which is what a JDK's directory is compared to.
func (a *Advisor) augmentJDKs(scan scanner.ImageScan, jdks []imagefs.JDK, home string, severities []string) scanner.RuntimeAugment {
	state := scanner.JavaImageState{Kind: scanner.JavaImageComplete, HasJDK: len(jdks) > 0}
	if len(jdks) == 0 {
		return scanner.RuntimeAugment{JavaImage: &state}
	}
	snap := a.snap.Load()

	var checked []jdkRelease
	for _, j := range jdks {
		var c ReleaseCheck
		if snap != nil {
			c = snap.CheckRelease(j.Dir, []byte(j.Release), severities)
		} else {
			c = classifyOnly(j)
		}
		if !c.Checked {
			state.HasExcluded = true
			a.log().Info("a Java runtime of an image is not checked",
				"image", scan.Image, "dir", sanitize(j.Dir), "vendor", releaseVendor(j.Release), "reason", c.Reason)
			continue
		}
		checked = append(checked, jdkRelease{jdk: j, check: c})
	}
	if len(checked) == 0 {
		return scanner.RuntimeAugment{
			Retired:   []string{inventory.JavaRuntimePackage},
			JavaImage: &state,
		}
	}
	for _, c := range checked {
		if c.check.Unchecked || snap == nil {
			return scanner.RuntimeAugment{
				Unchecked:       []string{inventory.JavaRuntimePackage},
				UncheckedReason: map[string]string{inventory.JavaRuntimePackage: scanner.ReasonAdvisories},
				JavaImage:       &state,
			}
		}
	}

	_, _, envTemurin := detectVersion(scan.ConfigEnv)

	var aug scanner.RuntimeAugment
	for _, c := range checked {
		if len(c.check.Suppressed) > 0 {
			state.Suppressed = true
		}
		bin, alts, incomplete := executables(c.jdk)
		same := envTemurin && home != "" && home == c.jdk.Dir && !c.jdk.MixedLayers
		findings := makeFindings(scan.Image, c.check.Version, bin, c.check.Advisories)
		for i := range findings {
			f := &findings[i]
			f.RuntimeSource = scanner.RuntimeSourceRelease
			f.RuntimeSameAsEnv = same
			f.AltTargets = append([]string(nil), alts...)
			f.TargetsIncomplete = incomplete
			if !c.jdk.MixedLayers {
				f.LayerDiffID = c.jdk.LayerDiffID
			}
		}
		aug.Findings = append(aug.Findings, findings...)
		aug.Packages = append(aug.Packages, runtimePackages(bin, c.check.Version))
	}
	sort.SliceStable(aug.Findings, func(i, j int) bool {
		if aug.Findings[i].Target != aug.Findings[j].Target {
			return aug.Findings[i].Target < aug.Findings[j].Target
		}
		return aug.Findings[i].VulnID < aug.Findings[j].VulnID
	})
	aug.JavaImage = &state
	return aug
}

// classifyOnly classifies a JDK without advisory data: Checked says whether
// its vendor and version are of the kind that is matched.
func classifyOnly(j imagefs.JDK) ReleaseCheck {
	rel, err := ParseRelease([]byte(j.Release))
	if err != nil {
		return ReleaseCheck{Reason: err.Error()}
	}
	vendor, ok, reason := Classify(j.Dir, rel)
	return ReleaseCheck{Checked: ok, Reason: reason, Vendor: vendor}
}

// releaseVendor is the IMPLEMENTOR of a release file, for a log line.
func releaseVendor(content string) string {
	rel, err := ParseRelease([]byte(content))
	if err != nil || strings.TrimSpace(rel.Implementor) == "" {
		return "none"
	}
	return sanitize(rel.Implementor)
}

// executables returns the launcher of the JDK, <dir>/bin/java, with its links
// resolved; the other known launchers (jre/bin/java); and whether some
// launcher's path could not be resolved. A JDK whose bin/java is missing or
// unresolved has no launcher: bin is "" and incomplete is true, and a
// resolved jre/bin/java stays an alternative.
func executables(j imagefs.JDK) (bin string, alts []string, incomplete bool) {
	primary := path.Join(j.Dir, "bin/java")
	foundPrimary := false
	var others []string
	for _, e := range j.Executables {
		isPrimary := e.Declared == primary
		if isPrimary {
			foundPrimary = true
		}
		if !e.Known || e.Path == "" {
			incomplete = true
			continue
		}
		p := strings.TrimPrefix(path.Clean("/"+e.Path), "/")
		if isPrimary {
			bin = p
		} else {
			others = append(others, p)
		}
	}
	if !foundPrimary {
		incomplete = true
	}
	for _, p := range others {
		if p != bin && !slices.Contains(alts, p) {
			alts = append(alts, p)
		}
	}
	return bin, alts, incomplete
}

// javaHome is the JAVA_HOME of the image's environment, normalized like a
// JDK directory (no leading slash); "" when it is unset or not an absolute
// path.
func javaHome(env []string) string {
	home, ok := lastEnv(env, inventory.RuntimeLocationEnv(inventory.EcosystemJavaRuntime))
	if !ok || len(home) > maxHomeLen || !path.IsAbs(home) || strings.ContainsRune(home, 0) {
		return ""
	}
	return strings.TrimPrefix(path.Clean(home), "/")
}
