// Package javacore checks the JDK of an image against the OpenJDK
// vulnerability advisories. Trivy reports the packages a package manager
// installed, but not the JDK that the Temurin images unpack from a tarball,
// so KestreLynx reads JAVA_VERSION from the image configuration and matches
// it here.
//
// The advisory datasets are public bulk downloads joined locally, the same
// way as the KEV and EPSS feeds: nothing about the images being scanned is
// sent anywhere.
package javacore

import (
	"context"
	"path"
	"regexp"
	"sort"
	"strings"
	"sync/atomic"

	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

// Default dataset URLs. The advisory list URL has the advisory date appended
// to it for each advisory; the release list URL has the page number added as
// a query parameter.
const (
	DefaultAdvisoriesURL      = "https://openjdk.org/groups/vulnerability/advisories/"
	DefaultReleasesURL        = "https://api.adoptium.net/v3/info/release_versions?release_type=ga&vendor=eclipse&page_size=50"
	DefaultFeatureReleasesURL = "https://api.adoptium.net/v3/info/available_releases"
)

// maxHomeLen bounds the JAVA_HOME value that is used as a path.
const maxHomeLen = 4096

var (
	// temurinVersionRe is the JAVA_VERSION of a Temurin image: jdk-21.0.13.1+2.
	temurinVersionRe = regexp.MustCompile(`^jdk-((?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*)){0,5})\+[0-9]+$`)
	// temurin8VersionRe is the same for series 8: jdk8u512-b09.
	temurin8VersionRe = regexp.MustCompile(`^jdk8u([1-9][0-9]*)-b[0-9]+$`)
)

// Advisor is the scanner.RuntimeAdvisor for the JDK. Its zero value is ready
// to use and has no snapshot, so every detected runtime is unchecked. It is
// safe for concurrent use.
type Advisor struct {
	snap atomic.Pointer[Snapshot]
}

// Set fixes the snapshot every following Augment uses; nil means the
// advisories are unavailable.
func (a *Advisor) Set(s *Snapshot) { a.snap.Store(s) }

// Augment implements scanner.RuntimeAdvisor.
func (a *Advisor) Augment(scan scanner.ImageScan, severities []string) scanner.RuntimeAugment {
	ver, vendor, ok := detectVersion(scan.ConfigEnv)
	if !ok {
		return scanner.RuntimeAugment{}
	}
	snap := a.snap.Load()
	if snap == nil || snap.Unchecked(ver.series()) {
		return scanner.RuntimeAugment{Unchecked: []string{inventory.JavaRuntimePackage}}
	}
	bin := executablePath(scan.ConfigEnv)

	want := make(map[string]bool, len(severities))
	for _, s := range severities {
		want[strings.ToUpper(strings.TrimSpace(s))] = true
	}

	var findings []scanner.Finding
	var highest version
	haveFixed := false
	for _, adv := range snap.Match(vendor, ver) {
		if !want[adv.Severity] {
			continue
		}
		f := scanner.Finding{
			Image:        scan.Image,
			Class:        scanner.ClassLang,
			Package:      inventory.JavaRuntimePackage,
			InstalledVer: ver.String(),
			FixedVer:     adv.FixedVer,
			Status:       adv.Status,
			Severity:     scanner.Severity(adv.Severity),
			VulnID:       adv.VulnID,
			URL:          adv.URL,
			Title:        adv.Title,
			Type:         string(inventory.EcosystemJavaRuntime),
			Target:       bin,
			PkgPath:      bin,
		}
		if adv.Status == scanner.StatusFixed {
			if fv, ok := parseVersion(adv.FixedVer); ok {
				if !haveFixed {
					highest, haveFixed = fv, true
				} else if c, ok := fv.compare(highest); ok && c > 0 {
					highest = fv
				}
			}
		}
		findings = append(findings, f)
	}
	// The group's fixed version is the first finding's, so every fixed
	// finding carries the version that fixes them all.
	if haveFixed {
		for i := range findings {
			if findings[i].Status == scanner.StatusFixed {
				findings[i].FixedVer = highest.String()
			}
		}
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].VulnID < findings[j].VulnID })

	return scanner.RuntimeAugment{
		Findings: findings,
		Packages: []scanner.ResultPackages{{
			Target: bin,
			Class:  scanner.ClassLang,
			Type:   string(inventory.EcosystemJavaRuntime),
			Packages: []scanner.Package{{
				Name:    inventory.JavaRuntimePackage,
				Version: ver.String(),
				PkgPath: bin,
			}},
		}},
	}
}

// lastEnv returns the value of the last NAME=value entry of env, as a
// container runtime resolves a repeated variable.
func lastEnv(env []string, name string) (string, bool) {
	val, found := "", false
	for _, e := range env {
		if v, ok := strings.CutPrefix(e, name+"="); ok {
			val, found = v, true
		}
	}
	return val, found
}

// detectVersion reads the JDK version from the image's JAVA_VERSION. Only the
// forms Temurin sets count: jdk-21.0.13.1+2 and jdk8u512-b09. Other
// distributions set other forms, some that cannot be told from each other
// (21.0.10) and some that do not say what was installed, so they are not
// matched.
func detectVersion(env []string) (version, Vendor, bool) {
	val, found := lastEnv(env, inventory.RuntimeVersionEnv(inventory.EcosystemJavaRuntime))
	if !found {
		return version{}, "", false
	}
	if m := temurinVersionRe.FindStringSubmatch(val); m != nil {
		if v, ok := parseVersion(m[1]); ok && !v.legacy {
			return v, VendorTemurin, true
		}
		return version{}, "", false
	}
	if m := temurin8VersionRe.FindStringSubmatch(val); m != nil {
		if v, ok := parseVersion("8u" + m[1]); ok {
			return v, VendorTemurin, true
		}
	}
	return version{}, "", false
}

// executablePath is the java executable's path, container-rooted without a
// leading slash like Trivy's paths, from JAVA_HOME. It is empty when JAVA_HOME
// is unset, empty or not an absolute path: a guessed path would let the Sensor
// call the runtime unused and silence the finding, while no path only leaves
// its judgement open.
func executablePath(env []string) string {
	home, ok := lastEnv(env, inventory.RuntimeLocationEnv(inventory.EcosystemJavaRuntime))
	if !ok || len(home) > maxHomeLen || !path.IsAbs(home) || strings.ContainsRune(home, 0) {
		return ""
	}
	return strings.TrimPrefix(path.Join(home, "bin", "java"), "/")
}

// Refresher loads a Source into an Advisor once per cycle.
type Refresher struct {
	Source  *Source
	Advisor *Advisor
}

// Refresh loads the datasets and fixes them in the Advisor for the cycle's
// scans. On failure the Advisor is left with no snapshot and the error is
// returned for logging.
func (r Refresher) Refresh(ctx context.Context) error {
	snap, err := r.Source.Load(ctx)
	r.Advisor.Set(snap)
	return err
}
