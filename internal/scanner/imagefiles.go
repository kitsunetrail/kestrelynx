package scanner

import (
	"context"
	"errors"
	"strings"

	"github.com/kitsunetrail/kestrelynx/internal/imagefs"
	"github.com/kitsunetrail/kestrelynx/internal/inventory"
)

// ImageFileReader reads the Java runtimes out of an image's layers
// (*imagefs.Reader implements it).
type ImageFileReader interface {
	Read(ctx context.Context, t imagefs.Target) imagefs.Outcome
}

// ReasonRefOnly is the reason of the Permanent outcome of an image that was
// scanned by a mutable reference alone: there is nothing fixed to read.
const ReasonRefOnly imagefs.Reason = "ref_only"

// javaPathWords are the words a PATH element holds when a Java runtime may be
// on the path (jlink's /opt/jre/bin among them).
var javaPathWords = []string{"java", "jdk", "jre", "jvm"}

// hasJavaHints reports whether the scan gives a reason to look for a Java
// runtime in the image's layers: JAVA_HOME or JAVA_VERSION in the
// environment, a PATH element naming java, jdk, jre or jvm, a Result of Type
// "jar", or a package list or environment that Trivy's report cut short.
func hasJavaHints(scan ImageScan) bool {
	if scan.HasJarResult || scan.PackagesTruncated || scan.ConfigEnvTruncated {
		return true
	}
	for _, rp := range scan.Packages {
		if rp.Type == "jar" {
			return true
		}
	}
	for _, f := range scan.Findings {
		if f.Type == "jar" {
			return true
		}
	}
	for _, e := range scan.ConfigEnv {
		name, val, ok := strings.Cut(e, "=")
		if !ok {
			continue
		}
		switch name {
		case inventory.RuntimeLocationEnv(inventory.EcosystemJavaRuntime), inventory.RuntimeVersionEnv(inventory.EcosystemJavaRuntime):
			return true
		case "PATH":
			if pathNamesJava(val) {
				return true
			}
		}
	}
	return false
}

func pathNamesJava(pathVar string) bool {
	for _, el := range strings.Split(pathVar, ":") {
		low := strings.ToLower(el)
		for _, w := range javaPathWords {
			if strings.Contains(low, w) {
				return true
			}
		}
	}
	return false
}

// imageFileTarget names what to read for a scan that was pinned: the image
// Docker was asked to hand to Trivy by its config digest, or the registry
// manifest Trivy fetched. ok is false for a scan that was not pinned (the
// image is known by a mutable reference alone).
func imageFileTarget(scan ImageScan, target ScanTarget) (imagefs.Target, bool) {
	if !scan.Pinned || len(scan.DiffIDs) == 0 {
		return imagefs.Target{}, false
	}
	var it imagefs.Target
	switch {
	case pinnedByConfig(target):
		it = imagefs.DockerTarget(target.Subject.Key.Digest.String(), scan.Platform, scan.DiffIDs)
	case pinnedByRegistry(target):
		it = imagefs.RegistryTarget(target.Registry.Repository, target.Registry.Digest.String(), target.Subject.Key.Platform, scan.DiffIDs)
	default:
		return imagefs.Target{}, false
	}
	it.JavaHome = envValue(scan.ConfigEnv, inventory.RuntimeLocationEnv(inventory.EcosystemJavaRuntime))
	return it, true
}

// envValue is the value of the last entry of env named name, "" when there is
// none.
func envValue(env []string, name string) string {
	val := ""
	for _, e := range env {
		if n, v, ok := strings.Cut(e, "="); ok && n == name {
			val = v
		}
	}
	return val
}

// readImageFiles reads the image's Java runtimes for the Java advisor when
// the scan shows a hint of Java and a reader is set. The outcome is left on
// the scan; a scan that was not pinned gets a Permanent outcome saying so.
func (t Trivy) readImageFiles(ctx context.Context, scan ImageScan, target ScanTarget) ImageScan {
	if t.ImageFiles == nil || scan.Err != nil || !hasJavaHints(scan) {
		return scan
	}
	it, ok := imageFileTarget(scan, target)
	if !ok {
		scan.ImageFiles = &imagefs.Outcome{
			Kind: imagefs.Permanent, Reason: ReasonRefOnly,
			Detail: "the image is known by a reference alone",
			Err:    errors.New("the image is not pinned"),
		}
		return scan
	}
	out := t.ImageFiles.Read(ctx, it)
	scan.ImageFiles = &out
	return scan
}
