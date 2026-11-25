package remediation

import (
	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

// JavaState is what a scan knows about the Java runtime of its image.
type JavaState int

const (
	// JavaStateNotAttempted: the image's JDK files were not read; the
	// environment variables decide, and a Java package row means the runtime
	// was analysed.
	JavaStateNotAttempted JavaState = iota
	// JavaStateAnalysed: the JDK files were read to the end and every JDK
	// found was checked. The image may have no JDK at all.
	JavaStateAnalysed
	// JavaStateHeld: the Java runtime was not checked this cycle (reading
	// was put off, the image cannot be read, or advisory data was missing),
	// so the absence of its findings says nothing.
	JavaStateHeld
	// JavaStateExcluded: the JDK files were read, but a JDK of a vendor that
	// is not checked, or a CVE left out because the vendor's fix cannot be
	// told from the version, means the findings may be incomplete.
	JavaStateExcluded
	// JavaStateEnvFallback: the image could not be read and the environment
	// variables gave the runtime instead.
	JavaStateEnvFallback
)

// JavaStateOf derives the Java analysis state of a scan.
func JavaStateOf(scan scanner.ImageScan) JavaState {
	for _, p := range scan.RuntimeUnchecked {
		if p == inventory.JavaRuntimePackage {
			return JavaStateHeld
		}
	}
	switch scan.JavaImage.Kind {
	case scanner.JavaImageDeferred:
		return JavaStateHeld
	case scanner.JavaImagePermanent:
		if scan.JavaImage.UsedEnvFallback {
			return JavaStateEnvFallback
		}
		return JavaStateHeld
	case scanner.JavaImageComplete:
		if scan.JavaImage.HasExcluded || scan.JavaImage.Suppressed {
			return JavaStateExcluded
		}
		return JavaStateAnalysed
	}
	return JavaStateNotAttempted
}

// javaKind is the (result type, class) of the Java runtime's package rows.
var javaKind = kindKey{string(inventory.EcosystemJavaRuntime), inventory.ClassLang}

// javaCover says how one side of a comparison covers the Java runtime.
type javaCover int

const (
	// javaCoverRows: a Java package row says the runtime was analysed.
	javaCoverRows javaCover = iota
	// javaCoverYes: analysed, whether or not a package row exists.
	javaCoverYes
	// javaCoverNo: not analysed, whether or not a package row exists.
	javaCoverNo
)

// javaCoverage returns how the baseline and the candidate cover the Java
// runtime.
//
//   - The baseline is analysed or not by its own state. Rows decide for the
//     others.
//   - A candidate that is held or excluded did not analyse it. A candidate
//     that had to use the environment variables did not either when the
//     baseline was read from its files: the variables alone are not a basis
//     for resolving what the files showed.
//   - An analysed candidate did, with no JDK left it is analysed with no
//     findings. When both sides used stage 1 only, or one side did not
//     attempt stage 2, the package rows decide as before.
func javaCoverage(baseline, candidate scanner.ImageScan) (base, cand javaCover) {
	bs, cs := JavaStateOf(baseline), JavaStateOf(candidate)
	switch bs {
	case JavaStateAnalysed:
		base = javaCoverYes
	case JavaStateHeld:
		base = javaCoverNo
	}
	switch cs {
	case JavaStateAnalysed:
		cand = javaCoverYes
	case JavaStateHeld, JavaStateExcluded:
		cand = javaCoverNo
	case JavaStateEnvFallback:
		if bs == JavaStateAnalysed || bs == JavaStateExcluded {
			cand = javaCoverNo
		}
	}
	return base, cand
}
