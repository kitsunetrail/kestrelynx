package worker

import (
	"fmt"
	"path"
	"regexp"
	"runtime"
	"strings"
)

// CargoToolchainsDir is where the official rust image keeps its toolchains.
// The program starts the cargo and the rustc found there by their absolute
// paths, never the ones of rustup, which reads a toolchain file of the project
// and may fetch another toolchain. It is a variable only so that tests of the
// program can point it at a directory they made.
var CargoToolchainsDir = "/usr/local/rustup/toolchains"

// CargoToolchainBin returns the directory of the cargo and the rustc of the
// toolchain of the given exact Rust version, for the architecture goarch
// (runtime.GOARCH). It is an error for a version that is not a version, and
// for an architecture the official image is not built for here.
func CargoToolchainBin(version, goarch string) (string, error) {
	if !ValidSemver(version) {
		return "", fmt.Errorf("%q is not a version of Rust", version)
	}
	var triple string
	switch goarch {
	case "amd64":
		triple = "x86_64-unknown-linux-gnu"
	case "arm64":
		triple = "aarch64-unknown-linux-gnu"
	default:
		return "", fmt.Errorf("there is no Rust toolchain for the architecture %q", goarch)
	}
	return CargoToolchainsDir + "/" + version + "-" + triple + "/bin", nil
}

// cargoBinDir is CargoToolchainBin for the architecture this program runs on.
func cargoBinDir(version string) (string, error) {
	return CargoToolchainBin(version, runtime.GOARCH)
}

var (
	cargoElementRe = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]*$`)
	// crate names as crates.io has them, which never start with a dash.
	cargoNameRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
)

// ValidCargoInputPath reports why p is not a path a Cargo job may carry, or
// returns nil. It is a relative path of 1 to MaxCargoPathElements elements,
// each starting with an ASCII letter, digit or underscore and made of ASCII
// letters, digits and "._-", of at most 255 bytes. A file or directory that
// cargo reads settings from or writes its output to is refused: a toolchain
// file at any depth, and a first element of "target". A first element of
// ".cargo" is refused by the form of the elements.
func ValidCargoInputPath(p string) error {
	if err := ValidEntry(p); err != nil {
		return err
	}
	elems := strings.Split(p, "/")
	if len(elems) > MaxCargoPathElements {
		return fmt.Errorf("%q has %d elements, more than %d", p, len(elems), MaxCargoPathElements)
	}
	for _, e := range elems {
		if len(e) > 255 || !cargoElementRe.MatchString(e) {
			return fmt.Errorf("%q has an element that is not a plain name", p)
		}
		if e == "rust-toolchain" || e == "rust-toolchain.toml" {
			return fmt.Errorf("%q names a toolchain file", p)
		}
	}
	if elems[0] == "target" {
		return fmt.Errorf("%q is in the directory cargo builds into", p)
	}
	return nil
}

// CheckCargoInputPaths checks every path with ValidCargoInputPath and that no
// path is repeated or is also the directory of another.
func CheckCargoInputPaths(paths []string) error {
	files := make(map[string]bool, len(paths))
	dirs := map[string]bool{}
	for _, p := range paths {
		if err := ValidCargoInputPath(p); err != nil {
			return err
		}
		if files[p] {
			return fmt.Errorf("duplicate path %q", p)
		}
		files[p] = true
		for d := path.Dir(p); d != "."; d = path.Dir(d) {
			dirs[d] = true
		}
	}
	for p := range files {
		if dirs[p] {
			return fmt.Errorf("%q is both a file and a directory", p)
		}
	}
	return nil
}

// validateCargoInputs checks the declared inputs of a Cargo job: the paths,
// the role of each, the sizes and hashes and the totals.
func (j *Job) validateCargoInputs() error {
	if len(j.Inputs) > MaxCargoInputs {
		return fmt.Errorf("%d inputs exceed %d", len(j.Inputs), MaxCargoInputs)
	}
	paths := make([]string, 0, len(j.Inputs))
	var total int64
	lockfiles := 0
	rootManifest := false
	for _, in := range j.Inputs {
		paths = append(paths, in.Path)
		if err := ValidCargoInputPath(in.Path); err != nil {
			return fmt.Errorf("input: %w", err)
		}
		if len(SrcDirName)+1+len(in.Path) > MaxInputPathBytes {
			return fmt.Errorf("input %q is too long for the archive of the input", in.Path)
		}
		if in.Size < 0 || in.Size > MaxInputFileBytes {
			return fmt.Errorf("input %q size %d is outside 0..%d", in.Path, in.Size, MaxInputFileBytes)
		}
		total += in.Size
		if !ValidSHA256(in.SHA256) {
			return fmt.Errorf("input %q has no valid sha256", in.Path)
		}
		base := path.Base(in.Path)
		switch in.Role {
		case RoleLockfile:
			if in.Path != "Cargo.lock" {
				return fmt.Errorf("input %q is a lockfile, which is Cargo.lock at the root alone", in.Path)
			}
			lockfiles++
		case RoleManifest:
			if base != "Cargo.toml" {
				return fmt.Errorf("input %q is a manifest and is not named Cargo.toml", in.Path)
			}
			if in.Path == "Cargo.toml" {
				rootManifest = true
			}
		case RoleEmpty:
			if in.Size != 0 || in.SHA256 != EmptySHA256 {
				return fmt.Errorf("input %q is an empty file and has content", in.Path)
			}
			if base == "Cargo.toml" {
				return fmt.Errorf("input %q is named Cargo.toml and is not a manifest", in.Path)
			}
		default:
			return fmt.Errorf("input %q has the role %q, not one of %s, %s and %s", in.Path, in.Role, RoleLockfile, RoleManifest, RoleEmpty)
		}
	}
	if total > MaxInputTotalBytes {
		return fmt.Errorf("inputs total %d bytes, over %d", total, MaxInputTotalBytes)
	}
	if err := CheckCargoInputPaths(paths); err != nil {
		return fmt.Errorf("input: %w", err)
	}
	if lockfiles != 1 {
		return fmt.Errorf("a Cargo job carries exactly one Cargo.lock, not %d", lockfiles)
	}
	if !rootManifest {
		return fmt.Errorf("input %q is missing", "Cargo.toml")
	}
	return nil
}

// validateCargoResult checks that what the job asks to have returned fits in a
// result: every path under steps/<id>/ and final/ is short enough, the entries
// of the result (files and directories) are no more than a result may hold, and
// the declared sizes of the copies are within the total of a result. The
// program fails such a job at its first step anyway; this refuses it before
// anything runs.
func (j *Job) validateCargoResult() error {
	copies := len(j.Steps) + 1
	var size int64
	sizeOf := map[string]int64{}
	for _, in := range j.Inputs {
		sizeOf[in.Path] = in.Size
	}
	dirs := map[string]bool{StepsDir: true, FinalDir: true}
	files := 1 // result.json
	prefixes := []string{FinalDir}
	for _, s := range j.Steps {
		prefixes = append(prefixes, StepsDir+"/"+s.ID)
		dirs[StepsDir+"/"+s.ID] = true
	}
	for _, o := range j.Outputs {
		size += sizeOf[o] * int64(copies)
		for _, pre := range prefixes {
			full := pre + "/" + o
			if len(full) > 255 {
				return fmt.Errorf("the result path of output %q is %d bytes, over 255", o, len(full))
			}
			files++
			for d := path.Dir(full); d != "."; d = path.Dir(d) {
				dirs[d] = true
			}
		}
	}
	if n := files + len(dirs); n > MaxResultEntries {
		return fmt.Errorf("the result would hold %d entries, over %d", n, MaxResultEntries)
	}
	if size > MaxOutTotalBytes {
		return fmt.Errorf("the copies of the outputs are %d bytes, over %d", size, MaxOutTotalBytes)
	}
	return nil
}

// validateCargoPackage checks the crate of a cargo.update step: its name, the
// version it has and the one it moves to, which are different semantic
// versions without build metadata (cargo.update names the crate as name@from).
func validateCargoPackage(p Package) error {
	if !cargoNameRe.MatchString(p.Name) || strings.HasPrefix(p.Name, "-") {
		return fmt.Errorf("invalid crate name %q", p.Name)
	}
	if p.AtLeast != "" {
		return fmt.Errorf("%s takes no lowest version", OpCargoUpdate)
	}
	for _, v := range []struct{ what, val string }{{"current version", p.From}, {"version", p.Version}} {
		if !ValidSemver(v.val) || strings.Contains(v.val, "+") {
			return fmt.Errorf("invalid %s %q for %q", v.what, v.val, p.Name)
		}
	}
	if p.From == p.Version {
		return fmt.Errorf("crate %q is already at %s", p.Name, p.Version)
	}
	return nil
}
