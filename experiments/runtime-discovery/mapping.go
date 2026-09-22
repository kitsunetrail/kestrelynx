package main

import (
	"encoding/json"
	"fmt"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

// Ecosystem names, as a scan report labels the analyzer that produced a
// result. They are kept because the mapping rule from an observed file to a
// package is different for each, and because a combined confirmation rate
// across all of them says nothing on its own.
const (
	ecoGoBinary  = "gobinary"
	ecoJar       = "jar"
	ecoNodePkg   = "node-pkg"
	ecoPythonPkg = "python-pkg"
	ecoOS        = "os"
)

// Mapping input kinds: what the scan report itself offers for relating a
// package to a file on disk.
const (
	mappingInputTarget  = "target"   // the result's own target path (a scanned binary)
	mappingInputPkgPath = "pkg_path" // the package's own path within the image
	mappingInputNone    = "none"
)

// rawTrivyReport is the part of a scan report that carries the
// file-to-package relation. The product's own parser deliberately drops it
// — nothing downstream of the product needs a path — so the report is read
// a second time here rather than that parser being widened.
//
// Packages is populated only when the report was produced with Trivy's
// --list-all-pkgs flag: every package the scanner found, whether or not it
// carries a Finding. It is read only when -all-packages asks for it (see
// buildScanFileIndex); an ordinary scan without that flag simply has an
// empty Packages on every result, which is indistinguishable at this type
// from one that was never asked for it, so the flag's own caller is what
// decides whether an empty Packages set here is an error.
type rawTrivyReport struct {
	Results []struct {
		Target          string `json:"Target"`
		Class           string `json:"Class"`
		Type            string `json:"Type"`
		Vulnerabilities []struct {
			VulnerabilityID  string `json:"VulnerabilityID"`
			PkgName          string `json:"PkgName"`
			PkgPath          string `json:"PkgPath"`
			InstalledVersion string `json:"InstalledVersion"`
		} `json:"Vulnerabilities"`
		Packages []struct {
			Name     string `json:"Name"`
			Version  string `json:"Version"`
			FilePath string `json:"FilePath"`
			// Epoch and Release are the dpkg (and rpm) version's own other
			// two parts, reported separately from Version by
			// --list-all-pkgs. A Finding's own InstalledVersion is the
			// single combined string dpkg itself uses
			// (epoch:version-release, with the epoch prefix and release
			// suffix each dropped when absent), so an OS package read from
			// Packages has to be recombined the same way before it can be
			// compared against a Finding's own InstalledVersion at all -
			// Version alone is not the same string.
			Epoch   *int   `json:"Epoch"`
			Release string `json:"Release"`
		} `json:"Packages"`
	} `json:"Results"`
}

// scanFile is one file a scan report attributes packages to, together with
// every package attributed to it. One file holding several packages is the
// ordinary case, not an ambiguity: a single compiled binary carries every
// module built into it, and an archive can carry several libraries.
type scanFile struct {
	Path      string        // image-root-relative, no leading slash
	Ecosystem string        //
	Keys      []pkgGroupKey // every package group attributed to this file
}

// scanFileIndex is the file side of the two-stage mapping: which files a
// scan report names, and what each package needs in order to be reachable
// from an observed path at all.
type scanFileIndex struct {
	files map[string]*scanFile
	// mappingInput says what the report offers for each package group;
	// ecosystem says which analyzer produced it. A lang-class package with
	// neither a target nor a path is unmappable by the report's own
	// content, which is a different shortfall from one whose path is known
	// but whose supporting layout information was not saved.
	mappingInput map[pkgGroupKey]string
	ecosystem    map[pkgGroupKey]string
	// pathsOf lists the files a package group is attributed to, so a
	// package can be reported as reachable through several placements.
	pathsOf map[pkgGroupKey][]string
	// osByName indexes the operating-system package groups by name. Their
	// files come from the container's own package database rather than
	// from the scan report, so they are reached through the saved path
	// index instead of through a path the report carries.
	osByName map[string][]pkgGroupKey
	order    []string
	// widened is this same index with every package a --list-all-pkgs
	// scan's own Packages lists name added to it, and is nil unless
	// -all-packages asked for those. It is a separate copy rather than
	// these maps grown in place, because everything a Finding-bearing
	// package's own verdict rests on is read back out of them: the file a
	// path resolves to, how many files answered to it, the placements a
	// package is reachable through, and the operating-system names a
	// path index can reach. A package carrying no Finding at all that
	// added any of those would change the judgement passed on a package
	// it has nothing to do with, purely because the flag was given — so
	// the two populations are resolved against two indexes, and only the
	// zero-Finding groups read the wider one.
	widened *scanFileIndex
}

func newScanFileIndex() *scanFileIndex {
	return &scanFileIndex{
		files:        map[string]*scanFile{},
		mappingInput: map[pkgGroupKey]string{},
		ecosystem:    map[pkgGroupKey]string{},
		pathsOf:      map[pkgGroupKey][]string{},
		osByName:     map[string][]pkgGroupKey{},
	}
}

// clone copies the index deeply enough that widening the copy cannot be
// seen through the original: every map is new, every slice is its own, and
// so is every scanFile the copy's entries point at. A shallow copy would
// share the scanFile values and the slice backing arrays, which is exactly
// the sharing the copy exists to end.
func (idx *scanFileIndex) clone() *scanFileIndex {
	out := newScanFileIndex()
	for file, sf := range idx.files {
		cp := *sf
		cp.Keys = append([]pkgGroupKey(nil), sf.Keys...)
		out.files[file] = &cp
	}
	for k, v := range idx.mappingInput {
		out.mappingInput[k] = v
	}
	for k, v := range idx.ecosystem {
		out.ecosystem[k] = v
	}
	for k, paths := range idx.pathsOf {
		out.pathsOf[k] = append([]string(nil), paths...)
	}
	for name, keys := range idx.osByName {
		out.osByName[name] = append([]pkgGroupKey(nil), keys...)
	}
	out.order = append([]string(nil), idx.order...)
	return out
}

// buildScanFileIndex reads the file-to-package relation out of a raw scan
// report.
//
// A compiled-binary result carries its path on the result itself and none
// on the packages; every other language result carries it on each package.
// Operating-system packages carry neither, which is not a gap: their files
// come from the container's own package database, not from the report.
//
// includeAllPackages is false for every ordinary call: the loop below runs
// exactly as it always has, from Vulnerabilities alone, the returned index
// has no widened copy, and the returned []pkgGroup is always nil. When it
// is true (the -all-packages flag), a second pass over each result's own
// Packages list (populated only by a scan taken with Trivy's
// --list-all-pkgs) registers every package that pass never saw — one with
// no Finding at all — into a copy of the index, hung off it as widened,
// and returns them as their own zero-Finding pkgGroups so the caller can
// carry them through the identical per-package verdict computation
// Finding-bearing groups get. The returned index itself is the
// Vulnerabilities-only one either way, so the flag adds a population
// without moving the measurement it is reported beside. A Go-binary
// result's Packages are skipped: the design this call is part of keeps
// embedded-module evidence out of this population, the same way it always
// has for Go binaries with Findings.
func buildScanFileIndex(data []byte, includeAllPackages bool) (*scanFileIndex, []pkgGroup, error) {
	var raw rawTrivyReport
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, nil, fmt.Errorf("read the scan report's package paths: %w", err)
	}
	idx := newScanFileIndex()
	for _, res := range raw.Results {
		class := scanner.ClassLang
		if res.Class == "os-pkgs" {
			class = scanner.ClassOS
		}
		eco := res.Type
		if class == scanner.ClassOS {
			eco = ecoOS
		}
		for _, v := range res.Vulnerabilities {
			key := pkgGroupKey{Class: class, Package: v.PkgName, InstalledVer: v.InstalledVersion}
			idx.ecosystem[key] = eco
			if class == scanner.ClassOS && !containsKey(idx.osByName[v.PkgName], key) {
				idx.osByName[v.PkgName] = append(idx.osByName[v.PkgName], key)
			}
			file, input := "", mappingInputNone
			switch {
			case v.PkgPath != "":
				file, input = v.PkgPath, mappingInputPkgPath
			case eco == ecoGoBinary && res.Target != "":
				file, input = res.Target, mappingInputTarget
			}
			// A package seen once with a usable path keeps it: the same
			// package can appear in several results, and one appearance
			// without a path does not withdraw the other.
			if idx.mappingInput[key] != mappingInputNone && idx.mappingInput[key] != "" && input == mappingInputNone {
				continue
			}
			idx.mappingInput[key] = input
			if file == "" {
				continue
			}
			file = strings.TrimPrefix(file, "/")
			sf := idx.files[file]
			if sf == nil {
				sf = &scanFile{Path: file, Ecosystem: eco}
				idx.files[file] = sf
				idx.order = append(idx.order, file)
			}
			if !containsKey(sf.Keys, key) {
				sf.Keys = append(sf.Keys, key)
			}
			if !containsString(idx.pathsOf[key], file) {
				idx.pathsOf[key] = append(idx.pathsOf[key], file)
			}
		}
	}

	var extra []pkgGroup
	if includeAllPackages {
		idx.widened = idx.clone()
		var err error
		extra, err = registerAllPackages(idx.widened, raw)
		if err != nil {
			return nil, nil, err
		}
		sort.Strings(idx.widened.order)
	}

	sort.Strings(idx.order)
	sort.Slice(extra, func(i, j int) bool {
		if extra[i].key.Package != extra[j].key.Package {
			return extra[i].key.Package < extra[j].key.Package
		}
		if extra[i].key.InstalledVer != extra[j].key.InstalledVer {
			return extra[i].key.InstalledVer < extra[j].key.InstalledVer
		}
		return extra[i].key.Class < extra[j].key.Class
	})
	return idx, extra, nil
}

// dpkgFullVersion recombines a --list-all-pkgs OS package's separately
// reported Version/Epoch/Release into the single string dpkg (and a
// Finding's own InstalledVersion) uses: epoch:version-release, with the
// epoch prefix present only when the epoch is non-zero and the release
// suffix present only when non-empty. A Finding for the identical
// installed package always carries that combined form, never the bare
// Version alone, so an OS package read from Packages has to be
// recombined this way before it can be compared against one at all —
// otherwise every OS package in the population would look distinct from
// its own Finding-bearing self.
func dpkgFullVersion(version string, epoch *int, release string) string {
	v := version
	if release != "" {
		v = v + "-" + release
	}
	if epoch != nil && *epoch != 0 {
		v = fmt.Sprintf("%d:%s", *epoch, v)
	}
	return v
}

// registerAllPackages adds every package a --list-all-pkgs scan's own
// Packages lists name that groupFindings' Vulnerabilities-only pass above
// never saw — a bundled package with no Finding at all — into idx (so the
// same file/OS-name resolution Finding-bearing packages get also reaches
// these), and returns them as zero-Finding pkgGroups.
//
// idx here is always the widened copy, never the index a Finding-bearing
// package's own verdict is resolved against: this function overwrites a
// mapping input, appends placements to a package that already has one,
// and adds files and operating-system names that a path resolution can
// then answer with, and every one of those would otherwise change a
// Finding-bearing package's judgement as a side effect of the flag.
//
// A total absence of any Packages entry across the whole report, with the
// flag asking for them, is treated as the scan simply not having been
// taken with --list-all-pkgs: silently returning nothing would report a
// population of only Finding-bearing packages while claiming to cover
// every bundled one, so this is refused instead.
//
// pkgGroupKey has no ecosystem field (it is shared with the
// Finding-grouping path, whose own input carries no ecosystem to put in
// one), so a language package sharing an exact (class, name, version)
// with a package from a different ecosystem — an unlikely but possible
// coincidence this function cannot rule out — still collides into one
// entry here exactly as it would for two same-shaped Findings; this is
// an existing property of the key this function reuses rather than
// something newly introduced by reading Packages.
func registerAllPackages(idx *scanFileIndex, raw rawTrivyReport) ([]pkgGroup, error) {
	totalSeen := 0
	var extra []pkgGroup
	isExtra := map[pkgGroupKey]bool{}
	for _, res := range raw.Results {
		class := scanner.ClassLang
		if res.Class == "os-pkgs" {
			class = scanner.ClassOS
		}
		eco := res.Type
		if class == scanner.ClassOS {
			eco = ecoOS
		}
		totalSeen += len(res.Packages)
		if eco == ecoGoBinary {
			// Go's embedded-module list is excluded from this population
			// by design, the same way a Go binary's Findings already are
			// nowhere else in this file's per-package accounting.
			continue
		}
		for _, p := range res.Packages {
			version := p.Version
			if class == scanner.ClassOS {
				version = dpkgFullVersion(p.Version, p.Epoch, p.Release)
			}
			key := pkgGroupKey{Class: class, Package: p.Name, InstalledVer: version}
			_, hasFinding := idx.mappingInput[key]

			// Group dedup (isExtra/the returned pkgGroup slice) and
			// placement registration (the switch below) are deliberately
			// separate: the same package, whether it already carries a
			// Finding or not, can legitimately be bundled at more than
			// one path at once (two copies of the identical jar, say),
			// and every placement has to be reachable from an observed
			// path even though it is evaluated as one package group. A
			// key already registered from a Finding gets no new
			// zero-Finding group here - it already has a real one - but
			// an additional placement Packages names for it that the
			// Finding-only pass above never saw is still registered.
			if !hasFinding && !isExtra[key] {
				isExtra[key] = true
				idx.ecosystem[key] = eco
				extra = append(extra, pkgGroup{key: key})
			}

			switch {
			case class == scanner.ClassOS:
				if !containsKey(idx.osByName[p.Name], key) {
					idx.osByName[p.Name] = append(idx.osByName[p.Name], key)
				}
				if idx.mappingInput[key] == "" {
					idx.mappingInput[key] = mappingInputNone
				}
			case p.FilePath != "":
				file := strings.TrimPrefix(p.FilePath, "/")
				idx.mappingInput[key] = mappingInputPkgPath
				sf := idx.files[file]
				if sf == nil {
					sf = &scanFile{Path: file, Ecosystem: eco}
					idx.files[file] = sf
					idx.order = append(idx.order, file)
				}
				if !containsKey(sf.Keys, key) {
					sf.Keys = append(sf.Keys, key)
				}
				if !containsString(idx.pathsOf[key], file) {
					idx.pathsOf[key] = append(idx.pathsOf[key], file)
				}
			default:
				if idx.mappingInput[key] == "" {
					idx.mappingInput[key] = mappingInputNone
				}
			}
		}
	}
	if totalSeen == 0 {
		return nil, fmt.Errorf("-all-packages was given but the scan report carries no Packages entries at all; re-scan with trivy's --list-all-pkgs")
	}
	return extra, nil
}

func containsKey(keys []pkgGroupKey, k pkgGroupKey) bool {
	for _, e := range keys {
		if e == k {
			return true
		}
	}
	return false
}

func containsString(list []string, s string) bool {
	for _, e := range list {
		if e == s {
			return true
		}
	}
	return false
}

// fileMatch is one resolution of an observed path onto a file a scan
// report named.
type fileMatch struct {
	// File is the scan report's own spelling of the file, Rule the mapping
	// rule that reached it, and Via the intermediate step where there was
	// one (the installed-file manifest that said which distribution owns
	// the observed file, say).
	File      string
	Ecosystem string
	Rule      string
	Via       string
	Keys      []pkgGroupKey
}

// Why a path reached no package. The three are different findings and are
// counted apart: only the first says the observation itself could not be
// read, and treating the others as unresolved would report a shortfall in
// the collection where there is none.
const (
	// missPathUnresolved: the observation never produced a usable file
	// path at all.
	missPathUnresolved = "path_unresolved"
	// missUnmappable: the path names a place a mapping rule covers, but
	// the information needed to follow it through was not saved.
	missUnmappable = "unmappable"
	// missOutsideScan: the path resolved perfectly well and the scan
	// report simply attributes no package to it. Most paths a workload
	// touches are this.
	missOutsideScan = "outside_scan"
	// missDirectoryOpen: an open event named a path that saved layout
	// information records as a directory. Opening a directory is not use
	// of the package that ships it — ground truth itself excludes exactly
	// this (an O_DIRECTORY open verified against the exported rootfs's own
	// stat) — so it is kept apart from missOutsideScan rather than folded
	// into "the scan reports nothing here", which would be the wrong
	// reason: the scan may report plenty about the owning package, this
	// one event just never used it. Never produced for an exec (resolve's
	// own path), only for a genuine open event (resolveForEvent's).
	missDirectoryOpen = "directory_open"
)

// mappingOutcome is what stage one concluded about one observed path.
type mappingOutcome struct {
	Matches []fileMatch
	// Conflict is set when more than one scan-report file answered to the
	// same observed path. That is the one kind of ambiguity the design
	// treats as a failure to resolve: one file holding several packages is
	// normal, several files answering to one path is not.
	Conflict   bool
	Candidates []string
	Unresolved bool
	// MissKind says which of the three reasons applies, and UnresolvedWh
	// states it in words.
	MissKind     string
	UnresolvedWh string
}

// fileResolver turns an observed absolute path inside a container into the
// scan-report file it belongs to. It works only from saved inputs: the
// scan report, and the layout information the collection recorded at
// observation time. It never reads the container's filesystem, which by
// the time a result is recomputed may not exist.
type fileResolver struct {
	idx *scanFileIndex
	// The reading this resolver was built from, and the stretch of the
	// window it covers. An observation is resolved against the reading
	// that covered it, never against one taken of a different layout.
	mountViewID string
	generation  string
	firstSeen   time.Time
	lastSeen    time.Time
	sampleIDs   map[string]bool
	// usrMerge rewrites the top-level directory spellings that name one
	// place, so a path observed as /lib/x/libc.so.6 and a path recorded as
	// /usr/lib/x/libc.so.6 meet.
	usrMerge map[string]string
	// symlinks maps a recorded link's path to where it resolved to, used
	// longest-prefix-first so a layout that links each dependency into
	// place resolves to the one real directory.
	//
	// coversFrom and coversUntil widen a reading's stretch to the
	// neighbouring readings of the same mount view: from the previous
	// reading's last instant to the next reading's first. Between two
	// readings the layout changed at some instant nobody observed, so
	// both neighbours answer for that gap and resolveEvent turns their
	// disagreement into a conflict rather than a guess. The first reading
	// answers from its own first instant, and the last for the instants
	// after it. A zero coversUntil means unbounded on that side.
	coversFrom  time.Time
	coversUntil time.Time
	// symlinkTargets is every recorded link's own raw destination (the
	// readlink text, never pre-followed), keyed by the link's own path.
	// resolveSymlinkChain walks it component by component rather than this
	// resolver trusting any single entry's own precomputed destination, so
	// a chain (a tool update-alternatives switched, say) resolves through
	// as many recorded hops as it actually took, and a path this reading
	// never saw as a symlink at all is left alone.
	symlinkTargets map[string]string
	pythonDirs     []string
	// recordOwner maps one owned file to every distribution claiming it.
	// Claims are kept rather than overwritten: two distributions claiming
	// one file is a real ambiguity, and silently keeping the last one read
	// would attribute the file to whichever happened to be read last.
	recordOwner map[string][]string
	// ownedBy maps one path to every operating-system package the
	// container's own database says owns it. This is how an event reaches
	// an operating-system package at all: the scan report carries no path
	// for those, so without the saved index an execution of a program
	// installed by a package could never be related to it.
	ownedBy map[string][]OwnedPathEntry
	// alias holds the scan report's files under this reading's own
	// spelling of them. It is per reading rather than written back into
	// the scan index: a link or a merged directory in one reading is not
	// one in another, and folding them all into one shared index would let
	// a spelling that only ever existed in one layout answer for every
	// other.
	alias      map[string]*scanFile
	eggDirs    []string
	moduleDirs []ModuleDirListing
}

// addSymlinkTarget records one path's raw link target into table, the
// first time that path is seen. Within one reading every source describes
// the same layout, so a second entry for a path already recorded (the
// package database and a bin directory both naming the same symlink, say)
// is the same fact seen twice, not a disagreement to pick between.
func addSymlinkTarget(table map[string]string, path, target string) {
	if target == "" {
		return
	}
	if _, exists := table[path]; !exists {
		table[path] = target
	}
}

// newFileResolver builds the resolver from a scan report index and the
// auxiliary inputs saved for the database generations the window's valid
// samples actually read.
func newFileResolver(idx *scanFileIndex, auxes []AuxiliaryInputs) *fileResolver {
	r := &fileResolver{
		idx: idx, usrMerge: map[string]string{}, symlinkTargets: map[string]string{},
		recordOwner: map[string][]string{}, ownedBy: map[string][]OwnedPathEntry{},
		alias: map[string]*scanFile{}, sampleIDs: map[string]bool{},
	}
	for _, aux := range auxes {
		if r.mountViewID == "" {
			r.mountViewID, r.generation = aux.MountViewID, aux.AuxGeneration
		}
		if r.firstSeen.IsZero() || (!aux.FirstSeen.IsZero() && aux.FirstSeen.Before(r.firstSeen)) {
			r.firstSeen = aux.FirstSeen
		}
		if aux.LastSeen.After(r.lastSeen) {
			r.lastSeen = aux.LastSeen
		}
		for _, id := range aux.SampleIDs {
			r.sampleIDs[id] = true
		}
		for _, l := range aux.UsrMerge {
			if l.Resolved != "" && l.Resolved != l.Path {
				r.usrMerge[l.Path] = l.Resolved
			}
			// UsrMerge's own entries are folded into the same table
			// resolveSymlinkChain walks, not only used by mergeUsr's
			// single top-level rewrite: a symlink whose own raw target
			// still uses the pre-merge spelling (a package's own
			// /usr/bin/tool linking to ../../bin/real, say) has to have
			// that spelling merged too, at whatever point in the chain it
			// turns up, not only when it is the very first component.
			addSymlinkTarget(r.symlinkTargets, l.Path, l.Target)
		}
		for _, l := range aux.Symlinks {
			addSymlinkTarget(r.symlinkTargets, l.Path, l.Target)
		}
		for _, d := range aux.PythonSearchDirs {
			if !containsString(r.pythonDirs, d.Path) {
				r.pythonDirs = append(r.pythonDirs, d.Path)
			}
		}
		for _, e := range aux.EggInfoDists {
			r.eggDirs = append(r.eggDirs, e.Dir)
		}
		r.moduleDirs = append(r.moduleDirs, aux.ModuleDirs...)
		for _, rec := range aux.DistInfoRecords {
			for _, f := range rec.Files {
				owned := normalizeRecordEntry(rec, f)
				if owned == "" {
					continue
				}
				if !containsString(r.recordOwner[owned], rec.MetadataPath) {
					r.recordOwner[owned] = append(r.recordOwner[owned], rec.MetadataPath)
				}
			}
		}
		for _, e := range aux.OwnedPaths {
			r.ownedBy[e.Path] = append(r.ownedBy[e.Path], e)
		}
	}
	// Every path the resolver compares against goes through the same
	// normalisation the observed side does, so the two meet by
	// construction rather than by the two spellings happening to agree.
	r.normalizeIndexes()
	sort.Slice(r.pythonDirs, func(i, j int) bool { return len(r.pythonDirs[i]) > len(r.pythonDirs[j]) })
	return r
}

// normalizeIndexes rewrites every path the resolver will be compared
// against into the one spelling the observed side arrives in.
//
// Both sides go through the same rule, so a merged top-level directory or
// a link in a module tree cannot make the two miss each other. The
// original spellings are kept as well: a scan report names a file the way
// it names it, and a lookup by that name has to keep working.
func (r *fileResolver) normalizeIndexes() {
	for owned, metas := range r.recordOwner {
		n := r.normalize(owned)
		if n == owned {
			continue
		}
		for _, m := range metas {
			if !containsString(r.recordOwner[n], m) {
				r.recordOwner[n] = append(r.recordOwner[n], m)
			}
		}
	}
	// ownedBy is deliberately normalized through mergeUsr alone here, never
	// through the full chain-following normalize(): its keys are compared
	// against both the merged and the fully resolved spelling separately
	// in resolve() (see osOwnersAt), specifically so that a package
	// claiming a symlink and a different package claiming the file it
	// names stay two distinct facts. Folding this index through the same
	// chain resolution as recordOwner and the scan report's own files
	// would merge those two facts into one key before resolve() ever got
	// to compare them.
	for p, owners := range r.ownedBy {
		n := r.mergeUsr(p)
		if n == p {
			continue
		}
		for _, o := range owners {
			r.ownedBy[n] = append(r.ownedBy[n], o)
		}
	}
	for file, sf := range r.idx.files {
		n := strings.TrimPrefix(r.normalize("/"+file), "/")
		if n == file {
			continue
		}
		if _, exists := r.idx.files[n]; !exists {
			r.alias[n] = sf
		}
	}
}

// scanFileAt looks up one scan-report file, under the report's own
// spelling or under this reading's normalisation of it.
func (r *fileResolver) scanFileAt(file string) *scanFile {
	if sf := r.idx.files[file]; sf != nil {
		return sf
	}
	return r.alias[file]
}

// covers reports whether this reading is the one an observation should be
// resolved against: the same mount view, and either the sample it was
// taken during or a stretch of the window containing the instant.
func (r *fileResolver) covers(mountViewID, sampleID string, at time.Time) bool {
	if mountViewID != "" && r.mountViewID != "" && mountViewID != r.mountViewID {
		return false
	}
	if sampleID != "" && len(r.sampleIDs) > 0 {
		return r.sampleIDs[sampleID]
	}
	if at.IsZero() || r.firstSeen.IsZero() {
		return true
	}
	if !r.coversFrom.IsZero() && at.Before(r.coversFrom) {
		return false
	}
	if !r.coversUntil.IsZero() && at.After(r.coversUntil) {
		return false
	}
	return true
}

// resolverSet is every layout reading a window produced, so an observation
// can be resolved against the one that covered it rather than against all
// of them merged together.
type resolverSet struct {
	resolvers []*fileResolver
	fallback  *fileResolver
}

// newResolverSet groups the saved readings by mount view and layout
// generation, and marks each reading superseded once a later one for the
// same view exists.
func newResolverSet(idx *scanFileIndex, auxes []AuxiliaryInputs) *resolverSet {
	// Readings are grouped into stretches of one layout: consecutive
	// readings, in time order within a mount view, that found the same
	// generation. A generation that comes back after another one was
	// found in between is a new stretch, not a continuation of the old
	// one, so its bounds never swallow the other's.
	sorted := append([]AuxiliaryInputs(nil), auxes...)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].MountViewID != sorted[j].MountViewID {
			return sorted[i].MountViewID < sorted[j].MountViewID
		}
		return sorted[i].FirstSeen.Before(sorted[j].FirstSeen)
	})
	var groups [][]AuxiliaryInputs
	for _, aux := range sorted {
		n := len(groups)
		if n > 0 && groups[n-1][0].MountViewID == aux.MountViewID && groups[n-1][0].AuxGeneration == aux.AuxGeneration {
			groups[n-1] = append(groups[n-1], aux)
			continue
		}
		groups = append(groups, []AuxiliaryInputs{aux})
	}
	set := &resolverSet{fallback: newFileResolver(idx, nil)}
	for _, g := range groups {
		set.resolvers = append(set.resolvers, newFileResolver(idx, g))
	}
	// Each reading answers from the previous reading's last instant to the
	// next reading's first, per mount view, so no instant of the window
	// falls between two readings with nothing to resolve it. The first
	// reading answers from its own first instant: what the layout was
	// before anyone read it is not known, and a registered target is read
	// before its workload begins, so nothing the run measures precedes it.
	//
	// An instant before every reading of a mount view is answered by the
	// dataless fallback alone (see resolveEventVerb), never by treating
	// any one reading as if it also covered that earlier instant: a
	// package (name, version) set matching the scan's own population does
	// not prove the layout itself is unchanged back to container start —
	// /etc/localtime can be re-pointed, and a file can be replaced by
	// another of the same version, without either ever showing up in that
	// set — so nothing here widens a reading's own coversFrom on that
	// basis.
	byView := map[string][]*fileResolver{}
	for _, r := range set.resolvers {
		if r.firstSeen.IsZero() {
			continue
		}
		byView[r.mountViewID] = append(byView[r.mountViewID], r)
	}
	for _, rs := range byView {
		sort.SliceStable(rs, func(i, j int) bool { return rs[i].firstSeen.Before(rs[j].firstSeen) })
		for i, r := range rs {
			r.coversFrom = r.firstSeen
			if i > 0 && !rs[i-1].lastSeen.IsZero() {
				r.coversFrom = rs[i-1].lastSeen
			}
			if i+1 < len(rs) {
				r.coversUntil = rs[i+1].firstSeen
			}
		}
	}
	if len(set.resolvers) == 0 {
		set.resolvers = []*fileResolver{set.fallback}
	}
	return set
}

// forObservation picks the reading that covered one observation. With
// nothing matching, the fallback answers nothing rather than an arbitrary
// reading answering wrongly.
func (s *resolverSet) forObservation(mountViewID, sampleID string, at time.Time) *fileResolver {
	for _, r := range s.resolvers {
		if r.covers(mountViewID, sampleID, at) {
			return r
		}
	}
	return s.fallback
}

// resolveEvent resolves a path that carries no mount view of its own.
//
// Every reading valid at that instant is consulted. Agreement is the
// answer; disagreement is a conflict, which is what it is: two layouts
// that were both in force cannot both be the one the workload saw, and
// picking one would be a guess.
func (s *resolverSet) resolveEvent(observed string, at time.Time) mappingOutcome {
	return s.resolveEventVerb(observed, at, false)
}

// resolveEventVerb is resolveEvent's own version for one event, exec or
// open. isOpenEvent is true only for an open (never an exec — see
// resolveOS's own refuseDirectoryOpen parameter, which this passes
// through to every reading it consults, ordinary or fallback).
func (s *resolverSet) resolveEventVerb(observed string, at time.Time, isOpenEvent bool) mappingOutcome {
	var chosen mappingOutcome
	seen, resolvedSeen, unresolvedSeen := false, false, false
	for _, r := range s.resolvers {
		if !r.covers("", "", at) {
			continue
		}
		out := r.resolveForEvent(observed, isOpenEvent)
		if out.Unresolved {
			unresolvedSeen = true
			if !seen {
				chosen = out
			}
			seen = true
			continue
		}
		if !resolvedSeen {
			chosen, resolvedSeen = out, true
			seen = true
			continue
		}
		if !sameFiles(chosen, out) {
			chosen.Conflict = true
			chosen.Candidates = append(chosen.Candidates, out.Candidates...)
		}
	}
	if !seen {
		// No reading's ordinary coverage answers for this instant at all —
		// an event at or moments after container startup, before the
		// first reading of its mount view completed, most notably. The
		// dataless fallback resolver (built from no auxiliary inputs at
		// all) still answers from the observed path and the scan report
		// alone: a compiled binary's own path, a jar's own suffix, and a
		// module tree's own /node_modules/ boundary need no saved layout
		// to decide, so a require or an import from before the first
		// reading — genuinely arriving there in a real run measured for
		// this project, not merely a hypothetical — still resolves. Only
		// an installed Python distribution's own record, and
		// operating-system ownership, need the saved layout this dataless
		// resolver never has, and those stay unresolved for an instant
		// before the first reading — a package (name, version) set
		// matching the scan's own population does not prove the layout
		// itself is unchanged back to container start (/etc/localtime can
		// be re-pointed, and a file can be replaced by another of the
		// same version, without either ever showing up in that set), so
		// this is never widened on that basis.
		return s.fallback.resolveForEvent(observed, isOpenEvent)
	}
	// A reading that attributes the file and a neighbouring reading that
	// cannot disagree about the layout at this instant just as two
	// attributions would: the file's owner changed, or the file stopped
	// being one the report knows, somewhere in the stretch both answer
	// for. Neither reading's answer is taken over the other's.
	if resolvedSeen && unresolvedSeen {
		chosen.Conflict = true
	}
	return chosen
}

func sameFiles(a, b mappingOutcome) bool {
	if len(a.Matches) != len(b.Matches) {
		return false
	}
	for i := range a.Matches {
		if a.Matches[i].File != b.Matches[i].File {
			return false
		}
		if !sameKeys(a.Matches[i].Keys, b.Matches[i].Keys) {
			return false
		}
	}
	return true
}

// sameKeys reports whether two readings attribute a file to the same
// packages. The same path owned by a different package in a later
// reading is a change of layout, not an agreement about the file.
func sameKeys(a, b []pkgGroupKey) bool {
	if len(a) != len(b) {
		return false
	}
	seen := map[pkgGroupKey]int{}
	for _, k := range a {
		seen[k]++
	}
	for _, k := range b {
		if seen[k] == 0 {
			return false
		}
		seen[k]--
	}
	return true
}

// anyResolver returns one reading, for the questions that are about the
// saved inputs as a whole rather than about one observation.
func (s *resolverSet) anyResolver() *fileResolver {
	if len(s.resolvers) > 0 {
		return s.resolvers[0]
	}
	return s.fallback
}

// normalizeRecordEntry turns one first-column entry of an installed-file
// manifest into an absolute path inside the container. The specification
// allows either a path relative to the directory holding the .dist-info or
// an absolute one, so both are handled rather than one being assumed.
func normalizeRecordEntry(rec DistInfoRecord, entry string) string {
	entry = strings.TrimSpace(entry)
	if entry == "" {
		return ""
	}
	if strings.HasPrefix(entry, "/") {
		return path.Clean(entry)
	}
	base := rec.SearchDir
	if base == "" {
		base = path.Dir(rec.DistInfoDir)
	}
	return path.Clean(path.Join(base, entry))
}

// normalize brings an observed path into the one spelling everything else
// is compared in: absolute, with the merged top-level directories rewritten
// and every recorded symbolic link in its way followed to the end of the
// chain. A chain that loops or runs past maxMappingSymlinkHops is left at
// its merged-but-unresolved spelling rather than guessed at further; see
// resolveSymlinkChain.
func (r *fileResolver) normalize(p string) string {
	merged := r.mergeUsr(p)
	if resolved, _, ok := r.resolveSymlinkChain(merged); ok {
		return resolved
	}
	return merged
}

// mergeUsr rewrites a merged top-level directory's spelling (/lib/x, say)
// into the one the image's real files sit under (/usr/lib/x), so a path
// observed either way meets the same string. It does not follow any other
// symlink: that is resolveSymlinkChain's job, kept separate because the two
// answer different questions — mergeUsr says which of two spellings of one
// real place was used, resolveSymlinkChain says what a genuine link
// ultimately points at.
func (r *fileResolver) mergeUsr(p string) string {
	if p == "" {
		return ""
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	p = path.Clean(p)
	for from, to := range r.usrMerge {
		if p == from || strings.HasPrefix(p, from+"/") {
			return path.Clean(to + strings.TrimPrefix(p, from))
		}
	}
	return p
}

// maxMappingSymlinkHops bounds symlink-chain-following during matching, the
// same defense a real path resolution needs against a cycle. Matching runs
// after the container is gone, working only from the symlink table saved at
// observation time rather than a live filesystem, so this is its own bound
// rather than a shared one with resolveInRoot's.
const maxMappingSymlinkHops = 40

// resolveSymlinkChain walks p (already absolute and clean) through the
// recorded symlink table component by component, exactly as a real
// resolution inside the container would: an absolute link target is
// rebased at the container's own root, a relative one at the link's own
// containing directory, and a component the table says nothing about is
// kept as it is. ok is false when the chain loops or runs past
// maxMappingSymlinkHops; the caller then has nothing more to go on than p
// itself, and is never handed a partially-substituted guess. changed
// reports whether any recorded link was actually followed, so a caller can
// tell a path that never touched the table from one that happened to
// resolve back to its own starting spelling.
func (r *fileResolver) resolveSymlinkChain(p string) (resolved string, changed, ok bool) {
	if len(r.symlinkTargets) == 0 {
		return p, false, true
	}
	remaining := splitPath(p)
	var out []string
	hopsLeft := maxMappingSymlinkHops
	followedAny := false
	for len(remaining) > 0 {
		comp := remaining[0]
		remaining = remaining[1:]
		switch comp {
		case "", ".":
			continue
		case "..":
			if len(out) > 0 {
				out = out[:len(out)-1]
			}
			continue
		}
		candidate := "/" + strings.Join(append(append([]string{}, out...), comp), "/")
		target, isLink := r.symlinkTargets[candidate]
		if !isLink {
			out = append(out, comp)
			continue
		}
		if hopsLeft <= 0 {
			// A chain deeper than any real alternatives setup ever runs,
			// which is what a genuine cycle looks like from here: the same
			// link can legitimately be crossed more than once along one
			// path (a link to "." doubles back through itself for every
			// repeated component, and is still a well-defined place), so
			// only the hop count — the same defense resolveInRoot and
			// truth.py's own resolver use — decides this, never whether a
			// particular link's path was seen before.
			return p, false, false
		}
		hopsLeft--
		followedAny = true
		targetParts := splitPath(target)
		if strings.HasPrefix(target, "/") {
			// Re-rooted at this reading's own "/", never partway through
			// whatever "out" already held.
			remaining = append(targetParts, remaining...)
			out = nil
		} else {
			// Relative to the link's own containing directory, i.e. "out"
			// as it stands — the link's own final component is not part
			// of that directory.
			remaining = append(targetParts, remaining...)
		}
	}
	if len(out) == 0 {
		return "/", followedAny, true
	}
	return "/" + strings.Join(out, "/"), followedAny, true
}

// pycacheToSource turns a compiled-module path back into the source path
// its installer recorded. A compiled module is generated after
// installation and is often absent from the installed-file manifest, so a
// lookup on its own name finds nothing while the module it was compiled
// from is owned like any other file.
func pycacheToSource(p string) (string, bool) {
	if !strings.HasSuffix(p, ".pyc") {
		return "", false
	}
	dir, base := path.Dir(p), path.Base(p)
	name := strings.TrimSuffix(base, ".pyc")
	// "<module>.cpython-312.pyc" and "<module>.cpython-312.opt-1.pyc" both
	// reduce to "<module>.py"; the tag after the first "." is the
	// interpreter's, never part of the module name.
	if i := strings.IndexByte(name, '.'); i >= 0 {
		name = name[:i]
	}
	if path.Base(dir) == "__pycache__" {
		dir = path.Dir(dir)
	}
	return path.Join(dir, name+".py"), true
}

// nodePackageBoundary finds the package one path inside a module tree
// belongs to, and returns that package's own manifest path. The boundary
// is the deepest module directory in the path: a tree that keeps two
// versions of one package nests the second inside the first, and the
// shallower boundary would attribute the inner package's files to the
// outer one.
func nodePackageBoundary(p string) (string, bool) {
	const marker = "/node_modules/"
	last := strings.LastIndex(p, marker)
	if last < 0 {
		return "", false
	}
	rest := p[last+len(marker):]
	if rest == "" {
		return "", false
	}
	parts := strings.Split(rest, "/")
	name := parts[0]
	if strings.HasPrefix(name, "@") {
		if len(parts) < 2 {
			return "", false
		}
		name = name + "/" + parts[1]
	}
	return p[:last+len(marker)] + name + "/package.json", true
}

// nodeProjectManifest finds the application's own manifest for a path that
// nodePackageBoundary could not place — one outside any node_modules tree
// at all. Trivy's node-pkg analyzer lists an application's own package.json
// the same way it lists a dependency's, but that file sits above any
// module tree and so has no /node_modules/ boundary to find; walking up to
// the nearest ancestor directory the scan report actually names a
// package.json under is what reaches it.
func (r *fileResolver) nodeProjectManifest(norm string) (string, bool) {
	for dir := path.Dir(norm); ; dir = path.Dir(dir) {
		candidate := strings.TrimPrefix(path.Join(dir, "package.json"), "/")
		if sf := r.scanFileAt(candidate); sf != nil {
			return candidate, true
		}
		if dir == "/" {
			return "", false
		}
	}
}

// osOwnersAt looks up which operating-system package the container's own
// database claims for one exact, already-normalized path. Two or more
// claims is a real ambiguity, returned as candidates for a conflict rather
// than picked from; a claim whose recorded version matches no
// Finding-bearing group at that name is treated the same as no claim at
// all, since nothing this run scored can be credited to it.
func (r *fileResolver) osOwnersAt(p string) (m fileMatch, found bool, conflictCandidates []string) {
	owners := r.ownedBy[p]
	if len(owners) > 1 {
		for _, o := range owners {
			conflictCandidates = append(conflictCandidates, o.Package+" "+o.Version)
		}
		return fileMatch{}, false, conflictCandidates
	}
	if len(owners) != 1 {
		return fileMatch{}, false, nil
	}
	o := owners[0]
	var keys []pkgGroupKey
	for _, k := range r.idx.osByName[o.Package] {
		// The version has to agree as well. A name that matches at a
		// different version is the same package at a different state, and
		// confirming it would credit a version that is not the one
		// installed.
		if k.InstalledVer != "" && k.InstalledVer == o.Version {
			keys = append(keys, k)
		}
	}
	if len(keys) == 0 {
		return fileMatch{}, false, nil
	}
	return fileMatch{
		File: strings.TrimPrefix(p, "/"), Ecosystem: ecoOS,
		Rule: "os_package_path_index", Via: o.Package + " " + o.Version, Keys: keys,
	}, true, nil
}

// pathIsDir reports whether p (already normalized to whatever spelling
// r.ownedBy is keyed on) is a directory according to any saved
// package-database entry for it. An older reading that predates IsDir
// simply has it false on every entry, so this — and refuseDirectoryOpen's
// own check — costs nothing there: every path answers false, exactly the
// way it always did before either existed.
func (r *fileResolver) pathIsDir(p string) bool {
	for _, e := range r.ownedBy[p] {
		if e.IsDir {
			return true
		}
	}
	return false
}

// resolveOS is resolveVerb's own operating-system rule, factored out for
// readability — the directory check that used to live here has since
// moved to resolveVerb's own start, ahead of every rule, not only this
// one; see its own comment for why.
//
// The path as the kernel would have opened it (merged, before any symlink
// chain is followed) and the path that chain resolves to (norm) are
// checked separately and never silently collapsed into one. A tool
// update-alternatives switched (mawk selected as /usr/bin/awk, say) or a
// distribution-wide link (/etc/localtime, say) is owned by neither hop on
// its own, and is only reached through the resolved side. A symlink one
// package ships naming a file a different package ships (Ubuntu 26.04's
// own /usr/bin/cat, a uutils-coreutils symlink, naming rust-coreutils's
// own binary underneath ../lib/cargo/bin, say) is not an ambiguity
// either: ground truth itself counts using either hop as using both
// packages the chain names (the symlink is how the tool is invoked, the
// file underneath is what actually runs), so both are confirmed rather
// than neither.
//
// Either side being ambiguous on its own (two packages already
// disagreeing about who owns the observed path, or about who owns what it
// resolves to) is checked before either side's single-owner answer is
// used: that is the one real conflict here — one file with more than one
// owner — and a clean answer on one side does not resolve an ambiguity on
// the other, so preferring it would silently discard a real disagreement.
func (r *fileResolver) resolveOS(observed string) mappingOutcome {
	out := mappingOutcome{}
	if observed == "" || !strings.HasPrefix(observed, "/") {
		out.Unresolved, out.MissKind = true, missPathUnresolved
		out.UnresolvedWh = "the observation carries no usable absolute path"
		return out
	}
	norm := r.normalize(observed)
	merged := r.mergeUsr(observed)
	m1, found1, conflict1 := r.osOwnersAt(merged)
	m2, found2, conflict2 := r.osOwnersAt(norm)
	if found2 && merged != norm {
		m2.Via = "symlink:" + norm
	}
	switch {
	case len(conflict1) > 0 || len(conflict2) > 0:
		out.Conflict = true
		out.Candidates = append(out.Candidates, conflict1...)
		out.Candidates = append(out.Candidates, conflict2...)
		if found1 {
			out.Candidates = append(out.Candidates, m1.File)
		}
		if found2 {
			out.Candidates = append(out.Candidates, m2.File)
		}
	case found1 && found2 && !sameKeys(m1.Keys, m2.Keys):
		out.Matches = append(out.Matches, m1, m2)
		out.Candidates = append(out.Candidates, m1.File, m2.File)
	case found1:
		out.Matches = append(out.Matches, m1)
		out.Candidates = append(out.Candidates, m1.File)
	case found2:
		out.Matches = append(out.Matches, m2)
		out.Candidates = append(out.Candidates, m2.File)
	}
	if len(out.Matches) == 0 && !out.Conflict {
		out.Unresolved = true
		out.MissKind = missOutsideScan
		out.UnresolvedWh = "this path resolved, and the container's package database attributes no package to it"
	}
	return out
}

// resolve is stage one of the mapping: from an observed path to the file a
// scan report named. Stage two — spreading the evidence over every package
// that file carries — is the Keys of each match, and is not an ambiguity.
//
// It never refuses a directory open (see resolveForEvent): the sampling
// pass and every direct caller resolve() has ever had use it for an exec,
// a mapped file, or a plain path lookup, none of which a directory-open
// exclusion belongs on.
func (r *fileResolver) resolve(observed string) mappingOutcome {
	return r.resolveVerb(observed, false)
}

// resolveForEvent is resolve's own version for one event, exec or open.
// isOpenEvent is true only for an open (ev.Event != "exec"): see
// resolveOS's own refuseDirectoryOpen parameter, which this passes
// through unchanged.
func (r *fileResolver) resolveForEvent(observed string, isOpenEvent bool) mappingOutcome {
	return r.resolveVerb(observed, isOpenEvent)
}

func (r *fileResolver) resolveVerb(observed string, refuseDirectoryOpen bool) mappingOutcome {
	out := mappingOutcome{}
	if observed == "" {
		out.Unresolved, out.MissKind = true, missPathUnresolved
		out.UnresolvedWh = "the observation carries no path"
		return out
	}
	if !strings.HasPrefix(observed, "/") {
		out.Unresolved, out.MissKind = true, missPathUnresolved
		out.UnresolvedWh = "the path is not absolute, so the file it names cannot be determined"
		return out
	}
	norm := r.normalize(observed)
	rel := strings.TrimPrefix(norm, "/")
	// merged is the path as the kernel would actually have opened it: only
	// the merged top-level directories are rewritten, no symlink chain is
	// followed. It is the reference point for a rule that needs to tell
	// "the path as observed" apart from "what a chain resolves it to" —
	// the operating-system ownership check below, and the node_modules
	// boundary check's own fallback gating.
	merged := r.mergeUsr(observed)

	// A directory is checked before any package rule, not only the
	// operating-system one: opening a directory is not use of whatever
	// package ships it, and that has to hold regardless of which rule
	// would otherwise have matched the path (a bare module directory
	// under node_modules, say, is exactly as much "not use" of that
	// dependency as a bare operating-system directory is of the package
	// that ships it). Checking this first, before any rule below ever
	// calls add(), is what keeps a directory from being credited to a
	// package on the strength of a rule that has no idea it was ever
	// asked about a directory at all — see refuseDirectoryOpen's own
	// comment on resolveOS for why an event carries no file-type
	// information of its own by the time this runs.
	if refuseDirectoryOpen && (r.pathIsDir(merged) || r.pathIsDir(norm)) {
		out.Unresolved = true
		out.MissKind = missDirectoryOpen
		out.UnresolvedWh = "a directory was opened; opening a directory is not use of the package that ships it"
		return out
	}

	add := func(file, rule, via string) {
		sf := r.scanFileAt(file)
		if sf == nil {
			return
		}
		for _, m := range out.Matches {
			if m.File == file {
				return
			}
		}
		out.Matches = append(out.Matches, fileMatch{File: file, Ecosystem: sf.Ecosystem, Rule: rule, Via: via, Keys: sf.Keys})
		out.Candidates = append(out.Candidates, file)
	}

	// A compiled binary: the scan report names the binary itself, and the
	// packages hanging off it are every module built into it.
	if sf := r.scanFileAt(rel); sf != nil && sf.Ecosystem == ecoGoBinary {
		add(rel, "go_target_path", "")
	}
	// An archive: the scan report names the archive file directly.
	if strings.HasSuffix(rel, ".jar") {
		add(rel, "jar_path", "")
	}
	// A module tree: the package boundary decides which manifest the file
	// belongs to, and that manifest is what the report names. A path
	// outside any node_modules tree at all falls back to the nearest
	// ancestor manifest the report names — the application's own
	// package.json, which nodePackageBoundary has no boundary to find at
	// all.
	//
	// The fallback is gated on the path as observed (merged), never only
	// on the resolved one: a dependency's own file that a symlink chain
	// leads outside node_modules entirely (a content-addressed store kept
	// outside the project, say) is still that dependency's file, and
	// attributing it to the application's own manifest merely because the
	// dependency's own manifest could not be found afterward would be a
	// wrong package, not a recovered one.
	if manifest, ok := nodePackageBoundary(norm); ok {
		add(strings.TrimPrefix(manifest, "/"), "node_package_boundary", manifest)
	} else if _, hadBoundary := nodePackageBoundary(merged); !hadBoundary {
		if manifest, ok := r.nodeProjectManifest(norm); ok {
			add(manifest, "node_project_manifest", "")
		}
	}
	// An installed Python distribution: the installed-file manifest says
	// which distribution owns the file, and the distribution's metadata
	// file is what the report names.
	pyCandidates := []string{norm}
	if src, ok := pycacheToSource(norm); ok {
		pyCandidates = append(pyCandidates, src)
	}
	for _, cand := range pyCandidates {
		metas, ok := r.recordOwner[cand]
		if !ok {
			continue
		}
		for _, meta := range metas {
			add(strings.TrimPrefix(meta, "/"), "python_record", cand)
		}
		break
	}
	// An operating-system package: the scan report carries no path for
	// one, so the owner comes from the container's own database as it was
	// saved at observation time. Without this an execution of a program
	// an operating-system package installed could never be related back to
	// it, which is the whole of what an execution record is for on a
	// distribution image. See resolveOS for the rule itself.
	osOut := r.resolveOS(observed)
	out.Matches = append(out.Matches, osOut.Matches...)
	out.Candidates = append(out.Candidates, osOut.Candidates...)
	if osOut.Conflict {
		out.Conflict = true
	}

	if len(out.Matches) == 0 {
		if out.Conflict {
			return out
		}
		// A path that no rule reached is recorded with the reason, and is
		// never counted as evidence that nothing uses the file. Which
		// reason matters: a path that resolved perfectly well and simply
		// names nothing the scan reports is not a shortfall in the
		// observation.
		out.Unresolved = true
		out.MissKind, out.UnresolvedWh = r.explainMiss(norm, rel)
		return out
	}
	// More than one match is ordinarily a conflict: the rules above target
	// disjoint ecosystems, and two of them answering for the same path at
	// once is not expected. The operating-system rule's own two matches
	// (the observed path and what it resolves to, owned by two different
	// packages) are the one deliberate exception — already decided,
	// immediately above, to be two facts rather than a conflict — so they
	// are excluded from this count rather than re-litigated here.
	nonOS := 0
	for _, m := range out.Matches {
		if m.Rule != "os_package_path_index" {
			nonOS++
		}
	}
	if nonOS > 1 {
		out.Conflict = true
	}
	return out
}

// explainMiss says why no rule reached a file, distinguishing a path the
// scan simply reports nothing about from one whose mapping information was
// never saved.
func (r *fileResolver) explainMiss(norm, rel string) (kind, why string) {
	switch {
	case r.inEggInfoDistribution(norm):
		return missUnmappable, "the distribution this file belongs to is recorded in the older metadata form, which has no installed-file manifest to resolve it through"
	case r.inPythonSearchDir(norm) && len(r.recordOwner) == 0:
		return missUnmappable, "no installed-file manifest was saved at observation time, so nothing can say which distribution owns this file"
	case strings.Contains(norm, "/node_modules/") && len(r.moduleDirs) == 0:
		return missUnmappable, "no module-tree layout was saved at observation time, so this path's package boundary cannot be established"
	case strings.HasSuffix(rel, ".jar"):
		return missOutsideScan, "the scan report attributes no package to this archive"
	case len(r.ownedBy) == 0:
		return missUnmappable, "no package path index was saved at observation time, so an operating-system package owning this file could not be looked up"
	default:
		return missOutsideScan, "this path resolved, and neither the scan report nor the container's package database attributes a package to it"
	}
}

func (r *fileResolver) inPythonSearchDir(p string) bool {
	for _, d := range r.pythonDirs {
		if strings.HasPrefix(p, d+"/") {
			return true
		}
	}
	return false
}

// inEggInfoDistribution reports whether a path belongs to a distribution
// recorded in the older metadata form, which has no installed-file
// manifest.
//
// The metadata directory is named "<name>-<version>.egg-info", and the
// files themselves sit under "<name>". Both spellings are checked, and the
// version is stripped from the first, so a file under the package
// directory is recognised as belonging to a distribution nothing can
// resolve it through — which is a different finding from a file nothing
// reports at all.
func (r *fileResolver) inEggInfoDistribution(p string) bool {
	for _, d := range r.eggDirs {
		parent := path.Dir(d)
		base := strings.TrimSuffix(path.Base(d), ".egg-info")
		name := base
		if i := strings.LastIndexByte(base, '-'); i > 0 {
			name = base[:i]
		}
		if strings.HasPrefix(p, d+"/") ||
			strings.HasPrefix(p, path.Join(parent, base)+"/") ||
			strings.HasPrefix(p, path.Join(parent, name)+"/") {
			return true
		}
	}
	return false
}

// mappingInputsPresent reports whether everything the mapping rule for one
// package needs is available from saved inputs.
//
// The file-list state of an operating-system package database answers a
// different question and is never used here: a language package's
// reachability depends on what the scan report offers and on the layout
// information saved at observation time, not on whether some other
// database could list its own files.
func (r *fileResolver) mappingInputsPresent(key pkgGroupKey, input, eco string) (bool, string) {
	if input == mappingInputNone {
		return false, "the scan report offers neither a package path nor a scanned-binary path for this package"
	}
	switch eco {
	case ecoGoBinary:
		// The path in the report is the whole mapping rule: an observed
		// path either equals it or does not.
		return true, ""
	case ecoJar:
		// An archive packed inside another archive is named by the outer
		// file's path, a separator and the inner one's. That is not a file
		// anything can open: the only file the system ever sees is the
		// outer one. The mapping input is present, and what an observation
		// of the outer file supports saying has to carry the difference.
		nestedOnly := len(r.idx.pathsOf[key]) > 0
		for _, file := range r.idx.pathsOf[key] {
			if !strings.Contains(file, ".jar/") {
				nestedOnly = false
				break
			}
		}
		if nestedOnly {
			return true, "this package is only named inside another archive, which is not a file anything opens: it is reachable only through the archive containing it"
		}
		return true, ""
	case ecoNodePkg:
		for _, file := range r.idx.pathsOf[key] {
			if r.moduleTreeCovers("/" + file) {
				return true, ""
			}
		}
		return false, "no module-tree layout covering this package's manifest was saved at observation time"
	case ecoPythonPkg:
		for _, file := range r.idx.pathsOf[key] {
			meta := "/" + file
			for _, owners := range r.recordOwner {
				if containsString(owners, meta) {
					return true, ""
				}
			}
		}
		return false, "no installed-file manifest for this distribution was saved at observation time"
	}
	return input != mappingInputNone, ""
}

func (r *fileResolver) moduleTreeCovers(p string) bool {
	for _, m := range r.moduleDirs {
		if m.Kind != "node_modules" {
			continue
		}
		if strings.HasPrefix(p, m.Root+"/") {
			return true
		}
	}
	return false
}

// auxComplete reports whether the layout readings a window rests on were
// read whole.
//
// A reading cut short at one of the bounded-read limits, or one carrying a
// read failure, describes less than the container had. A lookup that misses
// in it is then not evidence that nothing owns the file, which is the
// difference between a rate over a complete picture and a rate over
// whatever could be read.
func auxComplete(auxes []AuxiliaryInputs) bool {
	for _, aux := range auxes {
		if len(aux.Truncations) > 0 || len(aux.Errors) > 0 || aux.OwnedPathsTruncated {
			return false
		}
		for _, r := range aux.DistInfoRecords {
			if r.Truncated || r.Error != "" {
				return false
			}
		}
		for _, m := range aux.ModuleDirs {
			if m.Truncated || m.Error != "" {
				return false
			}
		}
	}
	return true
}

// auxForWindow selects the layout readings that belong to this window.
//
// The test is which samples a reading covered, and nothing else. It is
// deliberately not the package database's validity: a container with no
// such database has no valid database generation at all, and keying on one
// discarded every language-package layout that had been saved for exactly
// the images where it is the only thing there is.
//
// A reading naming no sample — one taken during preparation, before the
// window opened — is kept: it describes the layout the window started
// with, which is the layout the first sample looked at.
func auxForWindow(rec *ContainerRecord, wv windowValidity) []AuxiliaryInputs {
	if len(rec.AuxiliaryInputs) == 0 {
		return nil
	}
	windowSamples := map[string]bool{}
	for _, cr := range rec.CollectionResults {
		windowSamples[cr.SampleID] = true
	}
	if len(windowSamples) == 0 {
		return rec.AuxiliaryInputs
	}
	var out []AuxiliaryInputs
	for _, aux := range rec.AuxiliaryInputs {
		if aux.Invalid {
			// The process this reading came through did not hold still
			// while it was being read, so what is in it may describe
			// whatever replaced that process. It stays in the record as a
			// record of the attempt and answers nothing.
			continue
		}
		if len(aux.SampleIDs) == 0 {
			out = append(out, aux)
			continue
		}
		for _, id := range aux.SampleIDs {
			if windowSamples[id] {
				out = append(out, aux)
				break
			}
		}
	}
	return out
}
