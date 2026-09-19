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
	// supersededAfterLastSeen is set when a later reading for the same
	// mount view exists, which is what stops an earlier layout from
	// answering about a stretch of the window it no longer described.
	supersededAfterLastSeen bool
	symlinks                []SymlinkEntry
	pythonDirs              []string
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

// newFileResolver builds the resolver from a scan report index and the
// auxiliary inputs saved for the database generations the window's valid
// samples actually read.
func newFileResolver(idx *scanFileIndex, auxes []AuxiliaryInputs) *fileResolver {
	r := &fileResolver{
		idx: idx, usrMerge: map[string]string{},
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
		}
		for _, l := range aux.Symlinks {
			if l.Resolved != "" && l.Resolved != l.Path {
				r.symlinks = append(r.symlinks, l)
			}
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
	// Longest link path first: a link inside a linked directory must win
	// over the directory's own link, or the inner one is never applied.
	sort.Slice(r.symlinks, func(i, j int) bool { return len(r.symlinks[i].Path) > len(r.symlinks[j].Path) })
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
	for p, owners := range r.ownedBy {
		n := r.normalize(p)
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
	if at.Before(r.firstSeen) {
		return false
	}
	if !r.lastSeen.IsZero() && at.After(r.lastSeen) {
		// A reading stops describing the layout once a later reading found
		// a different one. The last reading of the window keeps answering
		// past its own end, since nothing established that it changed.
		return !r.supersededAfterLastSeen
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
	byKey := map[string][]AuxiliaryInputs{}
	var order []string
	for _, aux := range auxes {
		key := aux.MountViewID + "\x00" + aux.AuxGeneration
		if _, seen := byKey[key]; !seen {
			order = append(order, key)
		}
		byKey[key] = append(byKey[key], aux)
	}
	set := &resolverSet{fallback: newFileResolver(idx, nil)}
	for _, key := range order {
		set.resolvers = append(set.resolvers, newFileResolver(idx, byKey[key]))
	}
	latest := map[string]time.Time{}
	for _, r := range set.resolvers {
		if r.firstSeen.After(latest[r.mountViewID]) {
			latest[r.mountViewID] = r.firstSeen
		}
	}
	for _, r := range set.resolvers {
		r.supersededAfterLastSeen = r.firstSeen.Before(latest[r.mountViewID])
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
	var chosen mappingOutcome
	seen := false
	for _, r := range s.resolvers {
		if !r.covers("", "", at) {
			continue
		}
		out := r.resolve(observed)
		if out.Unresolved {
			if !seen {
				chosen = out
			}
			seen = true
			continue
		}
		if !seen || chosen.Unresolved {
			chosen, seen = out, true
			continue
		}
		if !sameFiles(chosen, out) {
			chosen.Conflict = true
			chosen.Candidates = append(chosen.Candidates, out.Candidates...)
		}
	}
	if !seen {
		return s.fallback.resolve(observed)
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
// and any recorded symbolic link followed.
func (r *fileResolver) normalize(p string) string {
	if p == "" {
		return ""
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	p = path.Clean(p)
	for from, to := range r.usrMerge {
		if p == from || strings.HasPrefix(p, from+"/") {
			p = to + strings.TrimPrefix(p, from)
			break
		}
	}
	for _, l := range r.symlinks {
		if p == l.Path {
			return path.Clean(l.Resolved)
		}
		if strings.HasPrefix(p, l.Path+"/") {
			return path.Clean(l.Resolved + strings.TrimPrefix(p, l.Path))
		}
	}
	return p
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

// resolve is stage one of the mapping: from an observed path to the file a
// scan report named. Stage two — spreading the evidence over every package
// that file carries — is the Keys of each match, and is not an ambiguity.
func (r *fileResolver) resolve(observed string) mappingOutcome {
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
	// belongs to, and that manifest is what the report names.
	if manifest, ok := nodePackageBoundary(norm); ok {
		add(strings.TrimPrefix(manifest, "/"), "node_package_boundary", manifest)
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
	// distribution image.
	if owners := r.ownedBy[norm]; len(owners) > 0 {
		if len(owners) > 1 {
			// Two packages claiming one file is a real ambiguity, and it
			// is left unresolved rather than attributed to either.
			out.Conflict = true
			for _, o := range owners {
				out.Candidates = append(out.Candidates, o.Package+" "+o.Version)
			}
		} else {
			o := owners[0]
			var keys []pkgGroupKey
			for _, k := range r.idx.osByName[o.Package] {
				// The version has to agree as well. A name that matches at
				// a different version is the same package at a different
				// state, and confirming it would credit a version that is
				// not the one installed.
				if k.InstalledVer != "" && k.InstalledVer == o.Version {
					keys = append(keys, k)
				}
			}
			if len(keys) > 0 {
				out.Matches = append(out.Matches, fileMatch{
					File: strings.TrimPrefix(norm, "/"), Ecosystem: ecoOS,
					Rule: "os_package_path_index", Via: o.Package + " " + o.Version, Keys: keys,
				})
				out.Candidates = append(out.Candidates, strings.TrimPrefix(norm, "/"))
			}
		}
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
	if len(out.Matches) > 1 {
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
