package pkgdb

import (
	"fmt"
	"sort"
	"strings"

	"github.com/kitsunetrail/kestrelynx/internal/evidence"
)

// ParseDistroless builds an ownership Index from a distroless status.d
// directory's contents: one dpkg control stanza file per package (e.g.
// "curl") and, for most packages, a matching "<name>.md5sums" listing every
// file it installed (one "<md5>  <relative-path>" line per file, relative
// to "/"). files holds every entry the observer read out of status.d,
// however it ordered them; ParseDistroless pairs each non-".md5sums" file
// with its ".md5sums" counterpart by name.
//
// A package with no ".md5sums" at all is the one thing this database
// genuinely cannot answer about a package's files (distroless keeps no
// other file-ownership record); it is reported via that package's
// FileListPresent = false, not treated as an error for the whole Index.
func ParseDistroless(files []NamedReader, limits Limits) (*Index, Diagnostics, error) {
	idx := newIndex()
	var diag Diagnostics
	budget := &totalBudget{max: limits.MaxTotalBytes}

	byName := make(map[string]NamedReader, len(files))
	var metaFiles []string
	for _, f := range files {
		if strings.HasSuffix(f.Name, ".md5sums") {
			byName[f.Name] = f
			continue
		}
		metaFiles = append(metaFiles, f.Name)
		byName[f.Name] = f
	}
	sort.Strings(metaFiles)

	for i, pkgFile := range metaFiles {
		if limits.MaxFiles > 0 && i >= limits.MaxFiles {
			diag.Truncated = true
			break
		}
		// Clamped to whatever remains of the total budget — see ParseDpkg's
		// identical use of totalBudget for why the per-file cap alone isn't
		// enough.
		stanzaLimit := budget.clamp(limits.MaxStatusBytes)
		if stanzaLimit <= 0 {
			diag.Truncated = true
			break
		}

		var pkgName, pkgVer, pkgArch string
		stanzas, n, trunc, err := readControlEntries(byName[pkgFile].R, stanzaLimit)
		budget.add(n)
		if trunc {
			diag.Truncated = true
			diag.Errors = append(diag.Errors, FileError{Name: pkgFile,
				Err: fmt.Errorf("pkgdb: %s exceeds %d bytes", pkgFile, stanzaLimit)})
		} else if err != nil {
			diag.Errors = append(diag.Errors, FileError{Name: pkgFile, Err: err})
		}
		if len(stanzas) > 0 {
			pkgName, pkgVer, pkgArch = stanzas[0].Package, stanzas[0].Version, stanzas[0].Architecture
		}
		if pkgName == "" {
			// No usable Package: line — fall back to the filename so this
			// package is still tracked in the ledger under some name.
			pkgName = pkgFile
		}
		if pkgVer != "" {
			idx.setVersion(evidence.DBKindDistroless, pkgName, pkgVer)
		}

		sumsName := pkgFile + ".md5sums"
		sums, ok := byName[sumsName]
		fileListPresent := ok
		fileCount := 0
		if ok {
			listLimit := budget.clamp(limits.MaxListBytes)
			if listLimit <= 0 {
				diag.Truncated = true
				fileListPresent = false
			} else {
				lines, sn, strunc, serr := readLines(sums.R, listLimit)
				budget.add(sn)
				if serr != nil {
					diag.Errors = append(diag.Errors, FileError{Name: sumsName, Err: serr})
					fileListPresent = false
				} else if strunc {
					diag.Truncated = true
					diag.Errors = append(diag.Errors, FileError{Name: sumsName,
						Err: fmt.Errorf("pkgdb: %s exceeds %d bytes", sumsName, listLimit)})
					fileListPresent = false
				} else {
					for _, line := range lines {
						fields := strings.Fields(line)
						if len(fields) < 2 {
							continue
						}
						rel := strings.Join(fields[1:], " ")
						p := "/" + strings.TrimPrefix(rel, "/")
						if limits.MaxPathsPerPackage > 0 && fileCount >= limits.MaxPathsPerPackage {
							diag.Truncated = true
							break
						}
						idx.add(p, evidence.DBKindDistroless, pkgName)
						fileCount++
					}
				}
			}
		}

		idx.Ledger = append(idx.Ledger, LedgerEntry{
			DBKind: evidence.DBKindDistroless, Name: pkgName, Version: pkgVer, Arch: pkgArch,
			FileListPresent: fileListPresent, FileCount: fileCount,
		})
	}

	// See ParseDpkg: catches an overage that only becomes visible once the
	// final read is in.
	if budget.exceeded() {
		diag.Truncated = true
	}
	return idx, diag, nil
}
