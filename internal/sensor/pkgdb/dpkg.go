package pkgdb

import (
	"fmt"
	"strings"

	"github.com/kitsunetrail/kestrelynx/internal/evidence"
)

// ParseDpkg builds an ownership Index from a dpkg installation's status
// file and its info/*.list files, exactly as the observer read them: status
// is /var/lib/dpkg/status's content, and lists is every info/*.list file
// the observer found under info/ (deciding which files under info/ end in
// ".list" is the observer's job — this package only looks at the name it's
// given for each reader, and skips anything not ending in ".list" rather
// than assuming the caller already filtered).
func ParseDpkg(status NamedReader, lists []NamedReader, limits Limits) (*Index, Diagnostics, error) {
	idx := newIndex()
	var diag Diagnostics
	budget := &totalBudget{max: limits.MaxTotalBytes}

	listedPkgs := map[string]bool{}
	fileCounts := map[string]int{}

	for i, lf := range lists {
		if limits.MaxFiles > 0 && i >= limits.MaxFiles {
			diag.Truncated = true
			break
		}
		if !strings.HasSuffix(lf.Name, ".list") {
			continue
		}
		// Clamped to whatever remains of the total budget, not just the
		// per-file cap: a long run of files each individually under
		// MaxListBytes must still stop once their sum reaches
		// MaxTotalBytes, rather than only being caught by the next
		// iteration's top-of-loop check after already overshooting.
		readLimit := budget.clamp(limits.MaxListBytes)
		if readLimit <= 0 {
			diag.Truncated = true
			break
		}

		pkgName := strings.TrimSuffix(lf.Name, ".list")
		if j := strings.IndexByte(pkgName, ':'); j >= 0 {
			// A multiarch package's .list file is named "<pkg>:<arch>.list"
			// (e.g. "libc6:amd64.list"); the package identity is the part
			// before the colon.
			pkgName = pkgName[:j]
		}

		lines, n, trunc, err := readLines(lf.R, readLimit)
		budget.add(n)
		if err != nil {
			diag.Errors = append(diag.Errors, FileError{Name: lf.Name, Err: err})
			continue
		}
		if trunc {
			// The rest of this file was never read, so its file list is not
			// trustworthy as complete — recorded as a read failure for this
			// one package rather than an index-wide truncation, since every
			// other file the observer handed over is still read in full.
			// It is still also an index-wide Truncated: whatever this read
			// didn't reach (because the per-file or the shrunken remaining-
			// budget cap was hit) might have held the missing evidence.
			diag.Truncated = true
			diag.Errors = append(diag.Errors, FileError{Name: lf.Name,
				Err: fmt.Errorf("pkgdb: %s exceeds %d bytes", lf.Name, readLimit)})
			continue
		}

		listedPkgs[pkgName] = true
		count := 0
		for _, p := range lines {
			p = strings.TrimSpace(p)
			if p == "" || p == "/." {
				continue
			}
			if limits.MaxPathsPerPackage > 0 && count >= limits.MaxPathsPerPackage {
				diag.Truncated = true
				break
			}
			idx.add(p, evidence.DBKindDpkg, pkgName)
			count++
		}
		fileCounts[pkgName] += count
	}

	statusLimit := budget.clamp(limits.MaxStatusBytes)
	var stanzas []controlEntry
	if statusLimit > 0 {
		stanzas0, n, trunc, err := readControlEntries(status.R, statusLimit)
		stanzas = stanzas0
		budget.add(n)
		if trunc {
			diag.Truncated = true
			diag.Errors = append(diag.Errors, FileError{Name: status.Name,
				Err: fmt.Errorf("pkgdb: %s exceeds %d bytes", status.Name, statusLimit)})
		} else if err != nil {
			diag.Errors = append(diag.Errors, FileError{Name: status.Name, Err: err})
		}
	} else {
		diag.Truncated = true
	}

	// A last check across everything this call read, independent of any
	// single file's own truncation flag: it is what catches an overage that
	// only becomes visible once the final read is in (the read-contract's
	// aggregate budget is about total bytes actually pulled off disk, not
	// just whether any one file individually looked oversized).
	if budget.exceeded() {
		diag.Truncated = true
	}

	for _, s := range stanzas {
		if s.Package == "" {
			continue
		}
		idx.setVersion(evidence.DBKindDpkg, s.Package, s.Version)
		idx.Ledger = append(idx.Ledger, LedgerEntry{
			DBKind: evidence.DBKindDpkg, Name: s.Package, Version: s.Version, Arch: s.Architecture,
			FileListPresent: listedPkgs[s.Package], FileCount: fileCounts[s.Package],
		})
	}
	return idx, diag, nil
}
