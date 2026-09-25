package pkgdb

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"github.com/kitsunetrail/kestrelynx/internal/evidence"
)

// ParseApk builds an ownership Index from an Alpine apk database's
// installed file: stanzas separated by blank lines, each line
// "<letter>:<value>". P is the package name, V its version, A its
// architecture, F sets the "current directory" for the R entry lines that
// follow until the next F or blank line (F never carries over a blank-line
// record boundary). An R line with no preceding F line in the same record
// has no directory to be relative to and is a malformed record — recorded
// as a parse error and indexed nowhere, discarding only that package's file
// list.
//
// A record with no F/R lines at all is a package that installs no files:
// apk's virtual packages (`apk add --virtual` bundles a dependency set
// under a synthetic name). The database enumerates files inline, so such a
// record is a complete, empty file list, not an unreadable one.
func ParseApk(installed NamedReader, limits Limits) (*Index, Diagnostics, error) {
	idx := newIndex()
	var diag Diagnostics

	// Clamped to the total budget too, not just MaxApkBytes: a single input
	// file is still one read against the same aggregate budget every other
	// Parse* function shares (see ParseDpkg's totalBudget).
	budget := &totalBudget{max: limits.MaxTotalBytes}
	readLimit := budget.clamp(limits.MaxApkBytes)
	if readLimit <= 0 {
		diag.Truncated = true
		return idx, diag, nil
	}

	cr := &countingReader{r: io.LimitReader(installed.R, readLimit+1)}
	sc := bufio.NewScanner(cr)
	sc.Buffer(make([]byte, 64*1024), 1<<20)

	var pkg, ver, arch, dir string
	fileCount := 0
	dirSet, listBroken := false, false
	flush := func() {
		if pkg != "" {
			idx.setVersion(evidence.DBKindApk, pkg, ver)
			idx.Ledger = append(idx.Ledger, LedgerEntry{
				DBKind: evidence.DBKindApk, Name: pkg, Version: ver, Arch: arch,
				FileListPresent: !listBroken, FileCount: fileCount,
			})
		}
		pkg, ver, arch, dir = "", "", "", ""
		fileCount = 0
		dirSet, listBroken = false, false
	}
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			flush()
			continue
		}
		if len(line) < 2 || line[1] != ':' {
			continue
		}
		field, value := line[0], line[2:]
		switch field {
		case 'P':
			pkg = value
		case 'V':
			ver = value
		case 'A':
			arch = value
		case 'F':
			dir, dirSet = value, true
		case 'R':
			if pkg == "" {
				continue
			}
			if !dirSet {
				diag.Errors = append(diag.Errors, FileError{Name: installed.Name,
					Err: fmt.Errorf("pkgdb: package %q: R:%s has no preceding F: in its record", pkg, value)})
				listBroken = true
				continue
			}
			if limits.MaxPathsPerPackage > 0 && fileCount >= limits.MaxPathsPerPackage {
				diag.Truncated = true
				continue
			}
			full := "/" + value
			if dir != "" {
				full = "/" + strings.TrimPrefix(dir, "/") + "/" + value
			}
			idx.add(full, evidence.DBKindApk, pkg)
			fileCount++
		}
	}
	flush()
	if err := sc.Err(); err != nil {
		return idx, diag, err
	}
	budget.add(cr.n)
	if cr.n > readLimit {
		diag.Truncated = true
		diag.Errors = append(diag.Errors, FileError{Name: installed.Name,
			Err: fmt.Errorf("pkgdb: %s exceeds %d bytes", installed.Name, readLimit)})
	}
	if budget.exceeded() {
		diag.Truncated = true
	}
	return idx, diag, nil
}
