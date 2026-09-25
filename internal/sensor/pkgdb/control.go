package pkgdb

import (
	"bufio"
	"io"
	"strings"
)

// countingReader wraps an io.Reader to track how many bytes have passed
// through it, so a caller reading through a size limit can tell how much of
// the limit was actually used.
type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// totalBudget tracks how many bytes remain of Limits.MaxTotalBytes across
// every file a Parse* function reads, so a per-file cap (MaxListBytes,
// MaxStatusBytes, MaxApkBytes) never lets one read run past what the whole
// index is allowed to consume: without clamping each read to whatever is
// left of the total, a long enough run of files each individually under
// their own per-file cap can still add up to far more than MaxTotalBytes
// before the top-of-loop check between files ever notices.
type totalBudget struct {
	max int64 // Limits.MaxTotalBytes; <= 0 means unbounded
	n   int64 // bytes consumed so far
}

// clamp returns the largest a single read may be right now: whichever of
// perFile and the budget's remaining bytes is smaller. A remaining budget
// of zero or less yields zero, which callers treat as "cannot read this
// file at all" rather than attempting a zero-byte read that would report
// spurious content.
func (b *totalBudget) clamp(perFile int64) int64 {
	if b.max <= 0 {
		return perFile
	}
	remaining := b.max - b.n
	if remaining < 0 {
		remaining = 0
	}
	if perFile <= 0 || remaining < perFile {
		return remaining
	}
	return perFile
}

// add records n more bytes consumed.
func (b *totalBudget) add(n int64) { b.n += n }

// exceeded reports whether the total budget has been used up — checked
// after every read a Parse* function makes, including the last one, so an
// overage that only becomes visible once the final file is read is never
// missed.
func (b *totalBudget) exceeded() bool {
	return b.max > 0 && b.n > b.max
}

// controlEntry is one parsed stanza (Package/Version/Architecture) of a
// dpkg-control-format file.
type controlEntry struct {
	Package, Version, Architecture string
}

// readControlEntries parses a dpkg-control-format file (RFC822-like stanzas
// separated by blank lines) into one entry per stanza, reading at most
// maxBytes+1 bytes so an oversized input is detected as truncated rather
// than silently read in full. Continuation lines (leading whitespace) are
// ignored since none of the three fields read here ever wrap.
func readControlEntries(r io.Reader, maxBytes int64) (entries []controlEntry, bytesRead int64, truncated bool, err error) {
	cr := &countingReader{r: io.LimitReader(r, maxBytes+1)}
	sc := bufio.NewScanner(cr)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	var cur controlEntry
	flush := func() {
		if cur.Package != "" {
			entries = append(entries, cur)
		}
		cur = controlEntry{}
	}
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "":
			flush()
		case strings.HasPrefix(line, "Package:"):
			cur.Package = strings.TrimSpace(strings.TrimPrefix(line, "Package:"))
		case strings.HasPrefix(line, "Version:"):
			cur.Version = strings.TrimSpace(strings.TrimPrefix(line, "Version:"))
		case strings.HasPrefix(line, "Architecture:"):
			cur.Architecture = strings.TrimSpace(strings.TrimPrefix(line, "Architecture:"))
		}
	}
	flush()
	if serr := sc.Err(); serr != nil {
		return entries, cr.n, false, serr
	}
	return entries, cr.n, cr.n > maxBytes, nil
}

// readLines reads r line by line, at most maxBytes+1 bytes, reporting
// truncated when the input was longer than that.
func readLines(r io.Reader, maxBytes int64) (lines []string, bytesRead int64, truncated bool, err error) {
	cr := &countingReader{r: io.LimitReader(r, maxBytes+1)}
	sc := bufio.NewScanner(cr)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	if serr := sc.Err(); serr != nil {
		return lines, cr.n, false, serr
	}
	return lines, cr.n, cr.n > maxBytes, nil
}
