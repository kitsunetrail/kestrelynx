package sensor

import (
	"bytes"
	"encoding/json"
	"fmt"

	"golang.org/x/sys/unix"

	"github.com/kitsunetrail/kestrelynx/internal/evidence"
	"github.com/kitsunetrail/kestrelynx/internal/sensor/pkgdb"
)

// dbHandler is the parser process's parser.Handler: it turns a sequence of
// dbOp "file" requests into a pkgdb.Index per container generation, answers
// "lookup" requests against an already-built index, and forgets a
// generation's index on "forget". It never opens a file itself — every byte
// it reads comes from the fd the observer already opened through
// internal/sensor/rootfs's read contract and handed over — and it retains
// only what building an index requires: the completed pkgdb.Index (bounded
// by pkgdb's own per-package/per-file limits) and, transiently, one
// in-progress build's accumulated file contents.
//
// Handle is only ever called from parser.Run's single request-handling
// goroutine (never concurrently), so the maps below need no locking.
type dbHandler struct {
	limits   pkgdb.Limits
	sessions map[string]*dbBuildSession
	indices  map[string]*pkgdb.Index
}

func newDBHandler() *dbHandler {
	return &dbHandler{
		limits:   pkgdb.DefaultLimits(),
		sessions: map[string]*dbBuildSession{},
		indices:  map[string]*pkgdb.Index{},
	}
}

// dbBuildSession accumulates one container generation's package-database
// files across multiple "file" requests, until the one marked Last triggers
// the actual pkgdb.Parse* call. remaining bounds the total bytes this
// session will still accept, across every file it has been handed —
// enforced here, before any pkgdb.Parse* function ever runs, because that
// function's own MaxTotalBytes check only fires once every file has already
// been read into memory; without a check here, a generation with far more
// database files than pkgdb.Limits.MaxFiles could make this process
// accumulate far more than the read contract's aggregate budget before that
// check ever had a chance to apply.
type dbBuildSession struct {
	db        string
	remaining int64
	truncated bool
	status    *pkgdb.NamedReader
	files     []pkgdb.NamedReader
	failures  []fileFailure
}

// Handle implements parser.Handler.
func (h *dbHandler) Handle(kind string, fd int) (json.RawMessage, error) {
	var op dbOp
	if err := json.Unmarshal([]byte(kind), &op); err != nil {
		return nil, fmt.Errorf("dbhandler: malformed op: %w", err)
	}
	if op.Gen == "" {
		return nil, fmt.Errorf("dbhandler: op %q missing gen", op.Op)
	}

	switch op.Op {
	case dbOpFile:
		return h.handleFile(op, fd)
	case dbOpLookup:
		return h.handleLookup(op)
	case dbOpLedger:
		return h.handleLedger(op)
	case dbOpForget:
		delete(h.sessions, op.Gen)
		delete(h.indices, op.Gen)
		return json.RawMessage(`{"ok":true}`), nil
	default:
		return nil, fmt.Errorf("dbhandler: unknown op %q", op.Op)
	}
}

// roleCap returns the read contract's per-file byte cap for role, and false
// for a role this handler does not recognize.
func (h *dbHandler) roleCap(role string) (int64, bool) {
	switch role {
	case roleStatus, roleControl:
		return h.limits.MaxStatusBytes, true
	case roleList, roleMD5Sums:
		return h.limits.MaxListBytes, true
	case roleInstalled:
		return h.limits.MaxApkBytes, true
	default:
		return 0, false
	}
}

func (h *dbHandler) handleFile(op dbOp, fd int) (json.RawMessage, error) {
	cap0, ok := h.roleCap(op.Role)
	if !ok {
		return nil, fmt.Errorf("dbhandler: unknown role %q", op.Role)
	}

	session := h.sessions[op.Gen]
	if session == nil {
		session = &dbBuildSession{db: op.DB, remaining: h.limits.MaxTotalBytes}
		h.sessions[op.Gen] = session
	}

	allowed := cap0
	if session.remaining <= 0 {
		session.truncated = true
		allowed = 0
	} else if session.remaining < allowed {
		allowed = session.remaining
	}

	var data []byte
	var readTruncated bool
	if allowed > 0 {
		var err error
		data, readTruncated, err = readBounded(fd, allowed)
		if err != nil {
			session.failures = append(session.failures, fileFailure{Name: op.Name, Err: err.Error()})
		}
		session.remaining -= int64(len(data))
	}
	if readTruncated {
		session.truncated = true
	}

	name := op.Name
	switch op.Role {
	case roleStatus:
		session.status = &pkgdb.NamedReader{Name: "status", R: bytes.NewReader(data)}
	case roleInstalled:
		session.status = &pkgdb.NamedReader{Name: "installed", R: bytes.NewReader(data)}
	default:
		session.files = append(session.files, pkgdb.NamedReader{Name: name, R: bytes.NewReader(data)})
	}

	if !op.Last {
		return json.RawMessage(`{"ok":true}`), nil
	}
	return h.finishBuild(op.Gen, session)
}

// finishBuild calls the pkgdb.Parse* function matching session.db against
// everything accumulated so far, retains the resulting index for future
// "lookup" requests, and reports the ledger/diagnostics (never the index's
// own path->owner mapping — see dbOp's doc comment).
func (h *dbHandler) finishBuild(gen string, session *dbBuildSession) (json.RawMessage, error) {
	delete(h.sessions, gen)

	var idx *pkgdb.Index
	var diag pkgdb.Diagnostics
	var err error
	switch session.db {
	case dbDpkg:
		status := pkgdb.NamedReader{Name: "status", R: bytes.NewReader(nil)}
		if session.status != nil {
			status = *session.status
		}
		idx, diag, err = pkgdb.ParseDpkg(status, session.files, h.limits)
	case dbApk:
		installed := pkgdb.NamedReader{Name: "installed", R: bytes.NewReader(nil)}
		if session.status != nil {
			installed = *session.status
		}
		idx, diag, err = pkgdb.ParseApk(installed, h.limits)
	case dbDistroless:
		idx, diag, err = pkgdb.ParseDistroless(session.files, h.limits)
	default:
		return nil, fmt.Errorf("dbhandler: unknown db %q", session.db)
	}
	if err != nil {
		return nil, fmt.Errorf("dbhandler: parse %s: %w", session.db, err)
	}

	h.indices[gen] = idx

	res := buildResult{Truncated: diag.Truncated || session.truncated}
	var failures []fileFailure
	for _, e := range diag.Errors {
		failures = append(failures, fileFailure{Name: e.Name, Err: e.Err.Error()})
	}
	failures = append(failures, session.failures...)
	res.Failures, res.FailuresTruncated = boundFailures(failures)

	return json.Marshal(res)
}

// boundFailures caps failures at maxFailuresPerBuild entries and, if the
// result would still exceed half of maxResponsePayloadBytes once encoded
// (leaving the other half for everything else buildResult/the response
// envelope carries), halves it repeatedly until it fits — a loop that
// always terminates (every iteration strictly shrinks a slice bounded below
// by zero) rather than one bounded only by hoping real data never gets this
// large.
func boundFailures(failures []fileFailure) (bounded []fileFailure, truncated bool) {
	if len(failures) > maxFailuresPerBuild {
		failures = failures[:maxFailuresPerBuild]
		truncated = true
	}
	for len(failures) > 0 {
		body, err := json.Marshal(failures)
		if err != nil || len(body) <= maxResponsePayloadBytes/2 {
			break
		}
		failures = failures[:len(failures)/2]
		truncated = true
	}
	return failures, truncated
}

// handleLedger answers one byte-budgeted page of op.Gen's already-built
// index's ledger, starting at op.Offset (an entry count). It never returns
// an error for an offset past the end (an empty, HasMore=false page) or for
// a generation with no retained index at all (the same, since fetchLedger
// is only ever called once a "file" build has already completed) — either
// is the caller having nothing left to page through, not a protocol
// violation. Entries are added one at a time, each already marshaled to
// know its own real encoded size, until adding the next would exceed
// maxResponsePayloadBytes — except the very first entry of a page is always
// included even if it alone is oversized, so a single pathological entry
// can never stall pagination forever.
func (h *dbHandler) handleLedger(op dbOp) (json.RawMessage, error) {
	idx := h.indices[op.Gen]
	var page ledgerPage
	if idx == nil {
		return json.Marshal(page)
	}
	start := op.Offset
	if start < 0 {
		start = 0
	}
	if start >= len(idx.Ledger) {
		return json.Marshal(page)
	}

	used := 0
	for i := start; i < len(idx.Ledger); i++ {
		l := idx.Ledger[i]
		entry := ledgerEntry{
			Name: l.Name, Version: l.Version, Arch: l.Arch,
			FileListPresent: l.FileListPresent, FileCount: l.FileCount,
		}
		encoded, err := json.Marshal(entry)
		if err != nil {
			continue
		}
		if used+len(encoded) > maxResponsePayloadBytes && len(page.Entries) > 0 {
			page.HasMore = true
			return json.Marshal(page)
		}
		page.Entries = append(page.Entries, entry)
		used += len(encoded) + 1
	}
	return json.Marshal(page)
}

// handleLookup answers as many of op.Paths as fit within one response's own
// byte budget, in order — see lookupPage's own doc comment for how a caller
// asks for the remainder. Each path's own owner list is capped at
// maxOwnersPerPath, marked OwnersTruncated if that cut anything off, before
// its own encoded size is measured — the same "always include the first one
// even if oversized" rule handleLedger uses applies here too.
func (h *dbHandler) handleLookup(op dbOp) (json.RawMessage, error) {
	idx := h.indices[op.Gen]
	var page lookupPage

	used := 0
	for _, p := range op.Paths {
		r := lookupResult{Path: p}
		if idx != nil {
			if owners, ok := idx.Lookup(p); ok {
				for _, o := range owners {
					if len(r.Owners) >= maxOwnersPerPath {
						r.OwnersTruncated = true
						break
					}
					version, _ := idx.Version(o.DBKind, o.Name)
					r.Owners = append(r.Owners, lookupOwner{Name: o.Name, Version: version})
				}
			}
		}
		encoded, err := json.Marshal(r)
		if err != nil {
			continue
		}
		if used+len(encoded) > maxResponsePayloadBytes && len(page.Results) > 0 {
			page.More = true
			return json.Marshal(page)
		}
		page.Results = append(page.Results, r)
		used += len(encoded) + 1
	}
	return json.Marshal(page)
}

// dbKindFromString converts an evidence.PackageDBKind to the dbOp.DB string
// this package uses on the wire. The two vocabularies are defined to be
// identical strings (see dbOp's doc comment); this exists so a call site
// reads as a deliberate, named conversion rather than a bare string cast.
func dbKindFromString(k evidence.PackageDBKind) string { return string(k) }

// readChunkSize is how much readBounded grows its buffer by on each read: a
// small file only ever costs roughly this much backing-array memory, not
// whatever the role's full per-file cap happens to be (up to 32 MiB) —
// which matters because many small files (a container with a large number
// of packages, each contributing one small distroless control file, say)
// would otherwise each retain a full-sized, mostly-empty buffer for as long
// as this build's accumulated NamedReaders are held, multiplying the
// per-file cap by the file count instead of by the bytes actually present.
const readChunkSize = 32 * 1024

// readBounded reads at most limit+1 bytes from fd using a raw read(2) loop
// (never fstat, lseek, or anything else the parser's seccomp allow-list
// excludes — see sandbox.ParserFilter), reporting truncated if the file held
// more than limit bytes. It never assumes fd is seekable or even a regular
// file: a request always hands over a fresh, single-use descriptor, read
// front-to-back exactly once. The buffer grows in readChunkSize increments
// as data actually arrives (via append, which over-allocates by Go's own
// growth factor — bounded by how far the loop lets it grow, not by a fixed
// multiple of the file's real size) rather than being allocated at the full
// limit+1 up front, and the value finally returned is copied into a buffer
// sized to exactly what was read, so nothing past that point is retained.
//
// When truncated, the returned data is exactly limit+1 bytes, not just
// limit: the content this handler eventually hands to a pkgdb.Parse*
// function goes through that function's own
// io.LimitReader(r, maxBytes+1)-based truncation check (see e.g.
// readLines), which only fires when it actually sees one byte past its own
// limit. Trimming that extra byte here first would hide the overage from
// that check entirely — pkgdb would see an input that ends exactly at its
// own limit and conclude, wrongly, that the real file was never any longer
// than that.
func readBounded(fd int, limit int64) (data []byte, truncated bool, err error) {
	buf := make([]byte, 0, readChunkSize)
	for int64(len(buf)) <= limit {
		chunk := make([]byte, readChunkSize)
		n, rerr := unix.Read(fd, chunk)
		if rerr == unix.EINTR {
			continue
		}
		if rerr != nil {
			return copyExact(buf), false, fmt.Errorf("read: %w", rerr)
		}
		if n == 0 {
			return copyExact(buf), false, nil // EOF, genuinely shorter than limit
		}
		buf = append(buf, chunk[:n]...)
	}
	if int64(len(buf)) > limit {
		// buf may hold up to readChunkSize-1 bytes past limit+1 (the last
		// read is not itself bounded to stop exactly there) — trimmed to
		// exactly limit+1 both to match pkgdb's own truncation contract (see
		// this function's doc comment) and so the returned buffer never
		// retains more than that.
		return copyExact(buf[:limit+1]), true, nil
	}
	return copyExact(buf), false, nil
}

// copyExact returns a copy of b sized to exactly len(b), so the result never
// retains whatever spare capacity append's own growth left in the backing
// array it was built from.
func copyExact(b []byte) []byte {
	out := make([]byte, len(b))
	copy(out, b)
	return out
}
