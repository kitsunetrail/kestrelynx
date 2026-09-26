package sensor

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/unix"

	"github.com/kitsunetrail/kestrelynx/internal/evidence"
	"github.com/kitsunetrail/kestrelynx/internal/sensor/parser"
)

// errParserConnectionLost wraps any error from actually sending to or
// reading from the parser's socket (as opposed to a Response the parser
// sent back with OK == false, which means the parser is alive and simply
// rejected this one request). Callers use errors.Is against this to tell
// "the parser process itself has died" apart from "the parser looked at
// this file/lookup and said no", which is this one generation's own
// problem and never a reason to end the Sensor session.
var errParserConnectionLost = errors.New("sensor: parser connection lost")

// Every function in this file is called only from the dbworker goroutine
// (runDBWorker, dbworker.go), which is the sole owner of the parser socket
// fd for as long as the Sensor session runs: nothing here does its own
// locking or connection-sharing, because nothing else in this package ever
// touches that fd.

// indexFile is one package-database input the dbworker has already opened
// (through internal/sensor/rootfs's read contract) and is about to hand to
// the parser to fold into one container generation's index. File is closed
// by buildContainerIndex once it has been sent, whether or not sending
// succeeded — the same one-shot-descriptor discipline procfs.Handle and
// rootfs.Reader use elsewhere in this Sensor. Dev/Inode/Size are the
// observer's own fstat of File at the moment it was opened, carried
// alongside it so a caller can build an evidence.ParseFailure identifying
// exactly this content if the parser rejects it — see
// generationState.recordParseFailure's doc comment for why that identity
// (not just the file's name) is what decides whether a repeat failure is
// the "same input" or a new one.
type indexFile struct {
	Role  string
	Name  string
	Path  string
	Dev   string
	Inode uint64
	Size  int64
	File  *os.File
}

// buildContainerIndex sends every file in files, in order, to the parser
// over sockFD, building gen's package-database index there (see dbOp's doc
// comment for the wire protocol). The last file is marked Last, which is
// what makes the parser actually call the matching pkgdb.Parse* function
// and return the completed buildResult; every earlier file gets a plain
// acknowledgement this function checks (OK) but otherwise discards. files
// must not be empty and must already be in the order the caller wants
// pkgdb to see them (status/installed's own position among them does not
// matter — dbHandler recognizes it by Role, not by position).
//
// deadline is this build's own soft cap (see runDBWorker's own doc
// comment): before sending any file other than the first, if time.Now() is
// already past deadline, every remaining file (including the one that
// would have been marked Last) is closed unsent and softCapped is true —
// the parser's own dbBuildSession for gen is left half-built in this case,
// which the caller must clean up with forgetIndex before retrying.
//
// On a connection error, failedAt names whichever file was being sent when
// it happened, and lastWasFinal reports whether that file was the one
// marked Last. The two are not interchangeable for attribution purposes: a
// non-Last file's own identity is a reasonable attribution (that specific
// file's bytes may never have reached the parser, or its content may be
// exactly what a crash there was reacting to), but a failure while sending
// the Last file happens exactly when pkgdb.Parse* actually runs against
// everything accumulated so far — the true cause could just as easily be an
// earlier file's content, which the observer has no way to identify from
// here. A caller must attribute a lastWasFinal failure to the build's own
// mandatory file identity (see expectedMandatoryPath) instead of failedAt.
func buildContainerIndex(sockFD int, gen string, dbKind evidence.PackageDBKind, files []indexFile, deadline time.Time) (result buildResult, failedAt *indexFile, lastWasFinal bool, softCapped bool, err error) {
	if len(files) == 0 {
		return buildResult{}, nil, false, false, fmt.Errorf("sensor: buildContainerIndex: no files for generation %s", gen)
	}
	for i := range files {
		f := &files[i]
		last := i == len(files)-1
		if i > 0 && time.Now().After(deadline) {
			for j := i; j < len(files); j++ {
				files[j].File.Close()
			}
			return buildResult{}, nil, false, true, nil
		}
		res, serr := sendOneIndexFile(sockFD, gen, dbKind, f, last)
		if serr != nil {
			return buildResult{}, f, last, false, serr
		}
		if last {
			return res, nil, false, false, nil
		}
	}
	panic("unreachable: last file always returns above")
}

// sendOneIndexFile sends f to the parser as one file of gen's in-progress
// build, marked Last exactly when the caller says this is the final file of
// the whole build. It is buildContainerIndex's own per-file loop body,
// factored out so a caller that does not know its whole file batch up
// front — streamBuildFiles, whose files only become known one at a time, as
// each one's own backoff eligibility is checked (see gatherIndexFiles' own
// doc comment on why) — can send files one at a time as they become known,
// through the exact same disconnect-handling sendFileOp already provides,
// without duplicating it.
func sendOneIndexFile(sockFD int, gen string, dbKind evidence.PackageDBKind, f *indexFile, last bool) (buildResult, error) {
	return sendFileOp(sockFD, dbOp{
		Op: dbOpFile, Gen: gen, DB: dbKindFromString(dbKind),
		Role: f.Role, Name: f.Name, Last: last,
	}, f.File)
}

// sendFileOp sends one dbOp carrying f's fd, closes f (regardless of
// outcome), and reads back the parser's response. It returns a populated
// buildResult only when op.Last is true and the response actually carries
// one; a non-final file's plain acknowledgement decodes to a zero
// buildResult, which callers must not use.
func sendFileOp(sockFD int, op dbOp, f *os.File) (buildResult, error) {
	defer f.Close()
	kind, err := json.Marshal(op)
	if err != nil {
		return buildResult{}, fmt.Errorf("sensor: marshal dbOp: %w", err)
	}
	if err := parser.SendRequest(sockFD, string(kind), int(f.Fd())); err != nil {
		return buildResult{}, fmt.Errorf("%w: send: %v", errParserConnectionLost, err)
	}
	resp, err := parser.ReadResponse(sockFD)
	if err != nil {
		return buildResult{}, fmt.Errorf("%w: read response: %v", errParserConnectionLost, err)
	}
	if !resp.OK {
		// The parser is alive and answered; it just rejected this one file
		// (e.g. an internal decode error on content it could not make sense
		// of, or the size-limit fallback in parser.Run's own send path).
		// Deliberately not wrapped in errParserConnectionLost.
		return buildResult{}, fmt.Errorf("sensor: parser rejected file %s: %s", op.Name, resp.Error)
	}
	if !op.Last {
		return buildResult{}, nil
	}
	var res buildResult
	if err := json.Unmarshal(resp.Result, &res); err != nil {
		return buildResult{}, fmt.Errorf("sensor: unmarshal build result: %w", err)
	}
	return res, nil
}

// maxWireRequestBytes bounds the fully wire-encoded size (the actual bytes
// parser.SendRequest transmits: a JSON Request{"kind": "<dbOp JSON, itself
// escaped as a string>"} — two layers of JSON, not one, since dbOp travels
// as a string inside Request.Kind) of any request this file sends. It is a
// conservative margin under parser.Run's own fixed request buffer (4096
// bytes): every request is measured by actually marshaling it and checking
// len(), never estimated from raw content length, since JSON array syntax,
// per-element quoting, and the double-encoding here can roughly double the
// byte count relative to the paths' own raw lengths.
const maxWireRequestBytes = 3500

// dbOpEncodedSize returns the exact number of bytes parser.SendRequest would
// transmit for op — the same two-layer JSON encoding SendRequest itself
// performs (marshal op, then wrap the result in a Request as a string) —
// so a caller can decide whether adding one more element to a batch would
// cross maxWireRequestBytes before actually sending anything.
func dbOpEncodedSize(op dbOp) (int, error) {
	kind, err := json.Marshal(op)
	if err != nil {
		return 0, fmt.Errorf("marshal dbOp: %w", err)
	}
	full, err := json.Marshal(parser.Request{Kind: string(kind)})
	if err != nil {
		return 0, fmt.Errorf("marshal request: %w", err)
	}
	return len(full), nil
}

// lookupOutcome is one path's answer from a dbOpLookup round trip: its
// owners (if any) and whether the parser's own OwnersTruncated flag cut
// that owner list short (see lookupResult's own doc comment in dbop.go) —
// carried through here rather than discarded, since a truncated owner list
// must never be mistaken for a complete, if merely ambiguous, one: the
// generation this lookup belongs to has to withdraw not-observed for it
// regardless of how many owners were actually reported (see
// applyLookupResult).
type lookupOutcome struct {
	owners    []lookupOwner
	truncated bool
}

// lookupPaths resolves every path in paths against gen's already-built
// index (a prior, completed buildContainerIndex call for the same gen),
// chunking the request across as many dbOpLookup round trips as
// maxWireRequestBytes requires (measured by the request's own real encoded
// size, never estimated from the paths' raw byte lengths), and following
// every lookupPage.More continuation until each batch is fully answered.
// The returned map has one entry per path this function actually got an
// answer for — a path that, on its own, cannot fit under
// maxWireRequestBytes at all is left out of the result entirely (never
// given a false "zero owners" answer), and a caller must treat a missing
// key as "not answered", not "not owned" (Go's own two-value map access —
// v, ok := owners[path] — is what distinguishes the two: an answered path
// with no owner is present with a nil/empty slice, ok == true).
//
// An error from this function is not necessarily fatal to the parser
// connection: a normal, non-fatal rejection of one request (e.g. the
// size-budget fallback in parser.Run's own send path, when even one
// page's worth of answers would not fit) surfaces as a plain error here,
// the same as a real connection failure — callers must use errors.Is
// against errParserConnectionLost to tell the two apart (see
// handleLookupJob), never assume every error here ends the Sensor session.
func lookupPaths(sockFD int, gen string, paths []string) (map[string]lookupOutcome, error) {
	out := make(map[string]lookupOutcome, len(paths))
	if len(paths) == 0 {
		return out, nil
	}

	fd, cleanup, err := throwawayFD()
	if err != nil {
		return nil, fmt.Errorf("sensor: lookupPaths: %w", err)
	}
	defer cleanup()

	var batch []string
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		remaining := batch
		for len(remaining) > 0 {
			page, err := sendLookupOp(sockFD, gen, remaining, fd)
			if err != nil {
				return err
			}
			for _, r := range page.Results {
				out[r.Path] = lookupOutcome{owners: r.Owners, truncated: r.OwnersTruncated}
			}
			if !page.More || len(page.Results) == 0 {
				break
			}
			remaining = remaining[len(page.Results):]
		}
		batch = nil
		return nil
	}

	for _, p := range paths {
		trial := make([]string, len(batch)+1)
		copy(trial, batch)
		trial[len(batch)] = p

		size, err := dbOpEncodedSize(dbOp{Op: dbOpLookup, Gen: gen, Paths: trial})
		if err != nil {
			return nil, fmt.Errorf("sensor: measure lookup request size: %w", err)
		}
		if size <= maxWireRequestBytes {
			batch = trial
			continue
		}
		if len(batch) > 0 {
			if err := flush(); err != nil {
				return nil, err
			}
		}
		// Retry p alone, against a now-empty batch.
		soloSize, err := dbOpEncodedSize(dbOp{Op: dbOpLookup, Gen: gen, Paths: []string{p}})
		if err != nil {
			return nil, fmt.Errorf("sensor: measure lookup request size: %w", err)
		}
		if soloSize > maxWireRequestBytes {
			// p cannot be sent at all, alone or otherwise; leave it absent
			// from out rather than force it into an oversized request.
			continue
		}
		batch = []string{p}
	}
	if err := flush(); err != nil {
		return nil, err
	}
	return out, nil
}

func sendLookupOp(sockFD int, gen string, paths []string, throwaway int) (lookupPage, error) {
	kind, err := json.Marshal(dbOp{Op: dbOpLookup, Gen: gen, Paths: paths})
	if err != nil {
		return lookupPage{}, fmt.Errorf("sensor: marshal lookup op: %w", err)
	}
	if err := parser.SendRequest(sockFD, string(kind), throwaway); err != nil {
		return lookupPage{}, fmt.Errorf("%w: send: %v", errParserConnectionLost, err)
	}
	resp, err := parser.ReadResponse(sockFD)
	if err != nil {
		return lookupPage{}, fmt.Errorf("%w: read response: %v", errParserConnectionLost, err)
	}
	if !resp.OK {
		return lookupPage{}, fmt.Errorf("sensor: parser rejected lookup: %s", resp.Error)
	}
	var page lookupPage
	if err := json.Unmarshal(resp.Result, &page); err != nil {
		return lookupPage{}, fmt.Errorf("sensor: unmarshal lookup page: %w", err)
	}
	return page, nil
}

// fetchLedger retrieves gen's already-built index's whole ledger, paging
// through dbOpLedger requests (see dbOp's and buildResult's own doc
// comments for why the ledger is never returned in one message). deadline
// is the same one build-wide soft cap buildFromRoot applies to everything
// else about this build (see buildSoftCap's own doc comment) — checked
// between pages (never before the first, so a generation with a genuinely
// enormous ledger still gets at least one page's worth of progress every
// call) so a database with an extraordinary number of packages cannot
// spend this whole budget paging through its own ledger alone. A deadline
// timeout surfaces as a plain, non-fatal error (the parser itself is still
// alive and responding normally) — callers must not wrap it in
// errParserConnectionLost, the same rule every other error from this file
// already follows.
func fetchLedger(sockFD int, gen string, deadline time.Time) ([]ledgerEntry, error) {
	var all []ledgerEntry
	offset := 0
	for i := 0; ; i++ {
		if i > 0 && time.Now().After(deadline) {
			return nil, fmt.Errorf("sensor: fetchLedger: build deadline exceeded after %d page(s)", i)
		}
		page, err := sendLedgerOp(sockFD, gen, offset)
		if err != nil {
			return nil, err
		}
		if len(page.Entries) == 0 {
			break
		}
		all = append(all, page.Entries...)
		offset += len(page.Entries)
		if !page.HasMore {
			break
		}
	}
	return all, nil
}

func sendLedgerOp(sockFD int, gen string, offset int) (ledgerPage, error) {
	kind, err := json.Marshal(dbOp{Op: dbOpLedger, Gen: gen, Offset: offset})
	if err != nil {
		return ledgerPage{}, fmt.Errorf("sensor: marshal ledger op: %w", err)
	}
	fd, cleanup, err := throwawayFD()
	if err != nil {
		return ledgerPage{}, fmt.Errorf("sensor: sendLedgerOp: %w", err)
	}
	defer cleanup()
	if err := parser.SendRequest(sockFD, string(kind), fd); err != nil {
		return ledgerPage{}, fmt.Errorf("%w: send: %v", errParserConnectionLost, err)
	}
	resp, err := parser.ReadResponse(sockFD)
	if err != nil {
		return ledgerPage{}, fmt.Errorf("%w: read response: %v", errParserConnectionLost, err)
	}
	if !resp.OK {
		return ledgerPage{}, fmt.Errorf("sensor: parser rejected ledger fetch: %s", resp.Error)
	}
	var page ledgerPage
	if err := json.Unmarshal(resp.Result, &page); err != nil {
		return ledgerPage{}, fmt.Errorf("sensor: unmarshal ledger page: %w", err)
	}
	return page, nil
}

// forgetIndex releases gen's retained index in the parser, once the
// dbworker has decided that generation is gone, or that a soft-capped or
// otherwise aborted build left a half-built session behind that must not
// leak into the next attempt. Safe to call for a generation the parser
// never built an index for (e.g. one whose database build never completed)
// — dbHandler's "forget" case is a no-op then.
func forgetIndex(sockFD int, gen string) error {
	fd, cleanup, err := throwawayFD()
	if err != nil {
		return fmt.Errorf("sensor: forgetIndex: %w", err)
	}
	defer cleanup()

	kind, err := json.Marshal(dbOp{Op: dbOpForget, Gen: gen})
	if err != nil {
		return fmt.Errorf("sensor: marshal forget op: %w", err)
	}
	if err := parser.SendRequest(sockFD, string(kind), fd); err != nil {
		return fmt.Errorf("%w: send: %v", errParserConnectionLost, err)
	}
	resp, err := parser.ReadResponse(sockFD)
	if err != nil {
		return fmt.Errorf("%w: read response: %v", errParserConnectionLost, err)
	}
	if !resp.OK {
		return fmt.Errorf("sensor: parser rejected forget: %s", resp.Error)
	}
	return nil
}

// throwawayFD returns a fd suitable for a dbOp ("lookup", "ledger",
// "forget") whose payload travels entirely in the JSON Kind string, not the
// fd — the protocol's one-fd-per-request shape (see parser.Request's doc
// comment) still requires something to send, and dbHandler never reads from
// it for these ops. A pipe's read end is used rather than, say, a duplicate
// of an already-meaningful descriptor, specifically so it conveys no
// capability at all: an empty, freshly-created, otherwise-unconnected pipe.
// cleanup closes both ends this process still holds; the parser's own copy
// is closed by parser.Run right after Handle returns, as it is for every fd.
func throwawayFD() (fd int, cleanup func(), err error) {
	fds := make([]int, 2)
	if err := unix.Pipe2(fds, unix.O_CLOEXEC); err != nil {
		return -1, nil, fmt.Errorf("pipe2: %w", err)
	}
	r, w := fds[0], fds[1]
	unix.Close(w)
	return r, func() { unix.Close(r) }, nil
}
