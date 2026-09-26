package sensor

// dbOp is the whole vocabulary the dbworker goroutine and the parser's own
// dbHandler exchange about one container generation's OS package database,
// carried as JSON text inside parser.Request.Kind (never as a fd's
// content): parser.Request has no field for anything but a single fd per
// message, and putting this as a JSON string rather than a hand-rolled
// delimited one means an attacker-supplied Name (a package or file name
// read from a container's own filesystem) can never break the framing,
// however it is encoded — encoding/json already escapes it correctly as a
// normal JSON string.
//
// Which fields are meaningful depends on Op:
//
//   - "file": one package-database input file, read in full from the
//     accompanying fd. Gen identifies the generation being indexed, DB which
//     database format it belongs to, Role which file within that format
//     (see the role constants below), Name the file's own name exactly as
//     the observer found it (required for "list"/"control"/"md5sums", which
//     pkgdb.Parse* correlate by name; unused for "status"/"installed", the
//     one-per-generation inputs). Last marks the final file for this
//     generation: only once it arrives does the handler actually call the
//     matching pkgdb.Parse* function and retain the resulting index.
//   - "lookup": resolve as many of Paths as fit within one response's own
//     byte budget against Gen's already-built index — see lookupPage's own
//     doc comment for how a caller (dbworker) knows to ask again for
//     whatever did not fit. The accompanying fd carries no data (see
//     throwawayFD) — the payload travels in this JSON, itself chunked by
//     the caller to stay under the parser's own per-request size limit.
//   - "ledger": fetch one byte-budgeted page of Gen's already-built index's
//     ledger, starting at Offset (an entry count, not a byte offset) — the
//     ledger is never returned in a "file" build's own terminal response
//     (see buildResult's doc comment for why), so a caller that needs it
//     (to compute PackageDB.NoFileList) pages through it with repeated
//     "ledger" requests instead. The accompanying fd is unused, same as
//     "lookup".
//   - "forget": release Gen's retained index and any in-progress build
//     state. The accompanying fd is unused, same as "lookup".
type dbOp struct {
	Op     string   `json:"op"`
	Gen    string   `json:"gen"`
	DB     string   `json:"db,omitempty"`
	Role   string   `json:"role,omitempty"`
	Name   string   `json:"name,omitempty"`
	Last   bool     `json:"last,omitempty"`
	Paths  []string `json:"paths,omitempty"`
	Offset int      `json:"offset,omitempty"`
}

const (
	dbOpFile   = "file"
	dbOpLookup = "lookup"
	dbOpLedger = "ledger"
	dbOpForget = "forget"
)

// Role values for dbOp.Role when Op == "file". "status" and "installed" are
// each exactly one file per generation (dpkg's status, apk's installed);
// "list", "control" and "md5sums" each recur, once per package.
const (
	roleStatus    = "status"    // dpkg /var/lib/dpkg/status
	roleList      = "list"      // dpkg info/<pkg>.list
	roleInstalled = "installed" // apk lib/apk/db/installed
	roleControl   = "control"   // distroless status.d/<pkg>
	roleMD5Sums   = "md5sums"   // distroless status.d/<pkg>.md5sums
)

// DB values for dbOp.DB, matching evidence.PackageDBKind's own string values
// exactly (dbHandler converts between the two with a plain string
// conversion, never a lookup table, so the two vocabularies must never
// drift apart).
const (
	dbDpkg       = "dpkg"
	dbApk        = "apk"
	dbDistroless = "distroless"
)

// lookupOwner is one package that dbOpLookup's response reports as owning a
// looked-up path.
type lookupOwner struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// maxOwnersPerPath bounds how many owners lookupResult.Owners ever carries
// for one path: a real path with this many genuine, distinct package owners
// is not a realistic case this Sensor needs to represent exactly (an
// unavailable(attribution_ambiguous) verdict already applies once there is
// more than one owner at all), only bounded so a pathological or malformed
// package database cannot make one path's own answer unbounded.
const maxOwnersPerPath = 32

// lookupResult is one looked-up path's answer: which package(s), if any,
// claim it. Zero owners (with the path itself still present in a
// lookupPage.Results — see that type's own doc comment on why a caller must
// tell "answered with none" apart from "not answered at all") means the
// path is not recorded by this generation's package database at all (not an
// OS package file, or a database the generation's own file list never
// covered).
type lookupResult struct {
	Path            string        `json:"path"`
	Owners          []lookupOwner `json:"owners,omitempty"`
	OwnersTruncated bool          `json:"owners_truncated,omitempty"`
}

// lookupPage is one dbOpLookup response: as many of the request's own Paths
// as fit within the response's own byte budget (see
// maxResponsePayloadBytes), in the same order they were asked, plus More —
// true whenever some trailing subset of Paths could not be answered this
// round. A caller sees exactly len(Results) < len(the paths it asked)
// whenever More is true, and re-issues a "lookup" request for the remaining
// paths (Paths[len(Results):]) to get the rest — the same paging shape
// ledgerPage uses.
type lookupPage struct {
	Results []lookupResult `json:"results,omitempty"`
	More    bool           `json:"more,omitempty"`
}

// maxFailuresPerBuild bounds how many fileFailure entries a single
// buildResult ever carries: a container with more individually-failing
// package-database files than this has a database this Sensor cannot make
// sense of at all, and the exact identity of the 501st failing file is not
// worth risking the response's own size budget over — FailuresTruncated
// records that some were dropped, not which.
const maxFailuresPerBuild = 500

// fileFailure is one input file dbOpFile rejected while building an index —
// too large, or a genuine parse error — carried in a "file" build's terminal
// Response so the caller can turn it into an evidence.ParseFailure.
type fileFailure struct {
	Name string `json:"name"`
	Err  string `json:"err"`
}

// ledgerEntry mirrors pkgdb.LedgerEntry (this package cannot import pkgdb's
// own type across the observer/parser trust boundary as JSON without
// re-declaring it: LedgerEntry carries evidence.PackageDBKind, which decodes
// fine, but keeping a local copy here documents exactly what crosses the
// wire, independent of whatever fields pkgdb.LedgerEntry happens to gain
// later).
type ledgerEntry struct {
	Name            string `json:"name"`
	Version         string `json:"version"`
	Arch            string `json:"arch,omitempty"`
	FileListPresent bool   `json:"file_list_present"`
	FileCount       int    `json:"file_count"`
}

// buildResult is dbOpFile's terminal (Last == true) Response.Result:
// whatever went wrong building the index, but never the index's own ledger
// or path->owner mapping — a real image's ledger can hold hundreds of
// packages, and returning it all in one message risks exceeding the
// response's own size budget (this container's distributed seccomp profile
// excludes setsockopt entirely, so neither side can ever raise the
// underlying AF_UNIX socket's send buffer past its default size, quite
// aside from the byte budget this package enforces on top of that). A
// caller that needs the ledger pages through it afterward with "ledger"
// requests (see dbOp's doc comment and fetchLedger). Failures is itself
// capped at maxFailuresPerBuild; FailuresTruncated records when some were
// left out.
type buildResult struct {
	Truncated         bool          `json:"truncated"`
	Failures          []fileFailure `json:"failures,omitempty"`
	FailuresTruncated bool          `json:"failures_truncated,omitempty"`
}

// ledgerPage is one dbOpLedger response: as many ledger entries as fit
// within the response's own byte budget, starting at the request's Offset,
// plus whether more entries remain beyond this page.
type ledgerPage struct {
	Entries []ledgerEntry `json:"entries,omitempty"`
	HasMore bool          `json:"has_more,omitempty"`
}

// maxResponsePayloadBytes bounds the JSON-encoded size of the Result field
// alone (before it is wrapped in a Response and then, again, in the
// wireEnvelope parser.Run's own send path marshals) for every op this file
// defines. Kept comfortably under that path's own hard ceiling
// (maxResponseSendBytes, internal/sensor/parser/run.go, 128 KiB) so a
// response built to exactly this budget is never the one that trips that
// ceiling and gets replaced with a bare rejection — this package's own
// pagination is meant to make that fallback essentially unreachable in
// ordinary operation, not merely survivable when it happens.
const maxResponsePayloadBytes = 96 << 10 // 96 KiB
