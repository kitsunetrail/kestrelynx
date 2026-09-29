// User-facing wording for the Slack channel message and thread report, kept
// in one typed dictionary so a translation only ever has to fill in this
// file. Everything else in this package renders vulnerability data (CVE ids,
// package names, versions, image references, Trivy titles, URLs) untouched —
// only the surrounding English prose lives here.
//
// A finding's severity/status vocabulary (CRITICAL, HIGH, fixed, ...) and
// Slack mrkdwn syntax (*, _, <url|text>) are not translated either: the
// former is scanner-standard terminology callers already rely on verbatim
// (e.g. the generic webhook's severity_counts keys), and the latter is
// Slack's own markup, not prose.
package notify

// Language selects which messages dictionary a rendering uses.
type Language string

const (
	// LanguageEN is the default: the wording every existing deployment has
	// always seen. enMessages is the historical, byte-pinned English text —
	// changing any of its values changes what a live deployment shows.
	LanguageEN Language = "en"
	// LanguageJA selects the Japanese dictionary.
	LanguageJA Language = "ja"
)

// messages is every translatable string the Slack channel message and
// thread report can print. Fields group roughly by the view that uses them;
// each is a fmt format string — arguments are documented at each call site,
// and any field taking two or more verbs uses positional (%[1]s-style)
// verbs so a translation can reorder them freely.
type messages struct {
	// --- header / role line (format.go: writeHeader, writeRoleLine, FormatSlackText, FormatSlackDiffText) ---
	HeaderNamed                string // "🛡️ *KestreLynx* [%[1]s] — scan results for %[2]s\n" (environment name, generated-at)
	HeaderDefault              string // "🛡️ *KestreLynx* — scan results for %s\n" (generated-at)
	RoleEverythingOpen         string // "Everything currently open."
	RoleChangesSinceLastScan   string // "Changes since the last scan."
	ImagesScannedAffected      string // "%[1]d images scanned, %[2]d affected\n"
	AllClear                   string // "\n✅ All clear (no HIGH/CRITICAL vulnerabilities found)\n"
	LowerRiskSummarizedWebhook string // "\n_%d lower-risk fix(es) summarized — full list in the generic webhook payload._\n"
	LowerRiskSummarized        string // "\n_%d lower-risk fix(es) summarized._\n"

	// --- diff mode framing (format.go: FormatSlackDiffText) ---
	NoChangesSinceLastScan  string // "\nNo changes since last scan.\n"
	HeadingNewEOSL          string // "\n*⛔ New: base OS end-of-life (top priority)*\n"
	NewEOSLNote             string // " · includes %d newly end-of-life package(s)"
	WeeklyFullReportHeading string // "\n*📋 Weekly full report — everything currently open*\n"

	// --- replaced images (format.go: writeReplaced) ---
	ReplacedHeading string // "\n*🔄 Image content changed (%d)*\n"
	ReplacedLine    string // "• %[1]s: image updated (%[2]s → %[3]s)\n" (ref, prev digests, new digests)

	// --- identity / unresolved references (format.go: imageLabel, refLabel, unresolvedRefsLine, unconfirmedRefsLine) ---
	IdentityUnconfirmed string // "identity unconfirmed: scanned by reference"
	UnresolvedRefsLine  string // "⚠️ %[1]s — %[2]s\n" (IdentityUnconfirmed text, comma-joined refs)
	UnconfirmedRefsLine string // "⏳ unconfirmed this cycle, holding previous findings — %s\n" (comma-joined refs)

	// --- new/changed findings (format.go: writeChanges, changeSuffixParts, newCVEsSuffix; shared with triage.go: writeTriageChanges) ---
	NewSinceLastScanHeading string // "\n*🆕 New since last scan (%d)*\n"
	NewCVEsPrefix           string // "new: %s" (linked CVE ids)
	MoreCount               string // " (+%d more)" — shared by the new-CVE-id list, the collapsed lower-risk list, the runtime process list and the thread's "also:" list
	EscalatedTo             string // "⬆️ escalated to %s" (priority label: ACT NOW/WATCH/LOW)
	FixNowAvailable         string // "fix now available"
	Unmuted                 string // "↩️ Unmuted (%s)" (unmutedReason text)

	// --- resolved findings (format.go: writeResolved) ---
	ResolvedHeading       string // "\n*✅ Resolved since last scan (%d)*\n"
	BaseOSNoLongerEOL     string // "• %s — base OS no longer EOL\n" (ref)
	ResolvedImagePackages string // "• %[1]s: %[2]s\n" (ref, comma-joined packages)
	NoLongerEndOfLife     string // "• %[1]s: %[2]s — no longer end-of-life\n" (ref, package)

	// --- "open now" heartbeat, triage-off (format.go: writeNothingOpenNow, writeOpenNow) ---
	OpenNowUnconfirmedHolding string // "\n📌 Open now: unconfirmed — holding previous findings until re-confirmed\n"
	OpenNowNotRescanned       string // "\n📌 Open now: not re-scanned — holding previous findings until the next successful scan\n"
	OpenNowAllClear           string // "\n🎉 Open now: none — all clear\n"
	OpenNowCriticalHigh       string // "CRITICAL %[1]d / HIGH %[2]d across %[3]d image(s)"
	OpenNowPrefix             string // "\n📌 Open now: %s" (joined segments)
	OldestUnresolvedStale     string // " — ⏰ oldest unresolved %d day(s)"
	OldestUnresolved          string // " — oldest unresolved %d day(s)"
	DetailsInWebhook          string // "_Details in the generic webhook payload._\n"

	// --- EOL/CRITICAL/care/safe segments (format.go: openNowEOLSegments, writeHeadline; shared with triage.go: writeTriageHeadline, writeTriageOpenNow) ---
	SegEOLBase    string // "⛔ %d EOL base"
	SegEOLPackage string // "⛔ %d EOL package"
	SegCritical   string // "🔴 %d CRITICAL"
	SegNeedCare   string // "🟠 %d need care"
	SegSafe       string // "🟢 %d safe"
	SegWatch      string // "👀 %d watch" — shared by writeTriageHeadline and writeTriageOpenNow
	SegLow        string // "🔕 %d low" — shared by writeTriageHeadline and writeTriageOpenNow
	PriorityLine  string // "*Priority:* %s\n" (joined segments) — shared by writeHeadline and writeTriageHeadline

	// --- scan failures (format.go: writeScanErrors) ---
	ScanFailuresHeading string // "\n*⚠️ Scan failures*\n"
	ScanFailureLine     string // "• %[1]s — %[2]s\n" (ref, error text)

	// --- status sections, triage off (format.go: writeActionable, writeSection, writePackage) ---
	ActionableTitle       string // "✅ Actionable now (fixed)" (bare title; format.go wraps it "\n*%s*\n", thread.go wraps it "*%s*")
	WatchSectionTitle     string // "ℹ️ No fix yet (affected / waiting on upstream)"
	WontFixSectionTitle   string // "🔕 Upstream won't fix (will_not_fix)"
	SectionHeading        string // "\n*%s*\n" (a title above)
	ImageCritHighLine     string // "%[1]s %[2]s  CRITICAL %[3]d / HIGH %[4]d\n" (emoji, image label, critical count, high count)
	PackageFixedLine      string // "%[1]s %[2]s → %[3]s" (package, installed version, fixed version)
	PackageEOLLine        string // "%[1]s %[2]s (%[3]s)" (package, installed version, EOLPackageText)
	PackageNoFixLine      string // "%[1]s %[2]s (no fix available)" (package, installed version)
	PackageSeverityCounts string // " (CRITICAL %[1]d / HIGH %[2]d)"
	CollapsedLine         string // "   • +%[1]d lower-risk fixes (%[2]s): %[3]s" (count, severity summary, comma-joined names)

	// --- upgrade-risk labels (format.go: riskLabel) ---
	RiskDistroUpdate string // "🟢 upgrade: distro security patch"
	RiskSafe         string // "🟢 upgrade: low-risk"
	RiskCaution      string // "🟠 upgrade: major version bump — needs care"
	RiskUnknown      string // "⚪ upgrade: risk unknown"

	// --- end-of-life wording (format.go consts; used across format.go/triage.go/eol.go/thread.go) ---
	EOLPackageText   string // "end-of-life: no fix planned for this release"
	EOLSectionReason string // "vendor reports these CVEs as out of support for this release"
	EOLEvidenceMark  string // " — end-of-life: no fix planned for this release, consider a supported version"
	EOLSeeActNow     string // " — 🚨 see Act now"

	// --- triage headline / intel warnings (triage.go: writeTriageHeadline, writeIntelWarning, writeIntelStale) ---
	SegActNow            string // "🚨 %d act now" (writeTriageHeadline only; writeTriageOpenNow uses OpenNowActNow instead)
	IntelDegradedWarning string // "⚠️ Vulnerability intel (KEV/EPSS) unavailable — severity-only triage, nothing demoted to low\n"
	IntelKEVUnavailable  string // "⚠️ CISA KEV data unavailable — act-now detection may be incomplete\n"
	IntelEPSSUnavailable string // "⚠️ EPSS data unavailable — triage is using KEV and severity only\n"
	IntelStale           string // "\n_Intel data is %d day(s) old (feeds unreachable)._\n"

	// --- act now / watch / low buckets (triage.go: writeActNow, writeWatch, writeLow) ---
	ActNowHeading       string // "\n*🚨 Act now (%d) — exploited or likely to be*\n"
	ImageBullet         string // "• %s\n" (image label) — shared by writeActNow and writeWatch
	WatchHeading        string // "\n*👀 Watch (%d) — not urgent, keep an eye on*\n"
	LowHeading          string // "\n*🔕 Low priority (%[1]d)* — %[2]d finding(s) across %[3]d image(s), no exploitation signal (not in KEV, EPSS below threshold)."
	TriageLowInUseCount string // " · ▶ %d in use"

	// --- evidence lines (triage.go: writeEvidence, writeRefs, evidenceLine, shortEvidence) ---
	EvidenceMoreCVEs   string // " (+%d more CVE(s) in this package)"
	NoFixYetMitigation string // " — no fix yet, consider mitigation" — shared by triage.go writeEvidence and thread.go writeThreadDetail
	WontFixReplace     string // " — upstream won't fix, consider replacing" — shared by triage.go writeEvidence and thread.go writeThreadDetail
	AdvisoryLinkLabel  string // "advisory" (Slack link label text)
	AdvisoryLink       string // "<%[1]s|%[2]s>" (url, label)
	// VendorAdvisoryLinkLabel replaces analyze.Ref.Label as the Slack link
	// text for a "vendor" reference (the KEV note's advisory link) — display
	// only: analyze.Ref.Label itself and the webhook payload's ref label
	// always stay the English "vendor advisory" (analyze/triage.go,
	// format.go's refPayload). A "discussion" reference (the HN link) is
	// unaffected and keeps using ref.Label as-is.
	VendorAdvisoryLinkLabel string // "vendor advisory"
	RefsLine                string // "       📎 %s\n" (joined reference links)
	EvidenceSeverityOnly    string // "severity only (intel unavailable)"
	EvidenceKEV             string // "CISA KEV (exploited in the wild)"
	EvidenceEPSSPrefix      string // "EPSS %s" (epssString result)
	EvidenceRansomware      string // "🧨 ransomware campaign"
	ShortEvidenceKEV        string // " · CISA KEV"
	ShortEvidenceEPSSPrefix string // " · EPSS %s" (epssString result)

	// --- diff-mode triage (triage.go: writeTriageOpenNow) ---
	OpenNowActNow          string // "🚨 %d act-now"
	OldestActNowWatchStale string // " — ⏰ oldest act-now/watch unresolved %d day(s)"
	OldestActNowWatch      string // " — oldest act-now/watch unresolved %d day(s)"
	PriorityLabelActNow    string // "ACT NOW"
	PriorityLabelWatch     string // "WATCH"
	PriorityLabelLow       string // "LOW"

	// --- end-of-life sections (eol.go) ---
	FoldedEOLNote             string // " · includes %d end-of-life package(s)"
	EOSLLine                  string // "• %[1]s — base OS is EOL (no more security updates coming)%[2]s\n" (ref, FoldedEOLNote) — shared by format.go's diff loop and eol.go's eosLine
	EOSLHeading               string // "\n*⛔ Base OS end-of-life (top priority)*\n"
	EOLPackageHeading         string // "\n*⛔ Package end-of-life (%[1]d) — %[2]s*\n" (count, EOLSectionReason)
	EOLPackagesChangedHeading string // "\n*⛔ New: package end-of-life (%[1]d) — %[2]s*\n" (count, EOLSectionReason)
	EOLFoldNewPackages        string // "%d package(s) newly end-of-life"
	EOLFoldWithNewCVEs        string // "%d end-of-life package(s) with new CVEs"
	EOLFoldLine               string // "• %[1]s — %[2]s (base OS already EOL)\n" (ref, joined change descriptions)

	// --- thread report (thread.go) ---
	ThreadTitle              string // "📊 *Everything open now — %s*" (generated-at)
	EOLBaseImagesHeading     string // "*⛔ EOL base images (%d)*"
	MutedLine                string // "🔇 Muted — no fix available and not in use for 7+ days: %d\n" — shared by runtime.go's writeMutedCount and thread.go
	ThreadActNowHeading      string // "*🚨 ACT NOW (%d) — exploited or likely to be*"
	ThreadWatchHeading       string // "*👀 WATCH (%d) — not urgent, keep an eye on*"
	ThreadLowHeading         string // "\n*🔕 LOW (%d)* — no exploitation signal"
	ThreadLowDetailsSuffix   string // "; details in the generic webhook payload"
	ThreadLowInUseCount      string // "▶ in use among low: %d\n"
	EOLPackagesThreadHeading string // "*⛔ EOL packages (%[1]d) — %[2]s*" (count, EOLSectionReason)
	ThreadImageAgeLine       string // "     ⏱ open %[1]d day(s) — first seen %[2]s\n" (days, formatted date)
	ThreadFirstSeenToday     string // "     ⏱ first seen today\n"
	ThreadAlsoIDs            string // "     also: %s" (comma-joined CVE ids)
	ThreadContinued          string // " _(cont.)_" (appended to a section title repeated on a later message)

	// --- runtime warnings (runtime.go: writeRuntimeWarning) ---
	RuntimeWarningUnavailable       string // "⚠️ Runtime evidence unavailable: %s\n" (status text)
	RuntimeWarningEventsUnavailable string // "⚠️ Short-lived programs are not observed (eBPF unavailable: %s); using sampling only\n" (events reason text)

	// --- Sensor status text (runtime.go: runtimeStatusText) ---
	StatusTextNotReporting      string // "the Sensor has not reported yet"
	StatusTextEvidenceInvalid   string // "the evidence file failed validation"
	StatusTextStale             string // "the Sensor's last report is stale"
	StatusTextPermissionDenied  string // "the Sensor's reads are being denied"
	StatusTextIsolationFailed   string // "the Sensor's sandbox failed to start"
	StatusTextIsolationDegraded string // "the Sensor's sandbox is running degraded"
	StatusTextDegraded          string // "the Sensor is degraded"
	StatusTextOK                string // "ok"
	StatusTextUnknown           string // "unknown" (runtimeStatusText's own default branch)

	// --- unavailable-package reason text (runtime.go: reasonText) ---
	ReasonSensorNotReporting   string // "sensor not reporting"
	ReasonSensorStale          string // "sensor report is stale"
	ReasonEvidenceInvalid      string // "evidence invalid"
	ReasonIsolationFailed      string // "sensor isolation failed"
	ReasonPermissionDenied     string // "permission denied"
	ReasonInitializing         string // "index not built yet"
	ReasonStalled              string // "worker stalled"
	ReasonParseFailed          string // "package database parse failed"
	ReasonTruncated            string // "evidence truncated"
	ReasonIncomplete           string // "evidence incomplete"
	ReasonGenerationUnverified string // "container generation unverified"
	ReasonContainerNotObserved string // "container not observed"
	ReasonDBAbsent             string // "package database absent"
	ReasonDBError              string // "package database error"
	ReasonDBUnsupported        string // "package database unsupported"
	ReasonNoFileList           string // "no file list for this package"
	ReasonAttributionAmbiguous string // "multiple owners"
	ReasonFileReplaced         string // "file replaced"
	ReasonVersionMismatch      string // "version mismatch"
	ReasonEcosystemUnmapped    string // "ecosystem not mapped"
	ReasonBinaryPathUnknown    string // "binary path unknown"
	ReasonUnknown              string // "unknown" (reasonText's own default branch)

	// --- eBPF events-unavailable reason text (runtime.go: eventsReasonText) ---
	EventsReasonKernelUnsupported string // "kernel unsupported"
	EventsReasonBTFMissing        string // "BTF missing"
	EventsReasonPermission        string // "permission denied"
	EventsReasonAttachFailed      string // "attach failed"
	EventsReasonCgroupV1          string // "cgroup v1"
	EventsReasonUnknown           string // "unknown" (eventsReasonText's own default branch)

	// --- in-use evidence phrasing (runtime.go: runtimeKindLabel, runtimeKindPhraseUnattributed, runtimeKindsPhrase, runtimeInUsePhrase) ---
	KindRunningAs        string // "running as" (+ escaped executable path)
	KindLoadedBy         string // "loaded by" (+ escaped executable path)
	KindExecutedEvt      string // "executed" (+ escaped executable path)
	KindLibraryLoadEvent string // "library loaded" (+ escaped executable path)
	KindBinaryRunning    string // "in running binary" (+ escaped executable path)
	KindBinaryExecuted   string // "binary executed" (+ escaped executable path)
	KindRuntimeRunning   string // "runtime is running" (+ escaped executable path)
	KindRuntimeExecuted  string // "runtime executed" (+ escaped executable path)
	RuntimeInUseFallback string // "in use" — the shared, normally-unreachable fallback word for an unrecognized evidence kind, an evidence-kind-less in-use container, and the unattributed phrase's own fallback
	InUsePrefix          string // "▶ in use (%s)" (evidence kind phrase) — the act-now/thread full line
	InUseFallbackArrow   string // "▶ in use" — representativeContainer's own not-reached fallback
	HighPrivilegeNote    string // "runs with elevated privilege"
	LastConfirmedPrefix  string // "last confirmed %s" (formatted timestamp)

	// --- unattributed evidence phrasing (runtime.go: runtimeKindPhraseUnattributed) ---
	UnattrRunning             string // "running"
	UnattrLoadedAsLibrary     string // "loaded as a library"
	UnattrExecuted            string // "executed"
	UnattrLibraryLoadObserved string // "library load observed"
	ProcessesPrefix           string // "processes: %s" (comma-joined executable names)

	// --- compact watch-bucket wording (runtime.go: runtimeShortWord, runtimeWatchSuffix) ---
	ShortWordRunning  string // "running"
	ShortWordLoaded   string // "loaded"
	ShortWordExecuted string // "executed" (runtimeShortWord's own default branch)
	WatchInUseSuffix  string // " · ▶ in use (%s)" (ShortWord* value)

	// --- exposure phrasing (runtime.go: runtimeExposureText) ---
	ExposurePublishedAll      string // "published on all interfaces"
	ExposurePublishedLoopback string // "published on loopback only"
	ExposureListening         string // "listening (not published)"

	// --- muting (runtime.go: writeMutedCount, unmutedReason, writeRuntimeSummary) ---
	UnmutedNowInUse                string // "now in use"
	UnmutedActNow                  string // "act now"
	UnmutedFixAvailable            string // "fix available"
	UnmutedNowEndOfLife            string // "now end-of-life"
	UnmutedInsufficientObservation string // "insufficient observation"
	UnmutedNotEligible             string // "not an eligible status"
	RuntimeSummaryCounts           string // "\n🔎 Runtime: ▶ %[1]d in use · %[2]d not observed · %[3]d unavailable\n"
	RuntimeSummaryNote             string // "_In use: an OS package is executed or loaded by a running program; a language package is in a running binary or its runtime (python, node, java, …) is running. Not observed covers the observation window only and does not mean unused._\n"

	// --- thread per-package runtime line (runtime.go: writeRuntimeThreadLine) ---
	ThreadNotObserved           string // "▷ not observed"
	ThreadNotObservedShortLived string // " — short-lived programs not fully observed" (appended to ThreadNotObserved)
	ThreadRuntimeUnavailable    string // "▷ runtime evidence unavailable (%s)" (reason text)

	// --- Slack Web API delivery (slackapi.go: SlackAPINotifier.Send) ---
	// These two lines are appended to the channel summary text after
	// FormatSlackText/FormatSlackDiffText have already rendered it, so they
	// live outside those functions' own message tree — this is the only
	// other place notify appends user-facing text to a Slack message body.
	ThreadPostedNotice string // "\n_📊 Everything open now is in this message's thread ↓_\n"
	LastReportLink     string // "\n🔗 Everything open as of the last report → <%s|thread>\n" (permalink URL; the link label "thread" is part of this string)
}

// enMessages is the historical English wording, unchanged byte-for-byte from
// what this package printed before the language dictionary existed. Every
// golden test in testdata/golden pins this text; do not edit a value here
// without regenerating every affected golden file and checking each one by
// eye.
var enMessages = messages{
	HeaderNamed:                "🛡️ *KestreLynx* [%[1]s] — scan results for %[2]s\n",
	HeaderDefault:              "🛡️ *KestreLynx* — scan results for %s\n",
	RoleEverythingOpen:         "Everything currently open.",
	RoleChangesSinceLastScan:   "Changes since the last scan.",
	ImagesScannedAffected:      "%[1]d images scanned, %[2]d affected\n",
	AllClear:                   "\n✅ All clear (no HIGH/CRITICAL vulnerabilities found)\n",
	LowerRiskSummarizedWebhook: "\n_%d lower-risk fix(es) summarized — full list in the generic webhook payload._\n",
	LowerRiskSummarized:        "\n_%d lower-risk fix(es) summarized._\n",

	NoChangesSinceLastScan:  "\nNo changes since last scan.\n",
	HeadingNewEOSL:          "\n*⛔ New: base OS end-of-life (top priority)*\n",
	NewEOSLNote:             " · includes %d newly end-of-life package(s)",
	WeeklyFullReportHeading: "\n*📋 Weekly full report — everything currently open*\n",

	ReplacedHeading: "\n*🔄 Image content changed (%d)*\n",
	ReplacedLine:    "• %[1]s: image updated (%[2]s → %[3]s)\n",

	IdentityUnconfirmed: "identity unconfirmed: scanned by reference",
	UnresolvedRefsLine:  "⚠️ %[1]s — %[2]s\n",
	UnconfirmedRefsLine: "⏳ unconfirmed this cycle, holding previous findings — %s\n",

	NewSinceLastScanHeading: "\n*🆕 New since last scan (%d)*\n",
	NewCVEsPrefix:           "new: %s",
	MoreCount:               " (+%d more)",
	EscalatedTo:             "⬆️ escalated to %s",
	FixNowAvailable:         "fix now available",
	Unmuted:                 "↩️ Unmuted (%s)",

	ResolvedHeading:       "\n*✅ Resolved since last scan (%d)*\n",
	BaseOSNoLongerEOL:     "• %s — base OS no longer EOL\n",
	ResolvedImagePackages: "• %[1]s: %[2]s\n",
	NoLongerEndOfLife:     "• %[1]s: %[2]s — no longer end-of-life\n",

	OpenNowUnconfirmedHolding: "\n📌 Open now: unconfirmed — holding previous findings until re-confirmed\n",
	OpenNowNotRescanned:       "\n📌 Open now: not re-scanned — holding previous findings until the next successful scan\n",
	OpenNowAllClear:           "\n🎉 Open now: none — all clear\n",
	OpenNowCriticalHigh:       "CRITICAL %[1]d / HIGH %[2]d across %[3]d image(s)",
	OpenNowPrefix:             "\n📌 Open now: %s",
	OldestUnresolvedStale:     " — ⏰ oldest unresolved %d day(s)",
	OldestUnresolved:          " — oldest unresolved %d day(s)",
	DetailsInWebhook:          "_Details in the generic webhook payload._\n",

	SegEOLBase:    "⛔ %d EOL base",
	SegEOLPackage: "⛔ %d EOL package",
	SegCritical:   "🔴 %d CRITICAL",
	SegNeedCare:   "🟠 %d need care",
	SegSafe:       "🟢 %d safe",
	SegWatch:      "👀 %d watch",
	SegLow:        "🔕 %d low",
	PriorityLine:  "*Priority:* %s\n",

	ScanFailuresHeading: "\n*⚠️ Scan failures*\n",
	ScanFailureLine:     "• %[1]s — %[2]s\n",

	ActionableTitle:       "✅ Actionable now (fixed)",
	WatchSectionTitle:     "ℹ️ No fix yet (affected / waiting on upstream)",
	WontFixSectionTitle:   "🔕 Upstream won't fix (will_not_fix)",
	SectionHeading:        "\n*%s*\n",
	ImageCritHighLine:     "%[1]s %[2]s  CRITICAL %[3]d / HIGH %[4]d\n",
	PackageFixedLine:      "%[1]s %[2]s → %[3]s",
	PackageEOLLine:        "%[1]s %[2]s (%[3]s)",
	PackageNoFixLine:      "%[1]s %[2]s (no fix available)",
	PackageSeverityCounts: " (CRITICAL %[1]d / HIGH %[2]d)",
	CollapsedLine:         "   • +%[1]d lower-risk fixes (%[2]s): %[3]s",

	RiskDistroUpdate: "🟢 upgrade: distro security patch",
	RiskSafe:         "🟢 upgrade: low-risk",
	RiskCaution:      "🟠 upgrade: major version bump — needs care",
	RiskUnknown:      "⚪ upgrade: risk unknown",

	EOLPackageText:   "end-of-life: no fix planned for this release",
	EOLSectionReason: "vendor reports these CVEs as out of support for this release",
	EOLEvidenceMark:  " — end-of-life: no fix planned for this release, consider a supported version",
	EOLSeeActNow:     " — 🚨 see Act now",

	SegActNow:            "🚨 %d act now",
	IntelDegradedWarning: "⚠️ Vulnerability intel (KEV/EPSS) unavailable — severity-only triage, nothing demoted to low\n",
	IntelKEVUnavailable:  "⚠️ CISA KEV data unavailable — act-now detection may be incomplete\n",
	IntelEPSSUnavailable: "⚠️ EPSS data unavailable — triage is using KEV and severity only\n",
	IntelStale:           "\n_Intel data is %d day(s) old (feeds unreachable)._\n",

	ActNowHeading:       "\n*🚨 Act now (%d) — exploited or likely to be*\n",
	ImageBullet:         "• %s\n",
	WatchHeading:        "\n*👀 Watch (%d) — not urgent, keep an eye on*\n",
	LowHeading:          "\n*🔕 Low priority (%[1]d)* — %[2]d finding(s) across %[3]d image(s), no exploitation signal (not in KEV, EPSS below threshold).",
	TriageLowInUseCount: " · ▶ %d in use",

	EvidenceMoreCVEs:        " (+%d more CVE(s) in this package)",
	NoFixYetMitigation:      " — no fix yet, consider mitigation",
	WontFixReplace:          " — upstream won't fix, consider replacing",
	AdvisoryLinkLabel:       "advisory",
	AdvisoryLink:            "<%[1]s|%[2]s>",
	VendorAdvisoryLinkLabel: "vendor advisory",
	RefsLine:                "       📎 %s\n",
	EvidenceSeverityOnly:    "severity only (intel unavailable)",
	EvidenceKEV:             "CISA KEV (exploited in the wild)",
	EvidenceEPSSPrefix:      "EPSS %s",
	EvidenceRansomware:      "🧨 ransomware campaign",
	ShortEvidenceKEV:        " · CISA KEV",
	ShortEvidenceEPSSPrefix: " · EPSS %s",

	OpenNowActNow:          "🚨 %d act-now",
	OldestActNowWatchStale: " — ⏰ oldest act-now/watch unresolved %d day(s)",
	OldestActNowWatch:      " — oldest act-now/watch unresolved %d day(s)",
	PriorityLabelActNow:    "ACT NOW",
	PriorityLabelWatch:     "WATCH",
	PriorityLabelLow:       "LOW",

	FoldedEOLNote:             " · includes %d end-of-life package(s)",
	EOSLLine:                  "• %[1]s — base OS is EOL (no more security updates coming)%[2]s\n",
	EOSLHeading:               "\n*⛔ Base OS end-of-life (top priority)*\n",
	EOLPackageHeading:         "\n*⛔ Package end-of-life (%[1]d) — %[2]s*\n",
	EOLPackagesChangedHeading: "\n*⛔ New: package end-of-life (%[1]d) — %[2]s*\n",
	EOLFoldNewPackages:        "%d package(s) newly end-of-life",
	EOLFoldWithNewCVEs:        "%d end-of-life package(s) with new CVEs",
	EOLFoldLine:               "• %[1]s — %[2]s (base OS already EOL)\n",

	ThreadTitle:              "📊 *Everything open now — %s*",
	EOLBaseImagesHeading:     "*⛔ EOL base images (%d)*",
	MutedLine:                "🔇 Muted — no fix available and not in use for 7+ days: %d\n",
	ThreadActNowHeading:      "*🚨 ACT NOW (%d) — exploited or likely to be*",
	ThreadWatchHeading:       "*👀 WATCH (%d) — not urgent, keep an eye on*",
	ThreadLowHeading:         "\n*🔕 LOW (%d)* — no exploitation signal",
	ThreadLowDetailsSuffix:   "; details in the generic webhook payload",
	ThreadLowInUseCount:      "▶ in use among low: %d\n",
	EOLPackagesThreadHeading: "*⛔ EOL packages (%[1]d) — %[2]s*",
	ThreadImageAgeLine:       "     ⏱ open %[1]d day(s) — first seen %[2]s\n",
	ThreadFirstSeenToday:     "     ⏱ first seen today\n",
	ThreadAlsoIDs:            "     also: %s",
	ThreadContinued:          " _(cont.)_",

	RuntimeWarningUnavailable:       "⚠️ Runtime evidence unavailable: %s\n",
	RuntimeWarningEventsUnavailable: "⚠️ Short-lived programs are not observed (eBPF unavailable: %s); using sampling only\n",

	StatusTextNotReporting:      "the Sensor has not reported yet",
	StatusTextEvidenceInvalid:   "the evidence file failed validation",
	StatusTextStale:             "the Sensor's last report is stale",
	StatusTextPermissionDenied:  "the Sensor's reads are being denied",
	StatusTextIsolationFailed:   "the Sensor's sandbox failed to start",
	StatusTextIsolationDegraded: "the Sensor's sandbox is running degraded",
	StatusTextDegraded:          "the Sensor is degraded",
	StatusTextOK:                "ok",
	StatusTextUnknown:           "unknown",

	ReasonSensorNotReporting:   "sensor not reporting",
	ReasonSensorStale:          "sensor report is stale",
	ReasonEvidenceInvalid:      "evidence invalid",
	ReasonIsolationFailed:      "sensor isolation failed",
	ReasonPermissionDenied:     "permission denied",
	ReasonInitializing:         "index not built yet",
	ReasonStalled:              "worker stalled",
	ReasonParseFailed:          "package database parse failed",
	ReasonTruncated:            "evidence truncated",
	ReasonIncomplete:           "evidence incomplete",
	ReasonGenerationUnverified: "container generation unverified",
	ReasonContainerNotObserved: "container not observed",
	ReasonDBAbsent:             "package database absent",
	ReasonDBError:              "package database error",
	ReasonDBUnsupported:        "package database unsupported",
	ReasonNoFileList:           "no file list for this package",
	ReasonAttributionAmbiguous: "multiple owners",
	ReasonFileReplaced:         "file replaced",
	ReasonVersionMismatch:      "version mismatch",
	ReasonEcosystemUnmapped:    "ecosystem not mapped",
	ReasonBinaryPathUnknown:    "binary path unknown",
	ReasonUnknown:              "unknown",

	EventsReasonKernelUnsupported: "kernel unsupported",
	EventsReasonBTFMissing:        "BTF missing",
	EventsReasonPermission:        "permission denied",
	EventsReasonAttachFailed:      "attach failed",
	EventsReasonCgroupV1:          "cgroup v1",
	EventsReasonUnknown:           "unknown",

	KindRunningAs:        "running as",
	KindLoadedBy:         "loaded by",
	KindExecutedEvt:      "executed",
	KindLibraryLoadEvent: "library loaded",
	KindBinaryRunning:    "in running binary",
	KindBinaryExecuted:   "binary executed",
	KindRuntimeRunning:   "runtime is running",
	KindRuntimeExecuted:  "runtime executed",
	RuntimeInUseFallback: "in use",
	InUsePrefix:          "▶ in use (%s)",
	InUseFallbackArrow:   "▶ in use",
	HighPrivilegeNote:    "runs with elevated privilege",
	LastConfirmedPrefix:  "last confirmed %s",

	UnattrRunning:             "running",
	UnattrLoadedAsLibrary:     "loaded as a library",
	UnattrExecuted:            "executed",
	UnattrLibraryLoadObserved: "library load observed",
	ProcessesPrefix:           "processes: %s",

	ShortWordRunning:  "running",
	ShortWordLoaded:   "loaded",
	ShortWordExecuted: "executed",
	WatchInUseSuffix:  " · ▶ in use (%s)",

	ExposurePublishedAll:      "published on all interfaces",
	ExposurePublishedLoopback: "published on loopback only",
	ExposureListening:         "listening (not published)",

	UnmutedNowInUse:                "now in use",
	UnmutedActNow:                  "act now",
	UnmutedFixAvailable:            "fix available",
	UnmutedNowEndOfLife:            "now end-of-life",
	UnmutedInsufficientObservation: "insufficient observation",
	UnmutedNotEligible:             "not an eligible status",
	RuntimeSummaryCounts:           "\n🔎 Runtime: ▶ %[1]d in use · %[2]d not observed · %[3]d unavailable\n",
	RuntimeSummaryNote:             "_In use: an OS package is executed or loaded by a running program; a language package is in a running binary or its runtime (python, node, java, …) is running. Not observed covers the observation window only and does not mean unused._\n",

	ThreadNotObserved:           "▷ not observed",
	ThreadNotObservedShortLived: " — short-lived programs not fully observed",
	ThreadRuntimeUnavailable:    "▷ runtime evidence unavailable (%s)",

	ThreadPostedNotice: "\n_📊 Everything open now is in this message's thread ↓_\n",
	LastReportLink:     "\n🔗 Everything open as of the last report → <%s|thread>\n",
}

// jaMessages is the Japanese dictionary.
var jaMessages = messages{
	HeaderNamed:                "🛡️ *KestreLynx* [%[1]s] — %[2]sのスキャン結果\n",
	HeaderDefault:              "🛡️ *KestreLynx* — %sのスキャン結果\n",
	RoleEverythingOpen:         "未解決の所見の全体",
	RoleChangesSinceLastScan:   "前回のスキャンからの変化",
	ImagesScannedAffected:      "イメージ%[1]d件をスキャン、%[2]d件に影響あり\n",
	AllClear:                   "\n✅ 問題なし (HIGH/CRITICALの脆弱性なし)\n",
	LowerRiskSummarizedWebhook: "\n_低リスクの修正%d件を集約 — 全件は汎用Webhookのペイロードに記載_\n",
	LowerRiskSummarized:        "\n_低リスクの修正%d件を集約_\n",

	NoChangesSinceLastScan:  "\n前回のスキャンから変化なし\n",
	HeadingNewEOSL:          "\n*⛔ 新規: ベースOSのサポート終了(EOL) (最優先)*\n",
	NewEOSLNote:             " · 新たにサポート終了(EOL)となったパッケージ%d件を含む",
	WeeklyFullReportHeading: "\n*📋 週次全体レポート — 未解決の所見の全体*\n",

	ReplacedHeading: "\n*🔄 イメージの内容が変化 (%d件)*\n",
	ReplacedLine:    "• %[1]s: イメージ更新 (%[2]s → %[3]s)\n",

	IdentityUnconfirmed: "実体未確認: 参照によるスキャン",
	UnresolvedRefsLine:  "⚠️ %[1]s — %[2]s\n",
	UnconfirmedRefsLine: "⏳ 今回は未確認、前回の所見を保持 — %s\n",

	NewSinceLastScanHeading: "\n*🆕 前回のスキャンからの新規検出 (%d件)*\n",
	NewCVEsPrefix:           "新規: %s",
	MoreCount:               " (ほか +%d件)",
	EscalatedTo:             "⬆️ %sに優先度昇格",
	FixNowAvailable:         "修正版が利用可能",
	Unmuted:                 "↩️ 通知を再開 (%s)",

	ResolvedHeading:       "\n*✅ 前回のスキャンからの解消 (%d件)*\n",
	BaseOSNoLongerEOL:     "• %s — ベースOSのEOLが解消\n",
	ResolvedImagePackages: "• %[1]s: %[2]s\n",
	NoLongerEndOfLife:     "• %[1]s: %[2]s — サポート終了(EOL)が解消\n",

	OpenNowUnconfirmedHolding: "\n📌 現在の未解決: 未確認 — 再確認まで前回の所見を保持\n",
	OpenNowNotRescanned:       "\n📌 現在の未解決: 未再スキャン — 次のスキャン成功まで前回の所見を保持\n",
	OpenNowAllClear:           "\n🎉 現在の未解決: なし — 問題なし\n",
	OpenNowCriticalHigh:       "CRITICAL %[1]d件 / HIGH %[2]d件、イメージ%[3]d件",
	OpenNowPrefix:             "\n📌 現在の未解決: %s",
	OldestUnresolvedStale:     " — ⏰ 未解決の最長期間%d日",
	OldestUnresolved:          " — 未解決の最長期間%d日",
	DetailsInWebhook:          "_詳細は汎用Webhookのペイロードに記載_\n",

	SegEOLBase:    "⛔ EOLのベースOS%d件",
	SegEOLPackage: "⛔ EOLのパッケージ%d件",
	SegCritical:   "🔴 CRITICAL %d件",
	SegNeedCare:   "🟠 要注意%d件",
	SegSafe:       "🟢 安全%d件",
	SegWatch:      "👀 要監視%d件",
	SegLow:        "🔕 低優先度%d件",
	PriorityLine:  "*優先度:* %s\n",

	ScanFailuresHeading: "\n*⚠️ スキャン失敗*\n",
	ScanFailureLine:     "• %[1]s — %[2]s\n",

	ActionableTitle:       "✅ 今すぐ対応可能 (fixed)",
	WatchSectionTitle:     "ℹ️ 修正版なし (affected / 上流の対応待ち)",
	WontFixSectionTitle:   "🔕 上流では修正予定なし (will_not_fix)",
	SectionHeading:        "\n*%s*\n",
	ImageCritHighLine:     "%[1]s %[2]s  CRITICAL %[3]d / HIGH %[4]d\n",
	PackageFixedLine:      "%[1]s %[2]s → %[3]s",
	PackageEOLLine:        "%[1]s %[2]s (%[3]s)",
	PackageNoFixLine:      "%[1]s %[2]s (修正版なし)",
	PackageSeverityCounts: " (CRITICAL %[1]d / HIGH %[2]d)",
	CollapsedLine:         "   • 低リスクの修正 +%[1]d件 (%[2]s): %[3]s",

	RiskDistroUpdate: "🟢 アップグレード: ディストリのセキュリティパッチ",
	RiskSafe:         "🟢 アップグレード: 低リスク",
	RiskCaution:      "🟠 アップグレード: メジャーバージョン更新 — 要注意",
	RiskUnknown:      "⚪ アップグレード: リスク不明",

	EOLPackageText:   "サポート終了(EOL): このリリースでは修正予定なし",
	EOLSectionReason: "ベンダーがこれらのCVEをこのリリースのサポート対象外と報告",
	EOLEvidenceMark:  " — サポート終了(EOL): このリリースでは修正予定なし、サポート中のバージョンを検討",
	EOLSeeActNow:     " — 🚨 今すぐ対応を参照",

	SegActNow:            "🚨 今すぐ対応%d件",
	IntelDegradedWarning: "⚠️ 脅威情報 (KEV/EPSS) が利用できない — 深刻度のみで優先度を判定、低優先度への引き下げなし\n",
	IntelKEVUnavailable:  "⚠️ CISA KEVデータが利用できない — 今すぐ対応の検出に漏れの可能性あり\n",
	IntelEPSSUnavailable: "⚠️ EPSSデータが利用できない — KEVと深刻度のみで優先度を判定\n",
	IntelStale:           "\n_脅威情報は%d日前のもの (配信元に接続できない)_\n",

	ActNowHeading:       "\n*🚨 今すぐ対応 (%d件) — 悪用あり、または悪用の可能性が高い*\n",
	ImageBullet:         "• %s\n",
	WatchHeading:        "\n*👀 要監視 (%d件) — 緊急性は低いが継続監視*\n",
	LowHeading:          "\n*🔕 低優先度 (%[1]d件)* — イメージ%[3]d件で所見%[2]d件、悪用の兆候なし (KEV未掲載、EPSSはしきい値未満)",
	TriageLowInUseCount: " · ▶ 使用中%d件",

	EvidenceMoreCVEs:        " (このパッケージにほか +%d件のCVE)",
	NoFixYetMitigation:      " — 修正版なし、緩和策を検討",
	WontFixReplace:          " — 上流では修正予定なし、置き換えを検討",
	AdvisoryLinkLabel:       "アドバイザリ",
	AdvisoryLink:            "<%[1]s|%[2]s>",
	RefsLine:                "       📎 %s\n",
	EvidenceSeverityOnly:    "深刻度のみ (脅威情報が利用できない)",
	EvidenceKEV:             "CISA KEV (実際の攻撃で悪用あり)",
	EvidenceEPSSPrefix:      "EPSS %s",
	EvidenceRansomware:      "🧨 ランサムウェア攻撃",
	ShortEvidenceKEV:        " · CISA KEV",
	ShortEvidenceEPSSPrefix: " · EPSS %s",

	OpenNowActNow:          "🚨 今すぐ対応%d件",
	OldestActNowWatchStale: " — ⏰ 今すぐ対応/要監視の未解決の最長期間%d日",
	OldestActNowWatch:      " — 今すぐ対応/要監視の未解決の最長期間%d日",
	PriorityLabelActNow:    "今すぐ対応",
	PriorityLabelWatch:     "要監視",
	PriorityLabelLow:       "低優先度",

	FoldedEOLNote:             " · サポート終了(EOL)のパッケージ%d件を含む",
	EOSLLine:                  "• %[1]s — ベースOSがEOL (今後のセキュリティ更新なし)%[2]s\n",
	EOSLHeading:               "\n*⛔ ベースOSのサポート終了(EOL) (最優先)*\n",
	EOLPackageHeading:         "\n*⛔ パッケージのサポート終了(EOL) (%[1]d件) — %[2]s*\n",
	EOLPackagesChangedHeading: "\n*⛔ 新規: パッケージのサポート終了(EOL) (%[1]d件) — %[2]s*\n",
	EOLFoldNewPackages:        "パッケージ%d件が新たにサポート終了(EOL)",
	EOLFoldWithNewCVEs:        "新規CVEのあるサポート終了(EOL)のパッケージ%d件",
	EOLFoldLine:               "• %[1]s — %[2]s (ベースOSは既にEOL)\n",

	ThreadTitle:              "📊 *未解決の所見の全体 — %s*",
	EOLBaseImagesHeading:     "*⛔ EOLのベースOSのイメージ (%d件)*",
	MutedLine:                "🔇 通知オフ — 修正版がなく7日以上使用が確認されない: %d件\n",
	ThreadActNowHeading:      "*🚨 今すぐ対応 (%d件) — 悪用あり、または悪用の可能性が高い*",
	ThreadWatchHeading:       "*👀 要監視 (%d件) — 緊急性は低いが継続監視*",
	ThreadLowHeading:         "\n*🔕 低優先度 (%d件)* — 悪用の兆候なし",
	ThreadLowDetailsSuffix:   "; 詳細は汎用Webhookのペイロードに記載",
	ThreadLowInUseCount:      "▶ 低優先度のうち使用中: %d件\n",
	EOLPackagesThreadHeading: "*⛔ EOLのパッケージ (%[1]d件) — %[2]s*",
	ThreadImageAgeLine:       "     ⏱ 未解決%[1]d日 — 初回検出%[2]s\n",
	ThreadFirstSeenToday:     "     ⏱ 本日初検出\n",
	ThreadAlsoIDs:            "     ほか: %s",
	ThreadContinued:          " _(続き)_",

	RuntimeWarningUnavailable:       "⚠️ 稼働時の証拠が利用できない: %s\n",
	RuntimeWarningEventsUnavailable: "⚠️ 短命なプログラムは観測できない (eBPFが利用できない: %s); サンプリングのみ使用\n",

	StatusTextNotReporting:      "Sensorからの報告がまだない",
	StatusTextEvidenceInvalid:   "証拠ファイルの検証失敗",
	StatusTextStale:             "Sensorの最終報告が古い",
	StatusTextPermissionDenied:  "Sensorの読み取りが拒否されている",
	StatusTextIsolationFailed:   "Sensorのサンドボックス起動失敗",
	StatusTextIsolationDegraded: "Sensorのサンドボックスが一部制限の効かない状態で稼働中",
	StatusTextDegraded:          "Sensorの一部機能が利用できない",
	StatusTextOK:                "正常",
	StatusTextUnknown:           "不明",

	ReasonSensorNotReporting:   "Sensorの報告なし",
	ReasonSensorStale:          "Sensorの報告が古い",
	ReasonEvidenceInvalid:      "証拠が無効",
	ReasonIsolationFailed:      "Sensorの隔離失敗",
	ReasonPermissionDenied:     "権限不足",
	ReasonInitializing:         "索引が未構築",
	ReasonStalled:              "ワーカーの処理が停滞",
	ReasonParseFailed:          "パッケージデータベースの解析失敗",
	ReasonTruncated:            "証拠の切り詰め",
	ReasonIncomplete:           "証拠が不完全",
	ReasonGenerationUnverified: "コンテナの世代が未確認",
	ReasonContainerNotObserved: "コンテナが未観測",
	ReasonDBAbsent:             "パッケージデータベースなし",
	ReasonDBError:              "パッケージデータベースのエラー",
	ReasonDBUnsupported:        "パッケージデータベースが未対応",
	ReasonNoFileList:           "このパッケージのファイル一覧なし",
	ReasonAttributionAmbiguous: "所有元が複数",
	ReasonFileReplaced:         "ファイルが置き換えられている",
	ReasonVersionMismatch:      "バージョン不一致",
	ReasonEcosystemUnmapped:    "エコシステムの対応付けなし",
	ReasonBinaryPathUnknown:    "バイナリのパス不明",
	ReasonUnknown:              "不明",

	EventsReasonKernelUnsupported: "カーネルが未対応",
	EventsReasonBTFMissing:        "BTFなし",
	EventsReasonPermission:        "権限不足",
	EventsReasonAttachFailed:      "アタッチ失敗",
	EventsReasonCgroupV1:          "cgroup v1",
	EventsReasonUnknown:           "不明",

	KindRunningAs:        "実行中:",
	KindLoadedBy:         "読み込んだプログラム:",
	KindExecutedEvt:      "実行を観測:",
	KindLibraryLoadEvent: "ライブラリ読み込みを観測:",
	KindBinaryRunning:    "組み込み先の実行中バイナリ:",
	KindBinaryExecuted:   "バイナリの実行を観測:",
	KindRuntimeRunning:   "稼働中の実行環境:",
	KindRuntimeExecuted:  "実行環境の実行を観測:",
	RuntimeInUseFallback: "使用中",
	InUsePrefix:          "▶ 使用中 (%s)",
	InUseFallbackArrow:   "▶ 使用中",
	HighPrivilegeNote:    "高い権限で実行",
	LastConfirmedPrefix:  "最終確認%s",

	UnattrRunning:             "実行中",
	UnattrLoadedAsLibrary:     "ライブラリとして読み込み済み",
	UnattrExecuted:            "実行を観測",
	UnattrLibraryLoadObserved: "ライブラリの読み込みを観測",
	ProcessesPrefix:           "プロセス: %s",

	ShortWordRunning:  "実行中",
	ShortWordLoaded:   "読み込み済み",
	ShortWordExecuted: "実行を観測",
	WatchInUseSuffix:  " · ▶ 使用中 (%s)",

	ExposurePublishedAll:      "全インターフェースに公開",
	ExposurePublishedLoopback: "ループバックのみに公開",
	ExposureListening:         "待ち受け中 (未公開)",

	UnmutedNowInUse:                "使用中になった",
	UnmutedActNow:                  "今すぐ対応",
	UnmutedFixAvailable:            "修正版あり",
	UnmutedNowEndOfLife:            "サポート終了(EOL)となった",
	UnmutedInsufficientObservation: "観測不足",
	UnmutedNotEligible:             "対象外の状態",
	RuntimeSummaryCounts:           "\n🔎 稼働時の使用状況: ▶ 使用中%[1]d件 · 使用が確認されない%[2]d件 · 判定できない%[3]d件\n",
	RuntimeSummaryNote:             "_使用中: OSパッケージは稼働中のプログラムが実行または読み込み。言語パッケージは稼働中のバイナリに含まれるか、その実行環境 (python, node, java, …) が稼働中。使用が確認されないとは観測期間内に限った状態であり、未使用を意味しない。_\n",

	ThreadNotObserved:           "▷ 使用が確認されない",
	ThreadNotObservedShortLived: " — 短命なプログラムは完全には観測できていない",
	ThreadRuntimeUnavailable:    "▷ 稼働時の使用状況を判定できない (%s)",

	VendorAdvisoryLinkLabel: "ベンダーのアドバイザリ",

	ThreadPostedNotice: "\n_📊 未解決の所見の全体はこのメッセージのスレッド ↓_\n",
	LastReportLink:     "\n🔗 前回のレポート時点の未解決の所見の全体 → <%s|スレッド>\n",
}

// messagesFor resolves a Language to its dictionary, defaulting to English
// for the zero value or any value config validation should already have
// rejected.
func messagesFor(lang Language) messages {
	if lang == LanguageJA {
		return jaMessages
	}
	return enMessages
}

// resolveLanguage picks the language a variadic ...Language parameter
// selects: the first element when one was passed, else LanguageEN. It lets
// FormatSlackText, FormatSlackDiffText and BuildThreadMessages take an
// optional trailing language argument without breaking any existing call
// that only ever passed a Report (or Report/diff/etc.) — the overwhelming
// majority of call sites, including every golden test — which all keep
// rendering English exactly as before.
func resolveLanguage(lang []Language) Language {
	if len(lang) > 0 {
		return lang[0]
	}
	return LanguageEN
}
