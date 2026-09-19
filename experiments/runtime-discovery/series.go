package main

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

// Evidence-source names. Each is an independent way of reaching the same
// conclusion, needs different inputs, and can succeed while the others
// fail. Keeping them apart is what makes it possible to say which one a
// confirmation came from, and to stop one source's missing input from
// discarding another source's valid positive.
const (
	sourceSampling    = "sampling"
	sourceGoBinary    = "static_go_binary"
	sourceJarFD       = "open_archive_descriptor"
	sourceNodeFile    = "module_tree_file"
	sourcePythonExt   = "python_extension_module"
	sourceOSPathIndex = "os_package_path_index"
	sourceEventExec   = "event_exec"
	sourceEventOpen   = "event_open"
	sourceEventPrefix = "event_"
)

// The three evaluation series, as identifiers.
//
// The first applies the first stage's rules alone and must reproduce its
// saved results. The second adds the read-only mapping work. The third
// adds event evidence. The increments are reported separately, because
// "the combined total went up" does not say which of the two produced
// it — and the two cost entirely different things to deploy.
const (
	seriesS0 = "S0"
	seriesS1 = "S1"
	seriesS2 = "S2"
)

// Additional shortfall factors introduced by the mapping and the event
// evidence. They exist so that "no rule could reach this package" and "a
// rule could have reached it and nothing used it" stop being the same
// answer.
const (
	factorMappingInputMissing = "mapping_input_missing"
	factorEventNoObservation  = "event_no_observation"
	factorEventPathUnresolved = "event_path_unresolved"
	factorEventUnavailable    = "event_unavailable"
)

// Evidence granularity: what one positive actually covers. A compiled
// binary carries every module built into it, so executing it confirms the
// binary and nothing finer; a file-level positive names one file.
const (
	grainBinary = "binary"
	grainFile   = "file"
)

// Confirmation is one positive: which source produced it, what was
// observed, and what the observation supports being said about it.
type Confirmation struct {
	Source string `json:"source"`
	// Path is what was observed, File the scan-report file it resolved
	// onto, and Via the intermediate step where the rule needed one.
	Path string `json:"path"`
	File string `json:"file,omitempty"`
	Via  string `json:"via,omitempty"`
	// Verb is how the evidence may be described: a file that was executed
	// was run, a file that was opened was read. An archive that was opened
	// is never described as having been run.
	Verb        string            `json:"verb"`
	Grain       string            `json:"grain"`
	SampleID    string            `json:"sample_id,omitempty"`
	Generation  ProcessGeneration `json:"process_generation,omitempty"`
	ObservedAt  time.Time         `json:"observed_at,omitempty"`
	Ecosystem   string            `json:"ecosystem,omitempty"`
	ContainerID string            `json:"container_id,omitempty"`
	// Note carries a qualification the description must keep, such as a
	// nested archive whose outer file was read without any inner one being
	// shown to load.
	Note string `json:"note,omitempty"`
}

// SourceInputState is one evidence source's input availability for one
// window. A source whose inputs are missing contributes nothing; it does
// not invalidate the sources whose inputs are present.
type SourceInputState struct {
	Source string `json:"source"`
	// State is "ok", "missing" or "error".
	State  string `json:"state"`
	Reason string `json:"reason,omitempty"`
	// Positives is how many packages this source confirmed.
	Positives int `json:"positives"`
}

const (
	inputOK      = "ok"
	inputMissing = "missing"
	inputError   = "error"
)

// evidenceSet is every source's confirmations for one window, indexed by
// the package group each confirms.
type evidenceSet struct {
	byKey       map[pkgGroupKey][]Confirmation
	inputStates map[string]*SourceInputState
	order       []string

	// The ways the mapping reached no package, kept apart because they are
	// different findings. Only the first is a shortfall in the
	// observation: a path that resolved perfectly well and names nothing
	// the scan reports is the ordinary case, and counting it as
	// unresolved would report a collection failure where there is none.
	unresolvedEventPaths int
	unmappableEvents     int
	outsideScanEvents    int
	unresolvedPaths      int
	unmappablePaths      int
	outsideScanPaths     int
	candidateConflict    int

	eventState string
	eventNotes []string
}

func newEvidenceSet() *evidenceSet {
	return &evidenceSet{byKey: map[pkgGroupKey][]Confirmation{}, inputStates: map[string]*SourceInputState{}}
}

func (e *evidenceSet) state(source string) *SourceInputState {
	st := e.inputStates[source]
	if st == nil {
		st = &SourceInputState{Source: source, State: inputMissing}
		e.inputStates[source] = st
		e.order = append(e.order, source)
	}
	return st
}

func (e *evidenceSet) setState(source, state, reason string) {
	st := e.state(source)
	st.State, st.Reason = state, reason
}

func (e *evidenceSet) add(key pkgGroupKey, c Confirmation) {
	for _, existing := range e.byKey[key] {
		if existing.Source == c.Source && existing.Path == c.Path && existing.File == c.File {
			return
		}
	}
	e.byKey[key] = append(e.byKey[key], c)
}

// sourcesFor lists the distinct sources that confirmed one package group,
// in a stable order.
func (e *evidenceSet) sourcesFor(key pkgGroupKey, allowed func(string) bool) []string {
	seen := map[string]bool{}
	var out []string
	for _, c := range e.confirmationsFor(key, allowed) {
		if seen[c.Source] {
			continue
		}
		seen[c.Source] = true
		out = append(out, c.Source)
	}
	sort.Strings(out)
	return out
}

// confirmationsFor lists the positives one series admits for one package.
//
// A positive from a source whose own inputs were not available is not
// admitted, whatever was recorded against it. The input state is the
// constraint on adoption, not a note beside the result: a source that
// could not read what it needs has not established anything, and counting
// something it produced anyway would put an unfounded positive into the
// rate.
func (e *evidenceSet) confirmationsFor(key pkgGroupKey, allowed func(string) bool) []Confirmation {
	var out []Confirmation
	for _, c := range e.byKey[key] {
		if !allowed(c.Source) {
			continue
		}
		if st := e.inputStates[c.Source]; st == nil || st.State != inputOK {
			continue
		}
		out = append(out, c)
	}
	return out
}

// anyInputOKFor reports whether at least one of the evidence sources a
// given series admits has the inputs it needs.
//
// It is what replaces the first stage's unconditional "the observation
// failed, so nothing can be said": with several independent sources, one
// source's failure is not the window's. The series matters as well as the
// source — an event collection that worked says nothing about a series
// that does not use events, and letting it carry that series past the
// rule would report a judgement no admitted source could support.
func (e *evidenceSet) anyInputOKFor(series string) bool {
	allowed := allowFor(series)
	for name, st := range e.inputStates {
		if allowed(name) && st.State == inputOK {
			return true
		}
	}
	return false
}

// meansASource reports whether a source is one of the read-only mapping
// sources, which is what separates the increment the mapping produced from
// the increment the events produced.
func meansASource(s string) bool {
	switch s {
	case sourceGoBinary, sourceJarFD, sourceNodeFile, sourcePythonExt, sourceOSPathIndex:
		return true
	}
	return false
}

func eventSource(s string) bool { return strings.HasPrefix(s, sourceEventPrefix) }

func allowS0(s string) bool { return s == sourceSampling }
func allowS1(s string) bool { return s == sourceSampling || meansASource(s) }
func allowS2(s string) bool { return allowS1(s) || eventSource(s) }

func allowFor(series string) func(string) bool {
	switch series {
	case seriesS0:
		return allowS0
	case seriesS1:
		return allowS1
	default:
		return allowS2
	}
}

// buildEvidenceSet gathers every source's confirmations for one window.
//
// Each source is asked only for what it needs. The first stage's sampling
// needs both of the reads its own decision table is defined over; the
// read-only mapping sources need the process reads and the layout saved
// beside them, and not the package database; the event source needs
// neither. Deciding them together — as one "was this sample usable" test —
// is what would discard a positive one source established because a
// different source's input failed, which is the thing the series exist to
// avoid.
func buildEvidenceSet(rec *ContainerRecord, wv windowValidity, groups []pkgGroup, set *resolverSet, idx *scanFileIndex, events *EventLog, imageVerified bool) *evidenceSet {
	e := newEvidenceSet()
	sampleTimes := sampleStartTimes(rec)

	// Which reads actually succeeded, per sample and per process
	// generation.
	//
	// Not one verdict per sample. The first stage's own rule asks whether
	// both of its two reads worked together, and that is right for it —
	// but a source resting on one of them is not stopped by the other
	// failing. A process whose mappings could not be read still has an
	// executable link, and a compiled binary is identified by that link
	// alone; a process whose mappings were refused still has a descriptor
	// table, and an archive held open is seen there. Deciding all of them
	// on one combined answer discards positives that were actually made.
	reads := buildReadOutcomes(rec)

	// The sampling source: the first stage's own rule, unchanged.
	if wv.Valid > 0 {
		e.setState(sourceSampling, inputOK, "")
	} else {
		e.setState(sourceSampling, inputError,
			"no sample satisfied both of the reads the first stage's decision table is defined over")
	}
	for _, g := range groups {
		if g.key.Class == scanner.ClassLang {
			continue
		}
		confirmedSamples, confirmedPaths, _, _ := searchOwned(rec, wv.ValidSampleIDs, g.key)
		// The confirming samples are walked earliest first rather than in
		// whatever order the map yields. Only one confirmation per source
		// and path is kept, so an unordered walk records whichever sample
		// happened to come out first — and the same saved inputs would
		// then say the observation was made in a different sample, at a
		// different instant, from one run to the next.
		for _, sampleID := range orderedSamples(confirmedSamples, sampleTimes) {
			for _, p := range confirmedPaths {
				e.add(g.key, Confirmation{
					Source: sourceSampling, Path: p, Verb: "loaded", Grain: grainFile,
					SampleID: sampleID, ObservedAt: sampleTimes[sampleID], Ecosystem: ecoOS,
					ContainerID: rec.Subject.Docker.ContainerID,
				})
			}
		}
	}

	// What the scan report offers, which is one half of each read-only
	// source's input test. The other half is whether any observation was
	// usable for it, which is aggregated from the observations themselves
	// below rather than guessed at beforehand.
	hasGoTargets, hasJarFiles, hasNodeFiles, hasPythonFiles := false, false, false, false
	for _, f := range idx.files {
		switch f.Ecosystem {
		case ecoGoBinary:
			hasGoTargets = true
		case ecoJar:
			hasJarFiles = true
		case ecoNodePkg:
			hasNodeFiles = true
		case ecoPythonPkg:
			hasPythonFiles = true
		}
	}
	scanOffers := map[string]bool{
		sourceGoBinary:    hasGoTargets,
		sourceJarFD:       hasJarFiles,
		sourceNodeFile:    hasNodeFiles,
		sourcePythonExt:   hasPythonFiles,
		sourceOSPathIndex: true, // an operating-system package's files come from the container, not the report
	}
	// usable[source] records that at least one observation had everything
	// that source needs: a generation that held still, the read it rests
	// on, and — where the rule needs one — the saved layout covering that
	// observation. The window's input state is this, aggregated.
	usable := map[string]bool{}
	sawRead := map[string]bool{}

	for _, pr := range rec.PathResolution {
		source := pathSourceOf(pr)
		if !reads.lookup(pr.SampleID, pr.Generation, source) {
			continue
		}
		sawRead[source] = true
		observed := pr.Resolved
		if observed == "" {
			observed = pr.Path
		}
		resolver := set.forObservation(pr.MountViewID, pr.SampleID, sampleTimes[pr.SampleID])
		// The layout that covered this observation is what says whether
		// the rules needing one could have run at all here. A later
		// reading having a manifest says nothing about an earlier
		// observation, and an earlier one lacking it says nothing about a
		// later observation either.
		if len(resolver.recordOwner) > 0 && source == "maps" && hasPythonFiles {
			usable[sourcePythonExt] = true
		}
		if len(resolver.moduleDirs) > 0 && hasNodeFiles {
			usable[sourceNodeFile] = true
		}
		if len(resolver.ownedBy) > 0 {
			usable[sourceOSPathIndex] = true
		}
		if hasGoTargets && (source == "exe" || source == "maps") {
			usable[sourceGoBinary] = true
		}
		if hasJarFiles && source == "fd" {
			usable[sourceJarFD] = true
		}

		outcome := resolver.resolve(observed)
		if outcome.Conflict {
			e.candidateConflict++
			continue
		}
		if outcome.Unresolved {
			e.countPathMiss(outcome.MissKind)
			continue
		}
		for _, m := range outcome.Matches {
			confSource, grain, verb, note := meansAAttribution(m.Ecosystem, source)
			if confSource == "" {
				continue
			}
			for _, key := range m.Keys {
				e.add(key, Confirmation{
					Source: confSource, Path: observed, File: m.File, Via: m.Via,
					Verb: verb, Grain: grain, SampleID: pr.SampleID, Generation: pr.Generation,
					ObservedAt: sampleTimes[pr.SampleID], Ecosystem: m.Ecosystem,
					ContainerID: rec.Subject.Docker.ContainerID, Note: note,
				})
			}
		}
	}

	requiredRead := map[string]string{
		sourceGoBinary: "exe", sourceJarFD: "fd", sourcePythonExt: "maps",
	}
	for _, source := range []string{sourceGoBinary, sourceJarFD, sourceNodeFile, sourcePythonExt, sourceOSPathIndex} {
		switch {
		case !imageVerified:
			e.setState(source, inputMissing, "the running image could not be shown to be the scanned one")
		case !scanOffers[source]:
			e.setState(source, inputMissing, "the scan report names nothing this rule could reach")
		case usable[source]:
			e.setState(source, inputOK, "")
		case requiredRead[source] != "" && !sawRead[requiredRead[source]]:
			e.setState(source, inputMissing, "no usable "+readKindName(requiredRead[source])+" was recorded for any process generation")
		default:
			e.setState(source, inputMissing, "no observation was covered by a saved layout this rule could follow")
		}
	}

	// The event source.
	state, notes := deriveEventState(events)
	e.eventState, e.eventNotes = state, notes
	switch state {
	case eventStateNotAttempted:
		e.setState(sourceEventExec, inputMissing, "this run collected no events")
		e.setState(sourceEventOpen, inputMissing, "this run collected no events")
	case eventStateFailed:
		e.setState(sourceEventExec, inputError, strings.Join(notes, "; "))
		e.setState(sourceEventOpen, inputError, strings.Join(notes, "; "))
	default:
		e.setState(sourceEventExec, inputOK, strings.Join(notes, "; "))
		e.setState(sourceEventOpen, inputOK, strings.Join(notes, "; "))
	}
	if events != nil && state != eventStateFailed {
		containerID := rec.Subject.Docker.ContainerID
		start, end := rec.Window.ScheduledStart, rec.Window.ScheduledEnd
		for _, ev := range events.Events {
			if !ev.OK {
				continue // a failed open is not use, the same way a failed execution is not
			}
			if ev.ContainerID == "" || ev.ContainerID != containerID {
				continue // attributed elsewhere, or to nothing: never claimed for this container
			}
			if !inWindow(ev.Timestamp, start, end) {
				continue
			}
			if !ev.Resolved || ev.Path == "" {
				e.unresolvedEventPaths++
				continue
			}
			outcome := set.resolveEvent(ev.Path, ev.Timestamp)
			if outcome.Conflict {
				e.candidateConflict++
				continue
			}
			if outcome.Unresolved {
				e.countEventMiss(outcome.MissKind)
				continue
			}
			source, verb := sourceEventOpen, "opened"
			if ev.Event == "exec" {
				source, verb = sourceEventExec, "executed"
			}
			for _, m := range outcome.Matches {
				grain := grainFile
				note := ""
				if m.Ecosystem == ecoGoBinary {
					grain = grainBinary
					note = "the evidence covers the whole binary: every module built into it is reported, and none of them is shown to have run"
				}
				for _, key := range m.Keys {
					e.add(key, Confirmation{
						Source: source, Path: ev.Path, File: m.File, Via: m.Via,
						Verb: verb, Grain: grain, ObservedAt: ev.Timestamp,
						Generation:  ProcessGeneration{PID: ev.PID, Starttime: ev.Starttime},
						Ecosystem:   m.Ecosystem,
						ContainerID: ev.ContainerID, Note: note,
					})
				}
			}
		}
	}

	for source, st := range e.inputStates {
		count := 0
		for key := range e.byKey {
			for _, c := range e.byKey[key] {
				if c.Source == source {
					count++
					break
				}
			}
		}
		st.Positives = count
	}
	return e
}

// orderedSamples puts a set of sample identifiers into the order the
// samples were taken in, falling back to the identifier itself where a
// sample has no recorded start time, so that the order is total and does
// not depend on how a map was walked.
func orderedSamples(ids map[string]bool, at map[string]time.Time) []string {
	out := make([]string, 0, len(ids))
	for id := range ids {
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool {
		ti, tj := at[out[i]], at[out[j]]
		if !ti.Equal(tj) {
			return ti.Before(tj)
		}
		return out[i] < out[j]
	})
	return out
}

// readOutcomes says, per sample and per process generation, which of the
// three reads succeeded.
//
// A generation that did not hold still through the sample contributes
// nothing at all: its reads may describe whatever replaced it. Beyond
// that, each read stands on its own — the executable link, the memory
// mappings and the descriptor table fail independently, and a source
// resting on one of them is not stopped by another failing.
type readOutcomes struct {
	ok map[readKey]bool
}

type readKey struct {
	sampleID  string
	pid       int
	starttime string
	kind      string
}

func buildReadOutcomes(rec *ContainerRecord) readOutcomes {
	out := readOutcomes{ok: map[readKey]bool{}}
	for _, p := range rec.Processes {
		if p.Invalid {
			continue
		}
		key := func(kind string) readKey {
			return readKey{p.SampleID, p.Generation.PID, p.Generation.Starttime, kind}
		}
		if p.ExeError == "" && p.Exe != "" {
			out.ok[key("exe")] = true
		}
		if p.MapsError == "" {
			out.ok[key("maps")] = true
		}
		if p.FDError == "" && len(p.FileDescriptors) > 0 {
			out.ok[key("fd")] = true
		}
	}
	return out
}

// ok reports whether one read succeeded for one generation in one sample.
//
// A record written before the per-process reads were recorded separately
// carries no process rows to check against; such a record is read as
// having had the two reads the first stage was defined over, which is what
// it actually held.
func (r readOutcomes) lookup(sampleID string, gen ProcessGeneration, kind string) bool {
	if len(r.ok) == 0 {
		return kind == "exe" || kind == "maps"
	}
	return r.ok[readKey{sampleID, gen.PID, gen.Starttime, kind}]
}

func readKindName(kind string) string {
	switch kind {
	case "exe":
		return "executable link"
	case "maps":
		return "memory mapping"
	case "fd":
		return "open file descriptor"
	}
	return kind
}

// countPathMiss and countEventMiss keep the three reasons a path reached
// no package apart. Only the first is a shortfall in the observation.
func (e *evidenceSet) countPathMiss(kind string) {
	switch kind {
	case missPathUnresolved:
		e.unresolvedPaths++
	case missUnmappable:
		e.unmappablePaths++
	default:
		e.outsideScanPaths++
	}
}

func (e *evidenceSet) countEventMiss(kind string) {
	switch kind {
	case missPathUnresolved:
		e.unresolvedEventPaths++
	case missUnmappable:
		e.unmappableEvents++
	default:
		e.outsideScanEvents++
	}
}

// pathSourceOf says which read produced an observed path. A record written
// before the three were told apart carries none, and is read as the two
// reads that existed then — which is what those records actually held.
func pathSourceOf(pr PathResolutionRecord) string {
	if pr.Source == "" {
		return "maps"
	}
	return pr.Source
}

// meansAAttribution decides which read-only source an observed path
// belongs to, and what the observation supports being said about it.
//
// An executable link means the file was executed. A memory mapping means
// it was loaded. An open descriptor means only that it is open, which is
// the weakest of the three and is described as such.
func meansAAttribution(ecosystem, pathSource string) (source, grain, verb, note string) {
	switch ecosystem {
	case ecoGoBinary:
		verb, note = "opened", "the evidence covers the whole binary: every module built into it is reported, and none of them is shown to have run"
		if pathSource == "exe" {
			verb = "executed"
		}
		return sourceGoBinary, grainBinary, verb, note
	case ecoOS:
		// The package database's saved path index is what reaches an
		// operating-system package from a read the first stage's rule does
		// not cover, and from an event, which has no sample behind it at
		// all.
		verb = "opened"
		switch pathSource {
		case "exe":
			verb = "executed"
		case "maps":
			verb = "loaded"
		}
		return sourceOSPathIndex, grainFile, verb, ""
	case ecoJar:
		return sourceJarFD, grainFile, "opened", ""
	case ecoNodePkg:
		return sourceNodeFile, grainFile, "opened", ""
	case ecoPythonPkg:
		verb = "opened"
		if pathSource == "maps" {
			verb = "loaded"
		}
		return sourcePythonExt, grainFile, verb, ""
	}
	return "", "", "", ""
}

// seriesVerdict is one package group's outcome under one series.
type seriesVerdict struct {
	Verdict Verdict
	Factor  string
	Sources []string
	// Files are the scan-report files whose observation produced the
	// positives, and Grain the coarsest granularity among them.
	Files []string
	Grain string
	Notes []string
}

// decideSeries applies the decision table for one series to one package
// group.
//
// The order of the rules is fixed and is the same as the first stage's:
// collection failure before any judgement about use, then reachability,
// then confirmation, then the difference between "reachable and not seen"
// and "no way to reach it".
//
// Two rules change once several independent sources exist. The first no
// longer declares the whole window undetermined when one source's inputs
// are missing — only when every source's are. And the reachability rule
// no longer treats every language package as unreachable by construction:
// it asks whether this package's own mapping inputs are there.
func decideSeries(series string, g pkgGroup, rec *ContainerRecord, def Case, obsState string, wv windowValidity,
	ev *evidenceSet, set *resolverSet, idx *scanFileIndex) seriesVerdict {

	res := set.anyResolver()

	allowed := allowFor(series)
	key := g.key
	eco := idx.ecosystem[key]
	if eco == "" && key.Class == scanner.ClassOS {
		eco = ecoOS
	}
	input := idx.mappingInput[key]
	if input == "" {
		input = mappingInputNone
	}

	// Rule 1: a collection failure is settled before anything about use.
	//
	// The first stage's series applies its own rule unchanged. The later
	// ones ask whether any source this series admits has what it needs —
	// not whether any source at all does, which would let an event
	// collection carry a series that does not use events.
	if series == seriesS0 {
		if obsState == "observation_failed" {
			return seriesVerdict{Verdict: VerdictNotDetermined, Factor: dominantNotDeterminedFactor(rec)}
		}
	} else if !ev.anyInputOKFor(series) {
		return seriesVerdict{Verdict: VerdictNotDetermined, Factor: dominantNotDeterminedFactor(rec)}
	}

	// Rule 2: reachability.
	if key.Class == scanner.ClassLang {
		if series == seriesS0 {
			return seriesVerdict{Verdict: VerdictUnobserved, Factor: factorLangPkg}
		}
		if input == mappingInputNone {
			return seriesVerdict{Verdict: VerdictUnobserved, Factor: factorLangPkg}
		}
	}

	// Rule 3: a positive from any source this series admits.
	if confs := ev.confirmationsFor(key, allowed); len(confs) > 0 {
		sv := seriesVerdict{Verdict: VerdictConfirmed, Sources: ev.sourcesFor(key, allowed), Grain: grainFile}
		seenFile, seenNote := map[string]bool{}, map[string]bool{}
		for _, c := range confs {
			if c.File != "" && !seenFile[c.File] {
				seenFile[c.File] = true
				sv.Files = append(sv.Files, c.File)
			}
			if c.Grain == grainBinary {
				sv.Grain = grainBinary
			}
			if c.Note != "" && !seenNote[c.Note] {
				seenNote[c.Note] = true
				sv.Notes = append(sv.Notes, c.Note)
			}
		}
		sort.Strings(sv.Files)
		if len(sv.Files) > 1 {
			sv.Notes = append(sv.Notes, fmt.Sprintf("this package is installed in %d places; at least one of them was observed", len(sv.Files)))
		}
		return sv
	}

	// Rules 4 and 5. The first stage's file-list test answers a question
	// about an operating-system package database, so it is applied to
	// operating-system packages and to nothing else.
	if key.Class == scanner.ClassOS {
		present, found := packageFileListStatus(rec, wv, key)
		if found && present {
			expected, _ := expectedFor(def, key.Package)
			factor := factorNoObserved
			if expected.FactorHint == factorShortLived || expected.FactorHint == factorTransient {
				factor = expected.FactorHint
			}
			if series == seriesS2 && ev.eventState == eventStateFailed {
				// An operating-system package's own route is the sampling,
				// which worked. The event layer merely added nothing, and
				// the only thing worth recording about it here is that it
				// was unavailable at all.
				factor = factorEventUnavailable
			}
			return seriesVerdict{Verdict: VerdictUnobserved, Factor: factor}
		}
		sv := seriesVerdict{Verdict: VerdictUnresolved}
		switch {
		case !containerHasUsableDB(rec):
			sv.Factor = factorDBAbsent
		case wv.PkgdbReadFailures > 0 && !found:
			sv.Factor = factorDBError
		default:
			sv.Factor = factorNoFileList
		}
		return sv
	}

	// A language package's own mapping inputs decide the same split.
	present, why := res.mappingInputsPresent(key, input, eco)
	if !present {
		return seriesVerdict{Verdict: VerdictUnresolved, Factor: factorMappingInputMissing, Notes: []string{why}}
	}
	factor := factorNoObserved
	var notes []string
	if series == seriesS2 {
		factor, notes = eventShortfallFactor(ev)
	}
	sv := seriesVerdict{Verdict: VerdictUnobserved, Factor: factor, Notes: notes}
	if why != "" {
		// The mapping inputs are there, but the reason nothing reached
		// this package is a property of how it is packaged, not of the
		// window. Keeping that reason is what stops a later reader
		// concluding the package went unused.
		sv.Notes = append(sv.Notes, why)
	}
	return sv
}

// eventShortfallFactor names why the event evidence added nothing for a
// language package it could in principle have reached.
//
// Three answers are possible, and they mean different things: the
// collection was not available at all, it ran but some of what it saw
// could not be turned into a file path, or it ran and observed no use.
// Only the third is a statement about the package.
//
// The second counts only events that never produced a usable file path at
// all. An event whose path resolved perfectly well and simply names
// nothing the scan reports is not one of them: most of what a workload
// opens is that, and counting it here would mark every language package in
// the image as possibly-missed on the strength of ordinary activity.
//
// Even so, the second is a statement about the window rather than about
// this package: nothing says the unreadable paths were this package's. It
// is used anyway, because reporting "nothing used it" while some of the
// evidence could not be read would overstate what is known. The
// qualification travels with it so that is not lost.
func eventShortfallFactor(ev *evidenceSet) (string, []string) {
	switch {
	case ev.eventState == eventStateFailed:
		return factorEventUnavailable, nil
	case ev.eventState == eventStateNotAttempted:
		return factorNoObserved, nil
	case ev.unresolvedEventPaths > 0:
		return factorEventPathUnresolved, []string{fmt.Sprintf(
			"%d event(s) in this window never produced a usable file path; whether any of them was this package's is not known",
			ev.unresolvedEventPaths)}
	default:
		return factorEventNoObservation, nil
	}
}
