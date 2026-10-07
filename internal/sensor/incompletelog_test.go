package sensor

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/evidence"
)

// captureIncompleteLog redirects the incomplete-reason log to a buffer for
// the duration of the test.
func captureIncompleteLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := incompleteLogWriter
	incompleteLogWriter = &buf
	t.Cleanup(func() { incompleteLogWriter = prev })
	return &buf
}

func newIncompleteLogGeneration() *generationState {
	return newGenerationState(evidence.ContainerRef{Runtime: "docker", ID: strings64('a')}, InitProcess{PID: 1, Starttime: 1}, time.Unix(0, 0), evidence.CoverageNone)
}

func TestIncompleteLog_SampleOpenFailureLoggedOncePerGeneration(t *testing.T) {
	buf := captureIncompleteLog(t)
	r, _ := openTestRoot(t)
	defer r.Close()

	s := newTestSession()
	g := newIncompleteLogGeneration()
	s.generations[g.key()] = g

	for i := 0; i < 2; i++ {
		resolution := resolveCandidatesWithRoot(r, map[string][]sampleCandidate{
			"/usr/lib/missing.so": {{kind: evidence.KindMappedLibrary, dev: "08:01", inode: 5}},
		})
		if !resolution.incomplete {
			t.Fatalf("round %d: resolution.incomplete = false, want true for an unopenable candidate", i)
		}
		res := sampleResult{genKey: g.key(), incomplete: true, reasons: resolution.reasons}
		s.applySampleResult(g, res)
	}

	out := buf.String()
	if got := strings.Count(out, "sample_open_failed"); got != 1 {
		t.Fatalf("sample_open_failed logged %d times, want 1; output:\n%s", got, out)
	}
	want := "kestrelynx sensor: generation " + strings.Repeat("a", 12) + " init=1:1 incomplete: sample_open_failed path=\"/usr/lib/missing.so\""
	if !strings.HasPrefix(out, want) {
		t.Errorf("output = %q, want prefix %q", out, want)
	}
	if !g.incomplete {
		t.Errorf("g.incomplete = false, want true")
	}
}

func TestIncompleteLog_SnapshotTermLoggedOnce(t *testing.T) {
	buf := captureIncompleteLog(t)
	g := newIncompleteLogGeneration()
	g.pendingConfirms = 1

	for i := 0; i < 3; i++ {
		g.logTransientIncomplete(false, false)
	}
	out := buf.String()
	if got := strings.Count(out, "\n"); got != 1 || !strings.Contains(out, "incomplete: pending_confirms confirms=1") {
		t.Fatalf("output = %q, want exactly one pending_confirms line", out)
	}

	g.pendingMapsLookups = 2
	g.logTransientIncomplete(true, false)
	out = buf.String()
	for _, code := range []string{"pending_maps_lookups", "pending_route_event"} {
		if strings.Count(out, code) != 1 {
			t.Errorf("%s not logged exactly once in %q", code, out)
		}
	}
}

// Every term of toEvidence's Incomplete expression must have a reason, and
// the reasons must agree with the published value.
func TestIncompleteLog_EveryTransientTermHasReason(t *testing.T) {
	cases := map[string]func(g *generationState) (route, loss bool){
		"pending_lookup":    func(g *generationState) (bool, bool) { g.pendingLookup = &pendingLookup{}; return false, false },
		"queued_candidates": func(g *generationState) (bool, bool) { g.queuedCandidates = []candidateBatch{{}}; return false, false },
		"candidates_lost":   func(g *generationState) (bool, bool) { g.candidatesLostPermanently = true; return false, false },
		"pending_mount_view_events": func(g *generationState) (bool, bool) {
			g.pendingMountViewEvents = []pendingMountViewEvent{{}}
			return false, false
		},
		"pending_maps_lookups": func(g *generationState) (bool, bool) { g.pendingMapsLookups = 1; return false, false },
		"pending_confirms":     func(g *generationState) (bool, bool) { g.pendingConfirms = 1; return false, false },
		"pending_route_event":  func(g *generationState) (bool, bool) { return true, false },
		"pending_loss_delta":   func(g *generationState) (bool, bool) { return false, true },
	}
	for code, set := range cases {
		buf := captureIncompleteLog(t)
		g := newIncompleteLogGeneration()
		route, loss := set(g)
		if !g.toEvidence(route || loss).Incomplete {
			t.Errorf("%s: published Incomplete = false, want true", code)
		}
		g.logTransientIncomplete(route, loss)
		if !strings.Contains(buf.String(), "incomplete: "+code) {
			t.Errorf("%s: not logged, output %q", code, buf.String())
		}
	}
	buf := captureIncompleteLog(t)
	g := newIncompleteLogGeneration()
	g.logTransientIncomplete(false, false)
	if buf.Len() != 0 {
		t.Errorf("quiet generation logged %q", buf.String())
	}
}

func TestIncompleteLog_UntrustedPathIsQuotedAndCapped(t *testing.T) {
	buf := captureIncompleteLog(t)
	g := newIncompleteLogGeneration()

	evil := "/lib/x\nkestrelynx sensor: generation forged incomplete: x\x00" + strings.Repeat("A", 1000)
	g.markIncomplete("sample_open_failed", "path="+quoteDiag(evil))

	out := buf.String()
	if strings.Count(out, "\n") != 1 || !strings.HasSuffix(out, "\n") {
		t.Fatalf("output is not exactly one line: %q", out)
	}
	if !strings.Contains(out, `\n`) || !strings.Contains(out, `\x00`) {
		t.Errorf("control characters not escaped: %q", out)
	}
	if len(out) > 512 {
		t.Errorf("line length = %d, want it bounded well under 512 for a 1000+ byte path", len(out))
	}
	if !strings.Contains(out, `"...`) {
		t.Errorf("truncated string not marked: %q", out)
	}
}

func TestIncompleteReasons_BoundedWithDroppedCount(t *testing.T) {
	var r incompleteReasons
	for _, c := range []string{"a", "b", "c", "d", "e", "f", "a"} {
		r.add(c, "")
	}
	if len(r.list) != maxSampleReasons || r.dropped != 2 {
		t.Errorf("list=%d dropped=%d, want %d and 2", len(r.list), r.dropped, maxSampleReasons)
	}
}

func TestIncompleteLog_GenerationsOfSameContainerLoggedSeparately(t *testing.T) {
	buf := captureIncompleteLog(t)
	ref := evidence.ContainerRef{Runtime: "docker", ID: strings64('a')}
	before := newGenerationState(ref, InitProcess{PID: 10, Starttime: 100}, time.Unix(0, 0), evidence.CoverageNone)
	after := newGenerationState(ref, InitProcess{PID: 20, Starttime: 200}, time.Unix(0, 0), evidence.CoverageNone)

	before.markIncomplete("event_loss", "")
	after.markIncomplete("event_loss", "")

	out := buf.String()
	for _, want := range []string{
		"generation " + strings.Repeat("a", 12) + " init=10:100 incomplete: event_loss",
		"generation " + strings.Repeat("a", 12) + " init=20:200 incomplete: event_loss",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q; output:\n%s", want, out)
		}
	}
}
