package cverecord

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRecordURL(t *testing.T) {
	for id, want := range map[string]string{
		"CVE-2026-123007": "https://example.test/cves/2026/123xxx/CVE-2026-123007.json",
		"CVE-2024-0999":   "https://example.test/cves/2024/0xxx/CVE-2024-0999.json",
		"CVE-2024-3094":   "https://example.test/cves/2024/3xxx/CVE-2024-3094.json",
	} {
		// With and without the trailing slash of the base.
		for _, base := range []string{"https://example.test/cves/", "https://example.test/cves"} {
			got, ok := RecordURL(base, id)
			if !ok || got != want {
				t.Errorf("RecordURL(%q, %s) = %q, %v; want %q", base, id, got, ok, want)
			}
		}
	}
	for _, id := range []string{"TEMP-0000000-A338F9", "GHSA-abcd-efgh-ijkl", "CVE-2026-12", "CVE-2026-123007/../x", "cve-2026-123007", ""} {
		if _, ok := RecordURL(DefaultBaseURL, id); ok {
			t.Errorf("RecordURL accepted %q", id)
		}
	}
}

func score(s string) *Score { return &Score{BaseSeverity: s} }

func TestSeverityOf(t *testing.T) {
	cases := []struct {
		name string
		cna  []Metric
		adp  [][]Metric
		want string
	}{
		{"cna 4.0 before 3.1", []Metric{{V31: score("HIGH")}, {V4: score("CRITICAL")}}, nil, "CRITICAL"},
		{"cna 3.1 before 3.0", []Metric{{V30: score("LOW")}, {V31: score("high")}}, nil, "HIGH"},
		{"cna before adp", []Metric{{V31: score("MEDIUM")}}, [][]Metric{{{V4: score("CRITICAL")}}}, "MEDIUM"},
		{"adp when the cna has none", []Metric{{}}, [][]Metric{{}, {{V31: score("MEDIUM")}}}, "MEDIUM"},
		{"first adp with one", nil, [][]Metric{{{V31: score("LOW")}}, {{V31: score("HIGH")}}}, "LOW"},
		{"none", nil, nil, ""},
		{"blank", []Metric{{V31: score("  ")}}, nil, ""},
		// Any value counts here; only a record read for its severity is
		// limited to the four levels.
		{"a value that is not a level", []Metric{{V31: score("none")}}, [][]Metric{{{V31: score("HIGH")}}}, "NONE"},
	}
	for _, tc := range cases {
		if got := SeverityOf(tc.cna, tc.adp...); got != tc.want {
			t.Errorf("%s: SeverityOf = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// recordJSON builds a CVE record of id whose CNA states the CVSS 3.1
// severity sev ("" for no metrics).
func recordJSON(id, state, sev string) string {
	metrics := "[]"
	if sev != "" {
		metrics = fmt.Sprintf(`[{"cvssV3_1":{"baseScore":8.1,"baseSeverity":%q}}]`, sev)
	}
	return fmt.Sprintf(`{"dataType":"CVE_RECORD","cveMetadata":{"cveId":%q,"state":%q},"containers":{"cna":{"metrics":%s}}}`, id, state, metrics)
}

// noneThen builds a record of CVE-2026-123007 whose CNA states a CVSS 4.0
// severity of NONE, followed by another CNA metric and an ADP metric (either
// may be "").
func noneThen(cna, adp string) string {
	metrics := `{"cvssV4_0":{"baseScore":0,"baseSeverity":"NONE"}}`
	if cna != "" {
		metrics += "," + cna
	}
	return fmt.Sprintf(`{"cveMetadata":{"cveId":"CVE-2026-123007","state":"PUBLISHED"},"containers":{"cna":{"metrics":[%s]},"adp":[{"metrics":[%s]}]}}`, metrics, adp)
}

func TestSeverityOfRecord(t *testing.T) {
	const id = "CVE-2026-123007"
	// The shape of the published record: the CNA gives 3.1 and 4.0 in one list.
	real := `{"cveMetadata":{"cveId":"CVE-2026-123007","state":"PUBLISHED","assignerShortName":"f5"},
	  "containers":{"cna":{"metrics":[{"cvssV3_1":{"baseScore":8.1,"baseSeverity":"HIGH"}},{"cvssV4_0":{"baseScore":9.2,"baseSeverity":"CRITICAL"}}]}}}`
	adpOnly := `{"cveMetadata":{"cveId":"CVE-2026-123007","state":"PUBLISHED"},
	  "containers":{"cna":{},"adp":[{"title":"CVE Program Container"},{"metrics":[{"other":{"type":"ssvc"}},{"cvssV3_1":{"baseSeverity":"MEDIUM"}}]}]}}`
	cases := []struct {
		name, data, want string
		wantErr          bool
	}{
		{"cna 4.0 wins", real, "CRITICAL", false},
		{"adp", adpOnly, "MEDIUM", false},
		{"no metrics", recordJSON(id, "PUBLISHED", ""), "", false},
		{"rejected", recordJSON(id, "REJECTED", "HIGH"), "", false},
		{"a score of none", recordJSON(id, "PUBLISHED", "NONE"), "", false},
		{"a score of none is passed over for the next version", noneThen(`{"cvssV3_1":{"baseSeverity":"HIGH"}}`, ""), "HIGH", false},
		{"a score of none is passed over for the adp", noneThen("", `{"cvssV3_1":{"baseSeverity":"MEDIUM"}}`), "MEDIUM", false},
		{"an unknown level", recordJSON(id, "PUBLISHED", "SEVERE"), "", false},
		{"another CVE's record", recordJSON("CVE-2026-123008", "PUBLISHED", "HIGH"), "", true},
		{"not json", `<html>`, "", true},
	}
	for _, tc := range cases {
		got, err := severityOfRecord(id, []byte(tc.data))
		if got != tc.want || (err != nil) != tc.wantErr {
			t.Errorf("%s: severityOfRecord = %q, %v; want %q, error %v", tc.name, got, err, tc.want, tc.wantErr)
		}
	}
}

// listServer serves CVE records in the layout of the CVE list repository.
type listServer struct {
	*httptest.Server
	mu sync.Mutex
	// records maps a CVE ID to its body; status overrides the answer for an ID.
	records  map[string]string
	status   map[string]int
	requests []string
	// conditional counts the requests that came with If-None-Match.
	conditional int
}

func newListServer(t *testing.T) *listServer {
	t.Helper()
	ls := &listServer{records: map[string]string{}, status: map[string]int{}}
	ls.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ls.mu.Lock()
		defer ls.mu.Unlock()
		id := strings.TrimSuffix(filepath.Base(r.URL.Path), ".json")
		ls.requests = append(ls.requests, id)
		if want, _ := RecordURL("/cves/", id); r.URL.Path != want {
			http.Error(w, "wrong layout", http.StatusBadRequest)
			return
		}
		if code := ls.status[id]; code != 0 {
			http.Error(w, "forced", code)
			return
		}
		body, ok := ls.records[id]
		if !ok {
			http.NotFound(w, r)
			return
		}
		etag := fmt.Sprintf(`"%x"`, len(body)*31+int(body[len(body)/2]))
		if inm := r.Header.Get("If-None-Match"); inm != "" {
			ls.conditional++
			if inm == etag {
				w.WriteHeader(http.StatusNotModified)
				return
			}
		}
		w.Header().Set("ETag", etag)
		fmt.Fprint(w, body)
	}))
	t.Cleanup(ls.Close)
	return ls
}

func (ls *listServer) set(id, state, sev string) {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	ls.records[id] = recordJSON(id, state, sev)
}

func (ls *listServer) fail(id string, code int) {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	ls.status[id] = code
}

func (ls *listServer) count() int {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	return len(ls.requests)
}

// quiet discards the log lines of the sources under test.
var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

// clock is a settable time source.
type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func newSource(t *testing.T, ls *listServer) (*Source, *clock) {
	t.Helper()
	c := &clock{t: time.Date(2026, 11, 19, 0, 0, 0, 0, time.UTC)}
	return &Source{CacheDir: filepath.Join(t.TempDir(), "cve-records"), BaseURL: ls.URL + "/cves/", Now: c.now, Log: quiet}, c
}

func TestSeveritiesReadsRecords(t *testing.T) {
	ls := newListServer(t)
	ls.set("CVE-2026-123007", "PUBLISHED", "CRITICAL")
	ls.set("CVE-2026-121757", "PUBLISHED", "MEDIUM")
	ls.set("CVE-2026-91094", "PUBLISHED", "")
	ls.set("CVE-2026-0001", "REJECTED", "HIGH")
	s, _ := newSource(t, ls)

	got := s.Severities(context.Background(), []string{
		"CVE-2026-123007", "CVE-2026-121757", "CVE-2026-91094", "CVE-2026-0001",
		"CVE-2026-99999",      // no record
		"TEMP-0000000-A338F9", // not a CVE ID: never asked for
		"CVE-2026-123007",     // twice
	})
	want := map[string]string{"CVE-2026-123007": "CRITICAL", "CVE-2026-121757": "MEDIUM"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Severities = %v, want %v", got, want)
	}
	if n := ls.count(); n != 5 {
		t.Errorf("%d requests, want 5 (one per CVE ID): %v", n, ls.requests)
	}
}

func TestSeveritiesSameAnswerWithinACycle(t *testing.T) {
	ls := newListServer(t)
	ls.set("CVE-2026-123007", "PUBLISHED", "CRITICAL")
	s, c := newSource(t, ls)
	ctx := context.Background()
	ids := []string{"CVE-2026-123007", "CVE-2026-5000"}

	first := s.Severities(ctx, ids)
	// The records change and a day passes, all within the cycle.
	ls.set("CVE-2026-123007", "PUBLISHED", "LOW")
	ls.set("CVE-2026-5000", "PUBLISHED", "HIGH")
	c.t = c.t.Add(25 * time.Hour)
	second := s.Severities(ctx, ids)
	if !reflect.DeepEqual(first, second) || first["CVE-2026-123007"] != "CRITICAL" || len(first) != 1 {
		t.Fatalf("answers within a cycle differ: %v then %v", first, second)
	}
	if n := ls.count(); n != 2 {
		t.Errorf("%d requests within the cycle, want 2", n)
	}

	s.BeginCycle()
	third := s.Severities(ctx, ids)
	want := map[string]string{"CVE-2026-123007": "LOW", "CVE-2026-5000": "HIGH"}
	if !reflect.DeepEqual(third, want) {
		t.Fatalf("after BeginCycle Severities = %v, want %v", third, want)
	}
}

func TestSeveritiesCache(t *testing.T) {
	ls := newListServer(t)
	ls.set("CVE-2026-123007", "PUBLISHED", "CRITICAL")
	ls.set("CVE-2026-91094", "PUBLISHED", "")
	s, c := newSource(t, ls)
	ctx := context.Background()
	ids := []string{"CVE-2026-123007", "CVE-2026-91094"}
	want := map[string]string{"CVE-2026-123007": "CRITICAL"}

	if got := s.Severities(ctx, ids); !reflect.DeepEqual(got, want) {
		t.Fatalf("Severities = %v, want %v", got, want)
	}
	// A new process within refreshAfter answers from the cache, the record
	// without a severity included.
	c.t = c.t.Add(19 * time.Hour)
	s2 := &Source{CacheDir: s.CacheDir, BaseURL: s.BaseURL, Now: c.now, Log: quiet}
	if got := s2.Severities(ctx, ids); !reflect.DeepEqual(got, want) {
		t.Fatalf("from the cache Severities = %v, want %v", got, want)
	}
	if n := ls.count(); n != 2 {
		t.Fatalf("%d requests, want 2: the cache was not used", n)
	}
	// Past refreshAfter the records are asked for again, conditionally, and
	// an unchanged one keeps its answer.
	c.t = c.t.Add(2 * time.Hour)
	s2.BeginCycle()
	if got := s2.Severities(ctx, ids); !reflect.DeepEqual(got, want) {
		t.Fatalf("after a refresh Severities = %v, want %v", got, want)
	}
	if n := ls.count(); n != 4 || ls.conditional != 2 {
		t.Fatalf("%d requests (%d conditional), want 4 (2)", n, ls.conditional)
	}
	// The refresh counts: within refreshAfter of it nothing is asked for.
	c.t = c.t.Add(19 * time.Hour)
	s2.BeginCycle()
	s2.Severities(ctx, ids)
	if n := ls.count(); n != 4 {
		t.Fatalf("%d requests, want 4: the refresh time was not recorded", n)
	}
	// A changed record replaces the answer.
	ls.set("CVE-2026-91094", "PUBLISHED", "HIGH")
	c.t = c.t.Add(2 * time.Hour)
	s2.BeginCycle()
	got := s2.Severities(ctx, ids)
	if got["CVE-2026-91094"] != "HIGH" || got["CVE-2026-123007"] != "CRITICAL" {
		t.Fatalf("after the record changed Severities = %v", got)
	}
}

func TestSeveritiesKeepsAnAnswerThroughAnOutage(t *testing.T) {
	ls := newListServer(t)
	ls.set("CVE-2026-123007", "PUBLISHED", "CRITICAL")
	s, c := newSource(t, ls)
	ctx := context.Background()
	// CVE-2026-7000 has no readable record from the start.
	ls.fail("CVE-2026-7000", http.StatusInternalServerError)
	ids := []string{"CVE-2026-123007", "CVE-2026-7000"}
	s.Severities(ctx, ids)

	// The record cannot be read for weeks, in every way a request can fail.
	// A finding that got its severity must keep it: losing it would read as
	// the vulnerability being gone.
	for day, code := range []int{http.StatusInternalServerError, http.StatusNotFound, http.StatusBadGateway} {
		ls.fail("CVE-2026-123007", code)
		c.t = c.t.Add(9 * 24 * time.Hour)
		s.BeginCycle()
		got := s.Severities(ctx, ids)
		if got["CVE-2026-123007"] != "CRITICAL" || len(got) != 1 {
			t.Fatalf("step %d, status %d: Severities = %v, want the answer read before the outage", day, code, got)
		}
	}
	// A new process sees the same.
	s2 := &Source{CacheDir: s.CacheDir, BaseURL: s.BaseURL, Now: c.now, Log: quiet}
	if got := s2.Severities(ctx, ids); got["CVE-2026-123007"] != "CRITICAL" {
		t.Fatalf("a new process: Severities = %v", got)
	}
	// The records are readable again and one has changed.
	ls.fail("CVE-2026-123007", 0)
	ls.fail("CVE-2026-7000", 0)
	ls.set("CVE-2026-123007", "PUBLISHED", "HIGH")
	ls.set("CVE-2026-7000", "PUBLISHED", "MEDIUM")
	s.BeginCycle()
	want := map[string]string{"CVE-2026-123007": "HIGH", "CVE-2026-7000": "MEDIUM"}
	if got := s.Severities(ctx, ids); !reflect.DeepEqual(got, want) {
		t.Fatalf("after the outage Severities = %v, want %v", got, want)
	}
}

func TestSeveritiesRejectsAnotherRecord(t *testing.T) {
	ls := newListServer(t)
	ls.mu.Lock()
	ls.records["CVE-2026-123007"] = recordJSON("CVE-2026-1", "PUBLISHED", "CRITICAL")
	ls.mu.Unlock()
	s, _ := newSource(t, ls)
	if got := s.Severities(context.Background(), []string{"CVE-2026-123007"}); len(got) != 0 {
		t.Fatalf("Severities = %v from the record of another CVE", got)
	}
}

// manyIDs registers n published records of severity HIGH and returns their IDs.
func manyIDs(ls *listServer, from, n int) []string {
	var ids []string
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("CVE-2026-%04d", from+i)
		ids = append(ids, id)
		ls.set(id, "PUBLISHED", "HIGH")
	}
	return ids
}

func TestSeveritiesRequestLimits(t *testing.T) {
	ls := newListServer(t)
	ids := manyIDs(ls, 1000, 9)
	s, c := newSource(t, ls)
	s.callLimit, s.cycleLimit = 3, 5
	ctx := context.Background()

	// One call asks for no more than its own limit, so a report that names
	// many IDs leaves requests for the next one; the cycle has a limit too.
	a := s.Severities(ctx, ids[:4])
	b := s.Severities(ctx, ids[4:8])
	if len(a) != 3 || len(b) != 2 || ls.count() != 5 {
		t.Fatalf("got %d and %d answers with %d requests, want 3 and 2 with 5", len(a), len(b), ls.count())
	}
	// An ID that was not looked up keeps that answer for the cycle.
	if got := s.Severities(ctx, ids[3:4]); len(got) != 0 || ls.count() != 5 {
		t.Fatalf("an ID over the limit was answered later in the cycle: %v", got)
	}
	// What was read stays usable in a later cycle that has no requests left
	// when it gets to it, and the next cycle looks up the rest.
	c.t = c.t.Add(24 * time.Hour)
	s.BeginCycle()
	s.callLimit, s.cycleLimit = 9, 4
	got := s.Severities(ctx, ids)
	if len(got) != 9 {
		t.Fatalf("Severities = %d answers, want 9: 5 read before (4 of them again now) and 4 new", len(got))
	}
}

func TestSeveritiesKeepsABoundedNumberOfAnswers(t *testing.T) {
	ls := newListServer(t)
	known := manyIDs(ls, 1000, 2)
	s, c := newSource(t, ls)
	ctx := context.Background()
	s.Severities(ctx, known)
	requests := ls.count()

	// The next cycle starts with a report naming more IDs than a cycle keeps
	// answers for.
	c.t = c.t.Add(time.Hour)
	s.BeginCycle()
	s.idLimit = 3
	flood := manyIDs(ls, 5000, 10)
	if got := s.Severities(ctx, flood); len(got) != 3 {
		t.Fatalf("Severities = %d answers for the flood, want 3", len(got))
	}
	if len(s.cycle) != 3 {
		t.Fatalf("the cycle keeps %d answers, want 3", len(s.cycle))
	}
	if n := ls.count() - requests; n != 3 {
		t.Fatalf("%d requests for the flood, want 3", n)
	}
	// An ID read in an earlier cycle is still answered, from the cache and
	// the same way every time; one never read is not, and nothing is asked.
	for i := 0; i < 2; i++ {
		got := s.Severities(ctx, append([]string{flood[9]}, known...))
		if len(got) != 2 || got[known[0]] != "HIGH" || got[known[1]] != "HIGH" {
			t.Fatalf("past the limit Severities = %v, want the two answers read earlier", got)
		}
	}
	if n := ls.count() - requests; n != 3 {
		t.Fatalf("%d requests, want 3: an ID past the limit was asked for", n)
	}
}

func TestSeveritiesStopsAtTheDeadline(t *testing.T) {
	ls := newListServer(t)
	ls.set("CVE-2026-123007", "PUBLISHED", "CRITICAL")
	s, _ := newSource(t, ls)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got := s.Severities(ctx, []string{"CVE-2026-123007"}); len(got) != 0 {
		t.Fatalf("Severities = %v with a cancelled context", got)
	}
	// The answer of the cycle stays "none", so later scans agree with it.
	if got := s.Severities(context.Background(), []string{"CVE-2026-123007"}); len(got) != 0 {
		t.Fatalf("Severities = %v later in the same cycle, want none", got)
	}
}

func TestSeveritiesTimeLimitOfACall(t *testing.T) {
	// Every record takes 60ms; a call may take 150ms.
	slow := map[string]string{}
	var mu sync.Mutex
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requests++
		body := slow[strings.TrimSuffix(filepath.Base(r.URL.Path), ".json")]
		mu.Unlock()
		select {
		case <-time.After(60 * time.Millisecond):
		case <-r.Context().Done():
			return
		}
		fmt.Fprint(w, body)
	}))
	t.Cleanup(srv.Close)
	var ids []string
	for i := 0; i < 20; i++ {
		id := fmt.Sprintf("CVE-2026-%04d", 1000+i)
		ids = append(ids, id)
		slow[id] = recordJSON(id, "PUBLISHED", "HIGH")
	}
	s := &Source{CacheDir: filepath.Join(t.TempDir(), "cve-records"), BaseURL: srv.URL + "/cves/", Log: quiet, timeout: 150 * time.Millisecond}

	start := time.Now()
	got := s.Severities(context.Background(), ids)
	if took := time.Since(start); took > 2*time.Second {
		t.Fatalf("the call took %s with a limit of 150ms", took)
	}
	if len(got) == 0 || len(got) >= len(ids) {
		t.Fatalf("%d of %d answers, want some and not all", len(got), len(ids))
	}
	mu.Lock()
	n := requests
	mu.Unlock()
	if n >= len(ids) {
		t.Fatalf("%d requests: the call did not stop at its time limit", n)
	}
	// Later in the cycle the same answers, without another request.
	if again := s.Severities(context.Background(), ids); !reflect.DeepEqual(again, got) {
		t.Fatalf("answers changed within the cycle: %d then %d", len(got), len(again))
	}
	// The next cycle reads the rest.
	s.BeginCycle()
	s.timeout = time.Minute
	if got := s.Severities(context.Background(), ids); len(got) != len(ids) {
		t.Fatalf("the next cycle answered %d of %d", len(got), len(ids))
	}
}

func TestAFullCacheTakesNoNewAnswer(t *testing.T) {
	ls := newListServer(t)
	known := manyIDs(ls, 1000, 2)
	s, c := newSource(t, ls)
	s.cacheLimit = 2
	ctx := context.Background()
	if got := s.Severities(ctx, known); len(got) != 2 {
		t.Fatalf("Severities = %v", got)
	}

	// The cache is full. A new ID is not looked up at all: an answer that
	// cannot be kept would be gone again the first time its record cannot be
	// read, and the finding with it.
	more := manyIDs(ls, 5000, 3)
	for day := 1; day <= 3; day++ {
		c.t = c.t.Add(24 * time.Hour)
		s.BeginCycle()
		before := ls.count()
		got := s.Severities(ctx, append(append([]string(nil), more...), known...))
		if len(got) != 2 || got[known[0]] != "HIGH" || got[known[1]] != "HIGH" {
			t.Fatalf("day %d: Severities = %v, want the two kept answers only", day, got)
		}
		if n := ls.count() - before; n != 2 {
			t.Fatalf("day %d: %d requests, want 2 (the kept answers, refreshed)", day, n)
		}
	}
	// The kept answers are still there when their records cannot be read.
	for _, id := range known {
		ls.fail(id, http.StatusInternalServerError)
	}
	c.t = c.t.Add(24 * time.Hour)
	s.BeginCycle()
	if got := s.Severities(ctx, append(append([]string(nil), more...), known...)); len(got) != 2 {
		t.Fatalf("with the records unreadable Severities = %v, want the two kept answers", got)
	}
	// Once an answer is no longer asked for it leaves the cache, and makes
	// room for a new one.
	for _, id := range known {
		ls.fail(id, 0)
	}
	for day := 0; day < 32; day++ {
		c.t = c.t.Add(24 * time.Hour)
		s.BeginCycle()
		s.Severities(ctx, append([]string{known[0]}, more...))
	}
	got := s.Severities(ctx, more)
	if len(got) != 1 {
		t.Fatalf("after one answer left the cache Severities = %v, want one new answer", got)
	}
}

func TestAnswersPastTheCycleLimitStayInUse(t *testing.T) {
	ls := newListServer(t)
	known := manyIDs(ls, 1000, 2)
	s, c := newSource(t, ls)
	ctx := context.Background()
	s.Severities(ctx, known)
	flood := manyIDs(ls, 5000, 3)

	// For longer than an unused answer is kept, every cycle starts with a
	// report that takes all the answers a cycle keeps, and the two known
	// IDs are asked for after it. They are used every day and must stay.
	s.idLimit = 3
	for day := 1; day <= 40; day++ {
		c.t = c.t.Add(24 * time.Hour)
		s.BeginCycle()
		s.Severities(ctx, flood)
		got := s.Severities(ctx, known)
		if len(got) != 2 {
			t.Fatalf("day %d: Severities = %v, want the two answers read earlier", day, got)
		}
	}
	// A new process finds them in the cache file.
	s2 := &Source{CacheDir: s.CacheDir, BaseURL: s.BaseURL, Now: c.now, Log: quiet, idLimit: 3}
	s2.Severities(ctx, flood)
	if got := s2.Severities(ctx, known); len(got) != 2 {
		t.Fatalf("a new process: Severities = %v", got)
	}
}

func TestCachePruning(t *testing.T) {
	ls := newListServer(t)
	ls.set("CVE-2026-1111", "PUBLISHED", "HIGH")
	ls.set("CVE-2026-2222", "PUBLISHED", "HIGH")
	s, c := newSource(t, ls)
	ctx := context.Background()
	s.Severities(ctx, []string{"CVE-2026-1111", "CVE-2026-2222"})

	// Only one of them is asked for from now on.
	for i := 0; i < 32; i++ {
		c.t = c.t.Add(24 * time.Hour)
		s.BeginCycle()
		s.Severities(ctx, []string{"CVE-2026-1111"})
	}
	data, err := os.ReadFile(filepath.Join(s.CacheDir, cacheFile))
	if err != nil {
		t.Fatal(err)
	}
	var cache map[string]entry
	if err := json.Unmarshal(data, &cache); err != nil {
		t.Fatal(err)
	}
	if _, ok := cache["CVE-2026-2222"]; ok || len(cache) != 1 {
		t.Fatalf("cache = %v, want only CVE-2026-1111", cache)
	}
}

func TestLoadIgnoresABadCache(t *testing.T) {
	ls := newListServer(t)
	ls.set("CVE-2026-123007", "PUBLISHED", "CRITICAL")
	s, c := newSource(t, ls)
	if err := os.MkdirAll(s.CacheDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// An entry with a severity that is not a level, and an ID that is not one.
	bad := fmt.Sprintf(`{"CVE-2026-123007":{"severity":"URGENT","fetched":%q,"used":%q},"x":{"severity":"HIGH"}}`,
		c.t.Format(time.RFC3339), c.t.Format(time.RFC3339))
	if err := os.WriteFile(filepath.Join(s.CacheDir, cacheFile), []byte(bad), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := s.Severities(context.Background(), []string{"CVE-2026-123007"}); got["CVE-2026-123007"] != "CRITICAL" {
		t.Fatalf("Severities = %v, want the record's answer", got)
	}
	if err := os.WriteFile(filepath.Join(s.CacheDir, cacheFile), []byte("{"), 0o644); err != nil {
		t.Fatal(err)
	}
	s.BeginCycle()
	if got := s.Severities(context.Background(), []string{"CVE-2026-123007"}); got["CVE-2026-123007"] != "CRITICAL" {
		t.Fatalf("with an unreadable cache Severities = %v", got)
	}
}

// levelCounter is a slog handler that counts records by level.
type levelCounter struct {
	mu     sync.Mutex
	counts map[slog.Level]int
}

func (h *levelCounter) Enabled(context.Context, slog.Level) bool { return true }
func (h *levelCounter) WithAttrs([]slog.Attr) slog.Handler       { return h }
func (h *levelCounter) WithGroup(string) slog.Handler            { return h }
func (h *levelCounter) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.counts == nil {
		h.counts = map[slog.Level]int{}
	}
	h.counts[r.Level]++
	return nil
}

func (h *levelCounter) warnings() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.counts[slog.LevelWarn]
}

func TestAMissingRecordIsNotAWarning(t *testing.T) {
	ls := newListServer(t)
	ls.set("CVE-2026-123007", "PUBLISHED", "CRITICAL")
	s, c := newSource(t, ls)
	logs := &levelCounter{}
	s.Log = slog.New(logs)
	ctx := context.Background()

	// CVE-2026-80256 has no record: the scanner's database names IDs the
	// list never published. That is the same every cycle and nothing to
	// warn about.
	ids := []string{"CVE-2026-123007", "CVE-2026-80256"}
	for day := 0; day < 3; day++ {
		got := s.Severities(ctx, ids)
		if len(got) != 1 || got["CVE-2026-123007"] != "CRITICAL" {
			t.Fatalf("day %d: Severities = %v", day, got)
		}
		c.t = c.t.Add(24 * time.Hour)
		s.BeginCycle()
	}
	if n := logs.warnings(); n != 0 {
		t.Fatalf("%d warnings for an ID without a record, want none", n)
	}

	// A record that exists and cannot be read is still warned about.
	ls.fail("CVE-2026-9000", http.StatusInternalServerError)
	s.Severities(ctx, []string{"CVE-2026-9000"})
	if n := logs.warnings(); n != 1 {
		t.Fatalf("%d warnings for an unreadable record, want 1", n)
	}
}
