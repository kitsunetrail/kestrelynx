package main

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The logs under testdata/collected were taken from a running case
// container: started, signalled, and copied out of it. They are here
// because the shapes the test programs actually write and the shapes the
// reader accepts have to be the same shapes, and only a log that came out
// of a real run can establish that.
//
// The difference that motivates it: a program reading a process's start
// time out of the process table has a number, and writes a number. The
// hand-written records in this directory write it as text. A reader built
// against the hand-written ones alone accepts them and refuses every log
// the measurement would actually collect.
const collectedCase13Occurrences = "testdata/collected/13.occurrences.jsonl"
const collectedCase13Usage = "testdata/collected/13.usage.jsonl"

// readJSONL reads a fixture the case containers write: one JSON object per
// line, which is what appending to a log from a shell produces.
func readJSONL(t *testing.T, path string) []json.RawMessage {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("read collected log: %v", err)
	}
	defer f.Close()
	var out []json.RawMessage
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		out = append(out, json.RawMessage(line))
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("read collected log: %v", err)
	}
	return out
}

// buildGTBFromCollectedLogs assembles a ground-truth record the way a case
// runner does: the occurrence log and the usage log go in as they came out
// of the container, with no rewriting.
func buildGTBFromCollectedLogs(t *testing.T) []byte {
	t.Helper()
	gtb := map[string]any{
		"case_id":    "13",
		"kind":       "usage_log",
		"clock_base": "wall clock on both sides",
		"occurrences": func() []json.RawMessage {
			return readJSONL(t, collectedCase13Occurrences)
		}(),
		"usage_log": func() []json.RawMessage {
			var events []json.RawMessage
			for _, line := range readJSONL(t, collectedCase13Usage) {
				var probe struct {
					Event string `json:"event"`
				}
				if err := json.Unmarshal(line, &probe); err != nil {
					continue
				}
				if probe.Event == "stage" {
					continue // bookkeeping, not a usage event
				}
				events = append(events, line)
			}
			return events
		}(),
		"path_packages": []map[string]any{
			{"path": "/usr/bin/curl", "packages": []map[string]string{{"package": "curl", "class": "os"}}},
			{"path": "/usr/bin/git", "packages": []map[string]string{{"package": "git", "class": "os"}}},
		},
	}
	data, err := json.MarshalIndent(gtb, "", "  ")
	if err != nil {
		t.Fatalf("assemble ground truth: %v", err)
	}
	return data
}

// TestCollectedFixtureLogIsReadableAsGroundTruth runs a log taken from a
// real case container through the reader that consumes it.
func TestCollectedFixtureLogIsReadableAsGroundTruth(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gtb.json")
	if err := os.WriteFile(path, buildGTBFromCollectedLogs(t), 0o644); err != nil {
		t.Fatal(err)
	}

	gtb, err := readGTB(path)
	if err != nil {
		t.Fatalf("a ground-truth record assembled from a collected log was refused: %v", err)
	}
	if len(gtb.Occurrences) == 0 {
		t.Fatal("the collected log produced no occurrences")
	}
	for _, occ := range gtb.Occurrences {
		if occ.ID == "" {
			t.Error("an occurrence came back without its identifier")
		}
		if occ.Kind != occurrenceExec {
			t.Errorf("occurrence %s has kind %q, want an execution", occ.ID, occ.Kind)
		}
		// The start time is what the whole comparison across the two
		// process number spaces rests on. It is written as a number by the
		// program that read it, and it has to survive that.
		if occ.Starttime.empty() {
			t.Errorf("occurrence %s lost its process generation start time", occ.ID)
		}
		if occ.ContainerID == "" {
			t.Errorf("occurrence %s does not say which container it happened in", occ.ID)
		}
		if occ.PID == 0 || occ.TID == 0 {
			t.Errorf("occurrence %s has no process or thread number", occ.ID)
		}
	}
	if len(gtb.UsageLog) == 0 {
		t.Error("the collected usage log produced no events")
	}
	for _, ev := range gtb.UsageLog {
		if ev.Timestamp.IsZero() {
			t.Errorf("a usage event from the collected log has no time: %+v", ev)
		}
	}
}

// TestCollectedLogWorksThroughTheWholeTruthPipeline takes the same
// collected log all the way to a per-package truth, which is what a
// measurement does with it.
func TestCollectedLogWorksThroughTheWholeTruthPipeline(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gtb.json")
	if err := os.WriteFile(path, buildGTBFromCollectedLogs(t), 0o644); err != nil {
		t.Fatal(err)
	}
	gtb, err := readGTB(path)
	if err != nil {
		t.Fatal(err)
	}

	// A window spanning everything the log recorded.
	first := gtb.Occurrences[0].Timestamp
	last := gtb.Occurrences[len(gtb.Occurrences)-1].Timestamp
	start, end := first.Add(-time.Minute), last.Add(time.Minute)

	truth := buildGTBTruth(gtb, scopeSet([]string{"curl", "git"}), start, end)
	for _, pkg := range []string{"curl", "git"} {
		if !truth.Covered[pkg] {
			t.Errorf("%s was not decided from the collected log: %s", pkg, truth.UndeterminedWhy[pkg])
			continue
		}
		if !truth.Used[pkg] {
			t.Errorf("%s came back as unused, but the collected log records it being run", pkg)
		}
	}

	// And the same log is refused as an observation, in both directions.
	if _, err := readEventLog(path); err == nil {
		t.Error("a ground-truth record assembled from a collected log was read as an event log")
	}
}

// TestWindowBoundaryDoesNotMoveTheUsageInterval checks that a run's usage
// interval sits where the run did.
//
// An execution's outcome is only settled once it has finished, but the run
// happened when it started. Writing the later instant instead would slide
// every interval forward by the run's duration — and a window that ends
// inside a run would then conclude the package was not used, when the log
// itself says it was being used at that moment.
//
// The check is made at the boundary, since a window with a minute of slack
// on either side cannot see the difference.
func TestWindowBoundaryDoesNotMoveTheUsageInterval(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gtb.json")
	if err := os.WriteFile(path, buildGTBFromCollectedLogs(t), 0o644); err != nil {
		t.Fatal(err)
	}
	gtb, err := readGTB(path)
	if err != nil {
		t.Fatal(err)
	}

	// The first execution and the instant it ended, from the log itself.
	var firstExec, firstExit time.Time
	for _, ev := range gtb.UsageLog {
		if ev.Path != "/usr/bin/curl" {
			continue
		}
		switch {
		case ev.Event == "exec" && firstExec.IsZero():
			firstExec = ev.Timestamp
		case ev.Event == "exit" && !firstExec.IsZero() && firstExit.IsZero():
			firstExit = ev.Timestamp
		}
	}
	if firstExec.IsZero() || firstExit.IsZero() {
		t.Fatal("the collected log has no complete first run of curl to check against")
	}
	if !firstExit.After(firstExec) {
		t.Fatalf("the collected run ends at or before it starts: %s .. %s", firstExec, firstExit)
	}

	scope := scopeSet([]string{"curl"})
	cases := []struct {
		name        string
		start, end  time.Time
		wantUsed    bool
		wantSettled bool
		explanation string
	}{
		{
			name:  "a window ending in the middle of the run",
			start: firstExec.Add(-time.Second),
			end:   firstExec.Add(firstExit.Sub(firstExec) / 2),
			// The run was under way at the moment the window closed, so it
			// was in use inside the window.
			wantUsed: true, wantSettled: true,
			explanation: "the log says the program was running when the window closed",
		},
		{
			name:  "a window opening in the middle of the run",
			start: firstExec.Add(firstExit.Sub(firstExec) / 2),
			end:   firstExit.Add(time.Second),
			// Likewise from the other side.
			wantUsed: true, wantSettled: true,
			explanation: "the log says the program was already running when the window opened",
		},
		{
			name:  "a window closing before the run began",
			start: firstExec.Add(-2 * time.Second),
			end:   firstExec.Add(-time.Second),
			// Nothing in the log happened inside it, and non-use is still
			// not concluded: this log names library paths the independent
			// resolution does not map to a package, which withdraws the
			// completeness the conclusion would need. Proving use takes
			// one positive; proving non-use takes a log that covers
			// everything.
			wantUsed: false, wantSettled: false,
			explanation: "non-use needs a log that covers everything, and this one names paths nothing maps",
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			truth := buildGTBTruth(gtb, scope, tt.start, tt.end)
			if !truth.Covered["curl"] {
				if tt.wantSettled {
					t.Fatalf("curl was left undecided: %s", truth.UndeterminedWhy["curl"])
				}
				return
			}
			if got := truth.Used["curl"]; got != tt.wantUsed {
				t.Errorf("curl used = %v, want %v: %s", got, tt.wantUsed, tt.explanation)
			}
		})
	}
}
