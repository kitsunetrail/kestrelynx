package worker

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

// tableDoc is the table of the build as a document a test can change.
func tableDoc(t *testing.T) map[string]any {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(runtimesJSON, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

func docRows(doc map[string]any) []any { return doc["runtimes"].([]any) }

// docRow returns the row with the id, as a map the test can change.
func docRow(t *testing.T, doc map[string]any, id string) map[string]any {
	t.Helper()
	for _, r := range docRows(doc) {
		if m := r.(map[string]any); m["id"] == id {
			return m
		}
	}
	t.Fatalf("no row %s", id)
	return nil
}

// copyRow returns a deep copy of the row with the id.
func copyRow(t *testing.T, doc map[string]any, id string) map[string]any {
	t.Helper()
	b, err := json.Marshal(docRow(t, doc, id))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func encodeDoc(t *testing.T, doc map[string]any) []byte {
	t.Helper()
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func tableNow(t *testing.T) time.Time {
	t.Helper()
	u := EmbeddedRuntimeTable().Updated
	if u.IsZero() {
		t.Fatal("the table of the build has no updated")
	}
	return u.Add(time.Hour)
}

func ids(specs []RuntimeSpec) []string {
	out := make([]string, len(specs))
	for i, r := range specs {
		out[i] = r.ID
	}
	return out
}

// TestRuntimeTablePublishable is what the publishing workflow runs before it
// publishes runtimes.json: the file is a valid table of the build, it says
// when it was updated, and a build that fetches it now uses every row of it.
// The time is the real one: a table dated in the future would be refused by
// the builds that fetch it, and could not be corrected by one dated now.
func TestRuntimeTablePublishable(t *testing.T) {
	built, err := parseRuntimeTable(runtimesJSON)
	if err != nil {
		t.Fatalf("the table is not a table of the build: %v", err)
	}
	if built.Updated.IsZero() {
		t.Fatal("the table does not say when it was updated")
	}
	if now := time.Now(); built.Updated.After(now) {
		t.Fatalf("the table is dated %s, after now (%s)", built.Updated.Format(time.RFC3339), now.UTC().Format(time.RFC3339))
	}
	got, dropped, err := AdoptRuntimeTable(runtimesJSON, time.Now())
	if err != nil {
		t.Fatalf("a build that fetches the table refuses it: %v", err)
	}
	if len(dropped) != 0 {
		t.Fatalf("a build that fetches the table leaves rows out: %v", dropped)
	}
	if !got.Updated.Equal(built.Updated) || !reflect.DeepEqual(got.Runtimes(), built.Runtimes()) {
		t.Fatal("the fetched table differs from the table of the build")
	}
}

func TestAdoptRuntimeTableWholeTable(t *testing.T) {
	now := tableNow(t)
	cases := map[string]func(doc map[string]any) []byte{
		"not json":           func(map[string]any) []byte { return []byte("{") },
		"another schema":     func(d map[string]any) []byte { d["schema"] = 2; return nil },
		"no updated":         func(d map[string]any) []byte { delete(d, "updated"); return nil },
		"updated not UTC":    func(d map[string]any) []byte { d["updated"] = "2026-11-16T11:58:54+09:00"; return nil },
		"updated not a time": func(d map[string]any) []byte { d["updated"] = "yesterday"; return nil },
		"updated far ahead": func(d map[string]any) []byte {
			d["updated"] = now.Add(25 * time.Hour).UTC().Format(time.RFC3339)
			return nil
		},
		"too large": func(d map[string]any) []byte {
			d["padding"] = strings.Repeat("x", MaxRuntimeTableBytes)
			return nil
		},
		"too many rows": func(d map[string]any) []byte {
			rows := docRows(d)
			for len(rows) <= maxRuntimeRows {
				rows = append(rows, map[string]any{"id": "x", "kind": "future"})
			}
			d["runtimes"] = rows
			return nil
		},
		"row is not an object": func(d map[string]any) []byte { d["runtimes"] = append(docRows(d), "node24"); return nil },
	}
	for name, change := range cases {
		doc := tableDoc(t)
		raw := change(doc)
		if raw == nil {
			raw = encodeDoc(t, doc)
		}
		if _, _, err := AdoptRuntimeTable(raw, now); !errors.Is(err, ErrRuntimeTable) {
			t.Errorf("%s: err = %v, want the table refused", name, err)
		}
	}

	// A time less than a day ahead is the clock of the publisher running fast;
	// a day ahead is where the limit is.
	doc := tableDoc(t)
	doc["updated"] = now.Add(24*time.Hour - time.Second).UTC().Format(time.RFC3339)
	if _, _, err := AdoptRuntimeTable(encodeDoc(t, doc), now); err != nil {
		t.Errorf("a table dated just under 24 hours ahead is refused: %v", err)
	}
	doc["updated"] = now.Add(24 * time.Hour).UTC().Format(time.RFC3339)
	if _, _, err := AdoptRuntimeTable(encodeDoc(t, doc), now); !errors.Is(err, ErrRuntimeTable) {
		t.Errorf("a table dated exactly 24 hours ahead: err = %v, want it refused", err)
	}
}

func TestAdoptRuntimeTableRefusesBadRows(t *testing.T) {
	now := tableNow(t)
	many := func(n int) []any {
		out := make([]any, n)
		for i := range out {
			out[i] = "/tmp"
		}
		return out
	}
	cases := map[string]func(t *testing.T, d map[string]any){
		"image of another repository": func(t *testing.T, d map[string]any) { docRow(t, d, "node24")["image"] = "evil/node" },
		"image of another kind":       func(t *testing.T, d map[string]any) { docRow(t, d, "node24")["image"] = "python" },
		"bad index digest":            func(t *testing.T, d map[string]any) { docRow(t, d, "node24")["index_digest"] = "sha256:abc" },
		"no arm64 digest": func(t *testing.T, d map[string]any) {
			delete(docRow(t, d, "node24")["platforms"].(map[string]any), "linux/arm64")
		},
		"version off its series": func(t *testing.T, d map[string]any) { docRow(t, d, "node24")["version"] = "22.1.0" },
		"kind against its id":    func(t *testing.T, d map[string]any) { docRow(t, d, "node24")["kind"] = "python" },
		"series against its id":  func(t *testing.T, d map[string]any) { docRow(t, d, "node24")["series"] = "22" },
		"repeated id": func(t *testing.T, d map[string]any) {
			d["runtimes"] = append(docRows(d), copyRow(t, d, "node24"))
		},
		"gradle without an image": func(t *testing.T, d map[string]any) {
			r := docRow(t, d, "gradle9.8.2-jdk21")
			for _, k := range []string{"image", "tag", "exact_tag", "index_digest", "platforms", "covered_paths", "volumes", "tested"} {
				delete(r, k)
			}
		},
		"gradle version against its id": func(t *testing.T, d map[string]any) { docRow(t, d, "gradle9.8.2-jdk21")["version"] = "9.8.3" },
		"volume that is not covered": func(t *testing.T, d map[string]any) {
			r := docRow(t, d, "gradle9.8.2-jdk21")
			r["volumes"] = []any{"/home/gradle"}
			r["covered_paths"] = []any{"/tmp", "/var/tmp"}
		},
		"no covered path": func(t *testing.T, d map[string]any) { docRow(t, d, "node24")["covered_paths"] = []any{} },
		"a path listed twice": func(t *testing.T, d map[string]any) {
			docRow(t, d, "node24")["covered_paths"] = []any{"/tmp", "/var/tmp", "/run/lock", "/home/gradle", "/home/gradle"}
		},
		// A row this build leaves out is held to the limits all the same.
		"a row of an unknown kind that is very large": func(t *testing.T, d map[string]any) {
			var notes []any
			for i := 0; i < maxCoveredPaths; i++ {
				notes = append(notes, []any{strings.Repeat("x", maxRuntimeString), strings.Repeat("y", maxRuntimeString), strings.Repeat("z", maxRuntimeString), strings.Repeat("w", maxRuntimeString), strings.Repeat("v", maxRuntimeString)})
			}
			d["runtimes"] = append(docRows(d), map[string]any{"id": "ruby3.5", "kind": "ruby", "notes": notes})
		},
		"a row of an unknown kind with a long value": func(t *testing.T, d map[string]any) {
			d["runtimes"] = append(docRows(d), map[string]any{"id": "ruby3.5", "kind": "ruby", "note": strings.Repeat("x", maxRuntimeString+1)})
		},
		"a row of an unknown kind with too many paths": func(t *testing.T, d map[string]any) {
			d["runtimes"] = append(docRows(d), map[string]any{"id": "ruby3.5", "kind": "ruby", "covered_paths": many(maxCoveredPaths + 1)})
		},
		"a row of an unknown kind with too many volumes": func(t *testing.T, d map[string]any) {
			d["runtimes"] = append(docRows(d), map[string]any{"id": "ruby3.5", "kind": "ruby", "volumes": many(maxVolumes + 1)})
		},
		"a row of an unknown kind with too many platforms": func(t *testing.T, d map[string]any) {
			d["runtimes"] = append(docRows(d), map[string]any{"id": "ruby3.5", "kind": "ruby", "tested": map[string]any{"a": "", "b": "", "c": "", "d": "", "e": ""}})
		},
		"a row of an unknown kind that nests deep": func(t *testing.T, d map[string]any) {
			var v any = "x"
			for i := 0; i < maxRowDepth+2; i++ {
				v = []any{v}
			}
			d["runtimes"] = append(docRows(d), map[string]any{"id": "ruby3.5", "kind": "ruby", "deep": v})
		},
		"too many paths": func(t *testing.T, d map[string]any) {
			docRow(t, d, "node24")["covered_paths"] = many(maxCoveredPaths + 1)
		},
		"too many volumes": func(t *testing.T, d map[string]any) {
			docRow(t, d, "gradle9.8.2-jdk21")["volumes"] = many(maxVolumes + 1)
		},
		"a very long value": func(t *testing.T, d map[string]any) {
			docRow(t, d, "node24")["tag"] = strings.Repeat("a", maxRuntimeString+1)
		},
		"a field of another type": func(t *testing.T, d map[string]any) { docRow(t, d, "node24")["version"] = 24 },
		"too many platforms": func(t *testing.T, d map[string]any) {
			p := docRow(t, d, "node24")["platforms"].(map[string]any)
			for _, k := range []string{"a", "b", "c"} {
				p[k] = "sha256:" + strings.Repeat("0", 64)
			}
		},
	}
	for name, change := range cases {
		doc := tableDoc(t)
		change(t, doc)
		if _, _, err := AdoptRuntimeTable(encodeDoc(t, doc), now); !errors.Is(err, ErrRuntimeTable) {
			t.Errorf("%s: err = %v, want the table refused", name, err)
		}
	}
}

// A table with a great many paths and volumes must be refused by its size
// before the comparison of the two lists, which would otherwise take time in
// proportion to their product.
func TestAdoptRuntimeTableBoundsWork(t *testing.T) {
	doc := tableDoc(t)
	r := docRow(t, doc, "node24")
	const n = 20000
	paths, volumes := make([]any, n), make([]any, n)
	for i := range paths {
		paths[i] = "/p" + strings.Repeat("0", 6)
		volumes[i] = "/p" + strings.Repeat("0", 6)
	}
	r["covered_paths"], r["volumes"], r["volumes_empty"] = paths, volumes, false
	start := time.Now()
	if _, _, err := AdoptRuntimeTable(encodeDoc(t, doc), tableNow(t)); !errors.Is(err, ErrRuntimeTable) {
		t.Fatalf("err = %v, want the table refused", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("refusing the table took %s", d)
	}
}

func TestAdoptRuntimeTableLeavesOutWhatTheBuildCannotRun(t *testing.T) {
	now := tableNow(t)
	doc := tableDoc(t)
	built := len(docRows(doc))

	future := map[string]any{"id": "ruby3.5", "kind": "ruby", "series": map[string]any{"shape": "unknown"}, "image": 7}
	py4 := copyRow(t, doc, "python3.13")
	py4["id"], py4["series"], py4["version"] = "python4.0", "4.0", "4.0.1"
	uncovered := copyRow(t, doc, "node24")
	uncovered["id"], uncovered["series"], uncovered["version"] = "node30", "30", "30.1.0"
	uncovered["covered_paths"] = []any{"/tmp", "/var/tmp", "/run/lock", "/srv/cache"}
	doc["runtimes"] = append(docRows(doc), future, py4, uncovered)

	got, dropped, err := AdoptRuntimeTable(encodeDoc(t, doc), now)
	if err != nil {
		t.Fatalf("the table is refused: %v", err)
	}
	if got.Len() != built {
		t.Errorf("%d rows are used, want the %d the build can run", got.Len(), built)
	}
	want := []DroppedRuntime{
		{ID: "node30", Reason: "a path this build does not cover"},
		{ID: "python4.0", Reason: "an id this build cannot read"},
		{ID: "ruby3.5", Reason: "a kind this build does not have"},
	}
	if !reflect.DeepEqual(dropped, want) {
		t.Errorf("left out %v, want %v", dropped, want)
	}
}

func TestAdoptRuntimeTableTakesNewRowsAndRemovals(t *testing.T) {
	now := tableNow(t)
	doc := tableDoc(t)

	// A new series of each language and a new pair of Gradle and a JDK.
	node := copyRow(t, doc, "node24")
	node["id"], node["series"], node["version"], node["exact_tag"] = "node28", "28", "28.0.1", "28.0.1-trixie-slim"
	golang := copyRow(t, doc, "golang1.27")
	golang["id"], golang["series"], golang["version"] = "golang1.28", "1.28", "1.28.0"
	python := copyRow(t, doc, "python3.15")
	python["id"], python["series"], python["version"] = "python3.16", "3.16", "3.16.0"
	gradle := copyRow(t, doc, "gradle9.8.2-jdk21")
	gradle["id"], gradle["version"], gradle["tag"], gradle["exact_tag"] = "gradle9.10.0-jdk25", "9.10.0", "9.10.0-jdk25", "9.10.0-jdk25"
	gradle["jdk"] = "25"
	// An older version of a row and a row taken out are taken as they are.
	docRow(t, doc, "node22")["version"] = "22.0.1"
	var rows []any
	for _, r := range docRows(doc) {
		if r.(map[string]any)["id"] != "python3.11" {
			rows = append(rows, r)
		}
	}
	// A row that keeps its dates and loses its image.
	old := docRow(t, doc, "golang1.26")
	for _, k := range []string{"image", "tag", "exact_tag", "index_digest", "platforms", "covered_paths", "volumes_empty", "version", "tested"} {
		delete(old, k)
	}
	doc["runtimes"] = append(rows, node, golang, python, gradle)

	got, dropped, err := AdoptRuntimeTable(encodeDoc(t, doc), now)
	if err != nil || len(dropped) != 0 {
		t.Fatalf("err = %v, left out %v", err, dropped)
	}
	t.Cleanup(func() { SetRuntimeTable(EmbeddedRuntimeTable()) })
	SetRuntimeTable(got)

	for _, id := range []string{"node28", "golang1.28", "python3.16", "gradle9.10.0-jdk25"} {
		if r, ok := LookupRuntime(id); !ok || !r.HasImage() {
			t.Errorf("%s is not a runtime with an image", id)
		}
	}
	if r, _ := LookupRuntime("node22"); r.Version != "22.0.1" {
		t.Errorf("node22 is %s, want the version of the table", r.Version)
	}
	if _, ok := LookupRuntime("python3.11"); ok {
		t.Error("a row the table no longer has is still there")
	}
	if r, ok := LookupRuntime("golang1.26"); !ok || r.HasImage() {
		t.Error("a row that lost its image is gone or still has one")
	}
	// The record of the test came with the copied row, so the new pair is
	// found; without it the pair is in the table and is not run.
	if _, err := FindGradleRuntime("9.10.0", 25, "linux/amd64"); err != nil {
		t.Errorf("the new pair is not found: %v", err)
	}
	delete(gradle, "tested")
	got, _, err = AdoptRuntimeTable(encodeDoc(t, doc), now)
	if err != nil {
		t.Fatal(err)
	}
	SetRuntimeTable(got)
	if _, ok := LookupRuntime("gradle9.10.0-jdk25"); !ok {
		t.Error("a Gradle row without a test record is left out of the table")
	}
	if _, err := FindGradleRuntime("9.10.0", 25, "linux/amd64"); !errors.Is(err, ErrGradleVersionUnsupported) {
		t.Errorf("a Gradle row without a test record is run: %v", err)
	}
}

func TestRuntimeTableHandsOutCopies(t *testing.T) {
	r, ok := LookupRuntime("node24")
	if !ok {
		t.Fatal("no node24")
	}
	r.Platforms["linux/amd64"] = "changed"
	r.CoveredPaths[0] = "/changed"
	for _, row := range Runtimes() {
		if row.HasImage() {
			row.Platforms["linux/arm64"] = "changed"
		}
	}
	again, _ := LookupRuntime("node24")
	if again.Platforms["linux/amd64"] == "changed" || again.Platforms["linux/arm64"] == "changed" || again.CoveredPaths[0] == "/changed" {
		t.Fatal("a change to a copy reached the table")
	}
}

func TestCheckJobRuntime(t *testing.T) {
	j := goodJob()
	if err := CheckJobRuntime(*j); err != nil {
		t.Fatalf("a job of the table is refused: %v", err)
	}
	bad := map[string]func(*Job){
		"a runtime the table does not have": func(j *Job) { j.Runtime = Runtime{ID: "node98", Version: "98.0.1"} },
		"a runtime without an image":        func(j *Job) { j.Runtime = Runtime{ID: "node20", Version: "20.20.2"} },
		"another version than the row":      func(j *Job) { j.Runtime.Version = strings.Replace(j.Runtime.Version, ".", ".9", 1) },
		"a pip the row does not have":       func(j *Job) { j.Runtime.Pip = "26.2.1" },
	}
	for name, f := range bad {
		j := goodJob()
		f(j)
		if err := CheckJobRuntime(*j); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// The program in the work container is built without a table. What it checks
// of a job, and the command line it builds, must not need one.
func TestJobNeedsNoTable(t *testing.T) {
	j := goodJob() // made while the table is there: the test helpers read versions from it
	t.Cleanup(OverrideRuntimesForTest(nil))
	if len(Runtimes()) != 0 {
		t.Fatal("the table is not empty")
	}
	if err := j.Validate(); err != nil {
		t.Fatalf("a job is refused without a table: %v", err)
	}
	if _, err := Argv(*j, j.Steps[0]); err != nil {
		t.Fatalf("no command line without a table: %v", err)
	}
	// A series no table of this build has is still a runtime by its id.
	j.Runtime = Runtime{ID: "node98", Version: "98.0.1"}
	if err := j.Validate(); err != nil {
		t.Fatalf("a runtime that is one by its id is refused: %v", err)
	}
}

func TestRuntimeFromID(t *testing.T) {
	good := map[string]RuntimeSpec{
		"node24":            {ID: "node24", Kind: KindNode, Series: "24"},
		"python3.13":        {ID: "python3.13", Kind: KindPython, Series: "3.13"},
		"python3.9":         {ID: "python3.9", Kind: KindPython, Series: "3.9"},
		"golang1.26":        {ID: "golang1.26", Kind: KindGolang, Series: "1.26"},
		"gradle9.8.2-jdk21": {ID: "gradle9.8.2-jdk21", Kind: KindGradle, Series: "9", Version: "9.8.2", JDK: "21"},
		"gradle8.14-jdk17":  {ID: "gradle8.14-jdk17", Kind: KindGradle, Series: "8", Version: "8.14", JDK: "17"},
	}
	for id, want := range good {
		if got, ok := RuntimeFromID(id); !ok || !reflect.DeepEqual(got, want) {
			t.Errorf("%s: %+v, %v", id, got, ok)
		}
	}
	for _, id := range []string{
		"", "node", "node024", "node22.23", "node24 ", "Node24", "nodejs24", "python3", "python4.0", "python3.013", "python3.13.1",
		"golang2.0", "golang1", "go1.26", "gradle9.8.2", "gradle9-jdk21", "gradle9.8.2-jdk", "gradle9.8.2-jdk021", "gradle9.8.2-jdk21-alpine",
		"gradle-jdk21", "ruby3.5", "node24\n", strings.Repeat("node2", 20),
	} {
		if got, ok := RuntimeFromID(id); ok {
			t.Errorf("%q is read as %+v", id, got)
		}
	}
	// Every row of the table of the build is read as what the row says.
	for _, r := range Runtimes() {
		got, ok := RuntimeFromID(r.ID)
		if !ok || got.Kind != r.Kind || got.Series != r.Series || got.JDK != r.JDK || (r.Kind == KindGradle && got.Version != r.Version) {
			t.Errorf("%s is read as %+v", r.ID, got)
		}
	}
}
