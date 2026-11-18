package worker

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"time"
)

// Limits of a runtime table that was fetched or read back from the state
// directory. They are checked before a row is looked at more closely, so that
// what a table costs to check is bounded by its size.
const (
	// MaxRuntimeTableBytes is the largest table that is read at all.
	MaxRuntimeTableBytes = 4 << 20
	maxRuntimeRows       = 2048
	// maxRuntimeRowBytes bounds one row as it is written, whatever it holds: a
	// row of a kind this build does not have is left out without being read
	// further, and is bounded all the same.
	maxRuntimeRowBytes = 16 << 10
	maxRuntimeString   = 256
	maxCoveredPaths    = 16
	maxVolumes         = 8
	maxPlatformKeys    = 4
	// maxUpdatedAhead is how far in the future a table may not say it was
	// made: a table dated this far ahead or further is refused.
	// Only a table newer than the one in use replaces it, so a time far ahead
	// would keep every later table out.
	maxUpdatedAhead = 24 * time.Hour
)

// ErrRuntimeTable marks a table that is not used at all.
var ErrRuntimeTable = errors.New("runtime table refused")

// DroppedRuntime is a row of a fetched table that this build leaves out
// because it cannot run it. The other rows are used.
type DroppedRuntime struct {
	ID     string
	Reason string
}

// AdoptRuntimeTable reads a runtime table that did not come with the build: one
// fetched from the registry, or read back from the state directory. It
// returns the table this build can use from it, and the rows it left out.
//
// Such a table is published for every build that reads its schema, so it may
// hold rows a build does not know how to run. Those are left out one by one:
// a kind the build does not have, an id it cannot read, a path it does not
// cover with a tmpfs. Every other row must pass the checks of a table of the
// build, and its image must be the official image of its kind; one row that
// does not, and the whole table is refused (ErrRuntimeTable). Nothing here
// compares the table with the one in use: whether it is newer is for the
// caller to decide from Updated.
func AdoptRuntimeTable(raw []byte, now time.Time) (RuntimeTable, []DroppedRuntime, error) {
	refuse := func(format string, a ...any) (RuntimeTable, []DroppedRuntime, error) {
		return RuntimeTable{}, nil, fmt.Errorf("%w: %s", ErrRuntimeTable, fmt.Sprintf(format, a...))
	}
	if len(raw) > MaxRuntimeTableBytes {
		return refuse("%d bytes is more than %d", len(raw), MaxRuntimeTableBytes)
	}
	var f struct {
		Schema   int               `json:"schema"`
		Updated  string            `json:"updated"`
		Runtimes []json.RawMessage `json:"runtimes"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		return refuse("not a table: %v", err)
	}
	if f.Schema != 1 {
		return refuse("schema %d is not 1", f.Schema)
	}
	if len(f.Runtimes) > maxRuntimeRows {
		return refuse("%d rows is more than %d", len(f.Runtimes), maxRuntimeRows)
	}
	if len(f.Updated) > maxRuntimeString {
		return refuse("updated is too long")
	}
	updated, err := parseTableTime(f.Updated)
	if err != nil {
		return refuse("%v", err)
	}
	if !updated.Before(now.Add(maxUpdatedAhead)) {
		return refuse("updated %s is in the future", f.Updated)
	}

	var kept []RuntimeSpec
	var dropped []DroppedRuntime
	drop := func(id, reason string) {
		dropped = append(dropped, DroppedRuntime{ID: clipID(id), Reason: reason})
	}
	for i, rawRow := range f.Runtimes {
		// Every row is bounded before it is known what it is: a row this
		// build leaves out counts against the limits like one it uses.
		if err := checkRawRowSize(rawRow); err != nil {
			return refuse("row %d: %v", i, err)
		}
		// The id and the kind are read first: a row of a kind this build does
		// not have may be shaped in ways it cannot decode.
		var head struct {
			ID   string `json:"id"`
			Kind string `json:"kind"`
		}
		if err := json.Unmarshal(rawRow, &head); err != nil {
			return refuse("row %d is not a row: %v", i, err)
		}
		if len(head.ID) > maxRuntimeString || len(head.Kind) > maxRuntimeString {
			return refuse("row %d: a value is longer than %d bytes", i, maxRuntimeString)
		}
		if _, known := runtimeImages[RuntimeKind(head.Kind)]; !known {
			drop(head.ID, "a kind this build does not have")
			continue
		}
		var r RuntimeSpec
		if err := json.Unmarshal(rawRow, &r); err != nil {
			return refuse("row %d (%s): %v", i, clipID(head.ID), err)
		}
		if err := checkRowSize(r); err != nil {
			return refuse("row %d (%s): %v", i, clipID(head.ID), err)
		}
		if _, ok := RuntimeFromID(r.ID); !ok {
			drop(r.ID, "an id this build cannot read")
			continue
		}
		if _, ok := uncoverablePath(r); ok {
			drop(r.ID, "a path this build does not cover")
			continue
		}
		kept = append(kept, r)
	}
	specs, err := checkRuntimeRows(kept)
	if err != nil {
		return refuse("%v", err)
	}
	sort.Slice(dropped, func(i, j int) bool { return dropped[i].ID < dropped[j].ID })
	return RuntimeTable{Updated: updated, specs: specs}, dropped, nil
}

// Limits of a row whatever its kind: how deep it nests and how many members
// an object in it has.
const (
	maxRowDepth      = 6
	maxRowObjectKeys = 64
)

// checkRawRowSize bounds a row as it is written, without knowing its kind:
// its size, every string in it, every list, and the lists and maps the rows
// of this build know by name.
func checkRawRowSize(raw json.RawMessage) error {
	if len(raw) > maxRuntimeRowBytes {
		return fmt.Errorf("it is %d bytes, more than %d", len(raw), maxRuntimeRowBytes)
	}
	var row map[string]any
	if err := json.Unmarshal(raw, &row); err != nil {
		return fmt.Errorf("it is not a row: %v", err)
	}
	named := map[string]int{"covered_paths": maxCoveredPaths, "volumes": maxVolumes, "platforms": maxPlatformKeys, "tested": maxPlatformKeys}
	for k, v := range row {
		if limit, ok := named[k]; ok && sizeOf(v) > limit {
			return fmt.Errorf("%s lists more than %d", k, limit)
		}
	}
	return checkValueSize(row, 0)
}

// sizeOf is the number of members of a list or a map, and 0 for anything else.
func sizeOf(v any) int {
	switch v := v.(type) {
	case []any:
		return len(v)
	case map[string]any:
		return len(v)
	}
	return 0
}

func checkValueSize(v any, depth int) error {
	if depth > maxRowDepth {
		return errors.New("it nests too deep")
	}
	switch v := v.(type) {
	case string:
		if len(v) > maxRuntimeString {
			return fmt.Errorf("a value is longer than %d bytes", maxRuntimeString)
		}
	case []any:
		if len(v) > maxCoveredPaths {
			return fmt.Errorf("a list has more than %d members", maxCoveredPaths)
		}
		for _, e := range v {
			if err := checkValueSize(e, depth+1); err != nil {
				return err
			}
		}
	case map[string]any:
		if len(v) > maxRowObjectKeys {
			return fmt.Errorf("an object has more than %d members", maxRowObjectKeys)
		}
		for k, e := range v {
			if len(k) > maxRuntimeString {
				return fmt.Errorf("a name is longer than %d bytes", maxRuntimeString)
			}
			if err := checkValueSize(e, depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}

// checkRowSize bounds every value of a row: the strings, and how many paths,
// volumes and platforms it lists.
func checkRowSize(r RuntimeSpec) error {
	if len(r.CoveredPaths) > maxCoveredPaths || len(r.Volumes) > maxVolumes ||
		len(r.Platforms) > maxPlatformKeys || len(r.Tested) > maxPlatformKeys {
		return errors.New("it lists too many paths, volumes or platforms")
	}
	strs := []string{
		r.ID, string(r.Kind), r.Series, r.Version, r.Pip, r.JDK, r.Image, r.Tag, r.ExactTag, r.IndexDigest,
		r.Support, r.EOL, r.LTSFrom, r.Checked,
	}
	strs = append(strs, r.CoveredPaths...)
	strs = append(strs, r.Volumes...)
	for _, m := range []map[string]string{r.Platforms, r.Tested} {
		for k, v := range m {
			strs = append(strs, k, v)
		}
	}
	if slices.ContainsFunc(strs, func(s string) bool { return len(s) > maxRuntimeString }) {
		return fmt.Errorf("a value is longer than %d bytes", maxRuntimeString)
	}
	return nil
}

// clipID shortens an id that is written to the log.
func clipID(id string) string {
	if len(id) > 64 {
		return id[:64]
	}
	return id
}

// CheckJobRuntime checks, in the main process, that the runtime of a job is a
// row of the table in use that pins an image, and that the job carries exactly
// the versions of that row. The program in the work container has no table;
// it checks what the id says (Job.Validate) and what the executables report.
func CheckJobRuntime(j Job) error {
	spec, ok := LookupRuntime(j.Runtime.ID)
	if !ok || !spec.HasImage() {
		return fmt.Errorf("the runtime %q is not in the table", j.Runtime.ID)
	}
	if j.Runtime != spec.JobRuntime() {
		return fmt.Errorf("the job does not carry the versions of %s", j.Runtime.ID)
	}
	return nil
}
