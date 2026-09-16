package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
)

// ProcTicks is a process generation's start time, in the clock ticks the
// process table reports.
//
// It reads the same inside a container and outside it, which makes it the
// one identifier that can relate a workload's own record of what it did to
// an observation taken from the host. That is the whole reason it is
// carried, and it is why the type accepts both spellings it arrives in:
// the test programs write it as a number, because that is what they read
// out of the process table, and hand-written records write it as a string.
// A reader that took only one of the two would refuse the very logs the
// measurement depends on.
//
// It is not an identity on its own. The value is rounded to a tick, so two
// processes started within the same tick share it, and a comparison rests
// on it together with the process number correspondence and the path.
type ProcTicks string

func (t ProcTicks) String() string { return string(t) }

func (t ProcTicks) empty() bool { return string(t) == "" || string(t) == "0" }

// UnmarshalJSON accepts a JSON number or a JSON string, and refuses
// anything else rather than reading it as empty — an unreadable start time
// is not the same as an absent one, and silently treating it as absent
// would weaken every comparison that rests on it.
func (t *ProcTicks) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	switch {
	case len(data) == 0 || string(data) == "null":
		*t = ""
		return nil
	case data[0] == '"':
		var s string
		if err := json.Unmarshal(data, &s); err != nil {
			return err
		}
		*t = ProcTicks(s)
		return nil
	default:
		var n json.Number
		if err := json.Unmarshal(data, &n); err != nil {
			return fmt.Errorf("process generation start time: %q is neither a number nor a string", data)
		}
		if _, err := strconv.ParseInt(n.String(), 10, 64); err != nil {
			return fmt.Errorf("process generation start time: %q is not a whole number of clock ticks", n.String())
		}
		*t = ProcTicks(n.String())
		return nil
	}
}

// MarshalJSON writes the value as a string, so a record this program
// produces is read back by its own reader unchanged.
func (t ProcTicks) MarshalJSON() ([]byte, error) { return json.Marshal(string(t)) }
