// Thread-report rendering: the channel
// message stays the diff ("what changed"), while its thread carries the state
// ("what is open right now"). The thread expands urgent and watch findings in
// full — per-CVE evidence, references, and how long each finding has been
// open — and collapses low priority to a count, so the report stays readable
// on the day someone finally sits down to fix things.
package notify

import (
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/analyze"
)

// alsoIDsMax caps how many secondary CVE ids are listed per package before
// falling back to a count (the full list is in the generic webhook payload,
// when one is configured).
const alsoIDsMax = 8

// Ages supplies the first-seen times behind the thread's "open N day(s)"
// lines. Ordinary package groups use Finding; end-of-life package groups use
// EOL, which dates from when the package became end-of-life. Either may be
// nil, which omits the age lines of the groups it would cover.
type Ages struct {
	Finding func(image, pkg string) (time.Time, bool)
	EOL     func(image, pkg string) (time.Time, bool)
}

// forGroup picks the lookup that dates g.
func (a Ages) forGroup(g analyze.PackageGroup) func(image, pkg string) (time.Time, bool) {
	if analyze.IsEOL(g) {
		return a.EOL
	}
	return a.Finding
}

// openDays is the whole-day age of a finding at now (0 for today or a clock
// skew into the future).
func openDays(t, now time.Time) int {
	days := int(now.Sub(t).Hours() / 24)
	if days < 0 {
		return 0
	}
	return days
}
