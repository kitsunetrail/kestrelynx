package notify

import (
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// verbSpec is one fmt verb found in a messages field's value: its kind
// (the letter, e.g. 's' or 'd') and, for a positional verb (%[1]s), the
// index it names. index is 0 for a non-positional verb (%s).
type verbSpec struct {
	index int
	kind  byte
}

// verbPattern matches both positional (%[1]s) and plain (%s) fmt verbs. It
// only needs to recognize the verb kinds this package's dictionary actually
// uses (s, d); any other letter is still captured so a translation that
// introduces an unexpected verb is caught rather than silently ignored.
var verbPattern = regexp.MustCompile(`%\[(\d+)\]([a-zA-Z])|%([a-zA-Z])`)

// parseVerbs extracts every fmt verb from s, in the order they appear.
func parseVerbs(s string) []verbSpec {
	var out []verbSpec
	for _, m := range verbPattern.FindAllStringSubmatch(s, -1) {
		if m[1] != "" {
			idx, err := strconv.Atoi(m[1])
			if err != nil {
				panic(err) // unreachable: \d+ only matches digits
			}
			out = append(out, verbSpec{index: idx, kind: m[2][0]})
			continue
		}
		out = append(out, verbSpec{index: 0, kind: m[3][0]})
	}
	return out
}

// kindMultiset returns the sorted list of verb kinds in specs — order-
// independent, since a translation using positional verbs is free to say
// the same two facts in the opposite order.
func kindMultiset(specs []verbSpec) []byte {
	kinds := make([]byte, len(specs))
	for i, s := range specs {
		kinds[i] = s.kind
	}
	sort.Slice(kinds, func(i, j int) bool { return kinds[i] < kinds[j] })
	return kinds
}

// positionalIndexSet returns the set of distinct %[n] indices used in specs,
// or nil when none of them are positional.
func positionalIndexSet(specs []verbSpec) map[int]bool {
	var set map[int]bool
	for _, s := range specs {
		if s.index == 0 {
			continue
		}
		if set == nil {
			set = map[int]bool{}
		}
		set[s.index] = true
	}
	return set
}

// mrkdwnPairSymbols are the Slack mrkdwn delimiters that only ever make
// sense in balanced (even-count) pairs within one message: bold (*),
// italic (_), and inline code (`). A translation is never required to use
// the exact same markup as English, but if it uses one of these symbols at
// all, opening it without closing it corrupts every line that follows in
// the same Slack message — so this checks parity (even/odd), not count.
var mrkdwnPairSymbols = []byte{'*', '_', '`'}

// TestMessages_JapaneseFormatParity guards every field of jaMessages against
// the three ways a translation can silently break rendering even though it
// is well-formed Japanese text:
//  1. a missing/extra/renamed fmt verb (a %s turned into plain text, or a
//     %d added that Fprintf/Sprintf's caller never supplies) would either
//     drop data or panic at runtime;
//  2. a changed %[n] index set would feed an argument to the wrong verb;
//  3. an unpaired mrkdwn delimiter would corrupt the rest of the Slack
//     message it appears in, not just its own field's line.
//
// It never touches jaMessages/enMessages themselves — translation content
// is out of scope for a Go test — it only checks structural agreement.
func TestMessages_JapaneseFormatParity(t *testing.T) {
	enVal := reflect.ValueOf(enMessages)
	jaVal := reflect.ValueOf(jaMessages)
	typ := enVal.Type()

	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		en := enVal.Field(i).String()
		ja := jaVal.Field(i).String()

		t.Run(field.Name, func(t *testing.T) {
			enSpecs, jaSpecs := parseVerbs(en), parseVerbs(ja)

			enKinds, jaKinds := kindMultiset(enSpecs), kindMultiset(jaSpecs)
			if string(enKinds) != string(jaKinds) {
				t.Errorf("verb kinds/count differ: en=%q (%v) ja=%q (%v)", en, string(enKinds), ja, string(jaKinds))
			}

			enIdx, jaIdx := positionalIndexSet(enSpecs), positionalIndexSet(jaSpecs)
			if !reflect.DeepEqual(enIdx, jaIdx) {
				t.Errorf("positional %%[n] index set differs: en=%q (%v) ja=%q (%v)", en, enIdx, ja, jaIdx)
			}

			enNL, jaNL := strings.Count(en, "\n"), strings.Count(ja, "\n")
			if enNL != jaNL {
				t.Errorf("\\n count differs: en=%q (%d) ja=%q (%d)", en, enNL, ja, jaNL)
			}

			for _, sym := range mrkdwnPairSymbols {
				enCount := strings.Count(en, string(sym))
				jaCount := strings.Count(ja, string(sym))
				if enCount%2 != jaCount%2 {
					t.Errorf("mrkdwn %q count parity differs: en=%q (%d, %s) ja=%q (%d, %s)",
						sym, en, enCount, parityWord(enCount), ja, jaCount, parityWord(jaCount))
				}
			}
		})
	}
}

func parityWord(n int) string {
	if n%2 == 0 {
		return "even"
	}
	return "odd"
}
