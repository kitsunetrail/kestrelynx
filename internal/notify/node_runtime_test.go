package notify

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/analyze"
	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
	"github.com/kitsunetrail/kestrelynx/internal/state"
)

func uncheckedReport(refs ...string) analyze.Report {
	return uncheckedReportOf([]string{inventory.NodeRuntimePackage}, refs...)
}

// uncheckedReportOf marks every image in refs as having the given runtimes
// unchecked.
func uncheckedReportOf(pkgs []string, refs ...string) analyze.Report {
	var scans []scanner.ImageScan
	for _, ref := range refs {
		scans = append(scans, scanner.ImageScan{Image: ref, RuntimeUnchecked: pkgs})
	}
	return analyze.Build(scans, nil, analyze.Triage{}, time.Date(2026, 10, 9, 3, 0, 0, 0, time.UTC))
}

func TestRuntimeUncheckedNote(t *testing.T) {
	both := []string{inventory.PythonRuntimePackage, inventory.NodeRuntimePackage}
	all := []string{inventory.JavaRuntimePackage, inventory.PythonRuntimePackage, inventory.NodeRuntimePackage}
	cases := []struct {
		name string
		lang Language
		r    analyze.Report
		want string
	}{
		{"one runtime", LanguageEN, uncheckedReport("a:1", "b:1"), "ℹ️ Advisories for Node.js could not be fetched, so the runtime of 2 image(s) was not checked."},
		{"one runtime", LanguageJA, uncheckedReport("a:1", "b:1"), "ℹ️ Node.js の脆弱性情報を取得できなかったため、2 件のイメージの本体を照合していません。"},
		{"two runtimes", LanguageEN, uncheckedReportOf(both, "a:1", "b:1"), "ℹ️ Advisories for Node.js, Python runtime could not be fetched, so the runtime of 2 image(s) was not checked."},
		{"two runtimes", LanguageJA, uncheckedReportOf(both, "a:1", "b:1"), "ℹ️ Node.js・Python runtime の脆弱性情報を取得できなかったため、2 件のイメージの本体を照合していません。"},
		{"three runtimes", LanguageEN, uncheckedReportOf(all, "a:1", "b:1"), "ℹ️ Advisories for Java runtime, Node.js, Python runtime could not be fetched, so the runtime of 2 image(s) was not checked."},
		{"three runtimes", LanguageJA, uncheckedReportOf(all, "a:1", "b:1"), "ℹ️ Java runtime・Node.js・Python runtime の脆弱性情報を取得できなかったため、2 件のイメージの本体を照合していません。"},
		// One image with two runtimes counts once.
		{"one image", LanguageEN, uncheckedReportOf(both, "a:1"), "Node.js, Python runtime could not be fetched, so the runtime of 1 image(s) was not checked."},
		{"one image", LanguageJA, uncheckedReportOf(both, "a:1"), "Node.js・Python runtime の脆弱性情報を取得できなかったため、1 件のイメージの本体を照合していません。"},
	}
	for _, c := range cases {
		r := c.r
		if got := renderFull(r, c.lang); !strings.Contains(got, c.want) {
			t.Errorf("%s %s full view lacks the note %q:\n%s", c.name, c.lang, c.want, got)
		}
		d, _ := state.Compute(state.State{}, r)
		if got := renderDiff(r, d, false, false, c.lang); !strings.Contains(got, c.want) {
			t.Errorf("%s %s diff view lacks the note %q:\n%s", c.name, c.lang, c.want, got)
		}
	}
}

func TestRuntimeUncheckedNoteAbsentWhenChecked(t *testing.T) {
	r := analyze.Build([]scanner.ImageScan{{Image: "a:1"}}, nil, analyze.Triage{}, time.Date(2026, 10, 9, 3, 0, 0, 0, time.UTC))
	for _, lang := range []Language{LanguageEN, LanguageJA} {
		got := renderFull(r, lang)
		if strings.Contains(got, "Node.js") {
			t.Errorf("%s: unexpected Node.js note:\n%s", lang, got)
		}
	}
}

func TestWebhookRuntimeUnchecked(t *testing.T) {
	data, err := json.Marshal(BuildWebhookPayload(uncheckedReport("b:1", "a:1"), nil))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	got, _ := m["runtime_unchecked"].([]any)
	if len(got) != 2 {
		t.Fatalf("runtime_unchecked = %v, want two objects", m["runtime_unchecked"])
	}
	for i, img := range []string{"a:1", "b:1"} {
		e, _ := got[i].(map[string]any)
		if e["image"] != img || e["package"] != inventory.NodeRuntimePackage || e["reason"] != "advisories" || len(e) != 3 {
			t.Errorf("runtime_unchecked[%d] = %v, want image %s, package %s", i, got[i], img, inventory.NodeRuntimePackage)
		}
	}

	data, err = json.Marshal(BuildWebhookPayload(uncheckedReportOf([]string{inventory.PythonRuntimePackage, inventory.NodeRuntimePackage}, "a:1"), nil))
	if err != nil {
		t.Fatal(err)
	}
	if want := `"runtime_unchecked":[{"image":"a:1","package":"Node.js","reason":"advisories"},{"image":"a:1","package":"Python runtime","reason":"advisories"}]`; !strings.Contains(string(data), want) {
		t.Errorf("payload lacks %s:\n%s", want, data)
	}

	data, _ = json.Marshal(BuildWebhookPayload(analyze.Build(nil, nil, analyze.Triage{}, time.Date(2026, 10, 9, 3, 0, 0, 0, time.UTC)), nil))
	if strings.Contains(string(data), "runtime_unchecked") {
		t.Errorf("runtime_unchecked must be omitted when empty: %s", data)
	}
}

// javaNoteReport has the Java runtime of every image in refs not checked for
// the given reason.
func javaNoteReport(reason string, refs ...string) analyze.Report {
	var scans []scanner.ImageScan
	for _, ref := range refs {
		scans = append(scans, scanner.ImageScan{
			Image:                  ref,
			RuntimeUnchecked:       []string{inventory.JavaRuntimePackage},
			RuntimeUncheckedReason: map[string]string{inventory.JavaRuntimePackage: reason},
		})
	}
	return analyze.Build(scans, nil, analyze.Triage{}, time.Date(2026, 10, 9, 3, 0, 0, 0, time.UTC))
}

// retiredCycle returns the report of a cycle that retired the Java runtime of
// each image in refs, and the diff against a state that recorded it.
func retiredCycle(t *testing.T, refs ...string) (analyze.Report, state.Diff) {
	t.Helper()
	at := time.Date(2026, 10, 8, 3, 0, 0, 0, time.UTC)
	var prevScans, scans []scanner.ImageScan
	for _, ref := range refs {
		prevScans = append(prevScans, scanner.ImageScan{Image: ref, Findings: []scanner.Finding{{
			Image: ref, Package: inventory.JavaRuntimePackage, VulnID: "CVE-1", Status: scanner.StatusFixed, Severity: "HIGH",
		}}})
		scans = append(scans, scanner.ImageScan{Image: ref, RuntimeRetired: []string{inventory.JavaRuntimePackage}})
	}
	_, prev := state.Compute(state.State{}, analyze.Build(prevScans, nil, analyze.Triage{}, at))
	r := analyze.Build(scans, nil, analyze.Triage{}, at.AddDate(0, 0, 1))
	d, _ := state.Compute(prev, r)
	return r, d
}

func TestJavaRuntimeNotes(t *testing.T) {
	deferred := javaNoteReport(scanner.ReasonDeferred, "a:1", "b:1")
	unreadable := javaNoteReport(scanner.ReasonUnreadable, "a:1", "b:1")
	retired, retiredDiff := retiredCycle(t, "a:1", "b:1")
	cases := []struct {
		name string
		lang Language
		r    analyze.Report
		d    *state.Diff
		want string
	}{
		{"deferred", LanguageEN, deferred, nil, "ℹ️ Reading the Java runtime of 2 image(s) was postponed to the next scan."},
		{"deferred", LanguageJA, deferred, nil, "ℹ️ 2 件のイメージで Java 本体の読み取りを次回に回しました。"},
		{"unreadable", LanguageEN, unreadable, nil, "ℹ️ The Java runtime of 2 image(s) cannot be read."},
		{"unreadable", LanguageJA, unreadable, nil, "ℹ️ 2 件のイメージで Java 本体を読み取れません。"},
		{"retired", LanguageEN, retired, &retiredDiff, "ℹ️ Stopped checking the Java runtime of 2 image(s) because it changed to a distribution that is not checked."},
		{"retired", LanguageJA, retired, &retiredDiff, "ℹ️ 2 件のイメージで Java 本体が照合しない配布元に変わったため、照合をやめました。"},
	}
	for _, c := range cases {
		var got string
		if c.d != nil {
			got = renderDiff(c.r, *c.d, false, false, c.lang)
		} else {
			got = renderFull(c.r, c.lang)
			d, _ := state.Compute(state.State{}, c.r)
			if diffGot := renderDiff(c.r, d, false, false, c.lang); !strings.Contains(diffGot, c.want) {
				t.Errorf("%s %s diff view lacks %q:\n%s", c.name, c.lang, c.want, diffGot)
			}
		}
		if !strings.Contains(got, c.want) {
			t.Errorf("%s %s lacks %q:\n%s", c.name, c.lang, c.want, got)
		}
		// The advisories wording must not appear for these reasons.
		if strings.Contains(got, "could not be fetched") || strings.Contains(got, "取得できなかった") {
			t.Errorf("%s %s shows the advisories note:\n%s", c.name, c.lang, got)
		}
	}
	// A retirement note is a diff note: the full view of the same report has none.
	if got := renderFull(retired, LanguageEN); strings.Contains(got, "Stopped checking") {
		t.Errorf("full view shows the retirement note:\n%s", got)
	}
}

func TestJavaRuntimeNotesGolden(t *testing.T) {
	deferred := javaNoteReport(scanner.ReasonDeferred, "a:1", "b:1")
	unreadable := javaNoteReport(scanner.ReasonUnreadable, "a:1", "b:1")
	retired, retiredDiff := retiredCycle(t, "a:1", "b:1")
	for _, lang := range []Language{LanguageEN, LanguageJA} {
		for _, c := range []struct {
			name string
			r    analyze.Report
			d    *state.Diff
		}{
			{"java_deferred", deferred, nil},
			{"java_unreadable", unreadable, nil},
			{"java_retired", retired, &retiredDiff},
		} {
			m := Message{Report: c.r, Diff: c.d}
			msgs := BuildChannelMessages(m, ChannelFooter{}, lang)
			checkBlockGolden(t, string(lang)+"_"+c.name+"_slack", "golden", dumpMessages(msgs))
		}
	}
}

func TestWebhookRuntimeReasonAndRetired(t *testing.T) {
	r := javaNoteReport(scanner.ReasonDeferred, "a:1")
	data, _ := json.Marshal(BuildWebhookPayload(r, nil))
	if want := `"runtime_unchecked":[{"image":"a:1","package":"Java runtime","reason":"deferred"}]`; !strings.Contains(string(data), want) {
		t.Errorf("payload lacks %s:\n%s", want, data)
	}
	if strings.Contains(string(data), "runtime_retired") {
		t.Errorf("runtime_retired present without a diff: %s", data)
	}

	rr, d := retiredCycle(t, "b:1", "a:1")
	data, _ = json.Marshal(BuildWebhookPayload(rr, &d))
	if want := `"runtime_retired":[{"image":"a:1","package":"Java runtime"},{"image":"b:1","package":"Java runtime"}]`; !strings.Contains(string(data), want) {
		t.Errorf("payload lacks %s:\n%s", want, data)
	}
	if strings.Contains(string(data), "runtime_unchecked") {
		t.Errorf("runtime_unchecked present for a retirement: %s", data)
	}
}
