package remediation

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func mustGoMod(t *testing.T, src string) *goMod {
	t.Helper()
	gm, err := parseGoMod([]byte(src))
	if err != nil {
		t.Fatalf("parse %q: %v", src, err)
	}
	return gm
}

const diffBase = `module example.com/app

go 1.22

toolchain go1.22.5

require (
	golang.org/x/net v0.20.0
	golang.org/x/text v0.14.0 // indirect
)

retract v0.0.1

godebug panicnil=1
`

func TestDiffGoModAccepts(t *testing.T) {
	before := mustGoMod(t, diffBase)

	t.Run("nothing changed", func(t *testing.T) {
		ch, err := diffGoMod(before, mustGoMod(t, diffBase))
		if err != nil {
			t.Fatal(err)
		}
		if len(ch.raised) != 0 || len(ch.added) != 0 || len(ch.unchanged) != 2 || len(ch.moved()) != 0 {
			t.Errorf("change = %+v", ch)
		}
		if ch.goBefore != "1.22" || ch.goAfter != "1.22" || ch.tcBefore != "go1.22.5" || ch.tcAfter != "go1.22.5" {
			t.Errorf("lines = %+v", ch)
		}
	})
	t.Run("raised, added and unchanged", func(t *testing.T) {
		after := strings.Replace(diffBase, "golang.org/x/net v0.20.0", "golang.org/x/net v0.23.0", 1)
		after = strings.Replace(after, "// indirect\n)", "// indirect\n\tgolang.org/x/sys v0.18.0 // indirect\n)", 1)
		ch, err := diffGoMod(before, mustGoMod(t, after))
		if err != nil {
			t.Fatal(err)
		}
		if got := ch.raised["golang.org/x/net"]; got != [2]string{"v0.20.0", "v0.23.0"} || len(ch.raised) != 1 {
			t.Errorf("raised = %v", ch.raised)
		}
		if ch.added["golang.org/x/sys"] != "v0.18.0" || len(ch.added) != 1 {
			t.Errorf("added = %v", ch.added)
		}
		if ch.unchanged["golang.org/x/text"] != "v0.14.0" || len(ch.unchanged) != 1 {
			t.Errorf("unchanged = %v", ch.unchanged)
		}
		if want := map[string]string{"golang.org/x/net": "v0.23.0", "golang.org/x/sys": "v0.18.0"}; !reflect.DeepEqual(ch.moved(), want) {
			t.Errorf("moved = %v", ch.moved())
		}
		if want := map[string]string{"golang.org/x/net": "v0.23.0", "golang.org/x/sys": "v0.18.0", "golang.org/x/text": "v0.14.0"}; !reflect.DeepEqual(ch.written(), want) {
			t.Errorf("written = %v", ch.written())
		}
	})
	t.Run("go and toolchain lines before and after", func(t *testing.T) {
		after := strings.Replace(diffBase, "go 1.22\n", "go 1.24.0\n", 1)
		after = strings.Replace(after, "toolchain go1.22.5", "toolchain go1.24.3", 1)
		ch, err := diffGoMod(before, mustGoMod(t, after))
		if err != nil {
			t.Fatal(err)
		}
		if ch.goBefore != "1.22" || ch.goAfter != "1.24.0" || ch.tcBefore != "go1.22.5" || ch.tcAfter != "go1.24.3" {
			t.Errorf("lines = %+v", ch)
		}
	})
	t.Run("the order of requirements and blocks does not matter", func(t *testing.T) {
		after := strings.Replace(diffBase, "\tgolang.org/x/net v0.20.0\n\tgolang.org/x/text v0.14.0 // indirect\n",
			"\tgolang.org/x/text v0.14.0 // indirect\n\tgolang.org/x/net v0.20.0\n", 1)
		if _, err := diffGoMod(before, mustGoMod(t, after)); err != nil {
			t.Errorf("reordered requirements: %v", err)
		}
	})
}

func TestDiffGoModRefuses(t *testing.T) {
	before := mustGoMod(t, diffBase)
	for name, after := range map[string]string{
		"module line changed":      strings.Replace(diffBase, "module example.com/app", "module example.com/other", 1),
		"retract removed":          strings.Replace(diffBase, "retract v0.0.1\n", "", 1),
		"retract changed":          strings.Replace(diffBase, "retract v0.0.1", "retract v0.0.2", 1),
		"retract added":            diffBase + "retract v0.0.3\n",
		"godebug removed":          strings.Replace(diffBase, "godebug panicnil=1\n", "", 1),
		"godebug changed":          strings.Replace(diffBase, "panicnil=1", "panicnil=0", 1),
		"godebug added":            diffBase + "godebug asynctimerchan=1\n",
		"tool added":               diffBase + "tool example.com/t\n",
		"replace added":            diffBase + "replace golang.org/x/net => golang.org/x/net v0.19.0\n",
		"exclude added":            diffBase + "exclude golang.org/x/net v0.23.0\n",
		"requirement removed":      strings.Replace(diffBase, "\tgolang.org/x/net v0.20.0\n", "", 1),
		"indirect one removed":     strings.Replace(diffBase, "\tgolang.org/x/text v0.14.0 // indirect\n", "", 1),
		"requirement lowered":      strings.Replace(diffBase, "golang.org/x/net v0.20.0", "golang.org/x/net v0.19.0", 1),
		"indirect one lowered":     strings.Replace(diffBase, "golang.org/x/text v0.14.0", "golang.org/x/text v0.13.0", 1),
		"indirect mark added":      strings.Replace(diffBase, "golang.org/x/net v0.20.0", "golang.org/x/net v0.20.0 // indirect", 1),
		"indirect mark removed":    strings.Replace(diffBase, "golang.org/x/text v0.14.0 // indirect", "golang.org/x/text v0.14.0", 1),
		"indirect mark on a raise": strings.Replace(diffBase, "golang.org/x/net v0.20.0", "golang.org/x/net v0.23.0 // indirect", 1),
		"requirement twice":        strings.Replace(diffBase, "golang.org/x/net v0.20.0", "golang.org/x/net v0.20.0\n\tgolang.org/x/net v0.20.0", 1),
		"added one twice":          strings.Replace(diffBase, "// indirect\n)", "// indirect\n\tgolang.org/x/sys v0.18.0\n\tgolang.org/x/sys v0.19.0\n)", 1),
		"version without v":        strings.Replace(diffBase, "golang.org/x/net v0.20.0", "golang.org/x/net 0.23.0", 1),
		"added one without v":      strings.Replace(diffBase, "// indirect\n)", "// indirect\n\tgolang.org/x/sys 0.18.0\n)", 1),
	} {
		gm, err := parseGoMod([]byte(after))
		if err != nil {
			t.Errorf("%s: the case does not parse, so it does not test the comparison: %v", name, err)
			continue
		}
		if ch, err := diffGoMod(before, gm); err == nil {
			t.Errorf("%s: accepted, change %+v", name, ch)
		}
	}
}

func TestDiffGoModEquivalentVersionSpelling(t *testing.T) {
	// A version that compares equal but is written differently is not the
	// version that was there (build metadata is kept apart).
	before := mustGoMod(t, "module m\n\ngo 1.22\n\nrequire example.com/a v2.0.0+incompatible\n")
	after := mustGoMod(t, "module m\n\ngo 1.22\n\nrequire example.com/a v2.0.0\n")
	if _, err := diffGoMod(before, after); err == nil {
		t.Error("a requirement written differently at an equal version was accepted")
	}
}

func TestParseGoSumLines(t *testing.T) {
	h := fakeH1("a")
	lines, err := parseGoSumLines([]byte("a.com/m v1.0.0 " + h + "\r\n\r\na.com/m v1.0.0/go.mod " + h + "\n"))
	if err != nil || len(lines) != 2 || lines[0].key() != "a.com/m v1.0.0" || lines[1].key() != "a.com/m v1.0.0/go.mod" || lines[1].text() != "a.com/m v1.0.0/go.mod "+h {
		t.Fatalf("lines = %+v, %v", lines, err)
	}
	for name, src := range map[string]string{
		"two fields":    "a.com/m v1.0.0\n",
		"four fields":   "a.com/m v1.0.0 " + h + " x\n",
		"not h1":        "a.com/m v1.0.0 h2:" + strings.TrimPrefix(h, "h1:") + "\n",
		"short hash":    "a.com/m v1.0.0 h1:abc=\n",
		"bad character": "a.com/m v1.0.0 h1:" + strings.Repeat("!", 43) + "=\n",
	} {
		if _, err := parseGoSumLines([]byte(src)); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
}

func noBudget() error { return nil }

func TestCheckGoSumLines(t *testing.T) {
	reg := newFakeGoReg()
	reg.mod("golang.org/x/net", "v0.20.0", goModText("golang.org/x/net", "1.18"))
	reg.mod("golang.org/x/net", "v0.23.0", goModText("golang.org/x/net", "1.18"))
	reg.mod("golang.org/x/text", "v0.14.0", goModText("golang.org/x/text", "1.18"))
	reg.mod("golang.org/x/text", "v0.15.0", goModText("golang.org/x/text", "1.18"))
	reg.mod("golang.org/x/sys", "v0.18.0", goModText("golang.org/x/sys", "1.18"))

	orig := reg.sumLines("golang.org/x/net", "v0.20.0") + reg.sumLines("golang.org/x/text", "v0.14.0")
	netNew := reg.sumLines("golang.org/x/net", "v0.23.0")
	moved := map[string]string{"golang.org/x/net": "v0.23.0"}

	check := func(t *testing.T, orig, updated string, moved map[string]string) (*goSumResult, error) {
		t.Helper()
		reg.sumKeys = nil
		return checkGoSumLines(bg, reg, []byte(orig), []byte(updated), moved, noBudget)
	}

	t.Run("new lines that match the database", func(t *testing.T) {
		res, err := check(t, orig, orig+netNew, moved)
		if err != nil {
			t.Fatal(err)
		}
		if len(res.added) != 0 || res.checked != 1 {
			t.Errorf("added = %v, checked = %d", res.added, res.checked)
		}
		want := reg.sumLines("golang.org/x/net", "v0.20.0") + netNew + reg.sumLines("golang.org/x/text", "v0.14.0")
		if string(res.content) != want {
			t.Errorf("content =\n%s\nwant\n%s", res.content, want)
		}
	})
	t.Run("a new line the database does not record the same", func(t *testing.T) {
		bad := "golang.org/x/net v0.23.0 " + fakeH1("forged") + "\n" + reg.modLine("golang.org/x/net", "v0.23.0")
		if _, err := check(t, orig, orig+bad, moved); err == nil || !strings.Contains(err.Error(), "checksum database") {
			t.Errorf("zip hash: %v", err)
		}
		bad = reg.sumLines("golang.org/x/net", "v0.23.0")
		bad = strings.Replace(bad, "v0.23.0/go.mod h1:", "v0.23.0/go.mod h1:", 1)
		forged := "golang.org/x/net v0.23.0 " + reg.zipHash("golang.org/x/net", "v0.23.0") + "\ngolang.org/x/net v0.23.0/go.mod " + fakeH1("forged") + "\n"
		if _, err := check(t, orig, orig+forged, moved); err == nil {
			t.Error("a forged go.mod hash was accepted")
		}
	})
	t.Run("a new line for a version that is not a move is checked too", func(t *testing.T) {
		// golang.org/x/sys is not moved; its new lines still must match.
		forged := "golang.org/x/sys v0.18.0 " + fakeH1("forged") + "\n"
		if _, err := check(t, orig, orig+forged, moved); err == nil {
			t.Error("a forged line of a version that did not move was accepted")
		}
		good := reg.sumLines("golang.org/x/sys", "v0.18.0")
		res, err := check(t, orig, orig+netNew+good, moved)
		if err != nil {
			t.Fatal(err)
		}
		if res.checked != 2 {
			t.Errorf("checked = %d, want 2", res.checked)
		}
	})
	t.Run("a new line for a version that is not a move is not completed", func(t *testing.T) {
		// Only the zip line is new for x/sys; the go.mod line is not added
		// since x/sys did not move.
		zipOnly := "golang.org/x/sys v0.18.0 " + reg.zipHash("golang.org/x/sys", "v0.18.0") + "\n"
		res, err := check(t, orig, orig+netNew+zipOnly, moved)
		if err != nil {
			t.Fatal(err)
		}
		if len(res.added) != 0 || strings.Contains(string(res.content), "x/sys v0.18.0/go.mod") {
			t.Errorf("added = %v\n%s", res.added, res.content)
		}
	})
	t.Run("a moved version already in go.sum is checked on both hashes", func(t *testing.T) {
		// x/text v0.14.0 is in the original with correct hashes, and is
		// declared moved (as when an update lands on a version go.sum has).
		res, err := check(t, orig, orig, map[string]string{"golang.org/x/text": "v0.14.0"})
		if err != nil {
			t.Fatal(err)
		}
		if res.checked != 1 || len(reg.sumKeys) != 1 || reg.sumKeys[0] != "golang.org/x/text@v0.14.0" {
			t.Errorf("checked = %d %v", res.checked, reg.sumKeys)
		}
		// With the original wrong in the zip line, both orig and updated alike.
		wrongZip := "golang.org/x/text v0.14.0 " + fakeH1("wrong") + "\n" + reg.modLine("golang.org/x/text", "v0.14.0")
		if _, err := check(t, wrongZip, wrongZip, map[string]string{"golang.org/x/text": "v0.14.0"}); err == nil {
			t.Error("a wrong zip hash of a moved version, already in go.sum, was accepted")
		}
		wrongMod := reg.zipLineOnly("golang.org/x/text", "v0.14.0") + "golang.org/x/text v0.14.0/go.mod " + fakeH1("wrong") + "\n"
		if _, err := check(t, wrongMod, wrongMod, map[string]string{"golang.org/x/text": "v0.14.0"}); err == nil {
			t.Error("a wrong go.mod hash of a moved version, already in go.sum, was accepted")
		}
		// A version that did not move and was already there is not asked about.
		if _, err := check(t, wrongZip, wrongZip, nil); err != nil {
			t.Errorf("an old line that is not moved was checked: %v", err)
		}
		if len(reg.sumKeys) != 0 {
			t.Errorf("asked about %v", reg.sumKeys)
		}
	})
	t.Run("a version the database has no record of", func(t *testing.T) {
		reg.noSums["golang.org/x/net@v0.23.0"] = true
		defer delete(reg.noSums, "golang.org/x/net@v0.23.0")
		_, err := check(t, orig, orig+netNew, moved)
		if err == nil || !strings.Contains(err.Error(), "no record") {
			t.Errorf("err = %v", err)
		}
		if errors.Is(err, ErrReleaseNotFound) {
			t.Errorf("a missing record is a refusal, not a failed request: %v", err)
		}
		// A moved version with no new lines is asked about too.
		if _, err := check(t, orig, orig, moved); err == nil || !strings.Contains(err.Error(), "no record") {
			t.Errorf("moved without lines: %v", err)
		}
	})
	t.Run("a failed request is returned as it is", func(t *testing.T) {
		boom := errors.New("connection reset")
		reg.err = boom
		defer func() { reg.err = nil }()
		if _, err := check(t, orig, orig+netNew, moved); !errors.Is(err, boom) {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("missing lines of a moved version are added", func(t *testing.T) {
		for name, updated := range map[string]string{
			"both missing": orig,
			"zip present":  orig + "golang.org/x/net v0.23.0 " + reg.zipHash("golang.org/x/net", "v0.23.0") + "\n",
			"mod present":  orig + reg.modLine("golang.org/x/net", "v0.23.0"),
		} {
			res, err := check(t, orig, updated, moved)
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			if string(res.content) != reg.sumLines("golang.org/x/net", "v0.20.0")+netNew+reg.sumLines("golang.org/x/text", "v0.14.0") {
				t.Errorf("%s: content =\n%s", name, res.content)
			}
			wantAdded := map[string][]string{
				"both missing": {"golang.org/x/net v0.23.0 " + reg.zipHash("golang.org/x/net", "v0.23.0"), "golang.org/x/net v0.23.0/go.mod " + reg.modHash("golang.org/x/net", "v0.23.0")},
				"zip present":  {"golang.org/x/net v0.23.0/go.mod " + reg.modHash("golang.org/x/net", "v0.23.0")},
				"mod present":  {"golang.org/x/net v0.23.0 " + reg.zipHash("golang.org/x/net", "v0.23.0")},
			}[name]
			if !reflect.DeepEqual(res.added, wantAdded) {
				t.Errorf("%s: added = %v, want %v", name, res.added, wantAdded)
			}
		}
	})
	t.Run("the added lines of two moved modules", func(t *testing.T) {
		res, err := check(t, orig, orig, map[string]string{"golang.org/x/net": "v0.23.0", "golang.org/x/sys": "v0.18.0"})
		if err != nil {
			t.Fatal(err)
		}
		if len(res.added) != 4 || !goStringsAscending(res.added) {
			t.Errorf("added = %v", res.added)
		}
		if len(reg.sumKeys) != 2 || reg.sumKeys[0] != "golang.org/x/net@v0.23.0" || reg.sumKeys[1] != "golang.org/x/sys@v0.18.0" {
			t.Errorf("asked about %v", reg.sumKeys)
		}
	})
	t.Run("a line of the original removed", func(t *testing.T) {
		for name, updated := range map[string]string{
			"zip line":    reg.modLine("golang.org/x/net", "v0.20.0") + reg.sumLines("golang.org/x/text", "v0.14.0") + netNew,
			"go.mod line": "golang.org/x/net v0.20.0 " + reg.zipHash("golang.org/x/net", "v0.20.0") + "\n" + reg.sumLines("golang.org/x/text", "v0.14.0") + netNew,
			"everything":  netNew,
		} {
			if _, err := check(t, orig, updated, moved); err == nil || !strings.Contains(err.Error(), "removed") {
				t.Errorf("%s: err = %v", name, err)
			}
		}
	})
	t.Run("a line of the original changed", func(t *testing.T) {
		updated := strings.Replace(orig, reg.zipHash("golang.org/x/text", "v0.14.0"), fakeH1("other"), 1) + netNew
		if _, err := check(t, orig, updated, moved); err == nil || !strings.Contains(err.Error(), "changed") {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("two lines for one version and kind that differ", func(t *testing.T) {
		updated := orig + netNew + "golang.org/x/net v0.23.0 " + fakeH1("other") + "\n"
		if _, err := check(t, orig, updated, moved); err == nil || !strings.Contains(err.Error(), "two different") {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("a repeated identical line is kept once", func(t *testing.T) {
		res, err := check(t, orig, orig+netNew+netNew, moved)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Count(string(res.content), "golang.org/x/net v0.23.0 ") != 1 {
			t.Errorf("content =\n%s", res.content)
		}
	})
	t.Run("lines that are not go.sum lines", func(t *testing.T) {
		if _, err := check(t, orig, orig+"golang.org/x/net v0.23.0\n", moved); err == nil {
			t.Error("a short line was accepted")
		}
		if _, err := check(t, orig+"junk\n", orig, nil); err == nil || !strings.Contains(err.Error(), "original") {
			t.Errorf("a bad original: %v", err)
		}
	})
	t.Run("the budget is spent per request and its error is returned", func(t *testing.T) {
		out := errors.New("out of lookups")
		n := 0
		budget := func() error {
			n++
			if n > 1 {
				return out
			}
			return nil
		}
		reg.sumKeys = nil
		_, err := checkGoSumLines(bg, reg, []byte(orig), []byte(orig), map[string]string{"golang.org/x/net": "v0.23.0", "golang.org/x/sys": "v0.18.0"}, budget)
		if !errors.Is(err, out) {
			t.Errorf("err = %v", err)
		}
		if len(reg.sumKeys) != 1 {
			t.Errorf("asked %v after the budget ran out", reg.sumKeys)
		}
	})
}

func goStringsAscending(s []string) bool {
	for i := 1; i < len(s); i++ {
		if s[i-1] > s[i] {
			return false
		}
	}
	return true
}

// zipLineOnly writes only the zip line of a version.
func (f *fakeGoReg) zipLineOnly(path, version string) string {
	return path + " " + version + " " + f.zipHash(path, version) + "\n"
}

func TestGoSumOrder(t *testing.T) {
	h := fakeH1("x")
	in := []string{
		"b.com/m v1.0.0/go.mod " + h,
		"a.com/m v1.10.0 " + h,
		"a.com/m v1.9.0/go.mod " + h,
		"a.com/m v1.9.0 " + h,
		"a.com/m v1.10.0/go.mod " + h,
		"a.com/m/v2 v2.0.0 " + h,
		"a.com/m v1.0.0-rc.1 " + h,
		"a.com/m v1.0.0 " + h,
	}
	want := []string{
		"a.com/m v1.0.0-rc.1 " + h,
		"a.com/m v1.0.0 " + h,
		"a.com/m v1.9.0 " + h,
		"a.com/m v1.9.0/go.mod " + h,
		"a.com/m v1.10.0 " + h,
		"a.com/m v1.10.0/go.mod " + h,
		"a.com/m/v2 v2.0.0 " + h,
		"b.com/m v1.0.0/go.mod " + h,
	}
	// Every permutation order of the input sorts the same.
	for shift := 0; shift < len(in); shift++ {
		var got []string
		for i := range in {
			got = append(got, in[(i+shift)%len(in)])
		}
		sortStable(got)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("shift %d: got\n%s\nwant\n%s", shift, strings.Join(got, "\n"), strings.Join(want, "\n"))
		}
	}
	if goSumOrder("a.com/m v1.0.0 "+h, "a.com/m v1.0.0 "+h) {
		t.Error("a line orders before itself")
	}
}

func sortStable(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && goSumOrder(s[j], s[j-1]); j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

func TestCheckGoSumLinesOrdersTheCompletedFile(t *testing.T) {
	reg := newFakeGoReg()
	reg.mod("a.com/m", "v1.9.0", goModText("a.com/m", "1.18"))
	reg.mod("a.com/m", "v1.10.0", goModText("a.com/m", "1.18"))
	reg.mod("z.com/m", "v1.0.0", goModText("z.com/m", "1.18"))
	orig := reg.sumLines("a.com/m", "v1.9.0") + reg.sumLines("z.com/m", "v1.0.0")
	// The update returned its new lines first and out of order.
	updated := reg.sumLines("a.com/m", "v1.10.0") + orig
	res, err := checkGoSumLines(bg, reg, []byte(orig), []byte(updated), map[string]string{"a.com/m": "v1.10.0"}, noBudget)
	if err != nil {
		t.Fatal(err)
	}
	want := reg.sumLines("a.com/m", "v1.9.0") + reg.sumLines("a.com/m", "v1.10.0") + reg.sumLines("z.com/m", "v1.0.0")
	if string(res.content) != want {
		t.Errorf("content =\n%s\nwant\n%s", res.content, want)
	}
	if !strings.HasSuffix(string(res.content), "\n") || strings.HasSuffix(string(res.content), "\n\n") {
		t.Errorf("the file does not end in exactly one newline: %q", res.content[len(res.content)-3:])
	}
}
