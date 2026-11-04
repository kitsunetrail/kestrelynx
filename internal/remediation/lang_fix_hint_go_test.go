package remediation

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/worker"
)

// listedGoReg is a fake proxy that also lists the versions of a module.
type listedGoReg struct {
	*fakeGoReg
	list map[string][]string
}

func (l listedGoReg) Versions(_ context.Context, path string) ([]string, error) {
	vs, ok := l.list[path]
	if !ok {
		return nil, ErrReleaseNotFound
	}
	return vs, nil
}

// A retracted target is taken to the lowest later release that fixes it and
// is not retracted, of the same major version; pre-releases are not taken.
func TestGoRetractedTargetTakesTheNextFix(t *testing.T) {
	f := newGoFlow(t, ".")
	f.reg.mod(pNet, "v0.30.0", goModText(pNet, "1.18")+"\nretract [v0.23.0, v0.23.1]\n")
	f.reg.mod(pNet, "v0.23.2", goModText(pNet, "1.18", pText+" v0.15.0"))
	f.newMod = appMod(pNet+" v0.23.2", pErr+" v0.9.1 // indirect", pText+" v0.15.0 // indirect")
	f.cfg.Go = listedGoReg{f.reg, map[string][]string{pNet: {"v0.20.0", "v0.23.0", "v0.23.1", "v0.23.2-rc.1", "v0.23.2", "v0.24.0", "v1.0.0"}}}
	var asked []worker.Package
	f.work.script = func(n int, job worker.Job, src map[string][]byte) fakeOutcome {
		asked = job.Steps[0].Packages
		return fakeOutcome{edit: map[string]map[string][]byte{stepUpdate: {"go.mod": []byte(f.newMod), "go.sum": []byte(f.newSum)}}}
	}
	it, _ := f.run()
	wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
	if len(asked) != 1 || asked[0].Version != "v0.23.2" {
		t.Errorf("go get = %+v", asked)
	}
	if it.Packages[0].AdoptedVersion != "v0.23.2" {
		t.Errorf("adopted = %q", it.Packages[0].AdoptedVersion)
	}
	if !strings.Contains(strings.Join(it.Update.Notes, "\n"), "the update takes v0.23.2") {
		t.Errorf("notes = %q", it.Update.Notes)
	}
}

// Without a later release that is not retracted, or without a list of the
// versions, the target stays left to a person as retracted.
func TestGoRetractedTargetWithoutANextFix(t *testing.T) {
	for name, list := range map[string][]string{
		"every later fix retracted": {"v0.20.0", "v0.23.0", "v0.23.1"},
		"only another major":        {"v0.23.0", "v1.0.0", "v2.0.0"},
		"no list":                   nil,
	} {
		t.Run(name, func(t *testing.T) {
			f := newGoFlow(t, ".")
			f.reg.mod(pNet, "v0.30.0", goModText(pNet, "1.18")+"\nretract [v0.23.0, v0.23.1]\n")
			if list != nil {
				f.cfg.Go = listedGoReg{f.reg, map[string][]string{pNet: list}}
			}
			f.refused(CategoryManual, ReasonGoRetracted)
		})
	}
}

// An update held back by the Go it needs names the module version whose
// go.mod asks for it, with the Go the binaries were built with when that held
// it back; the project's own lines name none.
func TestGoLineHints(t *testing.T) {
	t.Run("raised above the build Go", func(t *testing.T) {
		f := newGoFlow(t, ".")
		f.item.GoBuiltWith = "1.22.5"
		f.reg.mod(pNet, "v0.23.0", goModText(pNet, "1.24", pText+" v0.15.0"))
		f.newMod = strings.Replace(f.newMod, "go 1.22\n", "go 1.24\n", 1)
		it := f.refused(CategoryManual, ReasonGoLineRaised)
		want := GoLineHint{Module: pNet, Version: "v0.23.0", Go: "1.24", BuiltWith: "1.22.5", To: "v0.23.0"}
		if h := it.Packages[0].Hint(); h == nil || h.GoLine == nil || *h.GoLine != want {
			t.Errorf("hint = %+v", h)
		}
	})
	t.Run("a toolchain line alone names no module", func(t *testing.T) {
		f := newGoFlow(t, ".")
		f.item.GoBuiltWith = "1.22.5"
		f.newMod = strings.Replace(f.newMod, "go 1.22\n", "go 1.22\n\ntoolchain go1.23.4\n", 1)
		it := f.refused(CategoryManual, ReasonGoLineRaised)
		if h := it.Packages[0].FixHint; h != nil {
			t.Errorf("hint = %+v", h)
		}
	})
	t.Run("a toolchain line above the build Go names no module", func(t *testing.T) {
		f := newGoFlow(t, ".")
		f.item.GoBuiltWith = "1.23.4"
		f.reg.mod(pNet, "v0.23.0", goModText(pNet, "1.23", pText+" v0.15.0"))
		f.newMod = strings.Replace(f.newMod, "go 1.22\n", "go 1.23\n\ntoolchain go1.24.0\n", 1)
		it := f.refused(CategoryManual, ReasonGoLineRaised)
		if h := it.Packages[0].FixHint; h != nil {
			t.Errorf("hint = %+v", h)
		}
	})
	t.Run("the version taken past a retracted fix is the one named", func(t *testing.T) {
		f := newGoFlow(t, ".")
		f.item.GoBuiltWith = "1.23.4"
		f.reg.mod(pNet, "v0.30.0", goModText(pNet, "1.18")+"\nretract v0.23.0\n")
		f.reg.mod(pNet, "v0.23.2", goModText(pNet, "1.24", pText+" v0.15.0"))
		f.cfg.Go = listedGoReg{f.reg, map[string][]string{pNet: {"v0.23.0", "v0.23.2"}}}
		f.newMod = strings.Replace(appMod(pNet+" v0.23.2", pErr+" v0.9.1 // indirect", pText+" v0.15.0 // indirect"), "go 1.22\n", "go 1.24\n", 1)
		it := f.refused(CategoryManual, ReasonGoLineRaised)
		if h := it.Packages[0].Hint(); h == nil || h.GoLine == nil || h.GoLine.To != "v0.23.2" || h.GoLine.Version != "v0.23.2" {
			t.Errorf("hint = %+v", h)
		}
	})
	t.Run("no supported Go", func(t *testing.T) {
		f := newGoFlow(t, ".")
		f.reg.mods[pNet+"@v0.23.0"] = "module " + pNet + "\n\ngo 1.99\n\nrequire " + pText + " v0.15.0\n"
		it := f.refused(CategoryManual, ReasonGoRuntimeUnavailable)
		want := GoLineHint{Module: pNet, Version: "v0.23.0", Go: "1.99", To: "v0.23.0"}
		if h := it.Packages[0].Hint(); h == nil || h.GoLine == nil || *h.GoLine != want {
			t.Errorf("hint = %+v", h)
		}
	})
	t.Run("the project's own toolchain line", func(t *testing.T) {
		f := newGoFlow(t, ".")
		f.mod = strings.Replace(f.mod, "go 1.22\n", "go 1.22\n\ntoolchain go1.99.0\n", 1)
		f.setItem(group(typeGoBinary, pNet, "v0.20.0", FindingOrigin{Entity: "img", Workload: "compose/p/web", Target: "usr/local/bin/app"}, CVERef{VulnID: goCVENet, FixedVers: []string{"0.23.0"}}))
		f.build()
		it := f.refused(CategoryManual, ReasonGoRuntimeUnavailable)
		if h := it.Packages[0].FixHint; h != nil {
			t.Errorf("hint = %+v", h)
		}
	})
}

// goMajorFlow is a Go module that requires example.com/old v1.4.0 through
// example.com/mid v1.0.0 (or itself, when direct), whose fixes are all of v2.
func goMajorFlow(t *testing.T, direct bool) (*goFlow, LanguageItem) {
	t.Helper()
	const old, mid = "example.com/old", "example.com/mid"
	f := newGoFlow(t, ".")
	goWorld(f.reg, old, "v1.4.0")
	goWorld(f.reg, mid, "v1.0.0", old+" v1.4.0")
	goWorld(f.reg, mid, "v1.3.0")
	f.reg.latest[mid] = "v1.3.0"
	oldReq := old + " v1.4.0 // indirect"
	if direct {
		oldReq = old + " v1.4.0"
	}
	f.mod = appMod(pNet+" v0.20.0", mid+" v1.0.0", oldReq)
	f.sum = f.reg.sumLines(pNet, "v0.20.0") + f.reg.sumLines(mid, "v1.0.0") + f.reg.sumLines(old, "v1.4.0")
	f.build()
	lf, _, err := parseGo([]byte(f.sum), []byte(f.mod))
	if err != nil {
		t.Fatal(err)
	}
	g := group(typeGoBinary, old, "v1.4.0", FindingOrigin{Entity: "img", Workload: "compose/p/web", Target: "usr/local/bin/app"},
		CVERef{VulnID: "CVE-OLD-1", FixedVers: []string{"2.1.0"}}, CVERef{VulnID: "CVE-OLD-2", FixedVers: []string{"2.0.3"}})
	p := matchPackage(lf, g)
	if why := goMajorProblem(g.Name, p.Installed, p.SelectionLowerBound); why != "" {
		p.SelectionLowerBound = ""
		manualPackage(&p, ReasonFixInOtherMajor, why)
	}
	it := f.item
	it.Source.Files = []SourceFile{{Path: "go.mod", BlobSHA: gitBlobSHA([]byte(f.mod))}, {Path: "go.sum", BlobSHA: gitBlobSHA([]byte(f.sum))}}
	it.Packages = []LanguagePackage{p}
	classify(&it)
	if it.Category != CategoryManual || p.Reason != ReasonFixInOtherMajor {
		t.Fatalf("item = %s %s, package %s", it.Category, it.Reason, p.Reason)
	}
	return f, it
}

func runPlan(t *testing.T, cfg LangUpdateConfig, it LanguageItem) LanguageItem {
	t.Helper()
	up, err := NewLangUpdater(cfg)
	if err != nil {
		t.Fatal(err)
	}
	plan := &Plan{LanguageItems: []LanguageItem{it}}
	up.Run(context.Background(), plan)
	return plan.LanguageItems[0]
}

// A package whose fixes are all of another major version names the lowest of
// them that fixes it, and the module that brings the old one in with what its
// latest version requires; nothing is updated.
func TestGoOtherMajorHints(t *testing.T) {
	f, it := goMajorFlow(t, false)
	got := runPlan(t, f.cfg, it)
	h := got.Packages[0].Hint()
	if h == nil || h.Fix == nil || h.Fix.Version != "v2.1.0" || h.Direct {
		t.Fatalf("hint = %+v", h)
	}
	if len(h.HeldBy) != 1 || h.HeldBy[0] != (FixHolder{Parent: "example.com/mid", ParentVersion: "v1.0.0", Range: "v1.4.0"}) {
		t.Errorf("held by = %+v", h.HeldBy)
	}
	want := ChainHint{Package: "example.com/old", Parent: "example.com/mid", ParentVersion: "v1.0.0", Latest: &ChainHintRelease{Version: "v1.3.0", Dropped: true}}
	if len(h.Releases) != 1 || h.Releases[0].Parent != want.Parent || *h.Releases[0].Latest != *want.Latest {
		t.Errorf("releases = %+v", h.Releases)
	}
	if f.work.calls != 0 {
		t.Error("a container ran")
	}
}

// A package the project requires itself is named as such, with no modules
// looked up.
func TestGoOtherMajorHintsDirect(t *testing.T) {
	f, it := goMajorFlow(t, true)
	got := runPlan(t, f.cfg, it)
	h := got.Packages[0].Hint()
	if h == nil || !h.Direct || len(h.HeldBy) != 0 || h.Fix == nil {
		t.Fatalf("hint = %+v", h)
	}
}

// Without the proxy, the fix is still named.
func TestGoOtherMajorHintsWithoutTheProxy(t *testing.T) {
	f, it := goMajorFlow(t, false)
	f.reg.err = errors.New("proxy down")
	got := runPlan(t, f.cfg, it)
	h := got.Packages[0].Hint()
	if h == nil || h.Fix == nil || len(h.HeldBy) != 0 {
		t.Fatalf("hint = %+v", h)
	}
}

// The latest version of a dependent whose go.mod the proxy made up says
// nothing of what it requires.
func TestGoOtherMajorHintsMadeUpGoMod(t *testing.T) {
	f, it := goMajorFlow(t, false)
	f.reg.mod("example.com/mid", "v1.3.0", "module example.com/mid\n")
	got := runPlan(t, f.cfg, it)
	h := got.Packages[0].Hint()
	if h == nil || len(h.HeldBy) != 1 || len(h.Releases) != 0 {
		t.Fatalf("hint = %+v", h)
	}
}

// The go.mod files the hints read, the latest versions of the dependents
// included, stay within their bound.
func TestGoOtherMajorHintsReadBound(t *testing.T) {
	f, it := goMajorFlow(t, false)
	old := maxGoHintReads
	maxGoHintReads = 1
	defer func() { maxGoHintReads = old }()
	before := f.reg.gomods
	runPlan(t, f.cfg, it)
	// go.mod of the requirements: example.com/mid v1.0.0 is the one read
	// (golang.org/x/net sorts after it); the latest of mid is not.
	if n := f.reg.gomodCalls["example.com/mid@v1.3.0"]; n != 0 {
		t.Errorf("latest read %d times past the bound (go.mod reads %d)", n, f.reg.gomods-before)
	}
}
