package remediation

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
	"github.com/kitsunetrail/kestrelynx/internal/worker"
)

// goFlow wires a Go item to fakes: a proxy, a work container whose go get
// returns newMod and newSum, and a scanner that reports the vulnerabilities
// of the module versions a go.mod requires.
type goFlow struct {
	t    *testing.T
	reg  *fakeGoReg
	dir  string
	mod  string
	sum  string
	item LanguageItem
	work *fakeWork
	fs   *fakeFS
	gh   *fakeGH
	cfg  LangUpdateConfig

	// newMod and newSum are what the work container returns.
	newMod, newSum string
	// vulns are the vulnerability ids of a module version, by "path@version".
	vulns map[string][]string
	// scans are the files of each scan.
	scans []map[string][]byte
	// scanHook changes the report of the n-th scan.
	scanHook func(n int, s *scanner.FSScan)
}

const (
	goTestNow = "2026-10-29T00:00:00Z"
	goCVENet  = "CVE-NET"
)

func goPath(dir, name string) string {
	if dir == "" || dir == "." {
		return name
	}
	return dir + "/" + name
}

// newGoFlow is the flow of the usual update: x/net 0.20.0 to 0.23.0, which
// requires x/text 0.15.0, in a module at dir.
func newGoFlow(t *testing.T, dir string) *goFlow {
	t.Helper()
	reg := netWorld()
	mod := appMod(pNet+" v0.20.0", pErr+" v0.9.1 // indirect", pText+" v0.14.0 // indirect")
	sum := reg.sumLines(pNet, "v0.20.0") + reg.sumLines(pErr, "v0.9.1") + reg.sumLines(pText, "v0.14.0")
	f := &goFlow{t: t, reg: reg, dir: dir, mod: mod, sum: sum,
		newMod: appMod(pNet+" v0.23.0", pErr+" v0.9.1 // indirect", pText+" v0.15.0 // indirect"),
		newSum: sum,
		vulns:  map[string][]string{pNet + "@v0.20.0": {goCVENet}},
	}
	reg.latest[pNet] = "v0.30.0"
	goWorld(reg, pNet, "v0.30.0", pText+" v0.20.0")
	f.setItem(group(typeGoBinary, pNet, "v0.20.0", FindingOrigin{Entity: "img", Workload: "compose/p/web", Target: "usr/local/bin/app"},
		CVERef{VulnID: goCVENet, FixedVers: []string{"0.23.0"}}))
	f.build()
	return f
}

// setItem builds the plan item of the flow's go.mod and go.sum.
func (f *goFlow) setItem(groups ...*findingGroup) {
	f.t.Helper()
	lf, _, err := parseGo([]byte(f.sum), []byte(f.mod))
	if err != nil {
		f.t.Fatal(err)
	}
	it := LanguageItem{
		Key: "deps:o/r@main:" + f.dir + "#go", Workloads: []string{"compose/p/web"}, Manager: ManagerGo, GoBuiltWith: "1.26.4",
		Source: SourceRecord{Repository: "o/r", BaseBranch: "main", Directory: f.dir, CommitSHA: testCommit, Origin: OriginConfig, Confidence: ConfidenceAsserted,
			Files:  []SourceFile{{Path: goPath(f.dir, "go.mod"), BlobSHA: gitBlobSHA([]byte(f.mod))}, {Path: goPath(f.dir, "go.sum"), BlobSHA: gitBlobSHA([]byte(f.sum))}},
			Absent: []string{goPath(f.dir, "go.work"), goPath(f.dir, "vendor")}},
	}
	var pkgs []LanguagePackage
	for _, g := range groups {
		pkgs = append(pkgs, matchPackage(lf, g))
	}
	reconcileVersions(lf, pkgs)
	it.Packages = pkgs
	classify(&it)
	if it.Category != CategoryDependencyUpdateCandidate {
		f.t.Fatalf("the item is not an update candidate: %s %s (%s)", it.Category, it.Reason, it.Detail)
	}
	f.item = it
}

// build creates the fakes from the current fields.
func (f *goFlow) build() {
	f.gh = ghFor(map[string]string{goPath(f.dir, "go.mod"): f.mod, goPath(f.dir, "go.sum"): f.sum})
	f.work = &fakeWork{script: func(n int, job worker.Job, src map[string][]byte) fakeOutcome {
		return fakeOutcome{edit: map[string]map[string][]byte{stepUpdate: {"go.mod": []byte(f.newMod), "go.sum": []byte(f.newSum)}}}
	}}
	f.fs = &fakeFS{fn: f.scan}
	now, _ := time.Parse(time.RFC3339, goTestNow)
	f.cfg = LangUpdateConfig{Scanner: f.fs, Work: f.work, PyPI: &fakePyPI{}, Npm: &fakeNpm{}, Go: f.reg, GitHub: f.gh,
		Prepared: fsConds, Images: map[string]ImageEnv{"img": debianAmd64}, MaxJobs: 5, Now: func() time.Time { return now }}
	f.cfg = withTestTools(f.t, f.cfg)
}

// scan reports, for each go.mod it is given, the module versions it requires
// and the vulnerabilities of each.
func (f *goFlow) scan(n int, files map[string][]byte) (scanner.FSScan, error) {
	f.scans = append(f.scans, files)
	scan := scanner.ImageScan{TrivyVersion: "0.71.2"}
	for name, content := range files {
		gm, err := parseGoMod(content)
		if err != nil {
			return scanner.FSScan{}, err
		}
		rp := scanner.ResultPackages{Target: name, Class: inventory.ClassLang, Type: typeGoModule}
		for _, r := range gm.requires {
			rp.Packages = append(rp.Packages, scanner.Package{Name: r.path, Version: r.version})
			for _, id := range f.vulns[r.path+"@"+r.version] {
				scan.Findings = append(scan.Findings, scanner.Finding{Class: inventory.ClassLang, Type: typeGoModule, Target: name, Package: r.path,
					InstalledVer: r.version, VulnID: id, Status: scanner.StatusFixed, Severity: scanner.SeverityHigh})
			}
		}
		scan.Packages = append(scan.Packages, rp)
	}
	res := scanner.FSScan{Conditions: fsConds, Report: scan}
	if f.scanHook != nil {
		f.scanHook(n, &res)
	}
	return res, nil
}

func (f *goFlow) run() (LanguageItem, LangUpdateUsage) {
	f.t.Helper()
	up, err := NewLangUpdater(f.cfg)
	if err != nil {
		f.t.Fatal(err)
	}
	item := f.item
	item.Packages = append([]LanguagePackage(nil), f.item.Packages...)
	plan := &Plan{LanguageItems: []LanguageItem{item}}
	use := up.Run(context.Background(), plan)
	return plan.LanguageItems[0], use
}

// refused runs the flow and requires a manual item with the reason, and that
// the item keeps no artifact.
func (f *goFlow) refused(cat Category, reason Reason) LanguageItem {
	f.t.Helper()
	it, _ := f.run()
	wantCategory(f.t, it, cat, reason)
	if len(it.Artifacts) != 0 {
		f.t.Errorf("a refused update keeps artifacts: %+v", it.Artifacts)
	}
	return it
}

func TestGoUpdateSucceeds(t *testing.T) {
	f := newGoFlow(t, ".")
	it, use := f.run()
	wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
	if use.Jobs != 1 || !it.UpdateExecuted || !it.PostUpdateCheckExecuted {
		t.Errorf("jobs = %d, executed = %v %v", use.Jobs, it.UpdateExecuted, it.PostUpdateCheckExecuted)
	}
	if p := it.Packages[0]; p.AdoptedVersion != "v0.23.0" || p.Action != ActionUpdate {
		t.Errorf("package = %+v", p)
	}

	// go.mod and go.sum, the second completed from the database.
	wantSum := f.sum + f.reg.sumLines(pNet, "v0.23.0") + f.reg.sumLines(pText, "v0.15.0")
	if len(it.Artifacts) != 2 || it.Artifacts[0].Path != "go.mod" || it.Artifacts[1].Path != "go.sum" {
		t.Fatalf("artifacts = %+v", it.Artifacts)
	}
	if string(it.Artifacts[0].Content) != f.newMod || it.Artifacts[0].SHA256 != sha256Hex([]byte(f.newMod)) {
		t.Errorf("go.mod artifact = %+v", it.Artifacts[0])
	}
	var wantLines []string
	for _, l := range strings.Split(strings.TrimSpace(wantSum), "\n") {
		wantLines = append(wantLines, l)
	}
	sortStable(wantLines)
	gotSum := parseSortedSum(t, it.Artifacts[1].Content)
	if gotSum != strings.Join(wantLines, "\n") || it.Artifacts[1].SHA256 != sha256Hex(it.Artifacts[1].Content) || it.Artifacts[1].Size != int64(len(it.Artifacts[1].Content)) || it.Artifacts[1].Mode != "100644" {
		t.Errorf("go.sum artifact = %q\nwant %q", it.Artifacts[1].Content, wantSum)
	}

	g := it.Update.Go
	if g == nil || len(g.Collateral) != 1 || g.Collateral[0] != (GoModuleMove{Path: pText, From: "v0.14.0", To: "v0.15.0"}) {
		t.Fatalf("go record = %+v", g)
	}
	if g.GoBefore != "1.22" || g.GoAfter != "1.22" || g.ToolchainBefore != "" || g.ToolchainAfter != "" {
		t.Errorf("go lines = %+v", g)
	}
	if len(g.SumAdded) != 4 {
		t.Errorf("sum added = %v", g.SumAdded)
	}
	for _, l := range g.SumAdded {
		if !strings.Contains(wantSum, l) {
			t.Errorf("added line %q is not in go.sum", l)
		}
	}

	if it.Update.Runtime == nil || it.Update.Runtime.ID != "golang1.26" {
		t.Errorf("runtime = %+v", it.Update.Runtime)
	}
	if len(f.work.jobs) != 1 {
		t.Fatalf("jobs = %d", len(f.work.jobs))
	}
	job := f.work.jobs[0]
	if job.Manager != worker.ManagerGo || job.Runtime.ID != "golang1.26" || len(job.Steps) != 1 || job.Steps[0].Op != worker.OpGoGet ||
		len(job.Steps[0].Packages) != 1 || job.Steps[0].Packages[0] != (worker.Package{Name: pNet, Version: "v0.23.0"}) {
		t.Errorf("job = %+v", job)
	}
	if string(f.work.srcs[0]["go.mod"]) != f.mod || string(f.work.srcs[0]["go.sum"]) != f.sum {
		t.Error("the container did not get the original go.mod and go.sum")
	}

	sc := it.SourceCheck
	if sc == nil || !sc.Passed || len(sc.Resolved) != 1 || sc.Resolved[0].VulnID != goCVENet || len(sc.Introduced) != 0 {
		t.Fatalf("source check = %+v", sc)
	}
	if len(sc.Before) != 1 || sc.Before[0].Path != "go.mod" || len(sc.After) != 1 || sc.After[0].Path != "go.mod" || sc.Before[0].SHA256 == sc.After[0].SHA256 {
		t.Errorf("source check files = %+v %+v", sc.Before, sc.After)
	}
	for _, files := range f.scans {
		if len(files) != 1 || files["go.mod"] == nil {
			t.Errorf("a scan took %v; only go.mod is scanned", goSortedKeys(files))
		}
	}
}

// parseSortedSum is the lines of a go.sum, in order, as one string.
func parseSortedSum(t *testing.T, b []byte) string {
	t.Helper()
	lines, err := parseGoSumLines(b)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, l := range lines {
		out = append(out, l.text())
	}
	return strings.Join(out, "\n")
}

func TestGoUpdateWithoutCollateral(t *testing.T) {
	f := newGoFlow(t, ".")
	goWorld(f.reg, pNet, "v0.23.0", pText+" v0.14.0")
	f.newMod = appMod(pNet+" v0.23.0", pErr+" v0.9.1 // indirect", pText+" v0.14.0 // indirect")
	it, _ := f.run()
	wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
	if len(it.Update.Go.Collateral) != 0 || len(it.Update.Go.SumAdded) != 2 {
		t.Errorf("go record = %+v", it.Update.Go)
	}
}

// A target the output writes past the version asked for, which no
// requirement explains, is refused: the walk starts from the version asked
// for.
func TestGoUpdateTargetPastItsVersion(t *testing.T) {
	f := newGoFlow(t, ".")
	goWorld(f.reg, pNet, "v0.24.0", pText+" v0.15.0")
	f.newMod = appMod(pNet+" v0.24.0", pErr+" v0.9.1 // indirect", pText+" v0.15.0 // indirect")
	f.refused(CategoryManual, ReasonUnexplainedDiff)
}

func TestGoUpdateWithAnAddedRequirement(t *testing.T) {
	const sys = "golang.org/x/sys"
	f := newGoFlow(t, ".")
	goWorld(f.reg, pNet, "v0.23.0", pText+" v0.15.0", sys+" v0.18.0")
	goWorld(f.reg, sys, "v0.18.0")
	f.newMod = appMod(pNet+" v0.23.0", pErr+" v0.9.1 // indirect", pText+" v0.15.0 // indirect", sys+" v0.18.0 // indirect")
	it, _ := f.run()
	wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
	var added *GoModuleMove
	for i, m := range it.Update.Go.Collateral {
		if m.Path == sys {
			added = &it.Update.Go.Collateral[i]
		}
	}
	if added == nil || added.From != "" || added.To != "v0.18.0" {
		t.Errorf("collateral = %+v", it.Update.Go.Collateral)
	}
}

func TestGoUpdateRuntimeChoice(t *testing.T) {
	r126, _ := worker.LookupRuntime("golang1.26")
	r127, _ := worker.LookupRuntime("golang1.27")
	v126, _ := parseGoRelease(r126.Version)
	v127, _ := parseGoRelease(r127.Version)
	at := func(s string) time.Time { tm, _ := time.Parse("2006-01-02", s); return tm }
	for name, c := range map[string]struct {
		need goRelease
		now  time.Time
		want string
	}{
		"an old go line":              {goRelease{1, 22, 0}, at("2026-10-29"), "golang1.26"},
		"the newest 1.26 patch":       {v126, at("2026-10-29"), "golang1.26"},
		"a patch past the table 1.26": {goRelease{v126.major, v126.minor, v126.patch + 1}, at("2026-10-29"), "golang1.27"},
		"the newest 1.27 patch":       {v127, at("2026-10-29"), "golang1.27"},
		"a patch past the table 1.27": {goRelease{v127.major, v127.minor, v127.patch + 1}, at("2026-10-29"), ""},
		"a newer series":              {goRelease{1, 99, 0}, at("2026-10-29"), ""},
		"1.26 past its support":       {goRelease{1, 22, 0}, at(r126.EOL).AddDate(0, 0, 1), "golang1.27"},
		"nothing in support":          {goRelease{1, 22, 0}, at(r127.EOL).AddDate(0, 0, 1), ""},
	} {
		spec, ok := goRuntimeFor(c.need, c.now)
		if (c.want != "") != ok || (ok && spec.ID != c.want) {
			t.Errorf("%s: got %q %v, want %q", name, spec.ID, ok, c.want)
		}
	}

	// The target's go line decides in the flow.
	f := newGoFlow(t, ".")
	goWorld(f.reg, pNet, "v0.23.0", pText+" v0.15.0")
	f.reg.mods[pNet+"@v0.23.0"] = "module " + pNet + "\n\ngo " + r127.Version + "\n\nrequire " + pText + " v0.15.0\n"
	f.newMod = strings.Replace(f.newMod, "go 1.22\n", "go "+r127.Version+"\n", 1)
	f.item.GoBuiltWith = r127.Version
	it, _ := f.run()
	wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
	if it.Update.Runtime.ID != "golang1.27" || f.work.jobs[0].Runtime.ID != "golang1.27" {
		t.Errorf("runtime = %+v, job %+v", it.Update.Runtime, f.work.jobs[0].Runtime)
	}

	// A target that needs a Go no supported series has: nothing runs.
	f = newGoFlow(t, ".")
	f.reg.mods[pNet+"@v0.23.0"] = "module " + pNet + "\n\ngo 1.99\n\nrequire " + pText + " v0.15.0\n"
	f.refused(CategoryManual, ReasonGoRuntimeUnavailable)
	if f.work.calls != 0 {
		t.Error("a container ran")
	}
	// The original toolchain line counts too.
	f = newGoFlow(t, ".")
	f.mod = strings.Replace(f.mod, "go 1.22\n", "go 1.22\n\ntoolchain go1.99.0\n", 1)
	f.setItem(group(typeGoBinary, pNet, "v0.20.0", FindingOrigin{Entity: "img", Workload: "compose/p/web", Target: "usr/local/bin/app"}, CVERef{VulnID: goCVENet, FixedVers: []string{"0.23.0"}}))
	f.build()
	f.refused(CategoryManual, ReasonGoRuntimeUnavailable)
	// The clock decides what is in support.
	f = newGoFlow(t, ".")
	far := at(r127.EOL).AddDate(1, 0, 0)
	f.cfg.Now = func() time.Time { return far }
	f.refused(CategoryManual, ReasonGoRuntimeUnavailable)
}

func TestGoUpdateGoLineCeiling(t *testing.T) {
	// line writes the go and toolchain lines of the result; a raised go line
	// is declared by the target's new version, as go get raises it.
	line := func(f *goFlow, goLine, toolchain string) {
		if goLine != "1.22" {
			f.reg.mod(pNet, "v0.23.0", goModText(pNet, goLine, pText+" v0.15.0"))
		}
		m := strings.Replace(f.newMod, "go 1.22\n", "go "+goLine+"\n", 1)
		if toolchain != "" {
			m = strings.Replace(m, "go "+goLine+"\n", "go "+goLine+"\n\ntoolchain "+toolchain+"\n", 1)
		}
		f.newMod = m
	}
	t.Run("a go line above what the binaries were built with", func(t *testing.T) {
		f := newGoFlow(t, ".")
		f.item.GoBuiltWith = "1.22.5"
		line(f, "1.24", "")
		f.refused(CategoryManual, ReasonGoLineRaised)
	})
	t.Run("a go line above what the versions moved to declare", func(t *testing.T) {
		f := newGoFlow(t, ".")
		f.item.GoBuiltWith = "1.26.4"
		f.newMod = strings.Replace(f.newMod, "go 1.22\n", "go 1.24.0\n", 1)
		f.refused(CategoryManual, ReasonUnexplainedDiff)
	})
	t.Run("a go line raised short of what the versions moved to declare", func(t *testing.T) {
		f := newGoFlow(t, ".")
		f.item.GoBuiltWith = "1.26.4"
		f.reg.mod(pNet, "v0.23.0", goModText(pNet, "1.25.0", pText+" v0.15.0"))
		f.newMod = strings.Replace(f.newMod, "go 1.22\n", "go 1.23.0\n", 1)
		f.refused(CategoryManual, ReasonUnexplainedDiff)
	})
	t.Run("a toolchain line taken away", func(t *testing.T) {
		f := newGoFlow(t, ".")
		f.mod = strings.Replace(f.mod, "go 1.22\n", "go 1.22\n\ntoolchain go1.24.2\n", 1)
		f.setItem(group(typeGoBinary, pNet, "v0.20.0", FindingOrigin{Entity: "img", Workload: "compose/p/web", Target: "usr/local/bin/app"}, CVERef{VulnID: goCVENet, FixedVers: []string{"0.23.0"}}))
		f.build()
		f.refused(CategoryManual, ReasonOutputFilesInvalid)
	})
	t.Run("a go line raised when the build Go is not known", func(t *testing.T) {
		f := newGoFlow(t, ".")
		f.item.GoBuiltWith = ""
		line(f, "1.23", "")
		f.refused(CategoryManual, ReasonGoLineRaised)
	})
	t.Run("a go line left alone when the build Go is not known", func(t *testing.T) {
		f := newGoFlow(t, ".")
		f.item.GoBuiltWith = ""
		it, _ := f.run()
		wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
	})
	t.Run("a go line raised up to the build Go is accepted", func(t *testing.T) {
		f := newGoFlow(t, ".")
		f.item.GoBuiltWith = "1.24.0"
		line(f, "1.24.0", "")
		it, _ := f.run()
		wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
		if it.Update.Go.GoAfter != "1.24.0" {
			t.Errorf("go after = %q", it.Update.Go.GoAfter)
		}
	})
	t.Run("patch numbers are compared", func(t *testing.T) {
		f := newGoFlow(t, ".")
		f.item.GoBuiltWith = "1.24.0"
		line(f, "1.24.1", "")
		f.refused(CategoryManual, ReasonGoLineRaised)
	})
	t.Run("a toolchain line above the build Go", func(t *testing.T) {
		f := newGoFlow(t, ".")
		f.item.GoBuiltWith = "1.22.5"
		line(f, "1.22", "go1.23.4")
		f.refused(CategoryManual, ReasonGoLineRaised)
	})
	t.Run("a toolchain line added within the build Go", func(t *testing.T) {
		f := newGoFlow(t, ".")
		f.item.GoBuiltWith = "1.22.5"
		line(f, "1.22", "go1.22.5")
		it, _ := f.run()
		wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
		if it.Update.Go.ToolchainAfter != "go1.22.5" || it.Update.Go.ToolchainBefore != "" {
			t.Errorf("go record = %+v", it.Update.Go)
		}
	})
	t.Run("a go line that went down", func(t *testing.T) {
		f := newGoFlow(t, ".")
		line(f, "1.21", "")
		f.refused(CategoryManual, ReasonOutputFilesInvalid)
	})
	t.Run("a go line that is not a release", func(t *testing.T) {
		f := newGoFlow(t, ".")
		line(f, "1.23rc1", "")
		it, _ := f.run()
		if it.Category == CategoryPRCandidate {
			t.Errorf("accepted: %s %s", it.Category, it.Reason)
		}
	})
}

func TestGoUpdateTargetVersion(t *testing.T) {
	t.Run("retracted by the latest go.mod", func(t *testing.T) {
		for name, retract := range map[string]string{
			"one version":      "retract v0.23.0",
			"an interval":      "retract [v0.22.0, v0.24.0]",
			"the low end":      "retract [v0.23.0, v0.25.0]",
			"the high end":     "retract [v0.20.0, v0.23.0]",
			"in a block":       "retract (\n\tv0.1.0\n\tv0.23.0\n)",
			"with a rationale": "retract v0.23.0 // broken release",
		} {
			f := newGoFlow(t, ".")
			f.reg.mod(pNet, "v0.30.0", goModText(pNet, "1.18")+"\n"+retract+"\n")
			it := f.refused(CategoryManual, ReasonGoRetracted)
			if f.work.calls != 0 {
				t.Errorf("%s: a container ran", name)
			}
			if it.Packages[0].Reason != ReasonGoRetracted {
				t.Errorf("%s: package reason = %s", name, it.Packages[0].Reason)
			}
		}
	})
	t.Run("a retraction of other versions is no matter", func(t *testing.T) {
		for name, retract := range map[string]string{
			"another version": "retract v0.22.0",
			"just below":      "retract [v0.20.0, v0.22.9]",
			"just above":      "retract [v0.23.1, v0.25.0]",
		} {
			f := newGoFlow(t, ".")
			f.reg.mod(pNet, "v0.30.0", goModText(pNet, "1.18")+"\n"+retract+"\n")
			if it, _ := f.run(); it.Category != CategoryPRCandidate {
				t.Errorf("%s: %s %s (%s)", name, it.Category, it.Reason, it.Detail)
			}
		}
	})
	t.Run("the latest go.mod cannot be used", func(t *testing.T) {
		f := newGoFlow(t, ".")
		f.reg.mod(pNet, "v0.30.0", "module (\n")
		f.refused(CategoryManual, ReasonDistributionMismatch)
		f = newGoFlow(t, ".")
		f.reg.mod(pNet, "v0.30.0", goModText("example.com/other", "1.18"))
		f.refused(CategoryManual, ReasonDistributionMismatch)
		f = newGoFlow(t, ".")
		delete(f.reg.latest, pNet)
		f.refused(CategoryManual, ReasonDistributionMismatch)
		f = newGoFlow(t, ".")
		delete(f.reg.mods, pNet+"@v0.30.0")
		f.refused(CategoryManual, ReasonDistributionMismatch)
		if f.work.calls != 0 {
			t.Error("a container ran")
		}
	})
	t.Run("the proxy names another version", func(t *testing.T) {
		f := newGoFlow(t, ".")
		f.reg.reported[pNet+"@v0.23.0"] = "v0.23.1"
		f.refused(CategoryManual, ReasonDistributionMismatch)
	})
	t.Run("the proxy has no such version", func(t *testing.T) {
		f := newGoFlow(t, ".")
		delete(f.reg.mods, pNet+"@v0.23.0")
		f.refused(CategoryManual, ReasonDistributionMismatch)
	})
	t.Run("the proxy cannot be reached", func(t *testing.T) {
		f := newGoFlow(t, ".")
		f.reg.err = errors.New("dial tcp: no route to host")
		f.refused(CategoryFailed, ReasonDistributionLookup)
		if f.work.calls != 0 {
			t.Error("a container ran")
		}
	})
	t.Run("the target is not in go.mod", func(t *testing.T) {
		f := newGoFlow(t, ".")
		f.item.Packages[0].Name = "golang.org/x/other"
		it, _ := f.run()
		if it.Category == CategoryPRCandidate || f.work.calls != 0 {
			t.Errorf("%s %s, %d jobs", it.Category, it.Reason, f.work.calls)
		}
	})
}

func TestGoUpdateIncompatibleRequery(t *testing.T) {
	const inc = "example.com/inc"
	build := func(t *testing.T, newModule string) *goFlow {
		f := newGoFlow(t, ".")
		f.mod = appMod(inc+" v2.0.0+incompatible", pNet+" v0.20.0")
		f.sum = f.reg.sumLines(inc, "v2.0.0+incompatible") + f.reg.sumLines(pNet, "v0.20.0")
		goWorld(f.reg, inc, "v2.0.0+incompatible")
		f.reg.latest[inc] = "v2.1.0+incompatible"
		goWorld(f.reg, inc, "v2.1.0+incompatible")
		f.reg.mod(inc, "v2.0.5+incompatible", newModule)
		f.newMod = appMod(inc+" v2.0.5+incompatible", pNet+" v0.20.0")
		f.newSum = f.sum
		f.vulns = map[string][]string{inc + "@v2.0.0+incompatible": {"CVE-INC"}}
		f.setItem(group(typeGoBinary, inc, "v2.0.0+incompatible", FindingOrigin{Entity: "img", Workload: "compose/p/web", Target: "usr/local/bin/app"},
			CVERef{VulnID: "CVE-INC", FixedVers: []string{"2.0.5"}}))
		f.build()
		return f
	}
	t.Run("asked again with +incompatible", func(t *testing.T) {
		f := build(t, goModText(inc, "1.18"))
		it, _ := f.run()
		wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
		if got := f.work.jobs[0].Steps[0].Packages; len(got) != 1 || got[0].Version != "v2.0.5+incompatible" {
			t.Errorf("packages = %+v", got)
		}
		if it.Packages[0].AdoptedVersion != "v2.0.5+incompatible" {
			t.Errorf("adopted = %q", it.Packages[0].AdoptedVersion)
		}
	})
	t.Run("a go.mod the proxy made up is refused", func(t *testing.T) {
		f := build(t, "module "+inc+"\n")
		f.refused(CategoryManual, ReasonUnexplainedDiff)
	})
	t.Run("a version of the first series is not asked again", func(t *testing.T) {
		f := newGoFlow(t, ".")
		delete(f.reg.mods, pNet+"@v0.23.0")
		f.refused(CategoryManual, ReasonDistributionMismatch)
		if f.reg.infos != 1 {
			t.Errorf("info lookups = %d, want 1", f.reg.infos)
		}
	})
}

func TestGoUpdateOtherMajor(t *testing.T) {
	const m = "example.com/m/v2"
	f := newGoFlow(t, ".")
	f.mod = appMod(m + " v2.3.1")
	f.sum = f.reg.sumLines(m, "v2.3.1")
	f.newMod, f.newSum = appMod(m+" v3.0.0"), f.sum
	goWorld(f.reg, m, "v2.3.1")
	goWorld(f.reg, m, "v3.0.0")
	f.reg.latest[m] = "v3.0.0"
	f.vulns = map[string][]string{m + "@v2.3.1": {"CVE-M"}}
	f.setItem(group(typeGoBinary, m, "v2.3.1", FindingOrigin{Entity: "img", Workload: "compose/p/web", Target: "usr/local/bin/app"}, CVERef{VulnID: "CVE-M", FixedVers: []string{"2.3.2"}}))
	f.build()
	// The plan never gives a target of another major; if one were given, the
	// update stops before it runs anything.
	f.item.Packages[0].SelectionLowerBound = "3.0.0"
	f.refused(CategoryManual, ReasonFixInOtherMajor)
	if f.work.calls != 0 {
		t.Error("a container ran")
	}
}

func TestGoUpdateRefusesTheContainersOutput(t *testing.T) {
	const sys = "golang.org/x/sys"
	good := func(f *goFlow) string { return f.newMod }
	for name, c := range map[string]struct {
		edit   func(f *goFlow)
		cat    Category
		reason Reason
	}{
		"go.mod unchanged":  {func(f *goFlow) { f.newMod = f.mod }, CategoryManual, ReasonTargetNotUpdated},
		"go.mod unparsable": {func(f *goFlow) { f.newMod = "module (\n" }, CategoryManual, ReasonOutputFilesInvalid},
		"a replace added":   {func(f *goFlow) { f.newMod = good(f) + "replace " + pNet + " => ../net\n" }, CategoryManual, ReasonOutputFilesInvalid},
		"an exclude added":  {func(f *goFlow) { f.newMod = good(f) + "exclude " + pNet + " v0.21.0\n" }, CategoryManual, ReasonOutputFilesInvalid},
		"the module line changed": {func(f *goFlow) {
			f.newMod = strings.Replace(good(f), "module example.com/app", "module example.com/evil", 1)
		}, CategoryManual, ReasonOutputFilesInvalid},
		"a requirement removed": {func(f *goFlow) {
			f.newMod = strings.Replace(good(f), "\t"+pErr+" v0.9.1 // indirect\n", "", 1)
		}, CategoryManual, ReasonOutputFilesInvalid},
		"a requirement lowered": {func(f *goFlow) {
			f.newMod = strings.Replace(good(f), pText+" v0.15.0", pText+" v0.13.0", 1)
		}, CategoryManual, ReasonOutputFilesInvalid},
		"an indirect mark dropped": {func(f *goFlow) {
			f.newMod = strings.Replace(good(f), pErr+" v0.9.1 // indirect", pErr+" v0.9.1", 1)
		}, CategoryManual, ReasonOutputFilesInvalid},
		"the target below its target": {func(f *goFlow) {
			goWorld(f.reg, pNet, "v0.22.0", pText+" v0.15.0")
			f.newMod = strings.Replace(good(f), pNet+" v0.23.0", pNet+" v0.22.0", 1)
		}, CategoryManual, ReasonTargetNotUpdated},
		"the target removed": {func(f *goFlow) {
			f.newMod = strings.Replace(good(f), "\t"+pNet+" v0.23.0\n", "", 1)
		}, CategoryManual, ReasonOutputFilesInvalid},
		"a move nothing explains": {func(f *goFlow) {
			f.newMod = strings.Replace(good(f), pErr+" v0.9.1", pErr+" v0.9.2", 1)
		}, CategoryManual, ReasonUnexplainedDiff},
		"a requirement added that nothing explains": {func(f *goFlow) {
			goWorld(f.reg, sys, "v0.18.0")
			f.newMod = strings.Replace(good(f), "// indirect\n)", "// indirect\n\t"+sys+" v0.18.0 // indirect\n)", 1)
		}, CategoryManual, ReasonUnexplainedDiff},
		"a written version below what the target requires": {func(f *goFlow) {
			f.newMod = strings.Replace(good(f), pText+" v0.15.0", pText+" v0.14.0", 1)
		}, CategoryManual, ReasonUnexplainedDiff},
		"a target whose go.mod the proxy made up": {func(f *goFlow) {
			f.reg.mods[pNet+"@v0.23.0"] = "module " + pNet + "\n"
		}, CategoryManual, ReasonUnexplainedDiff},
		"a forged go.sum line": {func(f *goFlow) {
			f.newSum = f.sum + pNet + " v0.23.0 " + fakeH1("forged") + "\n"
		}, CategoryManual, ReasonDistributionMismatch},
		"a forged go.mod line in go.sum": {func(f *goFlow) {
			f.newSum = f.sum + pNet + " v0.23.0/go.mod " + fakeH1("forged") + "\n"
		}, CategoryManual, ReasonDistributionMismatch},
		"a go.sum line removed": {func(f *goFlow) {
			f.newSum = f.reg.sumLines(pNet, "v0.20.0") + f.reg.sumLines(pText, "v0.14.0")
		}, CategoryManual, ReasonDistributionMismatch},
		"a go.sum line changed": {func(f *goFlow) {
			f.newSum = strings.Replace(f.sum, f.reg.zipHash(pErr, "v0.9.1"), fakeH1("changed"), 1)
		}, CategoryManual, ReasonDistributionMismatch},
		"a go.sum that is not one":  {func(f *goFlow) { f.newSum = "not a go.sum\n" }, CategoryManual, ReasonDistributionMismatch},
		"no record in the database": {func(f *goFlow) { f.reg.noSums[pNet+"@v0.23.0"] = true }, CategoryManual, ReasonDistributionMismatch},
		"the proxy's go.mod is not the one the database records": {func(f *goFlow) {
			f.reg.sums[pNet+"@v0.23.0"] = GoSums{Zip: f.reg.zipHash(pNet, "v0.23.0"), Mod: fakeH1("other go.mod")}
		}, CategoryManual, ReasonDistributionMismatch},
	} {
		t.Run(name, func(t *testing.T) {
			f := newGoFlow(t, ".")
			c.edit(f)
			f.refused(c.cat, c.reason)
		})
	}
}

// A failed request to the proxy or the checksum database, after the
// container ran, is a lookup that failed, not an answer that is refused.
func TestGoUpdateFailedRequestAfterTheUpdate(t *testing.T) {
	f := newGoFlow(t, ".")
	f.reg.noSums = map[string]bool{}
	calls := 0
	f.cfg.Go = &failingSums{fakeGoReg: f.reg, after: &calls}
	f.refused(CategoryFailed, ReasonDistributionLookup)
}

// failingSums answers every request but the checksum database's, which fails
// as a network error would.
type failingSums struct {
	*fakeGoReg
	after *int
}

func (f *failingSums) Sums(context.Context, string, string) (GoSums, error) {
	*f.after++
	return GoSums{}, errors.New("read tcp: connection reset by peer")
}

func TestGoUpdateFailedGoModRequestAfterTheUpdate(t *testing.T) {
	f := newGoFlow(t, ".")
	f.cfg.Go = &failingGoMod{fakeGoReg: f.reg, fail: pText + "@v0.15.0"}
	f.refused(CategoryFailed, ReasonDistributionLookup)
}

type failingGoMod struct {
	*fakeGoReg
	fail string
}

func (f *failingGoMod) GoMod(ctx context.Context, path, version string) ([]byte, error) {
	if path+"@"+version == f.fail {
		return nil, errors.New("read tcp: connection reset by peer")
	}
	return f.fakeGoReg.GoMod(ctx, path, version)
}

func TestGoFailureMapping(t *testing.T) {
	if f := goFailure(bg, errRegistryBudget, ReasonDistributionMismatch); f.category != CategoryDeferred || f.reason != ReasonRegistryCheckLimit {
		t.Errorf("budget: %s %s", f.category, f.reason)
	}
	if f := goFailure(bg, errGoFetchLimit, ReasonDistributionMismatch); f.category != CategoryManual || f.reason != ReasonGoDependenciesUncheckable {
		t.Errorf("fetch limit: %s %s", f.category, f.reason)
	}
	if f := goFailure(bg, errors.New("the hash differs"), ReasonDistributionMismatch); f.category != CategoryManual || f.reason != ReasonDistributionMismatch {
		t.Errorf("refusal: %s %s", f.category, f.reason)
	}
	if f := goFailure(bg, &goLookupError{what: "the proxy", err: errors.New("reset")}, ReasonDistributionMismatch); f.category != CategoryFailed || f.reason != ReasonDistributionLookup {
		t.Errorf("lookup error: %s %s", f.category, f.reason)
	}
	ctx, cancel := context.WithCancel(bg)
	cancel()
	if f := goFailure(ctx, errors.New("x"), ReasonDistributionMismatch); f.category != CategoryDeferred {
		t.Errorf("cancelled: %s %s", f.category, f.reason)
	}
}

func TestGoUpdateLookupBudget(t *testing.T) {
	f := newGoFlow(t, ".")
	up, err := NewLangUpdater(f.cfg)
	if err != nil {
		t.Fatal(err)
	}
	r := &updateRun{u: up}
	for i := 0; i < maxRegistryChecks; i++ {
		if err := r.spendGoLookup(); err != nil {
			t.Fatalf("lookup %d refused: %v", i, err)
		}
	}
	if err := r.spendGoLookup(); !errors.Is(err, errRegistryBudget) {
		t.Errorf("err = %v", err)
	}
}

func TestGoUpdateVulnerabilities(t *testing.T) {
	t.Run("a vulnerability only a collateral version has", func(t *testing.T) {
		f := newGoFlow(t, ".")
		f.vulns[pText+"@v0.15.0"] = []string{"CVE-TEXT"}
		it := f.refused(CategoryManual, ReasonSourceIntroduced)
		if sc := it.SourceCheck; sc == nil || sc.Passed || len(sc.Introduced) != 1 || sc.Introduced[0].VulnID != "CVE-TEXT" || sc.Introduced[0].Version != "v0.15.0" {
			t.Errorf("source check = %+v", sc)
		}
	})
	t.Run("the same vulnerability in the old collateral version remains", func(t *testing.T) {
		f := newGoFlow(t, ".")
		f.vulns[pText+"@v0.14.0"] = []string{"CVE-TEXT"}
		f.vulns[pText+"@v0.15.0"] = []string{"CVE-TEXT"}
		it, _ := f.run()
		wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
		if sc := it.SourceCheck; len(sc.Remaining) != 1 || sc.Remaining[0].VulnID != "CVE-TEXT" || len(sc.Introduced) != 0 {
			t.Errorf("source check = %+v", sc)
		}
	})
	t.Run("a vulnerability of a requirement that did not move remains", func(t *testing.T) {
		f := newGoFlow(t, ".")
		f.vulns[pErr+"@v0.9.1"] = []string{"CVE-ERR"}
		it, _ := f.run()
		wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
		if sc := it.SourceCheck; len(sc.Remaining) != 1 || sc.Remaining[0].Package != pErr {
			t.Errorf("source check = %+v", sc)
		}
	})
	t.Run("the target's vulnerability is still reported", func(t *testing.T) {
		f := newGoFlow(t, ".")
		f.vulns[pNet+"@v0.23.0"] = []string{goCVENet}
		f.refused(CategoryManual, ReasonSourceTargetStillDetected)
	})
	t.Run("the original scan does not report the target's vulnerability", func(t *testing.T) {
		f := newGoFlow(t, ".")
		f.vulns = map[string][]string{}
		f.refused(CategoryManual, ReasonSourceTargetNotDetectedBefore)
	})
	t.Run("the scan after the update does not list the target", func(t *testing.T) {
		f := newGoFlow(t, ".")
		f.scanHook = func(n int, s *scanner.FSScan) {
			if n == 1 {
				s.Report.Packages = nil
			}
		}
		f.refused(CategoryManual, ReasonSourceTargetNotAnalysedAfter)
	})
	t.Run("the scan conditions differ", func(t *testing.T) {
		f := newGoFlow(t, ".")
		f.scanHook = func(n int, s *scanner.FSScan) {
			if n == 1 {
				s.Conditions = testConds("db2")
			}
		}
		f.refused(CategoryNotComparable, ReasonConditionsDiffer)
	})
	t.Run("a scan that failed", func(t *testing.T) {
		f := newGoFlow(t, ".")
		f.fs.fn = func(int, map[string][]byte) (scanner.FSScan, error) {
			return scanner.FSScan{}, errors.New("trivy crashed")
		}
		f.refused(CategoryFailed, ReasonSourceScanFailed)
	})
	t.Run("a scan with its package list cut short", func(t *testing.T) {
		f := newGoFlow(t, ".")
		f.scanHook = func(n int, s *scanner.FSScan) { s.Report.PackagesTruncated = n == 0 }
		f.refused(CategoryNotComparable, ReasonSourceScanIncomplete)
	})
}

func TestGoUpdateSourcesThatAppeared(t *testing.T) {
	for _, name := range []string{"go.work", "vendor"} {
		t.Run(name, func(t *testing.T) {
			f := newGoFlow(t, "svc")
			f.gh.files["svc/"+name] = []byte("x")
			f.refused(CategoryFailed, ReasonSourceChanged)
			if f.work.calls != 0 {
				t.Error("a container ran")
			}
		})
	}
	t.Run("a go.work above the module", func(t *testing.T) {
		f := newGoFlow(t, "svc")
		f.item.Source.Absent = append(f.item.Source.Absent, "go.work")
		f.gh.files["go.work"] = []byte("go 1.22\n")
		f.refused(CategoryFailed, ReasonSourceChanged)
	})
	t.Run("a go.work in another directory is no matter", func(t *testing.T) {
		f := newGoFlow(t, "svc")
		f.item.Source.Absent = append(f.item.Source.Absent, "other/go.work")
		f.gh.files["other/go.work"] = []byte("go 1.22\n")
		it, _ := f.run()
		wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
		if it.Artifacts[0].Path != "svc/go.mod" || it.Artifacts[1].Path != "svc/go.sum" {
			t.Errorf("artifacts = %+v", it.Artifacts)
		}
	})
	t.Run("a go.sum that is not the blob of the plan", func(t *testing.T) {
		f := newGoFlow(t, ".")
		f.item.Source.Files[1].BlobSHA = gitBlobSHA([]byte("other"))
		f.refused(CategoryFailed, ReasonSourceChanged)
	})
}

func TestGoUpdateNeedsAProxyClient(t *testing.T) {
	f := newGoFlow(t, ".")
	f.cfg.Go = nil
	f.refused(CategoryFailed, ReasonUpdateInputInvalid)
	if f.work.calls != 0 {
		t.Error("a container ran")
	}
}

func TestGoUpdateSharesTheGoModCacheBetweenItems(t *testing.T) {
	a, b := newGoFlow(t, "a"), newGoFlow(t, "b")
	for k, v := range b.gh.files {
		a.gh.files[k] = v
	}
	// One proxy, two modules with the same dependencies.
	up, err := NewLangUpdater(a.cfg)
	if err != nil {
		t.Fatal(err)
	}
	plan := &Plan{LanguageItems: []LanguageItem{a.item, b.item}}
	up.Run(context.Background(), plan)
	for i, it := range plan.LanguageItems {
		if it.Category != CategoryPRCandidate {
			t.Fatalf("item %d: %s %s (%s)", i, it.Category, it.Reason, it.Detail)
		}
	}
	for _, k := range []string{pNet + "@v0.23.0", pText + "@v0.15.0"} {
		if n := a.reg.gomodCalls[k]; n != 1 {
			t.Errorf("%s was fetched %d times for two items", k, n)
		}
	}
}

// Two targets, one of which requires the other above the version asked for:
// go get names only the first, and the second is raised by its requirement,
// which explains the move; the raised version is checked for retraction.
func TestGoUpdateTargetRaisedByAnotherTarget(t *testing.T) {
	setup := func(t *testing.T) *goFlow {
		f := newGoFlow(t, ".")
		f.reg.mod(pText, "v0.14.5", goModText(pText, "1.18"))
		f.reg.latest[pText] = "v0.16.0"
		f.vulns[pText+"@v0.14.0"] = []string{"CVE-TEXT"}
		origin := FindingOrigin{Entity: "img", Workload: "compose/p/web", Target: "usr/local/bin/app"}
		f.setItem(
			group(typeGoBinary, pNet, "v0.20.0", origin, CVERef{VulnID: goCVENet, FixedVers: []string{"0.23.0"}}),
			group(typeGoBinary, pText, "v0.14.0", origin, CVERef{VulnID: "CVE-TEXT", FixedVers: []string{"0.14.5"}}),
		)
		f.build()
		return f
	}
	t.Run("adopted at the required version", func(t *testing.T) {
		f := setup(t)
		it, _ := f.run()
		wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
		job := f.work.jobs[0]
		if len(job.Steps) != 1 || len(job.Steps[0].Packages) != 1 || job.Steps[0].Packages[0].Name != pNet {
			t.Errorf("go get names %+v; only x/net", job.Steps[0].Packages)
		}
		for _, p := range it.Packages {
			if p.Name == pText && p.AdoptedVersion != "v0.15.0" {
				t.Errorf("x/text adopted %q", p.AdoptedVersion)
			}
		}
		found := false
		for _, n := range it.Update.Notes {
			found = found || strings.Contains(n, pText+" was not named in go get")
		}
		if !found {
			t.Errorf("notes = %v", it.Update.Notes)
		}
	})
	t.Run("the raised version is retracted", func(t *testing.T) {
		f := setup(t)
		f.reg.mod(pText, "v0.16.0", goModText(pText, "1.18")+"\nretract v0.15.0\n")
		f.refused(CategoryManual, ReasonGoRetracted)
	})
}
