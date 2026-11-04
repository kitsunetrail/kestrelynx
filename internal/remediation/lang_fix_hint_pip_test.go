package remediation

import (
	"reflect"
	"strings"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/scanner"
	"github.com/kitsunetrail/kestrelynx/internal/worker"
)

// pipHeldHarness is the pip fixture with botocore 1.0.0 pinned next to
// urllib3, asking for urllib3 below 1.26.5 (the update pins 1.26.17), and a
// check of the rewritten file that pip cannot resolve.
func pipHeldHarness(t *testing.T) *harness {
	t.Helper()
	h := newHarness(t, "pip")
	h.files["requirements.txt"] = "urllib3==1.26.4\nbotocore==1.0.0\n"
	h.item = itemFor(t, ManagerPip, h.files, urllibGroup())
	h.gh = ghFor(h.files)
	h.cfg.GitHub = h.gh
	h.pypi.requires = map[string][]string{"botocore==1.0.0": {"urllib3<1.26.5,>=1.25.4", `crt>=1; extra == "crt"`}}
	h.work.script = func(n int, job worker.Job, src map[string][]byte) fakeOutcome {
		if n == 0 {
			rep := pipReportItems(pipItem{name: "urllib3", ver: "1.26.4"}, pipItem{name: "botocore", ver: "1.0.0", requires: []string{"urllib3<1.26.5,>=1.25.4"}})
			return fakeOutcome{edit: map[string]map[string][]byte{stepBaseline: {worker.PipReportName: rep}}}
		}
		return fakeOutcome{failStep: stepCheck}
	}
	return h
}

// A check that pip cannot resolve, where a pinned package asks for the target
// at versions that leave out the pinned fix, leaves the target to a person as
// held back, with what holds it and what the newest release of that declares.
func TestPipHeldBackByADependent(t *testing.T) {
	h := pipHeldHarness(t)
	h.pypi.requires["botocore==1.2.0"] = []string{"urllib3<3,>=1.25.4"}
	h.cfg.PyPI = versionedPyPI{h.pypi, map[string][]string{"botocore": {"1.0.0", "1.1.0", "1.2.0", "1.3.0rc1"}, "urllib3": {"1.26.4", "1.26.17", "2.0.6"}}}
	it, _ := h.run()
	wantCategory(t, it, CategoryManual, ReasonDependentsHoldBack)
	p := it.Packages[0]
	if p.Reason != ReasonDependentsHoldBack || !strings.Contains(p.Detail, `botocore 1.0.0 asks for urllib3 "<1.26.5,>=1.25.4", which leaves out 1.26.17`) {
		t.Fatalf("package = %s %q", p.Reason, p.Detail)
	}
	want := &FixHint{
		HeldBy: []FixHolder{{Parent: "botocore", ParentVersion: "1.0.0", Range: "<1.26.5,>=1.25.4"}},
		Releases: []ChainHint{{Package: "urllib3", Parent: "botocore", ParentVersion: "1.0.0",
			Latest: &ChainHintRelease{Version: "1.2.0", Range: "<3,>=1.25.4", Fixes: true}}},
	}
	if got := p.Hint(); !reflect.DeepEqual(got, want) {
		t.Errorf("hint = %+v, want %+v", got, want)
	}
}

// Without a list of the versions of the dependent the holder is still
// recorded; only the release it would be judged by is not.
func TestPipHeldBackWithoutVersions(t *testing.T) {
	h := pipHeldHarness(t)
	it, _ := h.run()
	wantCategory(t, it, CategoryManual, ReasonDependentsHoldBack)
	want := &FixHint{HeldBy: []FixHolder{{Parent: "botocore", ParentVersion: "1.0.0", Range: "<1.26.5,>=1.25.4"}}}
	if got := it.Packages[0].Hint(); !reflect.DeepEqual(got, want) {
		t.Errorf("hint = %+v, want %+v", got, want)
	}
}

// A requirement that allows the pinned fix does not hold the package back:
// the check that failed keeps its own reason.
func TestPipCheckFailureWithoutAHolder(t *testing.T) {
	h := pipHeldHarness(t)
	h.pypi.requires["botocore==1.0.0"] = []string{"urllib3<3,>=1.25.4"}
	it, _ := h.run()
	wantCategory(t, it, CategoryManual, ReasonPostUpdateCheckFailed)
	if it.Packages[0].FixHint != nil {
		t.Errorf("hint = %+v", it.Packages[0].FixHint)
	}
}

// When another package of the set is not held back, the update is made again
// without the one that is, and the pull request candidate leaves it out with
// its holder.
func TestPipHeldBackPackageIsLeftOut(t *testing.T) {
	h := pipHeldHarness(t)
	h.files["requirements.txt"] = "urllib3==1.26.4\nbotocore==1.0.0\nidna==3.6\n"
	idna := group(typePythonPkg, "idna", "3.6", pyOrigin(), CVERef{VulnID: "CVE-2024-3651", FixedVers: []string{"3.7"}})
	h.item = itemFor(t, ManagerPip, h.files, urllibGroup(), idna)
	h.gh = ghFor(h.files)
	h.cfg.GitHub = h.gh
	before := []pipItem{{name: "urllib3", ver: "1.26.4"}, {name: "botocore", ver: "1.0.0", requires: []string{"urllib3<1.26.5,>=1.25.4"}}, {name: "idna", ver: "3.6"}}
	after := []pipItem{{name: "urllib3", ver: "1.26.4"}, {name: "botocore", ver: "1.0.0", requires: []string{"urllib3<1.26.5,>=1.25.4"}}, {name: "idna", ver: "3.7"}}
	h.work.script = func(n int, job worker.Job, src map[string][]byte) fakeOutcome {
		switch {
		case n == 0 || n == 2:
			return fakeOutcome{edit: map[string]map[string][]byte{stepBaseline: {worker.PipReportName: pipReportItems(before...)}}}
		case n == 1:
			return fakeOutcome{failStep: stepCheck}
		}
		if !strings.Contains(string(src["requirements.txt"]), "urllib3==1.26.4") {
			t.Errorf("second run rewrote urllib3: %q", src["requirements.txt"])
		}
		return fakeOutcome{edit: map[string]map[string][]byte{stepCheck: {worker.PipReportName: pipReportItems(after...)}}}
	}
	h.fs.fn = func(n int, files map[string][]byte) (scanner.FSScan, error) {
		if n == 0 {
			return fsReport("pip", [][2]string{{"urllib3", "1.26.4"}, {"botocore", "1.0.0"}, {"idna", "3.6"}},
				[][3]string{{"urllib3", "1.26.4", "CVE-2021-33503"}, {"urllib3", "1.26.4", "CVE-2023-43804"}, {"idna", "3.6", "CVE-2024-3651"}}), nil
		}
		return fsReport("pip", [][2]string{{"urllib3", "1.26.4"}, {"botocore", "1.0.0"}, {"idna", "3.7"}},
			[][3]string{{"urllib3", "1.26.4", "CVE-2021-33503"}, {"urllib3", "1.26.4", "CVE-2023-43804"}}), nil
	}
	it, _ := h.run()
	wantCategory(t, it, CategoryPRCandidate, ReasonUpdateVerified)
	var u, i LanguagePackage
	for _, p := range it.Packages {
		switch p.Name {
		case "urllib3":
			u = p
		case "idna":
			i = p
		}
	}
	if !u.LeftOut || u.Reason != ReasonDependentsHoldBack || u.Hint() == nil || u.Hint().HeldBy[0].Parent != "botocore" {
		t.Errorf("urllib3 = %+v", u)
	}
	if i.AdoptedVersion != "3.7" || i.Hint() != nil {
		t.Errorf("idna = %+v", i)
	}
	if got := string(it.Artifacts[0].Content); got != "urllib3==1.26.4\nbotocore==1.0.0\nidna==3.7\n" {
		t.Errorf("artifact = %q", got)
	}
}

// A hint is read with its reason only, and dropped from a package whose
// reason it is not.
func TestPackageHintsDropAHintWithoutItsReason(t *testing.T) {
	it := &LanguageItem{Manager: ManagerPip, Packages: []LanguagePackage{
		{Name: "a", Reason: ReasonUpdateVerified, FixHint: &FixHint{HeldBy: []FixHolder{{Parent: "p", ParentVersion: "1"}}}},
		{Name: "b", Reason: ReasonDependentsHoldBack, FixHint: &FixHint{HeldBy: []FixHolder{{Parent: "p", ParentVersion: "1"}}}},
	}}
	if it.Packages[0].Hint() != nil {
		t.Error("hint read without its reason")
	}
	u := &LangUpdater{}
	u.packageHints(t.Context(), it)
	if it.Packages[0].FixHint != nil || it.Packages[1].FixHint == nil {
		t.Errorf("hints = %+v, %+v", it.Packages[0].FixHint, it.Packages[1].FixHint)
	}
}

// A package of the set is not judged by what its current version asks for:
// the version it is pinned to may ask otherwise.
func TestPipHeldBackNotByAPackageOfTheSet(t *testing.T) {
	h := pipHeldHarness(t)
	boto := group(typePythonPkg, "botocore", "1.0.0", pyOrigin(), CVERef{VulnID: "CVE-2099-0001", FixedVers: []string{"1.2.0"}})
	h.item = itemFor(t, ManagerPip, h.files, urllibGroup(), boto)
	it, _ := h.run()
	wantCategory(t, it, CategoryManual, ReasonPostUpdateCheckFailed)
	for _, p := range it.Packages {
		if p.FixHint != nil {
			t.Errorf("%s hint = %+v", p.Name, p.FixHint)
		}
	}
}

// The current release of a dependent that is also its newest is judged by the
// range it declares: it leaves out the pinned fix and may still allow a later
// fixed version.
func TestPipHeldBackCurrentReleaseIsJudged(t *testing.T) {
	h := pipHeldHarness(t)
	h.pypi.requires["botocore==1.0.0"] = []string{"urllib3!=1.26.17,<3,>=1.25.4"}
	h.work.script = func(n int, job worker.Job, src map[string][]byte) fakeOutcome {
		if n == 0 {
			rep := pipReportItems(pipItem{name: "urllib3", ver: "1.26.4"}, pipItem{name: "botocore", ver: "1.0.0", requires: []string{"urllib3!=1.26.17,<3,>=1.25.4"}})
			return fakeOutcome{edit: map[string]map[string][]byte{stepBaseline: {worker.PipReportName: rep}}}
		}
		return fakeOutcome{failStep: stepCheck}
	}
	h.cfg.PyPI = versionedPyPI{h.pypi, map[string][]string{"botocore": {"1.0.0"}, "urllib3": {"1.26.4", "1.26.17", "2.0.6"}}}
	it, _ := h.run()
	wantCategory(t, it, CategoryManual, ReasonDependentsHoldBack)
	want := []ChainHint{{Package: "urllib3", Parent: "botocore", ParentVersion: "1.0.0",
		Latest: &ChainHintRelease{Version: "1.0.0", Range: "!=1.26.17,<3,>=1.25.4", Fixes: true}}}
	if got := it.Packages[0].Hint(); got == nil || !reflect.DeepEqual(got.Releases, want) {
		t.Errorf("hint = %+v, want releases %+v", got, want)
	}
}

// Every requirement a dependent has in force for the package counts: the
// current release is judged by all of them together.
func TestPipHeldBackJudgesEveryRequirementOfTheDependent(t *testing.T) {
	h := pipHeldHarness(t)
	reqs := []string{"urllib3!=1.26.17,<3,>=1.25.4", "urllib3<=1.26.17"}
	h.pypi.requires["botocore==1.0.0"] = reqs
	h.work.script = func(n int, job worker.Job, src map[string][]byte) fakeOutcome {
		if n == 0 {
			rep := pipReportItems(pipItem{name: "urllib3", ver: "1.26.4"}, pipItem{name: "botocore", ver: "1.0.0", requires: reqs})
			return fakeOutcome{edit: map[string]map[string][]byte{stepBaseline: {worker.PipReportName: rep}}}
		}
		return fakeOutcome{failStep: stepCheck}
	}
	h.cfg.PyPI = versionedPyPI{h.pypi, map[string][]string{"botocore": {"1.0.0"}, "urllib3": {"1.26.4", "1.26.17", "2.0.6"}}}
	it, _ := h.run()
	wantCategory(t, it, CategoryManual, ReasonDependentsHoldBack)
	want := &FixHint{
		HeldBy: []FixHolder{{Parent: "botocore", ParentVersion: "1.0.0", Range: "!=1.26.17,<3,>=1.25.4,<=1.26.17"}},
		Releases: []ChainHint{{Package: "urllib3", Parent: "botocore", ParentVersion: "1.0.0",
			Latest: &ChainHintRelease{Version: "1.0.0", Range: "!=1.26.17,<3,>=1.25.4,<=1.26.17"}}},
	}
	if got := it.Packages[0].Hint(); !reflect.DeepEqual(got, want) {
		t.Errorf("hint = %+v, want %+v", got, want)
	}
}
