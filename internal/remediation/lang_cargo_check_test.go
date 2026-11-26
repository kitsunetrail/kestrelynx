package remediation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
)

// The real pairs of Cargo.lock in testdata/cargo (check_tokio_*.Cargo.lock)
// were made with Cargo 1.100.0 in the rust:slim image, from the Cargo.toml of
// exp1.Cargo.toml (tokio "1" with the rt feature) and an empty src/lib.rs:
//
//	cargo generate-lockfile
//	cargo update -p tokio --precise 1.18.0   # check_tokio_1_18_0.Cargo.lock
//	cargo update -p tokio --precise 1.18.4   # check_tokio_1_18_4.Cargo.lock
//	(back from the 1.18.0 file)
//	cargo update -p tokio --precise 1.23.1   # check_tokio_1_23_1.Cargo.lock
//
// check_index.jsonl holds the lines of the crates.io sparse index for the
// versions these files name, without their feature tables.

// fakeCargoIndex answers from a fixed table and counts the requests.
type fakeCargoIndex struct {
	rels  map[string][]CargoRelease
	size  map[string]int64 // the bytes of each crate's index file, 0 when not set
	calls map[string]int
	err   map[string]error
}

func (f *fakeCargoIndex) Versions(_ context.Context, name string, limit int64) ([]CargoRelease, int64, error) {
	if f.calls == nil {
		f.calls = map[string]int{}
	}
	f.calls[name]++
	if err := f.err[name]; err != nil {
		return nil, 0, err
	}
	rels, ok := f.rels[name]
	if !ok {
		return nil, 0, ErrReleaseNotFound
	}
	if n := f.size[name]; n > limit {
		return nil, limit + 1, fmt.Errorf("the index of %s is %d bytes: %w", name, n, errCargoIndexOverLimit)
	}
	return rels, f.size[name], nil
}

func (f *fakeCargoIndex) total() int {
	n := 0
	for _, c := range f.calls {
		n += c
	}
	return n
}

// tcr is one crate of a test world: a package of the workspace or a crate of
// crates.io, with what Cargo.lock lists for it and what its declaration
// (the index's, or the Cargo.toml's for a package of the workspace) says.
type tcr struct {
	name, ver string
	member    bool
	deps      []string // entries of the dependencies list, "name version"
	decl      []string // "crate=requirement"
	rust      string   // the rust-version the index declares
	yanked    bool
	ck        string // a checksum to write in the lock, instead of the right one
	src       string // a source to write in the lock, instead of crates.io
}

func tckOf(name, ver string) string {
	h := sha256.Sum256([]byte(name + " " + ver))
	return hex.EncodeToString(h[:])
}

func tlock(version int, cs []tcr) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "version = %d\n", version)
	for _, c := range cs {
		fmt.Fprintf(&b, "\n[[package]]\nname = %q\nversion = %q\n", c.name, c.ver)
		if !c.member {
			src := c.src
			if src == "" {
				src = cratesIOSource
			}
			ck := c.ck
			if ck == "" {
				ck = tckOf(c.name, c.ver)
			}
			fmt.Fprintf(&b, "source = %q\nchecksum = %q\n", src, ck)
		}
		if len(c.deps) > 0 {
			b.WriteString("dependencies = [\n")
			for _, d := range c.deps {
				fmt.Fprintf(&b, " %q,\n", d)
			}
			b.WriteString("]\n")
		}
	}
	return []byte(b.String())
}

func splitDecl(s string) (string, string) {
	n, r, _ := strings.Cut(s, "=")
	return n, r
}

// tindex lists every crate of crates.io of the worlds as the index would; a
// crate of a later world wins over one of an earlier world.
func tindex(worlds ...[]tcr) *fakeCargoIndex {
	f := &fakeCargoIndex{rels: map[string][]CargoRelease{}}
	have := map[string]int{}
	for _, w := range worlds {
		for _, c := range w {
			if c.member {
				continue
			}
			rel := CargoRelease{Name: c.name, Version: c.ver, Checksum: tckOf(c.name, c.ver), Yanked: c.yanked, RustVersion: c.rust}
			for _, d := range c.decl {
				n, r := splitDecl(d)
				rel.Deps = append(rel.Deps, CargoIndexDep{Name: n, Req: r, Kind: "normal"})
			}
			k := c.name + "\x00" + c.ver
			if i, ok := have[k]; ok {
				f.rels[c.name][i] = rel
				continue
			}
			have[k] = len(f.rels[c.name])
			f.rels[c.name] = append(f.rels[c.name], rel)
		}
	}
	return f
}

func tmembers(cs []tcr) []*cargoManifest {
	var out []*cargoManifest
	for _, c := range cs {
		if !c.member {
			continue
		}
		m := &cargoManifest{file: c.name + "/Cargo.toml", dir: c.name, hasPackage: true, name: c.name, version: c.ver}
		for _, d := range c.decl {
			n, r := splitDecl(d)
			m.deps = append(m.deps, cargoDep{table: "dependencies", key: n, pkg: n, req: r})
		}
		out = append(out, m)
	}
	return out
}

func tpick(cs []tcr, name string) *tcr {
	for i := range cs {
		if cs[i].name == name {
			return &cs[i]
		}
	}
	panic("no crate " + name)
}

func tdrop(cs []tcr, name string) []tcr {
	var out []tcr
	for _, c := range cs {
		if c.name != name {
			out = append(out, c)
		}
	}
	return out
}

func tgt(name, from, to string) cargoCheckTarget { return cargoCheckTarget{name, from, to} }

// tcase is one check: the worlds before and after, the targets and the record.
type tcase struct {
	before, after []tcr
	targets       []cargoCheckTarget
	rec           CargoRecord
	lockV         [2]int // the format versions, 4 and 4 when 0
	idx           *fakeCargoIndex
	spend         func() *updateFailure
}

func (tc tcase) run(t *testing.T) (*CargoLockChange, *updateFailure, *fakeCargoIndex) {
	t.Helper()
	if tc.lockV == [2]int{} {
		tc.lockV = [2]int{4, 4}
	}
	if tc.rec.LockVersion == 0 {
		tc.rec.LockVersion = tc.lockV[0]
	}
	idx := tc.idx
	if idx == nil {
		idx = tindex(tc.before, tc.after)
	}
	spend := tc.spend
	if spend == nil {
		spend = func() *updateFailure { return nil }
	}
	c := &cargoChecker{index: idx, spend: spend}
	ch, f := c.check(context.Background(), cargoCheckInput{
		before:  tlock(tc.lockV[0], tc.before),
		after:   tlock(tc.lockV[1], tc.after),
		members: tmembers(tc.before),
		targets: tc.targets,
		record:  tc.rec,
	})
	return ch, f, idx
}

func wantOK(t *testing.T, tc tcase) *CargoLockChange {
	t.Helper()
	ch, f, _ := tc.run(t)
	if f != nil {
		t.Fatalf("want the check to pass, got %s: %s", f.reason, f.detail)
	}
	return ch
}

func wantManual(t *testing.T, tc tcase, reason Reason, detail string) {
	t.Helper()
	ch, f, _ := tc.run(t)
	if f == nil {
		t.Fatalf("want %s, the check passed: %+v", reason, ch)
	}
	if f.category != CategoryManual || f.reason != reason {
		t.Fatalf("want manual %s, got %s %s: %s", reason, f.category, f.reason, f.detail)
	}
	if !strings.Contains(f.detail, detail) {
		t.Fatalf("detail %q lacks %q", f.detail, detail)
	}
}

// worldA is an application that depends on tokio, which a target update
// moves, and on rand, which it leaves alone.
func worldA() (before, after []tcr) {
	before = []tcr{
		{name: "app", ver: "0.1.0", member: true, deps: []string{"rand 0.8.0", "tokio 1.18.0"}, decl: []string{"tokio=^1", "rand=^0.8"}},
		{name: "libc", ver: "0.2.100"},
		{name: "pin-project-lite", ver: "0.2.0"},
		{name: "rand", ver: "0.8.0", deps: []string{"libc 0.2.100"}, decl: []string{"libc=^0.2"}},
		{name: "tokio", ver: "1.18.0", deps: []string{"pin-project-lite 0.2.0"}, decl: []string{"pin-project-lite=^0.2"}},
	}
	after = []tcr{
		{name: "app", ver: "0.1.0", member: true, deps: []string{"rand 0.8.0", "tokio 1.18.4"}, decl: []string{"tokio=^1", "rand=^0.8"}},
		{name: "libc", ver: "0.2.100"},
		{name: "pin-project-lite", ver: "0.2.0"},
		{name: "rand", ver: "0.8.0", deps: []string{"libc 0.2.100"}, decl: []string{"libc=^0.2"}},
		{name: "tokio", ver: "1.18.4", deps: []string{"pin-project-lite 0.2.0"}, decl: []string{"pin-project-lite=^0.2"}},
	}
	return
}

func caseA() tcase {
	b, a := worldA()
	return tcase{before: b, after: a, targets: []cargoCheckTarget{tgt("tokio", "1.18.0", "1.18.4")}}
}

// worldB is tokio taking a lower series of windows-sys with it while other,
// which tokio depends on too, keeps the higher series of it.
func worldB() (before, after []tcr) {
	before = []tcr{
		{name: "app", ver: "0.1.0", member: true, deps: []string{"tokio 1.18.0"}, decl: []string{"tokio=^1"}},
		{name: "other", ver: "1.0.0", deps: []string{"windows-sys 0.48.0"}, decl: []string{"windows-sys=^0.48"}},
		{name: "pin-project-lite", ver: "0.2.0"},
		{name: "tokio", ver: "1.18.0", deps: []string{"other 1.0.0", "pin-project-lite 0.2.0"}, decl: []string{"other=^1", "pin-project-lite=^0.2"}},
		{name: "windows-sys", ver: "0.48.0", deps: []string{"windows_x86_64_msvc 0.48.0"}, decl: []string{"windows_x86_64_msvc=^0.48"}},
		{name: "windows_x86_64_msvc", ver: "0.48.0"},
	}
	after = []tcr{
		{name: "app", ver: "0.1.0", member: true, deps: []string{"tokio 1.23.1"}, decl: []string{"tokio=^1"}},
		{name: "other", ver: "1.0.0", deps: []string{"windows-sys 0.48.0"}, decl: []string{"windows-sys=^0.48"}},
		{name: "pin-project-lite", ver: "0.2.0"},
		{name: "tokio", ver: "1.23.1", deps: []string{"other 1.0.0", "pin-project-lite 0.2.0", "windows-sys 0.42.0"}, decl: []string{"other=^1", "pin-project-lite=^0.2", "windows-sys=^0.42"}},
		{name: "windows-sys", ver: "0.42.0", deps: []string{"windows_x86_64_msvc 0.42.2"}, decl: []string{"windows_x86_64_msvc=^0.42"}},
		{name: "windows-sys", ver: "0.48.0", deps: []string{"windows_x86_64_msvc 0.48.0"}, decl: []string{"windows_x86_64_msvc=^0.48"}},
		{name: "windows_x86_64_msvc", ver: "0.42.2"},
		{name: "windows_x86_64_msvc", ver: "0.48.0"},
	}
	return
}

func caseB() tcase {
	b, a := worldB()
	return tcase{before: b, after: a, targets: []cargoCheckTarget{tgt("tokio", "1.18.0", "1.23.1")}}
}

// worldS is serde, which a package of the workspace depends on, and
// serde_derive, which it depends on too and serde takes along.
func worldS() (before, after []tcr) {
	before = []tcr{
		{name: "app", ver: "0.1.0", member: true, deps: []string{"serde 1.0.100", "serde_derive 1.0.100"}, decl: []string{"serde=^1", "serde_derive=^1"}},
		{name: "serde", ver: "1.0.100", deps: []string{"serde_derive 1.0.100"}, decl: []string{"serde_derive==1.0.100"}},
		{name: "serde_derive", ver: "1.0.100"},
	}
	after = []tcr{
		{name: "app", ver: "0.1.0", member: true, deps: []string{"serde 1.0.101", "serde_derive 1.0.101"}, decl: []string{"serde=^1", "serde_derive=^1"}},
		{name: "serde", ver: "1.0.101", deps: []string{"serde_derive 1.0.101"}, decl: []string{"serde_derive==1.0.101"}},
		{name: "serde_derive", ver: "1.0.101"},
	}
	return
}

func caseS() tcase {
	b, a := worldS()
	return tcase{before: b, after: a, targets: []cargoCheckTarget{tgt("serde", "1.0.100", "1.0.101")}}
}

func TestCargoCheckDirectDependencyUpdate(t *testing.T) {
	ch := wantOK(t, caseA())
	if len(ch.Targets) != 1 || ch.Targets[0] != (CargoCrateChange{"tokio", "1.18.0", "1.18.4"}) {
		t.Fatalf("targets %+v", ch.Targets)
	}
	if len(ch.Others) != 0 || ch.LockVersionFrom != 4 || ch.LockVersionTo != 4 {
		t.Fatalf("change %+v", ch)
	}
	if len(ch.Moved) != 1 || ch.Moved[0] != (CargoCrateRef{"tokio", "1.18.4"}) {
		t.Fatalf("moved %+v", ch.Moved)
	}
	if ch.NoRustVersion != 1 || ch.MaxRustVersion != "" {
		t.Fatalf("rust versions %+v", ch)
	}
}

func TestCargoCheckSharedDependencyRisingTogether(t *testing.T) {
	ch := wantOK(t, caseS())
	if len(ch.Others) != 1 || ch.Others[0] != (CargoCrateChange{"serde_derive", "1.0.100", "1.0.101"}) {
		t.Fatalf("others %+v", ch.Others)
	}
	// The package of the workspace asks for serde_derive at exactly the old
	// version: its edge cannot move.
	tc := caseS()
	tpick(tc.before, "app").decl = []string{"serde=^1", "serde_derive==1.0.100"}
	tpick(tc.after, "app").decl = []string{"serde=^1", "serde_derive==1.0.100"}
	wantManual(t, tc, ReasonLockfileInconsistent, "serde_derive")
}

func TestCargoCheckLowerSeriesBesideHigher(t *testing.T) {
	ch := wantOK(t, caseB())
	var names []string
	for _, o := range ch.Others {
		names = append(names, o.Name+" "+o.From+">"+o.To)
	}
	sort.Strings(names)
	want := "windows-sys >0.42.0,windows_x86_64_msvc >0.42.2"
	if strings.Join(names, ",") != want {
		t.Fatalf("others %v, want %s", names, want)
	}
}

func TestCargoCheckLowerSeriesRefused(t *testing.T) {
	// The declaration of the parent does not take the lower series.
	tc := caseB()
	tpick(tc.after, "tokio").decl = []string{"other=^1", "pin-project-lite=^0.2", "windows-sys=^0.48"}
	wantManual(t, tc, ReasonLockfileInconsistent, "windows-sys")

	// The declaration takes both, so the version the file had would do.
	tc = caseB()
	tpick(tc.after, "tokio").decl = []string{"other=^1", "pin-project-lite=^0.2", "windows-sys=>=0.42,<0.49"}
	wantManual(t, tc, ReasonUnexplainedDiff, "series below")

	// The lower series is added with nothing that leads to it from a crate
	// the update changes.
	tc = caseB()
	after := tc.after
	tpick(after, "tokio").deps = []string{"other 1.0.0", "pin-project-lite 0.2.0"}
	wantManual(t, tc, ReasonUnexplainedDiff, "windows-sys")

	// The higher series goes away.
	tc = caseB()
	after = tc.after
	after = tdrop(after, "windows_x86_64_msvc")
	after = append(after, tcr{name: "windows_x86_64_msvc", ver: "0.42.2"})
	other := tpick(after, "other")
	other.deps = []string{"windows-sys 0.42.0"}
	other.decl = []string{"windows-sys=>=0.42,<1"}
	tc.after = tdrop2(after, "windows-sys", "0.48.0")
	wantManual(t, tc, ReasonUnexplainedDiff, "did not keep")

	// The higher series stays, but at another version of it.
	tc = caseB()
	for i := range tc.after {
		if tc.after[i].name == "windows-sys" && tc.after[i].ver == "0.48.0" {
			tc.after[i].ver = "0.48.1"
		}
	}
	tpick(tc.after, "other").deps = []string{"windows-sys 0.48.1"}
	wantManual(t, tc, ReasonUnexplainedDiff, "did not keep")

	// The higher series stays but its dependencies are changed.
	tc = caseB()
	for i := range tc.after {
		if tc.after[i].name == "windows-sys" && tc.after[i].ver == "0.48.0" {
			tc.after[i].deps = nil
		}
	}
	wantManual(t, tc, ReasonUnexplainedDiff, "changed the dependencies")
}

func TestCargoCheckTargetAtTwoVersions(t *testing.T) {
	// A crate the update brought along needs another series of the target,
	// so the file holds the target twice.
	tc := caseS()
	derive := tpick(tc.after, "serde_derive")
	derive.deps = []string{"serde 0.9.0"}
	derive.decl = []string{"serde=^0.9"}
	tc.after = append(tc.after, tcr{name: "serde", ver: "0.9.0"})
	wantManual(t, tc, ReasonMultipleVersions, "serde at 0.9.0 besides 1.0.101")
	if _, f, _ := tc.run(t); f.pkgs["serde"].reason != ReasonMultipleVersions {
		t.Fatalf("the failure is not of serde: %+v", f)
	}
}

// tdrop2 drops one version of a crate.
func tdrop2(cs []tcr, name, ver string) []tcr {
	var out []tcr
	for _, c := range cs {
		if c.name != name || c.ver != ver {
			out = append(out, c)
		}
	}
	return out
}

func TestCargoCheckSeriesChange(t *testing.T) {
	// tokio takes tokio-macros from series 1 to series 2.
	before := []tcr{
		{name: "app", ver: "0.1.0", member: true, deps: []string{"tokio 1.18.0"}, decl: []string{"tokio=^1"}},
		{name: "tokio", ver: "1.18.0", deps: []string{"tokio-macros 1.7.0"}, decl: []string{"tokio-macros=^1"}},
		{name: "tokio-macros", ver: "1.7.0"},
	}
	after := []tcr{
		{name: "app", ver: "0.1.0", member: true, deps: []string{"tokio 1.25.0"}, decl: []string{"tokio=^1"}},
		{name: "tokio", ver: "1.25.0", deps: []string{"tokio-macros 2.0.0"}, decl: []string{"tokio-macros=^2"}},
		{name: "tokio-macros", ver: "2.0.0"},
	}
	ch := wantOK(t, tcase{before: before, after: after, targets: []cargoCheckTarget{tgt("tokio", "1.18.0", "1.25.0")}})
	if len(ch.Others) != 2 || ch.Others[0] != (CargoCrateChange{"tokio-macros", "", "2.0.0"}) || ch.Others[1] != (CargoCrateChange{"tokio-macros", "1.7.0", ""}) {
		t.Fatalf("others %+v", ch.Others)
	}
}

func TestCargoCheckJoinsExistingVersion(t *testing.T) {
	// The new tokio depends on bytes, which hyper (outside what tokio leads
	// to) already has locked.
	before := []tcr{
		{name: "app", ver: "0.1.0", member: true, deps: []string{"hyper 1.0.0", "tokio 1.18.0"}, decl: []string{"hyper=^1", "tokio=^1"}},
		{name: "bytes", ver: "1.0.0"},
		{name: "hyper", ver: "1.0.0", deps: []string{"bytes 1.0.0"}, decl: []string{"bytes=^1"}},
		{name: "tokio", ver: "1.18.0", decl: []string{"bytes=^1"}},
	}
	after := []tcr{
		{name: "app", ver: "0.1.0", member: true, deps: []string{"hyper 1.0.0", "tokio 1.18.4"}, decl: []string{"hyper=^1", "tokio=^1"}},
		{name: "bytes", ver: "1.0.0"},
		{name: "hyper", ver: "1.0.0", deps: []string{"bytes 1.0.0"}, decl: []string{"bytes=^1"}},
		{name: "tokio", ver: "1.18.4", deps: []string{"bytes 1.0.0"}, decl: []string{"bytes=^1"}},
	}
	wantOK(t, tcase{before: before, after: after, targets: []cargoCheckTarget{tgt("tokio", "1.18.0", "1.18.4")}})
}

func TestCargoCheckFeatureOnlyEdges(t *testing.T) {
	// tokio-macros, whose version does not change, gains an edge to quote
	// (that the file has already) and loses its edge to syn.
	before := []tcr{
		{name: "app", ver: "0.1.0", member: true, deps: []string{"quote 1.0.0", "syn 1.0.0", "tokio 1.18.0"}, decl: []string{"quote=^1", "syn=^1", "tokio=^1"}},
		{name: "quote", ver: "1.0.0"},
		{name: "syn", ver: "1.0.0"},
		{name: "tokio", ver: "1.18.0", deps: []string{"tokio-macros 1.7.0"}, decl: []string{"tokio-macros=^1"}},
		{name: "tokio-macros", ver: "1.7.0", deps: []string{"syn 1.0.0"}, decl: []string{"syn=^1", "quote=^1"}},
	}
	after := []tcr{
		{name: "app", ver: "0.1.0", member: true, deps: []string{"quote 1.0.0", "syn 1.0.0", "tokio 1.18.4"}, decl: []string{"quote=^1", "syn=^1", "tokio=^1"}},
		{name: "quote", ver: "1.0.0"},
		{name: "syn", ver: "1.0.0"},
		{name: "tokio", ver: "1.18.4", deps: []string{"tokio-macros 1.7.0"}, decl: []string{"tokio-macros=^1"}},
		{name: "tokio-macros", ver: "1.7.0", deps: []string{"quote 1.0.0"}, decl: []string{"syn=^1", "quote=^1"}},
	}
	wantOK(t, tcase{before: before, after: after, targets: []cargoCheckTarget{tgt("tokio", "1.18.0", "1.18.4")}})

	// A new edge the parent does not declare.
	after[4].decl = []string{"syn=^1"}
	wantManual(t, tcase{before: before, after: after, targets: []cargoCheckTarget{tgt("tokio", "1.18.0", "1.18.4")}}, ReasonLockfileInconsistent, "quote")
}

func TestCargoCheckTwoTargets(t *testing.T) {
	tc := caseA()
	tpick(tc.before, "app").deps = []string{"rand 0.8.0", "tokio 1.18.0"}
	tpick(tc.after, "rand").ver = "0.8.1"
	tpick(tc.after, "app").deps = []string{"rand 0.8.1", "tokio 1.18.4"}
	tc.targets = append(tc.targets, tgt("rand", "0.8.0", "0.8.1"))
	ch := wantOK(t, tc)
	if len(ch.Targets) != 2 || len(ch.Moved) != 2 {
		t.Fatalf("change %+v", ch)
	}
}

func TestCargoCheckTargetNotReached(t *testing.T) {
	tc := caseA()
	tpick(tc.after, "tokio").ver = "1.18.2"
	tpick(tc.after, "app").deps = []string{"rand 0.8.0", "tokio 1.18.2"}
	wantManual(t, tc, ReasonTargetNotUpdated, "does not have tokio at 1.18.4")

	// The old version stays beside the new one: a file Cargo does not write.
	tc = caseA()
	tc.after = append(tc.after, tcr{name: "tokio", ver: "1.18.0", deps: []string{"pin-project-lite 0.2.0"}, decl: []string{"pin-project-lite=^0.2"}})
	wantManual(t, tc, ReasonOutputFilesInvalid, "one series")

	// The file is returned as it was.
	tc = caseA()
	tc.after = tc.before
	wantManual(t, tc, ReasonTargetNotUpdated, "tokio")
}

func TestCargoCheckChangeOutsideTheScope(t *testing.T) {
	// An unrelated crate is raised.
	tc := caseA()
	tpick(tc.after, "rand").ver = "0.8.1"
	tpick(tc.after, "app").deps = []string{"rand 0.8.1", "tokio 1.18.4"}
	wantManual(t, tc, ReasonUnexplainedDiff, "rand")

	// An unrelated crate is removed (with its dependency, so the file stays
	// consistent), and the package of the workspace drops its edge.
	tc = caseA()
	tc.after = tdrop(tdrop(tc.after, "rand"), "libc")
	tpick(tc.after, "app").deps = []string{"tokio 1.18.4"}
	wantManual(t, tc, ReasonUnexplainedDiff, "removed")

	// An unrelated crate gains a crate nothing declares.
	tc = caseA()
	tc.after = append(tc.after, tcr{name: "extra", ver: "1.0.0"})
	tpick(tc.after, "rand").deps = []string{"libc 0.2.100", "extra 1.0.0"}
	wantManual(t, tc, ReasonUnexplainedDiff, "extra")

	// A crate outside the scope points at another version that was there.
	tc = caseA()
	tc.before = append(tc.before, tcr{name: "libc", ver: "0.3.0"})
	tc.after = append(tc.after, tcr{name: "libc", ver: "0.3.0"})
	tpick(tc.before, "app").deps = []string{"libc 0.3.0", "rand 0.8.0", "tokio 1.18.0"}
	tpick(tc.before, "app").decl = []string{"tokio=^1", "rand=^0.8", "libc=^0.3"}
	tpick(tc.after, "app").deps = []string{"libc 0.3.0", "rand 0.8.0", "tokio 1.18.4"}
	tpick(tc.after, "app").decl = []string{"tokio=^1", "rand=^0.8", "libc=^0.3"}
	wantOK(t, tc)
	tpick(tc.after, "rand").deps = []string{"libc 0.3.0"}
	wantManual(t, tc, ReasonUnexplainedDiff, "now depends on libc 0.3.0")

	// A package of the workspace moves an edge it had to a crate that is not
	// the one that took its place.
	tc = caseS()
	tpick(tc.after, "app").deps = []string{"serde 1.0.101"}
	wantManual(t, tc, ReasonUnexplainedDiff, "no longer depends on")
}

func TestCargoCheckDowngrade(t *testing.T) {
	tc := caseA()
	tpick(tc.before, "pin-project-lite").ver = "0.2.5"
	tpick(tc.before, "tokio").deps = []string{"pin-project-lite 0.2.5"}
	tpick(tc.after, "tokio").deps = []string{"pin-project-lite 0.2.1"}
	tpick(tc.after, "pin-project-lite").ver = "0.2.1"
	wantManual(t, tc, ReasonUnexplainedDiff, "lowered pin-project-lite from 0.2.5 to 0.2.1")
}

func TestCargoCheckEdgeRequirements(t *testing.T) {
	// A parent whose version does not change now has an edge its
	// declaration does not allow.
	before := []tcr{
		{name: "app", ver: "0.1.0", member: true, deps: []string{"tokio 1.18.0"}, decl: []string{"tokio=^1"}},
		{name: "bar", ver: "1.0.0"},
		{name: "helper", ver: "1.0.0", deps: []string{"bar 1.0.0"}, decl: []string{"bar=~1.0"}},
		{name: "tokio", ver: "1.18.0", deps: []string{"helper 1.0.0"}, decl: []string{"helper=^1"}},
	}
	after := []tcr{
		{name: "app", ver: "0.1.0", member: true, deps: []string{"tokio 1.18.4"}, decl: []string{"tokio=^1"}},
		{name: "bar", ver: "1.5.0"},
		{name: "helper", ver: "1.0.0", deps: []string{"bar 1.5.0"}, decl: []string{"bar=~1.0"}},
		{name: "tokio", ver: "1.18.4", deps: []string{"helper 1.0.0"}, decl: []string{"helper=^1"}},
	}
	targets := []cargoCheckTarget{tgt("tokio", "1.18.0", "1.18.4")}
	wantManual(t, tcase{before: before, after: after, targets: targets}, ReasonLockfileInconsistent, "helper 1.0.0 requires bar ~1.0")
	after[2].decl = []string{"bar=^1"}
	ch := wantOK(t, tcase{before: before, after: after, targets: targets})
	if len(ch.Others) != 1 || ch.Others[0].Name != "bar" {
		t.Fatalf("others %+v", ch.Others)
	}

	// The declaration names another crate, or none at all.
	after[2].decl = []string{"baz=^1"}
	wantManual(t, tcase{before: before, after: after, targets: targets}, ReasonLockfileInconsistent, "does not declare a dependency on bar")

	// A requirement that is not read.
	after[2].decl = []string{"bar=^1.0.0-alpha"}
	wantManual(t, tcase{before: before, after: after, targets: targets}, ReasonUnexplainedDiff, "cannot be evaluated")

	// A dev dependency of the index does not stand for an edge.
	after[2].decl = nil
	idx := tindex(before, after)
	idx.rels["helper"][0].Deps = []CargoIndexDep{{Name: "bar", Req: "^1", Kind: "dev"}}
	wantManual(t, tcase{before: before, after: after, targets: targets, idx: idx}, ReasonLockfileInconsistent, "does not declare")

	// A renamed dependency is declared by its package.
	idx.rels["helper"][0].Deps = []CargoIndexDep{{Name: "other_name", Package: "bar", Req: "^1", Kind: "normal"}}
	wantOK(t, tcase{before: before, after: after, targets: targets, idx: idx})

	// Of several declarations one that allows is enough.
	idx.rels["helper"][0].Deps = []CargoIndexDep{{Name: "bar", Req: "~1.0", Kind: "normal"}, {Name: "bar", Req: "^1.4", Kind: "build"}}
	wantOK(t, tcase{before: before, after: after, targets: targets, idx: idx})
}

func TestCargoCheckPackageOfTheWorkspaceRequirements(t *testing.T) {
	// The declaration of the package of the workspace must allow the version
	// its edge moves to.
	tc := caseA()
	tpick(tc.before, "app").decl = []string{"tokio=~1.18.0", "rand=^0.8"}
	tpick(tc.after, "app").decl = []string{"tokio=~1.18.0", "rand=^0.8"}
	wantOK(t, tc)
	tc = caseA()
	tpick(tc.before, "app").decl = []string{"tokio==1.18.0", "rand=^0.8"}
	tpick(tc.after, "app").decl = []string{"tokio==1.18.0", "rand=^0.8"}
	wantManual(t, tc, ReasonLockfileInconsistent, "app 0.1.0 (workspace) requires tokio =1.18.0")

	// Another table, another declaration of the same crate.
	tc = caseA()
	tpick(tc.before, "app").decl = []string{"tokio==1.18.0", "rand=^0.8"}
	m := tmembers(tc.before)[0]
	m.deps = append(m.deps, cargoDep{table: "build-dependencies", key: "tokio", pkg: "tokio", req: "^1.18"})
	c := &cargoChecker{index: tindex(tc.before, tc.after), spend: func() *updateFailure { return nil }}
	if _, f := c.check(context.Background(), cargoCheckInput{before: tlock(4, tc.before), after: tlock(4, tc.after), members: []*cargoManifest{m}, targets: tc.targets, record: CargoRecord{LockVersion: 4}}); f != nil {
		t.Fatalf("%s: %s", f.reason, f.detail)
	}

	// A declaration the plan did not fill in.
	m.deps = []cargoDep{{table: "dependencies", key: "tokio", pkg: "tokio", inherit: true}}
	_, f := c.check(context.Background(), cargoCheckInput{before: tlock(4, tc.before), after: tlock(4, tc.after), members: []*cargoManifest{m}, targets: tc.targets, record: CargoRecord{LockVersion: 4}})
	if f == nil || f.reason != ReasonCargoManifestUnsupported {
		t.Fatalf("got %+v", f)
	}
}

func TestCargoCheckOrphan(t *testing.T) {
	// once_cell stays in the file while nothing depends on it.
	before, after := worldA()
	before = append(before, tcr{name: "once_cell", ver: "1.0.0"})
	after = append(after, tcr{name: "once_cell", ver: "1.0.0"})
	tpick(before, "tokio").deps = []string{"once_cell 1.0.0", "pin-project-lite 0.2.0"}
	tpick(before, "tokio").decl = []string{"once_cell=^1", "pin-project-lite=^0.2"}
	wantManual(t, tcase{before: before, after: after, targets: []cargoCheckTarget{tgt("tokio", "1.18.0", "1.18.4")}}, ReasonUnexplainedDiff, "once_cell")

	// The same when it is the old tokio's dependency that is dropped.
	tpick(after, "tokio").deps = []string{"pin-project-lite 0.2.0"}
	wantOK(t, tcase{before: before, after: tdrop(after, "once_cell"), targets: []cargoCheckTarget{tgt("tokio", "1.18.0", "1.18.4")}})
}

func TestCargoCheckDistribution(t *testing.T) {
	// The checksum differs from the index's.
	tc := caseA()
	tpick(tc.after, "tokio").ck = strings.Repeat("a", 64)
	wantManual(t, tc, ReasonDistributionMismatch, "checksum of tokio 1.18.4")

	// The checksum of a crate that stays differs from what it was.
	tc = caseA()
	tpick(tc.after, "libc").ck = strings.Repeat("b", 64)
	wantManual(t, tc, ReasonDistributionMismatch, "checksum of libc 0.2.100 changed")

	// The checksum is left out of a crate (the file cannot be read).
	tc = caseA()
	text := string(tlock(4, tc.after))
	i := strings.Index(text, `name = "tokio"`)
	j := strings.Index(text[i:], "checksum")
	k := strings.Index(text[i+j:], "\n")
	cut := []byte(text[:i+j] + text[i+j+k+1:])
	c := &cargoChecker{index: tindex(tc.before, tc.after), spend: func() *updateFailure { return nil }}
	_, f := c.check(context.Background(), cargoCheckInput{before: tlock(4, tc.before), after: cut, members: tmembers(tc.before), targets: tc.targets, record: CargoRecord{LockVersion: 4}})
	if f == nil || f.category != CategoryManual || f.reason != ReasonOutputFilesInvalid {
		t.Fatalf("got %+v", f)
	}

	// The version is yanked.
	tc = caseA()
	tpick(tc.after, "tokio").yanked = true
	wantManual(t, tc, ReasonReleaseYanked, "tokio 1.18.4")

	// The index has no such version, or no such crate.
	tc = caseA()
	idx := tindex(tc.before, tc.after)
	idx.rels["tokio"] = idx.rels["tokio"][:1]
	tc.idx = idx
	wantManual(t, tc, ReasonDistributionMismatch, "no version 1.18.4 of tokio")
	tc = caseA()
	idx = tindex(tc.before, tc.after)
	delete(idx.rels, "tokio")
	tc.idx = idx
	wantManual(t, tc, ReasonDistributionMismatch, "no crate tokio")

	// A failed request is not a refusal of the file.
	tc = caseA()
	idx = tindex(tc.before, tc.after)
	idx.err = map[string]error{"tokio": errors.New("connection reset")}
	tc.idx = idx
	_, f, _ = tc.run(t)
	if f == nil || f.category != CategoryFailed || f.reason != ReasonDistributionLookup {
		t.Fatalf("got %+v", f)
	}
}

func TestCargoCheckSourceChanges(t *testing.T) {
	// A source other than crates.io.
	tc := caseA()
	tpick(tc.after, "tokio").src = "git+https://example.com/tokio"
	wantManual(t, tc, ReasonUnsupportedSource, "not crates.io")

	// A package of the workspace becomes a crate of crates.io.
	tc = caseA()
	tpick(tc.after, "app").member = false
	wantManual(t, tc, ReasonUnexplainedDiff, "does not list the package app 0.1.0")

	// A crate of crates.io becomes a package of the workspace.
	tc = caseA()
	tpick(tc.after, "libc").member = true
	wantManual(t, tc, ReasonUnexplainedDiff, "lists libc 0.2.100 without a source")
}

func TestCargoCheckMembers(t *testing.T) {
	// A package of the workspace is added.
	tc := caseA()
	tc.after = append(tc.after, tcr{name: "extra", ver: "0.1.0", member: true})
	wantManual(t, tc, ReasonUnexplainedDiff, "extra 0.1.0")

	// One is dropped.
	tc = caseA()
	tc.after = append(tdrop(tc.after, "app"), tcr{name: "app", ver: "0.2.0", member: true, deps: []string{"rand 0.8.0", "tokio 1.18.4"}})
	wantManual(t, tc, ReasonUnexplainedDiff, "app 0.1.0")

	// A crate of crates.io is given the name and version of one.
	tc = caseA()
	tc.after = append(tc.after, tcr{name: "app", ver: "0.1.0"})
	wantManual(t, tc, ReasonUnexplainedDiff, "both a package of the workspace and a crate of crates.io named app 0.1.0")
}

func TestCargoCheckLockVersion(t *testing.T) {
	tc := caseA()
	tc.lockV = [2]int{3, 4}
	ch := wantOK(t, tc)
	if ch.LockVersionFrom != 3 || ch.LockVersionTo != 4 {
		t.Fatalf("change %+v", ch)
	}

	for _, rec := range []CargoRecord{
		{RustVersion: "1.78"},
		{RustVersion: "1.85.1"},
		{Toolchains: []CargoToolchain{{Path: "rust-toolchain.toml", Channel: "stable"}}},
		{RustVersion: "1.80", Toolchains: []CargoToolchain{{Path: "rust-toolchain", Channel: "1.79.0", Version: "1.79.0"}, {Path: "rust-toolchain.toml", Channel: "stable"}}},
	} {
		tc = caseA()
		tc.lockV, tc.rec = [2]int{3, 4}, rec
		wantOK(t, tc)
	}
	for _, rec := range []CargoRecord{
		{RustVersion: "1.77"},
		{RustVersion: "1.60.1"},
		{Toolchains: []CargoToolchain{{Path: "rust-toolchain.toml", Channel: "nightly"}}},
		{Toolchains: []CargoToolchain{{Path: "rust-toolchain.toml", Channel: "beta"}}},
		{Toolchains: []CargoToolchain{{Path: "rust-toolchain.toml", Channel: "nightly-2024-01-01"}}},
		{Toolchains: []CargoToolchain{{Path: "rust-toolchain", Channel: "1.77", Version: "1.77"}}},
		{Toolchains: []CargoToolchain{{Path: "rust-toolchain.toml"}}},
		{RustVersion: "1.80", Toolchains: []CargoToolchain{{Path: "a/rust-toolchain", Channel: "stable"}, {Path: "rust-toolchain", Channel: "1.70.0", Version: "1.70.0"}}},
	} {
		tc = caseA()
		tc.lockV, tc.rec = [2]int{3, 4}, rec
		wantManual(t, tc, ReasonLockfileFormatChanged, "from 3 to 4")
	}

	for _, v := range [][2]int{{4, 3}, {3, 3}, {4, 4}} {
		if v[0] == v[1] {
			tc = caseA()
			tc.lockV = v
			wantOK(t, tc)
			continue
		}
		tc = caseA()
		tc.lockV = v
		wantManual(t, tc, ReasonLockfileFormatChanged, "from 4 to 3")
	}

	// A version the plan did not record, or one that is not read.
	tc = caseA()
	tc.rec.LockVersion = 3
	_, f, _ := tc.run(t)
	if f == nil || f.category != CategoryFailed || f.reason != ReasonUpdateInputInvalid {
		t.Fatalf("got %+v", f)
	}
	tc = caseA()
	c := &cargoChecker{index: tindex(tc.before, tc.after), spend: func() *updateFailure { return nil }}
	_, f = c.check(context.Background(), cargoCheckInput{before: tlock(4, tc.before), after: []byte(strings.Replace(string(tlock(4, tc.after)), "version = 4", "version = 5", 1)), members: tmembers(tc.before), targets: tc.targets, record: CargoRecord{LockVersion: 4}})
	if f == nil || f.reason != ReasonUnsupportedLockfile {
		t.Fatalf("got %+v", f)
	}
}

func TestCargoCheckRustVersion(t *testing.T) {
	tc := caseA()
	tpick(tc.after, "tokio").rust = "1.63"
	tc.rec.RustVersion = "1.60"
	wantManual(t, tc, ReasonCargoRustVersionTooNew, "tokio 1.18.4 declares the rust-version 1.63, above the rust-version 1.60")

	// Equal is enough, and a patch number counts.
	tc.rec.RustVersion = "1.63"
	ch := wantOK(t, tc)
	if ch.MaxRustVersion != "1.63" || ch.NoRustVersion != 0 {
		t.Fatalf("change %+v", ch)
	}
	tc.rec.RustVersion = "1.62.9"
	wantManual(t, tc, ReasonCargoRustVersionTooNew, "tokio")

	// Without a rust-version nothing is refused; the highest declared is
	// noted, and those that declare none are counted.
	tc = caseS()
	tpick(tc.after, "serde").rust = "1.31"
	tpick(tc.after, "serde_derive").rust = "1.56.1"
	ch = wantOK(t, tc)
	if ch.MaxRustVersion != "1.56.1" || ch.NoRustVersion != 0 {
		t.Fatalf("change %+v", ch)
	}
	tpick(tc.after, "serde_derive").rust = ""
	ch = wantOK(t, tc)
	if ch.MaxRustVersion != "1.31" || ch.NoRustVersion != 1 {
		t.Fatalf("change %+v", ch)
	}

	// A crate that stays is not asked about.
	tc = caseA()
	tpick(tc.after, "pin-project-lite").rust = "1.99"
	tc.rec.RustVersion = "1.60"
	wantOK(t, tc)
}

func TestCargoCheckBudgetAndCache(t *testing.T) {
	// Each crate is asked for once, and each question is paid for.
	tc := caseB()
	spent := 0
	tc.spend = func() *updateFailure { spent++; return nil }
	_, f, idx := tc.run(t)
	if f != nil {
		t.Fatalf("%s: %s", f.reason, f.detail)
	}
	for n, c := range idx.calls {
		if c != 1 {
			t.Fatalf("%s was asked for %d times", n, c)
		}
	}
	if spent != idx.total() || spent == 0 {
		t.Fatalf("spent %d, asked %d", spent, idx.total())
	}

	// The budget runs out.
	tc = caseB()
	spent = 0
	tc.spend = func() *updateFailure {
		spent++
		if spent > 2 {
			return &updateFailure{category: CategoryDeferred, reason: ReasonRegistryCheckLimit, detail: "limit"}
		}
		return nil
	}
	_, f, idx = tc.run(t)
	if f == nil || f.category != CategoryDeferred || f.reason != ReasonRegistryCheckLimit {
		t.Fatalf("got %+v", f)
	}
	if idx.total() != 2 {
		t.Fatalf("asked %d times", idx.total())
	}

	// A checker without what it needs does not run.
	c := &cargoChecker{}
	if _, f := c.check(context.Background(), cargoCheckInput{}); f == nil || f.category != CategoryFailed {
		t.Fatalf("got %+v", f)
	}
}

func TestCargoCheckInput(t *testing.T) {
	for name, mod := range map[string]func(*tcase){
		"no target":       func(tc *tcase) { tc.targets = nil },
		"not in the lock": func(tc *tcase) { tc.targets = []cargoCheckTarget{tgt("tokio", "1.17.0", "1.18.4")} },
		"not a step up":   func(tc *tcase) { tc.targets = []cargoCheckTarget{tgt("tokio", "1.18.0", "1.18.0")} },
		"other series":    func(tc *tcase) { tc.targets = []cargoCheckTarget{tgt("tokio", "1.18.0", "2.0.0")} },
		"twice":           func(tc *tcase) { tc.targets = append(tc.targets, tgt("Tokio", "1.18.0", "1.18.4")) },
	} {
		tc := caseA()
		mod(&tc)
		_, f, _ := tc.run(t)
		if f == nil || f.category != CategoryFailed || f.reason != ReasonUpdateInputInvalid {
			t.Fatalf("%s: got %+v", name, f)
		}
	}
	// The file that was given before the update cannot be read.
	tc := caseA()
	c := &cargoChecker{index: tindex(tc.before, tc.after), spend: func() *updateFailure { return nil }}
	_, f := c.check(context.Background(), cargoCheckInput{before: []byte("not = [toml"), after: tlock(4, tc.after), members: tmembers(tc.before), targets: tc.targets})
	if f == nil || f.reason != ReasonDependencyFileUnusable {
		t.Fatalf("got %+v", f)
	}
}

// --- the real files ---

func readCargoTestdata(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/cargo/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// realCargoIndex reads check_index.jsonl: lines of several crates.
func realCargoIndex(t *testing.T, file string) *fakeCargoIndex {
	t.Helper()
	by := map[string][]string{}
	for _, line := range strings.Split(string(readCargoTestdata(t, file)), "\n") {
		if line == "" {
			continue
		}
		i := strings.Index(line, `"name":"`) + len(`"name":"`)
		name := line[i : i+strings.Index(line[i:], `"`)]
		by[name] = append(by[name], line)
	}
	f := &fakeCargoIndex{rels: map[string][]CargoRelease{}}
	for n, lines := range by {
		rels, err := parseCargoIndex([]byte(strings.Join(lines, "\n")), n)
		if err != nil {
			t.Fatal(err)
		}
		f.rels[n] = rels
	}
	return f
}

func realCargoInput(t *testing.T, afterFile string, to string) (cargoCheckInput, *fakeCargoIndex) {
	t.Helper()
	m, err := parseCargoManifest("Cargo.toml", readCargoTestdata(t, "exp1.Cargo.toml"))
	if err != nil {
		t.Fatal(err)
	}
	return cargoCheckInput{
		before:  readCargoTestdata(t, "check_tokio_1_18_0.Cargo.lock"),
		after:   readCargoTestdata(t, afterFile),
		members: []*cargoManifest{m},
		targets: []cargoCheckTarget{tgt("tokio", "1.18.0", to)},
		record:  CargoRecord{LockVersion: 4, Members: []CargoMember{{Path: ".", Name: "exp1", Version: "0.1.0"}}},
	}, realCargoIndex(t, "check_index.jsonl")
}

func TestCargoCheckRealTokio1184(t *testing.T) {
	in, idx := realCargoInput(t, "check_tokio_1_18_4.Cargo.lock", "1.18.4")
	c := &cargoChecker{index: idx, spend: func() *updateFailure { return nil }}
	ch, f := c.check(context.Background(), in)
	if f != nil {
		t.Fatalf("%s: %s", f.reason, f.detail)
	}
	if len(ch.Others) != 1 || ch.Others[0] != (CargoCrateChange{"once_cell", "1.21.4", ""}) {
		t.Fatalf("others %+v", ch.Others)
	}
	if len(ch.Moved) != 1 || ch.Moved[0] != (CargoCrateRef{"tokio", "1.18.4"}) {
		t.Fatalf("moved %+v", ch.Moved)
	}
}

func TestCargoCheckRealTokio1231(t *testing.T) {
	in, idx := realCargoInput(t, "check_tokio_1_23_1.Cargo.lock", "1.23.1")
	c := &cargoChecker{index: idx, spend: func() *updateFailure { return nil }}
	ch, f := c.check(context.Background(), in)
	if f != nil {
		t.Fatalf("%s: %s", f.reason, f.detail)
	}
	var added []string
	for _, o := range ch.Others {
		added = append(added, o.Name+" "+o.From+">"+o.To)
	}
	want := "autocfg >1.5.1,once_cell 1.21.4>,windows-sys >0.42.0,windows_aarch64_gnullvm >0.42.2,windows_aarch64_msvc >0.42.2,windows_i686_gnu >0.42.2,windows_i686_msvc >0.42.2,windows_x86_64_gnu >0.42.2,windows_x86_64_gnullvm >0.42.2,windows_x86_64_msvc >0.42.2"
	if strings.Join(added, ",") != want {
		t.Fatalf("others\n%s\nwant\n%s", strings.Join(added, ","), want)
	}
	if len(ch.Moved) != 10 {
		t.Fatalf("moved %+v", ch.Moved)
	}
	if ch.NoRustVersion != 0 && ch.MaxRustVersion == "" {
		t.Fatalf("change %+v", ch)
	}

	// The same file with a crate the index lists another checksum for.
	in.after = []byte(strings.Replace(string(in.after), "5a3e1820f08b8513f676f7ab6c1f99ff312fb97b553d30ff4dd86f9f15728aa7", strings.Repeat("0", 64), 1))
	_, f = (&cargoChecker{index: idx, spend: func() *updateFailure { return nil }}).check(context.Background(), in)
	if f == nil || f.reason != ReasonDistributionMismatch || !strings.Contains(f.detail, "windows-sys 0.42.0") {
		t.Fatalf("got %+v", f)
	}

	// With the project's rust-version below what a new crate needs.
	in, idx = realCargoInput(t, "check_tokio_1_23_1.Cargo.lock", "1.23.1")
	in.record.RustVersion = "1.30"
	_, f = (&cargoChecker{index: idx, spend: func() *updateFailure { return nil }}).check(context.Background(), in)
	if f == nil || f.reason != ReasonCargoRustVersionTooNew {
		t.Fatalf("got %+v", f)
	}

	// windows-sys is taken out of tokio's dependencies: the edge is gone but
	// the crate stays, and nothing depends on it.
	in, idx = realCargoInput(t, "check_tokio_1_23_1.Cargo.lock", "1.23.1")
	after := string(in.after)
	i := strings.Index(after, `name = "tokio"`)
	j := strings.Index(after[i:], ` "windows-sys",\n`[:len(` "windows-sys",`)])
	after = after[:i+j] + strings.Replace(after[i+j:], ` "windows-sys",`+"\n", "", 1)
	in.after = []byte(after)
	_, f = (&cargoChecker{index: idx, spend: func() *updateFailure { return nil }}).check(context.Background(), in)
	if f == nil || f.reason != ReasonUnexplainedDiff {
		t.Fatalf("got %+v", f)
	}
}

// The wide pair: a package with tokio (with its macros), serde with derive,
// serde_derive and rand, whose lock holds windows-sys 0.48 (mio's) and two
// series of syn. check_wide.Cargo.toml and the locks were made in the same
// way as above, with
//
//	cargo update -p tokio --precise 1.20.1
//	cargo update -p serde --precise 1.0.150   # and serde_derive likewise
//
// for the file before, and from it -p tokio --precise 1.20.4 or 1.23.1,
// -p serde --precise 1.0.152 and -p rand --precise 0.8.5.
func wideInput(t *testing.T, before, after string, target cargoCheckTarget) (cargoCheckInput, *fakeCargoIndex) {
	t.Helper()
	m, err := parseCargoManifest("Cargo.toml", readCargoTestdata(t, "check_wide.Cargo.toml"))
	if err != nil {
		t.Fatal(err)
	}
	return cargoCheckInput{
		before:  readCargoTestdata(t, before),
		after:   readCargoTestdata(t, after),
		members: []*cargoManifest{m},
		targets: []cargoCheckTarget{target},
		record:  CargoRecord{LockVersion: 4},
	}, realCargoIndex(t, "check_index_wide.jsonl")
}

func TestCargoCheckRealWide(t *testing.T) {
	ok := func() *updateFailure { return nil }
	for _, c := range []struct {
		name, before, after string
		target              cargoCheckTarget
		others              int
	}{
		{"tokio patch", "check_wide_before.Cargo.lock", "check_wide_tokio_1_20_4.Cargo.lock", tgt("tokio", "1.20.1", "1.20.4"), 1},
		{"tokio with windows-sys", "check_wide_before.Cargo.lock", "check_wide_tokio_1_23_1.Cargo.lock", tgt("tokio", "1.20.1", "1.23.1"), 9},
		{"serde with serde_derive", "check_wide_before.Cargo.lock", "check_wide_serde_1_0_152.Cargo.lock", tgt("serde", "1.0.150", "1.0.152"), 1},
		{"rand", "check_wide_rand.Cargo.lock", "check_wide_before.Cargo.lock", tgt("rand", "0.8.5", "0.8.8"), 0},
	} {
		in, idx := wideInput(t, c.before, c.after, c.target)
		ch, f := (&cargoChecker{index: idx, spend: ok}).check(context.Background(), in)
		if f != nil {
			t.Fatalf("%s: %s: %s", c.name, f.reason, f.detail)
		}
		if len(ch.Others) != c.others {
			t.Fatalf("%s: others %+v", c.name, ch.Others)
		}
	}

	// The tokio update also takes rand to the other version the files have.
	in, idx := wideInput(t, "check_wide_before.Cargo.lock", "check_wide_tokio_1_20_4.Cargo.lock", tgt("tokio", "1.20.1", "1.20.4"))
	rand8 := realChecksum(t, "check_wide_before.Cargo.lock", "rand")
	rand5 := realChecksum(t, "check_wide_rand.Cargo.lock", "rand")
	after := strings.Replace(string(in.after), "name = \"rand\"\nversion = \"0.8.8\"", "name = \"rand\"\nversion = \"0.8.5\"", 1)
	in.after = []byte(strings.Replace(after, rand8, rand5, 1))
	_, f := (&cargoChecker{index: idx, spend: ok}).check(context.Background(), in)
	if f == nil || f.reason != ReasonUnexplainedDiff || !strings.Contains(f.detail, "rand") {
		t.Fatalf("got %+v", f)
	}
}

// realChecksum is the checksum a testdata lock gives the crate.
func realChecksum(t *testing.T, file, name string) string {
	t.Helper()
	l, err := parseCargoLock(readCargoTestdata(t, file))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range l.crates {
		if c.name == name {
			return c.checksum
		}
	}
	t.Fatalf("no %s in %s", name, file)
	return ""
}

// The check reads the index within the budget it is given, which the choosing
// of the releases has already spent from: what is left after that bounds it.
func TestCargoCheckSharesIndexBytes(t *testing.T) {
	tc := caseA()
	idx := tindex(tc.before, tc.after)
	idx.size = map[string]int64{"tokio": 30 << 20}
	in := cargoCheckInput{before: tlock(4, tc.before), after: tlock(4, tc.after), members: tmembers(tc.before), targets: tc.targets, record: CargoRecord{LockVersion: 4}}
	ok := func() *updateFailure { return nil }

	// On its own the check fits in the budget.
	if _, f := (&cargoChecker{index: idx, spend: ok}).check(context.Background(), in); f != nil {
		t.Fatalf("got %+v", f)
	}
	// After 40 MiB were read to choose the releases, it does not.
	spent := &cargoIndexBudget{used: 40 << 20}
	_, f := (&cargoChecker{index: idx, spend: ok, bytes: spent}).check(context.Background(), in)
	if f == nil || f.category != CategoryManual || f.reason != ReasonRegistryCheckLimit {
		t.Fatalf("got %+v", f)
	}
	if spent.used <= 40<<20 {
		t.Fatalf("the check did not count what it read: %d", spent.used)
	}
}
