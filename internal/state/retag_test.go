package state

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/kitsunetrail/kestrelynx/internal/analyze"
	"github.com/kitsunetrail/kestrelynx/internal/inventory"
	"github.com/kitsunetrail/kestrelynx/internal/scanner"
)

func digestOf(c byte) string { return "sha256:" + strings.Repeat(string(c), 64) }

// composeCtr builds a Docker container of ref (config digest content) running
// as the given Compose service.
func composeCtr(ref, content, project, service string) inventory.Container {
	d, ok := inventory.ParseDigest(inventory.DigestConfig, content)
	if !ok {
		panic("bad digest")
	}
	return inventory.Container{
		Name:     service + "-1",
		Workload: inventory.Workload{Kind: inventory.WorkloadCompose, Group: project, Name: service},
		Image:    inventory.RunningImage{Ref: ref, Config: d},
	}
}

func buildAt(now time.Time, scans []scanner.ImageScan, cs ...inventory.Container) analyze.Report {
	return analyze.Build(scans, cs, analyze.Triage{}, now)
}

const repo = "ghcr.io/acme/app"

func refChangePairs(d Diff) []string {
	var out []string
	for _, c := range d.RefChanges {
		out = append(out, c.PreviousRef+" -> "+c.Ref)
	}
	return out
}

func TestRefChange_MainUpdatedSensorUntouched(t *testing.T) {
	a, b, s := repo+":sha-A", repo+":sha-B", repo+":sensor"
	cA, cB, cS := digestOf('a'), digestOf('b'), digestOf('c')
	pkg := func(img string) scanner.Finding { return finding(img, "openssl", "CVE-1", scanner.StatusFixed) }
	sensorPkg := finding(s, "libz", "CVE-9", scanner.StatusFixed)

	r1 := buildAt(day1,
		[]scanner.ImageScan{resolvedScan(a, cA, pkg(a)), resolvedScan(s, cS, sensorPkg)},
		composeCtr(a, cA, "p", "app"), composeCtr(s, cS, "p", "sensor"))
	_, st1 := Compute(empty(), r1)
	if got := st1.Images[a].Workloads; !reflect.DeepEqual(got, []string{"compose/p/app"}) {
		t.Fatalf("workloads recorded = %v", got)
	}

	r2 := buildAt(day2,
		[]scanner.ImageScan{resolvedScan(b, cB, pkg(b)), resolvedScan(s, cS, sensorPkg)},
		composeCtr(b, cB, "p", "app"), composeCtr(s, cS, "p", "sensor"))
	before, _ := json.Marshal(st1)
	d, st2 := Compute(st1, r2)
	after, _ := json.Marshal(st1)
	if string(before) != string(after) {
		t.Error("Compute modified prev")
	}

	wantKinds(t, "ref changes", refChangePairs(d), a+" -> "+b)
	if len(d.Changes) != 0 || len(d.Resolved) != 0 || len(d.Replaced) != 0 {
		t.Errorf("want 0 new / 0 resolved / 0 replaced, got %+v", d)
	}
	rc := d.RefChanges[0]
	if rc.Repository != repo || !reflect.DeepEqual(rc.Workloads, []string{"compose/p/app"}) {
		t.Errorf("RefChange = %+v", rc)
	}
	if !d.HasChanges() {
		t.Error("a reference change alone must count as a change")
	}
	e, ok := st2.Findings[key(b, "openssl")]
	if !ok || !e.FirstSeen.Equal(day1) || e.ContentID != cB {
		t.Errorf("carried entry = %+v ok=%v (want FirstSeen day1, ContentID from this cycle)", e, ok)
	}
	if _, ok := st2.Findings[key(a, "openssl")]; ok {
		t.Error("old reference key must not remain")
	}
	if _, ok := st2.Findings[key(s, "libz")]; !ok {
		t.Error("sensor entry must be untouched")
	}
	if _, ok := st2.Images[a]; ok {
		t.Error("old reference image record must be gone")
	}
}

func TestRefChange_NewCVEAndResolvedPackage(t *testing.T) {
	a, b := repo+":sha-A", repo+":sha-B"
	cA, cB := digestOf('a'), digestOf('b')
	r1 := buildAt(day1, []scanner.ImageScan{resolvedScan(a, cA,
		finding(a, "openssl", "CVE-1", scanner.StatusFixed),
		finding(a, "zlib", "CVE-2", scanner.StatusFixed))},
		composeCtr(a, cA, "p", "app"))
	_, st1 := Compute(empty(), r1)

	r2 := buildAt(day2, []scanner.ImageScan{resolvedScan(b, cB,
		finding(b, "openssl", "CVE-1", scanner.StatusFixed),
		finding(b, "openssl", "CVE-3", scanner.StatusFixed))},
		composeCtr(b, cB, "p", "app"))
	d, _ := Compute(st1, r2)
	wantKinds(t, "ref changes", refChangePairs(d), a+" -> "+b)
	wantKinds(t, "changes", changeKinds(d), b+" openssl new_cves")
	if len(d.Resolved) != 1 || d.Resolved[0].Image != b || d.Resolved[0].Package != "zlib" {
		t.Errorf("Resolved = %+v, want zlib under the new reference", d.Resolved)
	}
}

// plainCycle runs two cycles and returns the second diff.
func twoCycles(prevScans []scanner.ImageScan, prevCs []inventory.Container, scans []scanner.ImageScan, cs []inventory.Container) (Diff, State) {
	_, st1 := Compute(empty(), buildAt(day1, prevScans, prevCs...))
	return Compute(st1, buildAt(day2, scans, cs...))
}

func TestRefChange_FallsBackToOldBehavior(t *testing.T) {
	a, b := repo+":sha-A", repo+":sha-B"
	cA, cB, cC := digestOf('a'), digestOf('b'), digestOf('c')
	fa := func(img string) scanner.Finding { return finding(img, "openssl", "CVE-1", scanner.StatusFixed) }

	cases := []struct {
		name  string
		prevS []scanner.ImageScan
		prevC []inventory.Container
		scans []scanner.ImageScan
		cs    []inventory.Container
	}{
		{
			name:  "two vanished, one appeared (2 to 1)",
			prevS: []scanner.ImageScan{resolvedScan(a, cA, fa(a)), resolvedScan(repo+":x", cC, fa(repo+":x"))},
			prevC: []inventory.Container{composeCtr(a, cA, "p", "app"), composeCtr(repo+":x", cC, "p", "app")},
			scans: []scanner.ImageScan{resolvedScan(b, cB, fa(b))},
			cs:    []inventory.Container{composeCtr(b, cB, "p", "app")},
		},
		{
			name:  "one vanished, two appeared (1 to 2)",
			prevS: []scanner.ImageScan{resolvedScan(a, cA, fa(a))},
			prevC: []inventory.Container{composeCtr(a, cA, "p", "app")},
			scans: []scanner.ImageScan{resolvedScan(b, cB, fa(b)), resolvedScan(repo+":y", cC, fa(repo+":y"))},
			cs:    []inventory.Container{composeCtr(b, cB, "p", "app"), composeCtr(repo+":y", cC, "p", "app")},
		},
		{
			name:  "workload differs",
			prevS: []scanner.ImageScan{resolvedScan(a, cA, fa(a))},
			prevC: []inventory.Container{composeCtr(a, cA, "p", "app")},
			scans: []scanner.ImageScan{resolvedScan(b, cB, fa(b))},
			cs:    []inventory.Container{composeCtr(b, cB, "p", "other")},
		},
		{
			name:  "repository differs",
			prevS: []scanner.ImageScan{resolvedScan(a, cA, fa(a))},
			prevC: []inventory.Container{composeCtr(a, cA, "p", "app")},
			scans: []scanner.ImageScan{resolvedScan("ghcr.io/acme/other:sha-B", cB, fa("ghcr.io/acme/other:sha-B"))},
			cs:    []inventory.Container{composeCtr("ghcr.io/acme/other:sha-B", cB, "p", "app")},
		},
		{
			name:  "new scan failed",
			prevS: []scanner.ImageScan{resolvedScan(a, cA, fa(a))},
			prevC: []inventory.Container{composeCtr(a, cA, "p", "app")},
			scans: []scanner.ImageScan{failedResolvedScan(b, cB, errors.New("pull failed"))},
			cs:    []inventory.Container{composeCtr(b, cB, "p", "app")},
		},
		{
			name:  "new reference unconfirmed",
			prevS: []scanner.ImageScan{resolvedScan(a, cA, fa(a))},
			prevC: []inventory.Container{composeCtr(a, cA, "p", "app")},
			scans: []scanner.ImageScan{remoteUnconfirmedScan(b, fa(b))},
			cs:    []inventory.Container{composeCtr(b, cB, "p", "app")},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d, _ := twoCycles(tc.prevS, tc.prevC, tc.scans, tc.cs)
			if len(d.RefChanges) != 0 {
				t.Errorf("RefChanges = %+v, want none", d.RefChanges)
			}
			if len(d.Resolved) == 0 && tc.name != "new scan failed" && tc.name != "new reference unconfirmed" {
				t.Errorf("old behaviour expected the old findings resolved: %+v", d)
			}
		})
	}
}

func TestRefChange_OldStateWithoutWorkloads(t *testing.T) {
	a, b := repo+":sha-A", repo+":sha-B"
	cA, cB := digestOf('a'), digestOf('b')
	_, st1 := Compute(empty(), buildAt(day1,
		[]scanner.ImageScan{resolvedScan(a, cA, finding(a, "openssl", "CVE-1", scanner.StatusFixed))},
		composeCtr(a, cA, "p", "app")))
	// A state file written before workloads were recorded.
	m := st1.Images[a]
	m.Workloads = nil
	st1.Images[a] = m

	d, _ := Compute(st1, buildAt(day2,
		[]scanner.ImageScan{resolvedScan(b, cB, finding(b, "openssl", "CVE-1", scanner.StatusFixed))},
		composeCtr(b, cB, "p", "app")))
	if len(d.RefChanges) != 0 || len(d.Resolved) != 1 || len(d.Changes) != 1 {
		t.Errorf("want old behaviour (1 resolved, 1 new, no ref change), got %+v", d)
	}

	// And the JSON of such a state has no workloads field.
	raw, _ := json.Marshal(m)
	if strings.Contains(string(raw), "workloads") {
		t.Errorf("empty workloads must be omitted: %s", raw)
	}
}

func TestRefChange_RollingUpdateIsNotPaired(t *testing.T) {
	a, b := repo+":sha-A", repo+":sha-B"
	cA, cB := digestOf('a'), digestOf('b')
	fa := func(img string) scanner.Finding { return finding(img, "openssl", "CVE-1", scanner.StatusFixed) }
	_, st1 := Compute(empty(), buildAt(day1, []scanner.ImageScan{resolvedScan(a, cA, fa(a))}, composeCtr(a, cA, "p", "app")))

	// During the rollout both run.
	d2, st2 := Compute(st1, buildAt(day2,
		[]scanner.ImageScan{resolvedScan(a, cA, fa(a)), resolvedScan(b, cB, fa(b))},
		composeCtr(a, cA, "p", "app"), composeCtr(b, cB, "p", "app")))
	if len(d2.RefChanges) != 0 {
		t.Errorf("rollout cycle: RefChanges = %+v", d2.RefChanges)
	}
	if _, ok := st2.Findings[key(a, "openssl")]; !ok {
		t.Error("A must keep its history while it still runs")
	}
	// After it, only B: B already has history, so nothing to carry; A resolves as before.
	d3, _ := Compute(st2, buildAt(day2.AddDate(0, 0, 1),
		[]scanner.ImageScan{resolvedScan(b, cB, fa(b))}, composeCtr(b, cB, "p", "app")))
	if len(d3.RefChanges) != 0 {
		t.Errorf("after rollout: RefChanges = %+v", d3.RefChanges)
	}
}

func TestRefChange_CarriesEOLEOSLAndMuted(t *testing.T) {
	a, b := repo+":sha-A", repo+":sha-B"
	cA, cB := digestOf('a'), digestOf('b')
	eolA := finding(a, "qt", "CVE-5", scanner.StatusEndOfLife)
	scanA := resolvedScan(a, cA, eolA)
	scanA.OSEOSL = true
	r1 := buildAt(day1, []scanner.ImageScan{scanA}, composeCtr(a, cA, "p", "app"))
	_, st1 := Compute(empty(), r1)
	if len(st1.EOSL) != 1 || len(st1.EOLPackages) != 1 {
		t.Fatalf("setup: EOSL=%v EOL=%v", st1.EOSL, st1.EOLPackages)
	}
	st1.Muted[key(a, "qt")] = true

	eolB := finding(b, "qt", "CVE-5", scanner.StatusEndOfLife)
	scanB := resolvedScan(b, cB, eolB)
	scanB.OSEOSL = true
	d, st2 := Compute(st1, buildAt(day2, []scanner.ImageScan{scanB}, composeCtr(b, cB, "p", "app")))

	wantKinds(t, "ref changes", refChangePairs(d), a+" -> "+b)
	if len(d.NewEOSL) != 0 || len(d.ResolvedEOSL) != 0 || len(d.NewEOLPackages) != 0 || len(d.ResolvedEOLPackages) != 0 {
		t.Errorf("EOL/EOSL must carry: %+v", d)
	}
	if !st2.EOSL[b].Equal(day1) {
		t.Errorf("EOSL date = %v, want day1", st2.EOSL[b])
	}
	if e := st2.EOLPackages[key(b, "qt")]; !e.FirstSeen.Equal(day1) {
		t.Errorf("EOL entry = %+v", e)
	}
	// Muted is history, re-judged each cycle: this cycle's groups are not
	// muted, so the carried flag turns into an unmuted notice and clears.
	if st2.Muted[key(b, "qt")] || st2.Muted[key(a, "qt")] {
		t.Errorf("Muted after cycle = %v, want re-judged (false)", st2.Muted)
	}
}

func TestRefChange_MutedHistoryUsedForUnmuted(t *testing.T) {
	a, b := repo+":sha-A", repo+":sha-B"
	cA, cB := digestOf('a'), digestOf('b')
	_, st1 := Compute(empty(), buildAt(day1,
		[]scanner.ImageScan{resolvedScan(a, cA, finding(a, "openssl", "CVE-1", scanner.StatusAffected))},
		composeCtr(a, cA, "p", "app")))
	st1.Muted[key(a, "openssl")] = true
	d, _ := Compute(st1, buildAt(day2,
		[]scanner.ImageScan{resolvedScan(b, cB, finding(b, "openssl", "CVE-1", scanner.StatusAffected))},
		composeCtr(b, cB, "p", "app")))
	wantKinds(t, "changes", changeKinds(d), b+" openssl unmuted")
}

func TestRefChange_SameRefContentChangeStillReplaced(t *testing.T) {
	ref := repo + ":latest"
	cA, cB := digestOf('a'), digestOf('b')
	_, st1 := Compute(empty(), buildAt(day1, []scanner.ImageScan{resolvedScan(ref, cA)}, composeCtr(ref, cA, "p", "app")))
	d, _ := Compute(st1, buildAt(day2, []scanner.ImageScan{resolvedScan(ref, cB)}, composeCtr(ref, cB, "p", "app")))
	if len(d.Replaced) != 1 || len(d.RefChanges) != 0 {
		t.Errorf("Replaced=%v RefChanges=%v", d.Replaced, d.RefChanges)
	}
}

func TestRefChange_KubernetesSidecarKeys(t *testing.T) {
	mk := func(ref, content, ctr string) inventory.Container {
		c := composeCtr(ref, content, "", "")
		c.Name = "ns/pod-abc/" + ctr
		c.Workload = inventory.Workload{Kind: inventory.WorkloadDeployment, Group: "ns", Name: "web"}
		return c
	}
	a, b := repo+":sha-A", repo+":sha-B"
	side := "ghcr.io/acme/side:1"
	cA, cB, cS := digestOf('a'), digestOf('b'), digestOf('c')
	_, st1 := Compute(empty(), buildAt(day1,
		[]scanner.ImageScan{resolvedScan(a, cA, finding(a, "openssl", "CVE-1", scanner.StatusFixed)), resolvedScan(side, cS)},
		mk(a, cA, "main"), mk(side, cS, "proxy")))
	if got := st1.Images[a].Workloads; !reflect.DeepEqual(got, []string{"deployment/ns/web/main"}) {
		t.Errorf("k8s key = %v", got)
	}
	d, _ := Compute(st1, buildAt(day2,
		[]scanner.ImageScan{resolvedScan(b, cB, finding(b, "openssl", "CVE-1", scanner.StatusFixed)), resolvedScan(side, cS)},
		mk(b, cB, "main"), mk(side, cS, "proxy")))
	wantKinds(t, "ref changes", refChangePairs(d), a+" -> "+b)
}

func TestWorkloadKey(t *testing.T) {
	cases := []struct {
		c    inventory.Container
		want string
	}{
		{inventory.Container{Workload: inventory.Workload{Kind: inventory.WorkloadCompose, Group: "p", Name: "s"}}, "compose/p/s"},
		{inventory.Container{Workload: inventory.Workload{Kind: inventory.WorkloadCompose, Group: "p"}}, ""},
		{inventory.Container{Name: "web"}, "container/web"},
		{inventory.Container{}, ""},
		{inventory.Container{Name: "ns/pod/c", Workload: inventory.Workload{Kind: inventory.WorkloadStatefulSet, Group: "ns", Name: "db"}}, "statefulset/ns/db/c"},
		{inventory.Container{Name: "noslash", Workload: inventory.Workload{Kind: inventory.WorkloadStatefulSet, Group: "ns", Name: "db"}}, ""},
	}
	for _, tc := range cases {
		if got := WorkloadKey(tc.c); got != tc.want {
			t.Errorf("WorkloadKey(%+v) = %q, want %q", tc.c, got, tc.want)
		}
	}
}

func TestRefChange_IPv6RegistryRetag(t *testing.T) {
	a, b := "[::1]:5000/team/app:a", "[::1]:5000/team/app:b"
	cA, cB := digestOf('a'), digestOf('b')
	_, st1 := Compute(empty(), buildAt(day1,
		[]scanner.ImageScan{resolvedScan(a, cA, finding(a, "openssl", "CVE-1", scanner.StatusFixed))},
		composeCtr(a, cA, "p", "app")))
	d, st2 := Compute(st1, buildAt(day2,
		[]scanner.ImageScan{resolvedScan(b, cB, finding(b, "openssl", "CVE-1", scanner.StatusFixed))},
		composeCtr(b, cB, "p", "app")))
	wantKinds(t, "ref changes", refChangePairs(d), a+" -> "+b)
	if len(d.Changes) != 0 || len(d.Resolved) != 0 {
		t.Errorf("want no new/resolved: %+v", d)
	}
	if d.RefChanges[0].Repository != "[::1]:5000/team/app" {
		t.Errorf("repository = %q", d.RefChanges[0].Repository)
	}
	if !st2.Findings[key(b, "openssl")].FirstSeen.Equal(day1) {
		t.Error("history not carried")
	}
}

// A reference shared by two workloads that diverge (one to a confirmed new
// reference, the other to a reference that failed to scan) is a 1-to-2
// match, not an update of the first.
func TestRefChange_SharedRefDivergesWithFailedSibling(t *testing.T) {
	a, b, c := repo+":sha-A", repo+":sha-B", repo+":sha-C"
	cA, cB, cC := digestOf('a'), digestOf('b'), digestOf('c')
	fa := func(img string) scanner.Finding { return finding(img, "openssl", "CVE-1", scanner.StatusFixed) }
	prevS := []scanner.ImageScan{resolvedScan(a, cA, fa(a))}
	prevC := []inventory.Container{composeCtr(a, cA, "p", "x"), composeCtr(a, cA, "p", "y")}

	for name, yScan := range map[string]scanner.ImageScan{
		"failed":      failedResolvedScan(c, cC, errors.New("pull failed")),
		"unconfirmed": remoteUnconfirmedScan(c, fa(c)),
	} {
		t.Run(name, func(t *testing.T) {
			d, _ := twoCycles(prevS, prevC,
				[]scanner.ImageScan{resolvedScan(b, cB, fa(b)), yScan},
				[]inventory.Container{composeCtr(b, cB, "p", "x"), composeCtr(c, cC, "p", "y")})
			if len(d.RefChanges) != 0 {
				t.Errorf("RefChanges = %+v, want none", d.RefChanges)
			}
		})
	}
}

// TestRefChange_SharedRefFansOutAcrossWorkloads covers a shared reference
// that one workload moves away from cleanly while another moves to two new
// references at once (a rolling update, say): every scan succeeds, but the
// vanished reference maps to three new ones, so nothing is carried over.
func TestRefChange_SharedRefFansOutAcrossWorkloads(t *testing.T) {
	a, b, c, dd := repo+":sha-A", repo+":sha-B", repo+":sha-C", repo+":sha-D"
	cA, cB, cC, cD := digestOf('a'), digestOf('b'), digestOf('c'), digestOf('d')
	fa := func(img string) scanner.Finding { return finding(img, "openssl", "CVE-1", scanner.StatusFixed) }
	d, _ := twoCycles(
		[]scanner.ImageScan{resolvedScan(a, cA, fa(a))},
		[]inventory.Container{composeCtr(a, cA, "p", "x"), composeCtr(a, cA, "p", "y")},
		[]scanner.ImageScan{resolvedScan(b, cB, fa(b)), resolvedScan(c, cC, fa(c)), resolvedScan(dd, cD, fa(dd))},
		[]inventory.Container{composeCtr(b, cB, "p", "x"), composeCtr(c, cC, "p", "y"), composeCtr(dd, cD, "p", "y")})
	if len(d.RefChanges) != 0 {
		t.Errorf("RefChanges = %+v, want none", d.RefChanges)
	}
}

// TestRefChange_TwoRefsMergeIntoOne covers the reverse: two vanished
// references whose workloads both now run the same new reference.
func TestRefChange_TwoRefsMergeIntoOne(t *testing.T) {
	a, e, b := repo+":sha-A", repo+":sha-E", repo+":sha-B"
	cA, cE, cB := digestOf('a'), digestOf('e'), digestOf('b')
	fa := func(img string) scanner.Finding { return finding(img, "openssl", "CVE-1", scanner.StatusFixed) }
	d, _ := twoCycles(
		[]scanner.ImageScan{resolvedScan(a, cA, fa(a)), resolvedScan(e, cE, fa(e))},
		[]inventory.Container{composeCtr(a, cA, "p", "x"), composeCtr(e, cE, "p", "y")},
		[]scanner.ImageScan{resolvedScan(b, cB, fa(b))},
		[]inventory.Container{composeCtr(b, cB, "p", "x"), composeCtr(b, cB, "p", "y")})
	if len(d.RefChanges) != 0 {
		t.Errorf("RefChanges = %+v, want none", d.RefChanges)
	}
}

// --- Kubernetes-shaped observations ---
//
// The Kubernetes adapter reports a running container with a registry digest
// and the node platform (no config digest), named "namespace/pod/container";
// its scans are remote and, when pinned, carry a registry-kind Subject.Key.
// analyze therefore leaves IdentityResolved false for such a reference.

var k8sPlatform = inventory.Platform{OS: "linux", Architecture: "amd64"}

func k8sRegistryKey(hex byte, platform inventory.Platform) inventory.EntityKey {
	d, ok := inventory.ParseDigest(inventory.DigestRegistry, digestOf(hex))
	if !ok {
		panic("bad digest")
	}
	return inventory.EntityKey{Digest: d, Platform: platform}
}

// k8sCtr is a running container of a Deployment's Pod.
func k8sCtr(ref string, hex byte, platform inventory.Platform, pod, container string) inventory.Container {
	d, _ := inventory.ParseDigest(inventory.DigestRegistry, digestOf(hex))
	repoName, _ := inventory.RepositoryOf(ref)
	return inventory.Container{
		Name:     "ns/" + pod + "/" + container,
		Workload: inventory.Workload{Kind: inventory.WorkloadDeployment, Group: "ns", Name: "web"},
		Image: inventory.RunningImage{
			Ref:      ref,
			Registry: inventory.RegistryRef{Repository: repoName, Digest: d},
			Platform: platform,
		},
	}
}

// k8sScan is the scan of one such entity. pinned selects a confirmed scan;
// otherwise it is a successful remote scan that could not be pinned.
func k8sScan(ref string, hex byte, platform inventory.Platform, pinned bool, finds ...scanner.Finding) scanner.ImageScan {
	key := k8sRegistryKey(hex, platform)
	s := scanner.ImageScan{
		Image:    ref,
		Subject:  inventory.ImageSubject{Ref: ref, Key: key, Resolved: platform.Known()},
		Source:   scanner.SourceRemote,
		Findings: finds,
	}
	if pinned {
		s.ScannedKey, s.Pinned = key, true
	}
	return s
}

func k8sFinding(img string) scanner.Finding {
	return finding(img, "openssl", "CVE-1", scanner.StatusFixed)
}

func TestRefChange_KubernetesPinnedCarriesOver(t *testing.T) {
	a, b := repo+":sha-A", repo+":sha-B"
	r1 := buildAt(day1, []scanner.ImageScan{k8sScan(a, 'a', k8sPlatform, true, k8sFinding(a))},
		k8sCtr(a, 'a', k8sPlatform, "web-1", "app"))
	_, st1 := Compute(empty(), r1)

	r2 := buildAt(day2, []scanner.ImageScan{k8sScan(b, 'b', k8sPlatform, true, k8sFinding(b))},
		k8sCtr(b, 'b', k8sPlatform, "web-2", "app"))
	if len(r2.Images) != 1 || r2.Images[0].IdentityResolved {
		t.Fatalf("fixture must reproduce the adapter's IdentityResolved=false, got %+v", r2.Images)
	}
	d, st2 := Compute(st1, r2)
	wantKinds(t, "ref changes", refChangePairs(d), a+" -> "+b)
	if len(d.Changes) != 0 || len(d.Resolved) != 0 {
		t.Errorf("want 0 new / 0 resolved, got %+v", d)
	}
	if got := d.RefChanges[0].Workloads; !reflect.DeepEqual(got, []string{"deployment/ns/web/app"}) {
		t.Errorf("workloads = %v", got)
	}
	if !st2.Findings[key(b, "openssl")].FirstSeen.Equal(day1) {
		t.Error("history not carried")
	}
}

func TestRefChange_KubernetesRejections(t *testing.T) {
	a, b := repo+":sha-A", repo+":sha-B"
	_, st1 := Compute(empty(), buildAt(day1,
		[]scanner.ImageScan{k8sScan(a, 'a', k8sPlatform, true, k8sFinding(a))},
		k8sCtr(a, 'a', k8sPlatform, "web-1", "app")))

	cases := map[string]analyze.Report{
		"platform unknown": buildAt(day2,
			[]scanner.ImageScan{k8sScan(b, 'b', inventory.Platform{}, false, k8sFinding(b))},
			k8sCtr(b, 'b', inventory.Platform{}, "web-2", "app")),
		"pin unconfirmed": buildAt(day2,
			[]scanner.ImageScan{k8sScan(b, 'b', k8sPlatform, false, k8sFinding(b))},
			k8sCtr(b, 'b', k8sPlatform, "web-2", "app")),
		"multiple entities": buildAt(day2,
			[]scanner.ImageScan{k8sScan(b, 'b', k8sPlatform, true, k8sFinding(b)), k8sScan(b, 'c', k8sPlatform, true, k8sFinding(b))},
			k8sCtr(b, 'b', k8sPlatform, "web-2", "app"), k8sCtr(b, 'c', k8sPlatform, "web-3", "app")),
	}
	for name, r := range cases {
		t.Run(name, func(t *testing.T) {
			d, _ := Compute(st1, r)
			if len(d.RefChanges) != 0 {
				t.Errorf("RefChanges = %+v, want none", d.RefChanges)
			}
			if len(d.Resolved) == 0 {
				t.Errorf("old behaviour expected (old finding resolved): %+v", d)
			}
		})
	}
}

// The main container and a sidecar of one Pod share a repository; only the
// container name tells them apart.
func TestRefChange_KubernetesSameRepoMainAndSidecar(t *testing.T) {
	mainA, mainB := repo+":main-A", repo+":main-B"
	sideA, sideB := repo+":side-A", repo+":side-B"
	prevScans := []scanner.ImageScan{
		k8sScan(mainA, 'a', k8sPlatform, true, k8sFinding(mainA)),
		k8sScan(sideA, 'c', k8sPlatform, true, k8sFinding(sideA)),
	}
	prevCs := []inventory.Container{
		k8sCtr(mainA, 'a', k8sPlatform, "web-1", "app"),
		k8sCtr(sideA, 'c', k8sPlatform, "web-1", "proxy"),
	}

	t.Run("only main updated", func(t *testing.T) {
		d, st := twoCycles(prevScans, prevCs,
			[]scanner.ImageScan{k8sScan(mainB, 'b', k8sPlatform, true, k8sFinding(mainB)), prevScans[1]},
			[]inventory.Container{k8sCtr(mainB, 'b', k8sPlatform, "web-2", "app"), k8sCtr(sideA, 'c', k8sPlatform, "web-2", "proxy")})
		wantKinds(t, "ref changes", refChangePairs(d), mainA+" -> "+mainB)
		if len(d.Changes) != 0 || len(d.Resolved) != 0 {
			t.Errorf("want 0 new / 0 resolved: %+v", d)
		}
		if _, ok := st.Findings[key(sideA, "openssl")]; !ok {
			t.Error("sidecar entry must be untouched")
		}
	})

	t.Run("both updated at once", func(t *testing.T) {
		d, _ := twoCycles(prevScans, prevCs,
			[]scanner.ImageScan{k8sScan(mainB, 'b', k8sPlatform, true, k8sFinding(mainB)), k8sScan(sideB, 'd', k8sPlatform, true, k8sFinding(sideB))},
			[]inventory.Container{k8sCtr(mainB, 'b', k8sPlatform, "web-2", "app"), k8sCtr(sideB, 'd', k8sPlatform, "web-2", "proxy")})
		wantKinds(t, "ref changes", refChangePairs(d), mainA+" -> "+mainB, sideA+" -> "+sideB)
		if len(d.Changes) != 0 || len(d.Resolved) != 0 {
			t.Errorf("want 0 new / 0 resolved: %+v", d)
		}
	})
}
