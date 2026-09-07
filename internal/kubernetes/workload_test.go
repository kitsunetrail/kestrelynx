package kubernetes

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/inventory"
)

// TestRunningContainers_ResolveWorkload drives resolveWorkload end to end
// through RunningContainers, one Pod fixture (plus whatever relay fixtures it
// needs) per case. Every allow-listed Kind and every rejection path in
// resolveWorkload's doc comment is exercised here.
func TestRunningContainers_ResolveWorkload(t *testing.T) {
	cases := []struct {
		name        string
		podFixture  string
		rsFixtures  []string
		jobFixtures []string
		want        inventory.Workload
	}{
		{
			name:       "Pod -> ReplicaSet -> Deployment",
			podFixture: "pod_owned_by_deployment.json",
			rsFixtures: []string{"replicaset_for_deployment.json"},
			want:       inventory.Workload{Kind: inventory.WorkloadDeployment, Group: "default", Name: "web"},
		},
		{
			name:       "Pod -> StatefulSet",
			podFixture: "pod_owned_by_statefulset.json",
			want:       inventory.Workload{Kind: inventory.WorkloadStatefulSet, Group: "default", Name: "db"},
		},
		{
			name:       "Pod -> DaemonSet",
			podFixture: "pod_owned_by_daemonset.json",
			want:       inventory.Workload{Kind: inventory.WorkloadDaemonSet, Group: "default", Name: "log-agent"},
		},
		{
			name:        "Pod -> Job -> CronJob",
			podFixture:  "pod_owned_by_cronjob.json",
			jobFixtures: []string{"job_for_cronjob.json"},
			want:        inventory.Workload{Kind: inventory.WorkloadCronJob, Group: "default", Name: "backup"},
		},
		{
			name:        "Pod -> Job, no CronJob owner",
			podFixture:  "pod_owned_by_bare_job.json",
			jobFixtures: []string{"job_bare.json"},
			want:        inventory.Workload{Kind: inventory.WorkloadJob, Group: "default", Name: "one-off-job"},
		},
		{
			name:       "Pod with no controller owner",
			podFixture: "pod_standalone.json",
			want:       inventory.Workload{Kind: inventory.WorkloadPod, Group: "default", Name: "debug-shell"},
		},
		{
			name:       "CRD owner outside the allow-list -> unknown",
			podFixture: "pod_owned_by_crd.json",
			want:       inventory.Workload{},
		},
		{
			name:       "same-named Kind under the wrong apiVersion -> unknown",
			podFixture: "pod_owned_by_replicaset_wrong_group.json",
			rsFixtures: []string{"replicaset_wrong_group_owner.json"},
			want:       inventory.Workload{},
		},
		{
			name:       "owner UID doesn't match the indexed ReplicaSet -> unknown",
			podFixture: "pod_owned_by_replicaset_stale_uid.json",
			rsFixtures: []string{"replicaset_for_deployment.json"},
			want:       inventory.Workload{},
		},
		{
			name:       "relay ReplicaSet missing from the list entirely -> unknown",
			podFixture: "pod_owned_by_missing_replicaset.json",
			want:       inventory.Workload{},
		},
		{
			name:       "bare ReplicaSet with no Deployment owner -> unknown",
			podFixture: "pod_owned_by_bare_replicaset.json",
			rsFixtures: []string{"replicaset_bare.json"},
			want:       inventory.Workload{},
		},
		{
			// A reference with Controller == false is not a controller
			// reference at all — this must resolve exactly like "no
			// ownerReferences", not like "owned by that ReplicaSet".
			name:       "controller:false reference is not a controller owner -> the Pod itself",
			podFixture: "pod_owner_controller_false.json",
			want:       inventory.Workload{Kind: inventory.WorkloadPod, Group: "default", Name: "web-ctrlfalse-abcde"},
		},
		{
			// Same as above but the "controller" key is missing from the
			// JSON entirely rather than explicitly false — Go's zero value
			// for bool must behave the same as an explicit false.
			name:       "controller field omitted -> the Pod itself",
			podFixture: "pod_owner_controller_omitted.json",
			want:       inventory.Workload{Kind: inventory.WorkloadPod, Group: "default", Name: "web-ctrlomit-abcde"},
		},
		{
			// Two controller:true references is malformed input; picking
			// either one would make the result depend on array order, so
			// this must resolve to unknown rather than a guess — and must
			// never be confused with "no controller owner" (which resolves
			// to WorkloadPod, not unknown).
			name:       "more than one controller:true reference -> unknown",
			podFixture: "pod_owner_controller_multiple.json",
			want:       inventory.Workload{},
		},
		{
			name:        "Job owned by a disallowed-Kind controller -> unknown",
			podFixture:  "pod_owned_by_job_disallowed_owner.json",
			jobFixtures: []string{"job_owned_by_disallowed_owner.json"},
			want:        inventory.Workload{},
		},
		{
			name:       "relay Job missing from the list entirely -> unknown",
			podFixture: "pod_owned_by_missing_job.json",
			want:       inventory.Workload{},
		},
		{
			name:        "owner UID doesn't match the indexed Job -> unknown",
			podFixture:  "pod_owned_by_job_stale_uid.json",
			jobFixtures: []string{"job_bare.json"},
			want:        inventory.Workload{},
		},
		{
			name:       "direct StatefulSet owner under the wrong apiVersion -> unknown",
			podFixture: "pod_owned_by_statefulset_wrong_group.json",
			want:       inventory.Workload{},
		},
		{
			name:       "direct DaemonSet owner under the wrong apiVersion -> unknown",
			podFixture: "pod_owned_by_daemonset_wrong_group.json",
			want:       inventory.Workload{},
		},
		{
			// The ReplicaSet named in the RS list is real, but the Pod's own
			// owner reference carries an empty UID — it must not resolve
			// through that RS just because the name happens to match.
			name:       "empty UID at Pod -> ReplicaSet -> unknown",
			podFixture: "pod_owned_by_replicaset_empty_uid.json",
			rsFixtures: []string{"replicaset_for_deployment.json"},
			want:       inventory.Workload{},
		},
		{
			name:       "empty UID at ReplicaSet -> Deployment -> unknown",
			podFixture: "pod_owned_by_replicaset_for_deployment_empty_uid.json",
			rsFixtures: []string{"replicaset_deployment_owner_empty_uid.json"},
			want:       inventory.Workload{},
		},
		{
			name:       "empty UID at Pod -> StatefulSet (direct owner) -> unknown",
			podFixture: "pod_owned_by_statefulset_empty_uid.json",
			want:       inventory.Workload{},
		},
		{
			name:        "empty UID at Job -> CronJob -> unknown",
			podFixture:  "pod_owned_by_job_for_cronjob_empty_uid.json",
			jobFixtures: []string{"job_owned_by_cronjob_empty_uid.json"},
			want:        inventory.Workload{},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeServer(t)
			f.on("/api/v1/nodes", ok(envelope("", loadFixture(t, "node_amd64.json"))))
			f.on("/api/v1/pods", ok(envelope("", loadFixture(t, tc.podFixture))))
			if len(tc.rsFixtures) > 0 {
				f.on("/apis/apps/v1/replicasets", ok(envelope("", loadFixtures(t, tc.rsFixtures)...)))
			}
			if len(tc.jobFixtures) > 0 {
				f.on("/apis/batch/v1/jobs", ok(envelope("", loadFixtures(t, tc.jobFixtures)...)))
			}
			srv := f.start()
			c := newTestClient(t, srv, nil)

			cs, err := c.RunningContainers(context.Background())
			if err != nil {
				t.Fatalf("RunningContainers: %v", err)
			}
			if len(cs) != 1 {
				t.Fatalf("got %d containers, want 1: %+v", len(cs), cs)
			}
			if cs[0].Workload != tc.want {
				t.Errorf("Workload = %+v, want %+v", cs[0].Workload, tc.want)
			}
		})
	}
}

// loadFixtures loads each named fixture in order, for building a multi-item
// LIST response.
func loadFixtures(t *testing.T, names []string) []json.RawMessage {
	t.Helper()
	items := make([]json.RawMessage, len(names))
	for i, name := range names {
		items[i] = loadFixture(t, name)
	}
	return items
}

// TestRunningContainers_Namespaces_WorkloadScopedByNamespace extends the
// existing namespace-scoping coverage (transport_test.go's
// TestRunningContainers_Namespaces_ScopedPaths only checks which paths were
// requested) to the resolution itself: a ReplicaSet's identity is
// namespace+uid, not uid alone, so a Pod in one namespace whose owner
// reference UID happens to collide with a ReplicaSet that actually lives in
// a different namespace must not resolve through it.
func TestRunningContainers_Namespaces_WorkloadScopedByNamespace(t *testing.T) {
	f := newFakeServer(t)
	f.on("/api/v1/nodes", ok(envelope("", loadFixture(t, "node_amd64.json"))))
	f.on("/api/v1/namespaces/team-a/pods", ok(envelope("", loadFixture(t, "pod_team_a_owned_by_rs.json"))))
	f.on("/api/v1/namespaces/team-b/pods", ok(envelope("", loadFixture(t, "pod_team_b_stale_reference.json"))))
	f.on("/apis/apps/v1/namespaces/team-a/replicasets", ok(envelope("", loadFixture(t, "replicaset_team_a.json"))))
	srv := f.start()
	c := newTestClient(t, srv, []string{"team-a", "team-b"})

	cs, err := c.RunningContainers(context.Background())
	if err != nil {
		t.Fatalf("RunningContainers: %v", err)
	}

	byName := map[string]inventory.Workload{}
	for _, ct := range cs {
		byName[ct.Name] = ct.Workload
	}

	wantA := inventory.Workload{Kind: inventory.WorkloadDeployment, Group: "team-a", Name: "web-a-deploy"}
	const nameA = "team-a/web-a-abcde/web"
	if got, ok := byName[nameA]; !ok || got != wantA {
		t.Errorf("%s Workload = %+v (present=%v), want %+v", nameA, got, ok, wantA)
	}

	const nameB = "team-b/web-b-abcde/web"
	if got, ok := byName[nameB]; !ok || got != (inventory.Workload{}) {
		t.Errorf("%s Workload = %+v (present=%v), want the zero value: its owner reference UID names team-a's ReplicaSet, not one that actually lives in team-b", nameB, got, ok)
	}
}

// TestRunningContainers_SortDeterministic_AfterWorkloadResolution proves
// sortContainers' Workload.Name tiebreak is actually exercised on
// resolver-produced Workload values (sort_test.go's
// TestSortContainers_Deterministic only exercises the comparator against
// hand-built inventory.Container values, never against resolveWorkload's
// output).
//
// Both pods share the same image identity and the same namespace
// (Workload.Group), so only Workload.Name can decide their order. Crucially,
// the two pods' own names (and so their Container.Name, "<namespace>/<pod>/
// <container>") sort the *opposite* way from their StatefulSet's name: pod
// "zzz-pod-a" is owned by StatefulSet "aaa-sts", and pod "aaa-pod-b" is owned
// by StatefulSet "zzz-sts". A regression that skipped the Workload.Name tier
// and fell straight through to comparing Container.Name would therefore
// produce the wrong order here.
func TestRunningContainers_SortDeterministic_AfterWorkloadResolution(t *testing.T) {
	f := newFakeServer(t)
	f.on("/api/v1/nodes", ok(envelope("", loadFixture(t, "node_amd64.json"))))
	// Served b-first so the input order is the reverse of the expected
	// output order: a missing sortContainers call would preserve this order
	// and fail below, just like a comparator that skips the Workload tier.
	f.on("/api/v1/pods", ok(envelope("",
		loadFixture(t, "pod_sort_b.json"), // pod "aaa-pod-b", StatefulSet "zzz-sts", must sort second
		loadFixture(t, "pod_sort_a.json"), // pod "zzz-pod-a", StatefulSet "aaa-sts", must sort first
	)))
	srv := f.start()
	c := newTestClient(t, srv, nil)

	cs, err := c.RunningContainers(context.Background())
	if err != nil {
		t.Fatalf("RunningContainers: %v", err)
	}
	if len(cs) != 2 {
		t.Fatalf("got %d containers, want 2", len(cs))
	}
	if cs[0].Image.Ref != cs[1].Image.Ref || cs[0].Image.Registry.Digest.Hex != cs[1].Image.Registry.Digest.Hex {
		t.Fatalf("test setup broken: both pods must share the same image identity so only the Workload tier decides order, got %+v and %+v", cs[0].Image, cs[1].Image)
	}
	if cs[0].Workload.Group != cs[1].Workload.Group {
		t.Fatalf("test setup broken: both pods must share the same namespace so only Workload.Name decides order, got %+v and %+v", cs[0].Workload, cs[1].Workload)
	}
	if cs[0].Name < cs[1].Name {
		t.Fatalf("test setup broken: the pods' own names must sort opposite to their Workload.Name, or this test can't distinguish a comparator that skips the Workload tier from a correct one; got Container.Name order [%q, %q]", cs[0].Name, cs[1].Name)
	}
	if cs[0].Workload.Name != "aaa-sts" || cs[1].Workload.Name != "zzz-sts" {
		t.Errorf("Workload.Name order = [%q, %q], want [\"aaa-sts\", \"zzz-sts\"]: sortContainers must order by Workload.Name, not by Container.Name, once Image and Workload.Group are tied", cs[0].Workload.Name, cs[1].Workload.Name)
	}
}
