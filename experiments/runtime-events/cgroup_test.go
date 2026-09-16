package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestContainerIDOf checks the directory names a container's own control
// group takes, and that names which merely contain hexadecimal are not
// mistaken for one.
func TestContainerIDOf(t *testing.T) {
	const id = "eb2e2dff3cfa6c0d60ed97ef902110848927aeaea702cb54e8f5813f5122c1ab"
	tests := []struct {
		name string
		want string
	}{
		{"docker-" + id + ".scope", id},
		{id, id},
		{"system.slice", ""},
		{"user.slice", ""},
		{"init.scope", ""},
		{"docker-short.scope", ""},
		{"deadbeef", ""},
	}
	for _, tt := range tests {
		if got := containerIDOf(tt.name); got != tt.want {
			t.Errorf("containerIDOf(%q) = %q, want %q", tt.name, got, tt.want)
		}
	}
}

// buildFakeHierarchy writes a directory tree shaped like a control group
// hierarchy, including a container placed under a parent of the
// deployment's own choosing and a group the workload created inside it.
func buildFakeHierarchy(t *testing.T, containerID string) string {
	t.Helper()
	root := t.TempDir()
	for _, dir := range []string{
		"system.slice",
		"custom.slice/docker-" + containerID + ".scope",
		"custom.slice/docker-" + containerID + ".scope/worker/inner",
		"user.slice",
	} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// TestBuildCgroupTableFollowsCustomParentsAndChildGroups checks that a
// container placed under a parent of the deployment's choosing is still
// found, and that a group the workload created inside the container is
// attributed to that container with the distance recorded rather than
// flattened away.
func TestBuildCgroupTableFollowsCustomParentsAndChildGroups(t *testing.T) {
	const id = "eb2e2dff3cfa6c0d60ed97ef902110848927aeaea702cb54e8f5813f5122c1ab"
	root := buildFakeHierarchy(t, id)
	table := buildCgroupTable(root)

	byPath := map[string]CgroupEntry{}
	for _, e := range table.Entries {
		byPath[e.Path] = e
	}
	scope := filepath.Join(root, "custom.slice", "docker-"+id+".scope")
	if got := byPath[scope]; got.ContainerID != id || got.Depth != 0 {
		t.Errorf("container's own group: container %q depth %d, want %q/0", got.ContainerID, got.Depth, id)
	}
	worker := filepath.Join(scope, "worker")
	if got := byPath[worker]; got.ContainerID != id || got.Depth != 1 {
		t.Errorf("group one level inside the container: container %q depth %d, want %q/1", got.ContainerID, got.Depth, id)
	}
	inner := filepath.Join(worker, "inner")
	if got := byPath[inner]; got.ContainerID != id || got.Depth != 2 {
		t.Errorf("group two levels inside the container: container %q depth %d, want %q/2", got.ContainerID, got.Depth, id)
	}
	if got := byPath[filepath.Join(root, "system.slice")]; got.ContainerID != "" {
		t.Errorf("a slice belonging to no container was credited to %q", got.ContainerID)
	}
}

// TestMergeClosesAnEntryWhenItsGroupIsReplaced checks that a control group
// identifier which comes to mean a different container has its old
// meaning closed at the moment the change was found, so an event from
// before that moment still resolves to the container that existed then and
// one from after does not inherit it.
func TestMergeClosesAnEntryWhenItsGroupIsReplaced(t *testing.T) {
	t0 := time.Date(2026, 9, 13, 10, 0, 0, 0, time.UTC)
	t1 := t0.Add(time.Minute)
	first := CgroupTable{
		GeneratedAt: t0, Snapshots: 1, UpdatedAt: []time.Time{t0},
		Entries: []CgroupEntry{{CgroupID: 100, Path: "/cg/app", ContainerID: "aaa", FirstSeen: t0, LastSeen: t0, Generation: 1}},
	}
	second := CgroupTable{
		GeneratedAt: t1, Snapshots: 1, UpdatedAt: []time.Time{t1},
		Entries: []CgroupEntry{{CgroupID: 200, Path: "/cg/app", ContainerID: "bbb", FirstSeen: t1, LastSeen: t1, Generation: 1}},
	}
	merged := mergeCgroupTable(first, second)
	if merged.Snapshots != 2 {
		t.Errorf("Snapshots = %d, want 2", merged.Snapshots)
	}
	if len(merged.Entries) != 2 {
		t.Fatalf("got %d entries, want both the closed one and its replacement", len(merged.Entries))
	}
	lookup := newCgroupLookup(merged)
	if id, _, ok := lookup.lookup(100, t0.Add(30*time.Second)); !ok || id != "aaa" {
		t.Errorf("an event from while the first container existed resolved to %q (ok=%v), want aaa", id, ok)
	}
	if _, _, ok := lookup.lookup(100, t1.Add(30*time.Second)); ok {
		t.Error("an identifier whose entry was closed still resolves after the close; the replacement would inherit its predecessor's events")
	}
	if id, _, ok := lookup.lookup(200, t1.Add(30*time.Second)); !ok || id != "bbb" {
		t.Errorf("the replacement resolved to %q (ok=%v), want bbb", id, ok)
	}
}

// TestLookupRefusesUnknownIdentifiers checks that an identifier the table
// does not carry resolves to nothing, rather than to the host or to
// whichever entry is nearest.
func TestLookupRefusesUnknownIdentifiers(t *testing.T) {
	now := time.Date(2026, 9, 13, 10, 0, 0, 0, time.UTC)
	lookup := newCgroupLookup(CgroupTable{Entries: []CgroupEntry{
		{CgroupID: 1, Path: "/cg/a", ContainerID: "aaa", FirstSeen: now},
	}})
	if _, _, ok := lookup.lookup(999, now); ok {
		t.Error("an unknown control group was attributed to something")
	}
	if _, _, ok := lookup.lookup(1, now.Add(-time.Hour)); ok {
		t.Error("an event from before the entry existed was attributed to it")
	}
}

// TestCgroupIdentifierMatchesTheDirectoryInode checks, against the real
// hierarchy on this host, the premise the table rests on: that a control
// group's identifier is its directory's inode number. If it does not hold
// here, the identifiers read through the kernel's own file handles are the
// ones to use, and the table says so rather than silently mixing the two.
func TestCgroupIdentifierMatchesTheDirectoryInode(t *testing.T) {
	if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err != nil {
		t.Skip("no unified control group hierarchy on this host")
	}
	table := buildCgroupTable("/sys/fs/cgroup")
	if len(table.Entries) == 0 {
		t.Skip("the control group hierarchy could not be read")
	}
	checked := 0
	for _, e := range table.Entries {
		if e.IDAgreement == "unchecked" {
			continue
		}
		checked++
		if e.IDAgreement == "disagree" {
			t.Logf("identifier and inode differ for %s: handle %d, inode %d", e.Path, e.HandleID, e.Inode)
		}
	}
	if checked == 0 {
		t.Skip("no control group's identifier could be read through a file handle")
	}
	if table.Calibration != "agree" && table.Calibration != "disagree" {
		t.Errorf("Calibration = %q after checking %d group(s), want a definite result", table.Calibration, checked)
	}
	t.Logf("calibration over %d control group(s): %s", checked, table.Calibration)
}
