package sensor

import (
	"os"
	"testing"
)

func TestScanProcs_FindsSelf(t *testing.T) {
	res, err := scanProcs()
	if err != nil {
		t.Fatalf("scanProcs: %v", err)
	}
	self, ok := res.Procs[os.Getpid()]
	if !ok {
		t.Fatalf("scanProcs did not find this process's own pid %d among %d entries", os.Getpid(), len(res.Procs))
	}
	if self.PID != os.Getpid() {
		t.Errorf("PID = %d, want %d", self.PID, os.Getpid())
	}
	if self.Starttime <= 0 {
		t.Errorf("Starttime = %d, want > 0", self.Starttime)
	}
}

func TestMatchesExcludedID(t *testing.T) {
	id := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"[:64]
	cases := []struct {
		prefix string
		want   bool
	}{
		{"abcdef012345", true},    // exactly 12 hex chars, matches
		{"abcdef012345678", true}, // longer prefix, still matches
		{"abcdef012346", false},   // 12 chars but does not match
		{"abcdef01234", false},    // 11 chars: too short to count at all
		{"", false},
	}
	for _, c := range cases {
		got := matchesExcludedID(id, []string{c.prefix})
		if got != c.want {
			t.Errorf("matchesExcludedID(%q, [%q]) = %v, want %v", id, c.prefix, got, c.want)
		}
	}
}

func TestGroupContainers_ExcludesSelfAndExcludeIDs(t *testing.T) {
	procs := map[int]procInfo{
		1: {PID: 1, PPID: 0, Starttime: 1, ContainerID: strings64('a')},
		2: {PID: 2, PPID: 1, Starttime: 2, ContainerID: strings64('a')},
		3: {PID: 3, PPID: 0, Starttime: 1, ContainerID: strings64('b')},
		4: {PID: 4, PPID: 0, Starttime: 1, ContainerID: strings64('c')},
		5: {PID: 5, PPID: 0, Starttime: 1, ContainerID: ""}, // not in any container
	}
	groups := groupContainers(procs, strings64('b'), []string{strings64('c')[:12]})
	if _, ok := groups[strings64('b')]; ok {
		t.Errorf("own container %q was not excluded", strings64('b'))
	}
	if _, ok := groups[strings64('c')]; ok {
		t.Errorf("excluded container %q was not excluded", strings64('c'))
	}
	g, ok := groups[strings64('a')]
	if !ok {
		t.Fatalf("container %q missing from groups", strings64('a'))
	}
	if len(g.Processes) != 2 {
		t.Errorf("container %q has %d pids, want 2", strings64('a'), len(g.Processes))
	}
}

func TestFindInit_PicksProcessWhoseParentIsOutsideContainer(t *testing.T) {
	// pid 100 is the container's init (its parent, 1, is outside the
	// container); pid 101 is a child of 100 (inside the container) with an
	// earlier starttime than 100 — findInit must not be fooled by that into
	// picking 101.
	procs := map[int]procInfo{
		1:   {PID: 1, PPID: 0, Starttime: 0, ContainerID: ""},
		100: {PID: 100, PPID: 1, Starttime: 50, ContainerID: "c"},
		101: {PID: 101, PPID: 100, Starttime: 10, ContainerID: "c"},
	}
	got := findInit(procs, "c", []int{100, 101})
	if got.PID != 100 {
		t.Errorf("findInit picked pid %d, want 100", got.PID)
	}
}

func TestFindInit_FallsBackToEarliestWhenNoStrictCandidate(t *testing.T) {
	// Every process's parent happens to also be in the group (a snapshot
	// read mid-churn) — findInit must still return something, the earliest
	// starttime among the group, rather than a zero value.
	procs := map[int]procInfo{
		200: {PID: 200, PPID: 201, Starttime: 20, ContainerID: "c"},
		201: {PID: 201, PPID: 200, Starttime: 10, ContainerID: "c"},
	}
	got := findInit(procs, "c", []int{200, 201})
	if got.PID != 201 {
		t.Errorf("findInit fallback picked pid %d, want 201 (earliest starttime)", got.PID)
	}
}

// strings64 returns a 64-hex-character string made of the given byte
// repeated, standing in for a container ID in these tests.
func strings64(b byte) string {
	buf := make([]byte, 64)
	for i := range buf {
		buf[i] = b
	}
	return string(buf)
}
