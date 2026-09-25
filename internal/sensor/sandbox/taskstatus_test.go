package sandbox

import "testing"

// TestAllCapsExclude covers the GuardedCaps check RunObserverSelfCheck
// relies on: it must catch a guarded capability bit in either CapEff or
// CapPrm, on any thread, and must not be fooled by other bits being set.
// This does not need a process that actually holds a capability (this
// sandboxed test environment has none to give it): the function under
// test only ever looks at the TaskStatus values it is handed, so synthetic
// ones exercise its logic directly.
func TestAllCapsExclude(t *testing.T) {
	const (
		capBPF     = 39 // matches unix.CAP_BPF
		capPerfmon = 38 // matches unix.CAP_PERFMON
		capOther   = 12 // some unrelated bit, must never trigger a match
	)
	guarded := maskFor([]uintptr{capBPF, capPerfmon})

	tests := []struct {
		name     string
		statuses []TaskStatus
		wantOK   bool
	}{
		{
			name:     "empty input",
			statuses: nil,
			wantOK:   true,
		},
		{
			name: "clean single thread",
			statuses: []TaskStatus{
				{TID: 1, CapEffective: 1 << capOther, CapPermitted: 1 << capOther},
			},
			wantOK: true,
		},
		{
			name: "guarded bit in CapEff",
			statuses: []TaskStatus{
				{TID: 1, CapEffective: 1 << capBPF},
			},
			wantOK: false,
		},
		{
			name: "guarded bit in CapPrm only (not CapEff)",
			statuses: []TaskStatus{
				{TID: 1, CapPermitted: 1 << capPerfmon},
			},
			wantOK: false,
		},
		{
			name: "second thread dirty, first clean",
			statuses: []TaskStatus{
				{TID: 1, CapEffective: 0, CapPermitted: 0},
				{TID: 2, CapEffective: 1 << capBPF, CapPermitted: 0},
			},
			wantOK: false,
		},
		{
			name: "unrelated bit set does not trigger",
			statuses: []TaskStatus{
				{TID: 1, CapEffective: 1 << capOther, CapPermitted: 1 << capOther},
			},
			wantOK: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ok, bad := AllCapsExclude(tc.statuses, guarded)
			if ok != tc.wantOK {
				t.Errorf("AllCapsExclude(%+v, %#x) ok = %v, want %v (offending: %+v)",
					tc.statuses, guarded, ok, tc.wantOK, bad)
			}
			if !tc.wantOK {
				if bad.CapEffective&guarded == 0 && bad.CapPermitted&guarded == 0 {
					t.Errorf("reported offending status %+v does not actually contain a guarded bit", bad)
				}
			}
		})
	}
}

// TestMaskFor confirms the capability-number-to-bitmask helper itself,
// since a mistake there would make TestAllCapsExclude's synthetic guarded
// mask meaningless.
func TestMaskFor(t *testing.T) {
	got := maskFor([]uintptr{0, 1, 39})
	want := uint64(1<<0 | 1<<1 | 1<<39)
	if got != want {
		t.Errorf("maskFor([0,1,39]) = %#x, want %#x", got, want)
	}
	if maskFor(nil) != 0 {
		t.Errorf("maskFor(nil) = %#x, want 0", maskFor(nil))
	}
}
