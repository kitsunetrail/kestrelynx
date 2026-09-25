package pkgdb

import "testing"

func TestTotalBudget_Clamp(t *testing.T) {
	cases := []struct {
		name        string
		max, n      int64
		perFile     int64
		wantClamped int64
	}{
		{"unbounded (max<=0) returns perFile untouched", 0, 0, 5, 5},
		{"plenty remaining, perFile is the smaller one", 100, 0, 5, 5},
		{"remaining is the smaller one", 10, 8, 5, 2},
		{"already exhausted", 10, 10, 5, 0},
		{"already over budget", 10, 12, 5, 0},
		{"unbounded perFile (<=0), remaining wins", 10, 4, 0, 6},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := &totalBudget{max: tc.max, n: tc.n}
			if got := b.clamp(tc.perFile); got != tc.wantClamped {
				t.Errorf("clamp(%d) = %d, want %d", tc.perFile, got, tc.wantClamped)
			}
		})
	}
}

func TestTotalBudget_ExceededAfterAdd(t *testing.T) {
	b := &totalBudget{max: 10}
	if b.exceeded() {
		t.Error("exceeded() = true before any bytes were added")
	}
	b.add(10)
	if b.exceeded() {
		t.Error("exceeded() = true at exactly the limit, want false")
	}
	b.add(1)
	if !b.exceeded() {
		t.Error("exceeded() = false one byte over the limit, want true")
	}
}

func TestTotalBudget_UnboundedNeverExceeded(t *testing.T) {
	b := &totalBudget{max: 0}
	b.add(1 << 40)
	if b.exceeded() {
		t.Error("exceeded() = true for an unbounded (max<=0) budget")
	}
}
