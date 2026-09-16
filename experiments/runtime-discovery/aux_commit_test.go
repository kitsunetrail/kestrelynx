package main

import (
	"testing"
	"time"
)

// auxReading builds one layout reading as collectAuxForMountView would
// return it: a fingerprint of what was read, and the identity of the
// process it was read through.
func auxReading(generation, readStarttime string, at time.Time) AuxiliaryInputs {
	return AuxiliaryInputs{
		MountViewID: "mnt:[1]", AuxGeneration: generation,
		ReadThroughPID: 1, ReadThroughStarttime: readStarttime, ReadThroughMountView: "mnt:[1]",
		CollectedAt: at, FirstSeen: at, LastSeen: at,
		OwnedPaths: []OwnedPathEntry{{Path: "/usr/bin/curl", DBKind: "dpkg", Package: "curl", Version: "1"}},
	}
}

func usableReadings(rec *ContainerRecord) []AuxiliaryInputs {
	var out []AuxiliaryInputs
	for _, aux := range rec.AuxiliaryInputs {
		if !aux.Invalid {
			out = append(out, aux)
		}
	}
	return out
}

// TestAFailedRereadDoesNotUndoAnEarlierGoodOne is the sequence that lost a
// whole window's layout: a clean reading, then a reading of the same
// layout during which the process it was being read through went away,
// then another clean reading.
//
// The middle one is unusable — what it describes may belong to whatever
// replaced that process. The first one is not: it was taken cleanly, and
// nothing about the later failure says otherwise. Folding the middle
// reading into the first and then marking the first unusable took the
// clean reading down with it, and every sample it covered was left with no
// layout to resolve against.
func TestAFailedRereadDoesNotUndoAnEarlierGoodOne(t *testing.T) {
	rec := &ContainerRecord{}
	state := newContainerCollectState(true, defaultAuxLimits())
	t0 := time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC)

	// A clean reading.
	commitAux(rec, state, auxReading("layout-1", "555", t0), "s0", "")
	if got := len(usableReadings(rec)); got != 1 {
		t.Fatalf("after the first reading: %d usable, want 1", got)
	}

	// The same layout, read through a process that did not survive.
	commitAux(rec, state, auxReading("layout-1", "555", t0.Add(time.Minute)), "s1",
		"the mapping inputs were read through pid 1, whose process generation did not survive the sample")

	usable := usableReadings(rec)
	if len(usable) != 1 {
		t.Fatalf("after the failed re-read: %d usable reading(s), want the earlier clean one to survive", len(usable))
	}
	if usable[0].AuxGeneration != "layout-1" || usable[0].Invalid {
		t.Errorf("the surviving reading is %+v", usable[0])
	}
	if len(rec.AuxiliaryInputs) != 2 {
		t.Errorf("the failed reading was not kept as a record of the attempt: %d entries", len(rec.AuxiliaryInputs))
	}

	// A third, clean reading. It has to be saved and usable — not folded
	// into the failed one, and not lost because a failure came between.
	commitAux(rec, state, auxReading("layout-1", "555", t0.Add(2*time.Minute)), "s2", "")
	usable = usableReadings(rec)
	if len(usable) == 0 {
		t.Fatal("the third, clean reading produced nothing usable")
	}
	covered := map[string]bool{}
	for _, aux := range usable {
		for _, id := range aux.SampleIDs {
			covered[id] = true
		}
	}
	for _, id := range []string{"s0", "s2"} {
		if !covered[id] {
			t.Errorf("sample %s has no usable layout reading covering it", id)
		}
	}
	if covered["s1"] {
		t.Error("the sample whose reading failed is covered by a usable reading")
	}
}

// TestReadingsThroughDifferentGenerationsAreKeptApart checks that two
// readings of one layout taken through different process generations stay
// separate. They were taken through different views of the filesystem, and
// merging them would have one reading claim it was taken through the
// other's process.
func TestReadingsThroughDifferentGenerationsAreKeptApart(t *testing.T) {
	rec := &ContainerRecord{}
	state := newContainerCollectState(true, defaultAuxLimits())
	t0 := time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC)

	commitAux(rec, state, auxReading("layout-1", "555", t0), "s0", "")
	commitAux(rec, state, auxReading("layout-1", "999", t0.Add(time.Minute)), "s1", "")
	if got := len(usableReadings(rec)); got != 2 {
		t.Errorf("%d usable reading(s), want one per process generation", got)
	}

	// The same layout through the same generation extends the reading
	// already there rather than adding another.
	commitAux(rec, state, auxReading("layout-1", "555", t0.Add(2*time.Minute)), "s2", "")
	usable := usableReadings(rec)
	if len(usable) != 2 {
		t.Fatalf("%d usable reading(s), want the two generations", len(usable))
	}
	if len(usable[0].SampleIDs) != 2 {
		t.Errorf("the first reading covers %v, want both of its samples", usable[0].SampleIDs)
	}
}

// TestAnUnusableReadingIsNotOfferedToTheMatching checks the other half:
// what the matching side is handed never includes a reading whose source
// did not hold still.
func TestAnUnusableReadingIsNotOfferedToTheMatching(t *testing.T) {
	rec := &ContainerRecord{
		CollectionResults: []CollectionResult{{SampleID: "s0"}, {SampleID: "s1"}},
	}
	state := newContainerCollectState(true, defaultAuxLimits())
	t0 := time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC)
	commitAux(rec, state, auxReading("layout-1", "555", t0), "s0", "")
	commitAux(rec, state, auxReading("layout-2", "999", t0.Add(time.Minute)), "s1", "the process did not survive")

	wv := computeWindowValidity(rec)
	offered := auxForWindow(rec, wv)
	if len(offered) != 1 {
		t.Fatalf("%d reading(s) offered to the matching, want only the usable one", len(offered))
	}
	if offered[0].AuxGeneration != "layout-1" {
		t.Errorf("the reading offered is %q, want the one taken cleanly", offered[0].AuxGeneration)
	}
}
