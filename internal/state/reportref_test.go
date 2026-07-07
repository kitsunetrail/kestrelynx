package state

import (
	"path/filepath"
	"testing"
)

func TestReportRef_ValidFor(t *testing.T) {
	ref := &ReportRef{Channel: "C1", TS: "1.2", Permalink: "https://x/p12"}
	cases := []struct {
		name string
		ref  *ReportRef
		ch   string
		want bool
	}{
		{"valid", ref, "C1", true},
		{"nil ref", nil, "C1", false},
		{"channel moved", ref, "C2", false},
		{"no permalink", &ReportRef{Channel: "C1", TS: "1.2"}, "C1", false},
		{"no ts", &ReportRef{Channel: "C1", Permalink: "https://x/p12"}, "C1", false},
	}
	for _, tc := range cases {
		if got := tc.ref.ValidFor(tc.ch); got != tc.want {
			t.Errorf("%s: ValidFor(%q) = %v, want %v", tc.name, tc.ch, got, tc.want)
		}
	}
}

func TestFileStore_RoundTripsLastFullReport(t *testing.T) {
	store := FileStore{Path: filepath.Join(t.TempDir(), "state.json")}
	st := empty()
	st.LastFullReport = &ReportRef{Channel: "C1", TS: "1.2", Permalink: "https://x/p12"}
	if err := store.Save(st); err != nil {
		t.Fatalf("Save: %v", err)
	}
	loaded, err := store.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.LastFullReport == nil || *loaded.LastFullReport != *st.LastFullReport {
		t.Errorf("LastFullReport = %+v, want %+v", loaded.LastFullReport, st.LastFullReport)
	}
}

func TestState_FirstSeen(t *testing.T) {
	st := empty()
	st.Findings[key("img:1", "pkg")] = Entry{FirstSeen: day1}
	if got, ok := st.FirstSeen("img:1", "pkg"); !ok || !got.Equal(day1) {
		t.Errorf("FirstSeen = %v, %v; want %v, true", got, ok, day1)
	}
	if _, ok := st.FirstSeen("img:1", "other"); ok {
		t.Error("unknown finding must report ok=false")
	}
}
