package imagefs

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"unsafe"
)

func TestSummarizeGzipAndPlainAgree(t *testing.T) {
	plain := tarOf(t, dir("./opt/"), file("./opt/jdk/release", releaseTemurin21), sym("/opt/j", "jdk"), hard("opt/jdk/release2", "opt/jdk/release"))
	a, idA, err := Summarize(bytes.NewReader(plain), Limits{})
	if err != nil {
		t.Fatal(err)
	}
	b, idB, err := Summarize(bytes.NewReader(gzipOf(plain)), Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if idA != digestOf(plain) || idB != idA {
		t.Errorf("diffIDs %s %s, want the sha256 of the tar %s", idA, idB, digestOf(plain))
	}
	if len(a.Entries) != 4 || len(a.Entries) != len(b.Entries) {
		t.Fatalf("entries %d / %d", len(a.Entries), len(b.Entries))
	}
	got := a.Entries[1]
	if got.Path != "opt/jdk/release" || got.Type != TypeFile || !got.HasContent || got.Content != releaseTemurin21 {
		t.Errorf("release entry %+v", got)
	}
	if e := a.Entries[2]; e.Path != "opt/j" || e.Type != TypeSymlink || e.Link != "jdk" {
		t.Errorf("symlink entry %+v", e)
	}
	if e := a.Entries[0]; e.Path != "opt" || e.Type != TypeDir {
		t.Errorf("dir entry %+v", e)
	}
}

func TestSummarizeRejectsOtherCompressions(t *testing.T) {
	for name, head := range map[string][]byte{
		"zstd":  {0x28, 0xb5, 0x2f, 0xfd, 0x04, 0x58, 0, 0, 0},
		"xz":    {0xfd, '7', 'z', 'X', 'Z', 0x00, 1, 2},
		"bzip2": []byte("BZh91AY&SY"),
	} {
		_, _, err := Summarize(bytes.NewReader(head), Limits{})
		if !errors.Is(err, ErrUnsupportedCompression) {
			t.Errorf("%s: err = %v, want ErrUnsupportedCompression", name, err)
		}
	}
}

func TestSummarizeCorrupt(t *testing.T) {
	junk := bytes.Repeat([]byte("not a tar header "), 100)
	if _, _, err := Summarize(bytes.NewReader(junk), Limits{}); !errors.Is(err, ErrCorruptLayer) {
		t.Errorf("junk: err = %v, want ErrCorruptLayer", err)
	}
	bad := append([]byte{0x1f, 0x8b}, bytes.Repeat([]byte{0xff}, 20)...)
	if _, _, err := Summarize(bytes.NewReader(bad), Limits{}); err == nil {
		t.Error("broken gzip accepted")
	}
}

func TestSummarizeReleaseRules(t *testing.T) {
	big := strings.Repeat("x", 16<<10+1)
	exact := strings.Repeat("y", 16<<10)
	sum, _, err := Summarize(bytes.NewReader(tarOf(t,
		file("a/release", releaseTemurin21),
		file("b/release", big),
		file("c/release", exact),
		hard("d/release", "a/release"), // readable: the target is a kept release
		hard("e/release", "a/other"),   // the target is not a release
		file("a/other", "x"),
		hard("f/release", "b/release"), // the target is too large to be kept
		hard("g/release", "missing/release"),
		sym("h/release", "../a/release"),
	)), Limits{})
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]Entry{}
	for _, e := range sum.Entries {
		by[e.Path] = e
	}
	if e := by["a/release"]; !e.HasContent || e.Content != releaseTemurin21 || e.Big {
		t.Errorf("a: %+v", e)
	}
	if e := by["b/release"]; !e.Big || e.HasContent {
		t.Errorf("b: big file kept or not marked: Big=%v HasContent=%v", e.Big, e.HasContent)
	}
	if e := by["c/release"]; !e.HasContent || len(e.Content) != 16<<10 {
		t.Errorf("c: a file of exactly 16 KiB must be kept")
	}
	if e := by["d/release"]; e.Type != TypeHardlink || !e.HasContent || e.Content != releaseTemurin21 || e.Unreadable {
		t.Errorf("d: %+v", e)
	}
	for _, p := range []string{"e/release", "f/release", "g/release"} {
		if e := by[p]; !e.Unreadable || e.HasContent {
			t.Errorf("%s: %+v, want unreadable", p, e)
		}
	}
	if e := by["h/release"]; e.Type != TypeSymlink || e.Link != "../a/release" {
		t.Errorf("h: %+v", e)
	}
}

func TestSummarizeWhiteoutsAndNormalization(t *testing.T) {
	sum, _, err := Summarize(bytes.NewReader(tarOf(t,
		wh("var/cache", "old"),
		opaque("opt/app"),
		wh(".", "top"),
		file("../../etc/./passwd", "x"),
		file(".wh..wh.plnk", ""), // aufs bookkeeping is not a whiteout
	)), Limits{})
	if err != nil {
		t.Fatal(err)
	}
	want := []Entry{
		{Path: "var/cache/old", Type: TypeWhiteout},
		{Path: "opt/app", Type: TypeOpaque},
		{Path: "top", Type: TypeWhiteout},
		{Path: "etc/passwd", Type: TypeFile},
	}
	if len(sum.Entries) != len(want) {
		t.Fatalf("entries %+v", sum.Entries)
	}
	for i, w := range want {
		if sum.Entries[i] != w {
			t.Errorf("entry %d = %+v, want %+v", i, sum.Entries[i], w)
		}
	}
}

func TestSummarizeLimits(t *testing.T) {
	many := []fe{}
	for i := 0; i < 20; i++ {
		many = append(many, file("dir/file-with-a-long-enough-name-"+string(rune('a'+i)), ""))
	}
	layer := tarOf(t, many...)
	if _, _, err := Summarize(bytes.NewReader(layer), Limits{MaxEntries: 10}); !errors.Is(err, ErrSummaryLimit) {
		t.Errorf("entries: err = %v", err)
	}
	if _, _, err := Summarize(bytes.NewReader(layer), Limits{MaxSummaryBytes: 200}); !errors.Is(err, ErrSummaryLimit) {
		t.Errorf("summary bytes: err = %v", err)
	}
	if _, _, err := Summarize(bytes.NewReader(gzipOf(layer)), Limits{MaxLayerBytes: 2048}); !errors.Is(err, ErrLayerTooLarge) {
		t.Errorf("layer size: err = %v", err)
	}
	if _, _, err := Summarize(bytes.NewReader(layer), Limits{}); err != nil {
		t.Errorf("within limits: %v", err)
	}
}

func TestSummarizeEmptyLayers(t *testing.T) {
	for name, b := range map[string][]byte{"no bytes": nil, "end marker only": tarOf(t)} {
		sum, id, err := Summarize(bytes.NewReader(b), Limits{})
		if err != nil || len(sum.Entries) != 0 || id != digestOf(b) {
			t.Errorf("%s: %v %v %s", name, sum, err, id)
		}
	}
}

// The diffID covers the stream to its very end, past the tar end marker.
func TestSummarizeDiffIDCoversTrailingBytes(t *testing.T) {
	b := append(tarOf(t, file("a", "x")), bytes.Repeat([]byte{0}, 4096)...)
	_, id, err := Summarize(bytes.NewReader(b), Limits{})
	if err != nil || id != digestOf(b) {
		t.Errorf("id %s err %v, want %s", id, err, digestOf(b))
	}
}

func TestDetachSharesNoMemory(t *testing.T) {
	big := strings.Repeat("a", 1<<20) + "/b"
	cut := big[len(big)-2:]
	own := detach(cut)
	if own != cut {
		t.Fatalf("content changed: %q", own)
	}
	if unsafe.StringData(own) == unsafe.StringData(cut) {
		t.Error("the copy shares memory with the string it was cut from")
	}
	if detach("") != "" {
		t.Error("empty")
	}
}

// Through the real Summarize: whatever the strings of an entry are cut from,
// the summary stores copies of its own.
func TestSummarizeStoresDetachedStrings(t *testing.T) {
	big := strings.Repeat("a", 1<<20) + "/tail"
	inside := func(s string) bool {
		if s == "" {
			return false
		}
		start := uintptr(unsafe.Pointer(unsafe.StringData(big)))
		p := uintptr(unsafe.Pointer(unsafe.StringData(s)))
		return p >= start && p < start+uintptr(len(big))
	}
	defer func() { beforeDetach = nil }()
	beforeDetach = func(e *Entry) {
		e.Path = big[len(big)-5:]
		if e.Type == TypeSymlink {
			e.Link = big[len(big)-4:]
		}
	}
	raw := tarOf(t, file("x/y", "1"), sym("l", "target"))
	sum, _, err := Summarize(bytes.NewReader(raw), Limits{})
	if err != nil || len(sum.Entries) != 2 {
		t.Fatalf("%+v %v", sum, err)
	}
	for _, e := range sum.Entries {
		if e.Path != "/tail" || inside(e.Path) {
			t.Errorf("path %q is not an independent copy", e.Path)
		}
	}
	if l := sum.Entries[1].Link; l != "tail" || inside(l) {
		t.Errorf("link %q is not an independent copy", l)
	}
}
