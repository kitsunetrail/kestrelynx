package ebpf

import (
	"errors"
	"testing"
)

// fakeCloser is a minimal io.Closer double for attachAllWith's generic T,
// which link.Link cannot fill in a test double (its isLink method is
// unexported, so nothing outside the link package can implement it).
type fakeCloser struct {
	name   string
	closed bool
}

func (f *fakeCloser) Close() error {
	f.closed = true
	return nil
}

func TestAttachAllWithUnwindsOnPartialFailure(t *testing.T) {
	points := []attachPoint{{name: "a"}, {name: "b"}, {name: "c"}, {name: "d"}}
	created := make([]*fakeCloser, 0, len(points))
	wantErr := errors.New("boom")

	_, err := attachAllWith(points, func(p attachPoint) (*fakeCloser, error) {
		if p.name == "c" {
			return nil, wantErr
		}
		c := &fakeCloser{name: p.name}
		created = append(created, c)
		return c, nil
	})

	if !errors.Is(err, wantErr) {
		t.Fatalf("attachAllWith error = %v, want it to wrap %v", err, wantErr)
	}
	if len(created) != 2 {
		t.Fatalf("attach func ran for %d points before failing, want 2 (a, b)", len(created))
	}
	for _, c := range created {
		if !c.closed {
			t.Errorf("attachPoint %q: Close was not called during unwind", c.name)
		}
	}
}

func TestAttachAllWithSucceeds(t *testing.T) {
	points := []attachPoint{{name: "a"}, {name: "b"}}

	got, err := attachAllWith(points, func(p attachPoint) (*fakeCloser, error) {
		return &fakeCloser{name: p.name}, nil
	})
	if err != nil {
		t.Fatalf("attachAllWith: %v", err)
	}
	if len(got) != len(points) {
		t.Fatalf("attachAllWith returned %d closers, want %d", len(got), len(points))
	}
	for _, c := range got {
		if c.closed {
			t.Errorf("attachPoint %q: Close was called even though attachAllWith succeeded", c.name)
		}
	}
}
