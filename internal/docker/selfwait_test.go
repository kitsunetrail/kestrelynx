package docker

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

var selfTestID = strings.Repeat("ab", 32)

func TestParseSelfContainerID(t *testing.T) {
	other := strings.Repeat("cd", 32)
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"hostname mount", "1234 1200 8:1 /var/lib/docker/containers/" + selfTestID + "/hostname /etc/hostname rw,relatime - ext4 /dev/sda1 rw\n", selfTestID},
		{"rootless data dir", "10 9 0:5 /home/u/.local/share/docker/containers/" + selfTestID + "/hostname /etc/hostname rw - ext4 /dev/sda1 rw\n", selfTestID},
		{"userns remap data dir", "10 9 0:5 /var/lib/docker/100000.100000/containers/" + selfTestID + "/resolv.conf /etc/resolv.conf rw - ext4 /dev/sda1 rw\n", selfTestID},
		{"hostname preferred over hosts", "1 0 0:1 /d/containers/" + other + "/hosts /etc/hosts rw - ext4 /dev/sda rw\n2 0 0:1 /d/containers/" + selfTestID + "/hostname /etc/hostname rw - ext4 /dev/sda rw\n", selfTestID},
		{"unrelated mount with id ignored", "1 0 0:1 /d/containers/" + other + "/hostname /data/other rw - ext4 /dev/sda rw\n", ""},
		{"no id", "1 0 0:1 / / rw - overlay overlay rw\n2 1 0:2 /hostname /etc/hostname rw - ext4 /dev/sda rw\n", ""},
		{"short id", "1 0 0:1 /d/containers/abcd/hostname /etc/hostname rw - ext4 /dev/sda rw\n", ""},
		{"malformed lines", "garbage\n\n1 2 3\n", ""},
		{"empty", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseSelfContainerID(tc.in); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// selfServer lists "other" only until the nth call (1-based), from which it
// also lists selfTestID. appearAt 0 means never.
func selfServer(t *testing.T, appearAt int32, calls *atomic.Int32) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		list := []rawContainer{{Id: strings.Repeat("cd", 32), Image: "other:1", Names: []string{"/other"}}}
		if appearAt > 0 && n >= appearAt {
			list = append(list, rawContainer{Id: selfTestID, Image: "self:1", Names: []string{"/self"}})
		}
		json.NewEncoder(w).Encode(list)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// fakeWait advances a fake clock instead of sleeping.
func fakeWait(slept *[]time.Duration) selfWait {
	var clock time.Time
	return selfWait{
		interval: 200 * time.Millisecond,
		limit:    5 * time.Second,
		sleep: func(ctx context.Context, d time.Duration) error {
			*slept = append(*slept, d)
			clock = clock.Add(d)
			if len(*slept) > 100 {
				return context.DeadlineExceeded
			}
			return nil
		},
		now: func() time.Time { return clock },
	}
}

func hasContainer(cs []string, id string) bool {
	for _, c := range cs {
		if c == id {
			return true
		}
	}
	return false
}

func ids(t *testing.T, c *Client) []string {
	t.Helper()
	cs, err := c.RunningContainers(context.Background())
	if err != nil {
		t.Fatalf("RunningContainers: %v", err)
	}
	var out []string
	for _, ct := range cs {
		out = append(out, ct.ID)
	}
	return out
}

func TestRunningContainers_WaitsForSelf(t *testing.T) {
	var calls atomic.Int32
	srv := selfServer(t, 3, &calls)
	c := newTestClient(srv)
	c.selfID = selfTestID
	var slept []time.Duration
	c.selfWait = fakeWait(&slept)

	got := ids(t, c)
	if !hasContainer(got, selfTestID) || len(got) != 2 {
		t.Errorf("got %v, want the list that contains self", got)
	}
	if calls.Load() != 3 || len(slept) != 2 {
		t.Errorf("calls=%d sleeps=%d, want 3 and 2", calls.Load(), len(slept))
	}
}

func TestRunningContainers_SelfNeverAppearsWarns(t *testing.T) {
	var calls atomic.Int32
	srv := selfServer(t, 0, &calls)
	c := newTestClient(srv)
	c.selfID = selfTestID
	var buf bytes.Buffer
	c.Log = slog.New(slog.NewTextHandler(&buf, nil))
	var slept []time.Duration
	w := fakeWait(&slept)
	// The fake sleep stops the wait once the fake clock reaches the limit.
	var clock time.Time
	w.now = func() time.Time { return clock }
	w.sleep = func(ctx context.Context, d time.Duration) error {
		slept = append(slept, d)
		clock = clock.Add(d)
		if clock.Sub(time.Time{}) >= w.limit {
			return context.DeadlineExceeded
		}
		return nil
	}
	c.selfWait = w

	got := ids(t, c)
	if hasContainer(got, selfTestID) || len(got) != 1 {
		t.Errorf("got %v, want the last list without self", got)
	}
	if calls.Load() != int32(len(slept)) {
		t.Errorf("calls=%d sleeps=%d", calls.Load(), len(slept))
	}
	if !strings.Contains(buf.String(), "level=WARN") || !strings.Contains(buf.String(), selfTestID[:12]) || !strings.Contains(buf.String(), "waited=5s") {
		t.Errorf("warning missing or incomplete: %s", buf.String())
	}
}

func TestRunningContainers_RealDeadlineBoundsWait(t *testing.T) {
	var calls atomic.Int32
	srv := selfServer(t, 0, &calls)
	c := newTestClient(srv)
	c.selfID = selfTestID
	c.Log = slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
	c.selfWait = defaultSelfWait()
	c.selfWait.limit = 120 * time.Millisecond
	c.selfWait.interval = 20 * time.Millisecond

	start := time.Now()
	got := ids(t, c)
	if el := time.Since(start); el > 2*time.Second {
		t.Errorf("wait took %v, want bounded near the limit", el)
	}
	if hasContainer(got, selfTestID) || calls.Load() < 2 {
		t.Errorf("got %v calls=%d", got, calls.Load())
	}
}

func TestRunningContainers_UnknownSelfDoesNotWait(t *testing.T) {
	var calls atomic.Int32
	srv := selfServer(t, 0, &calls)
	c := newTestClient(srv)
	var slept []time.Duration
	c.selfWait = fakeWait(&slept)
	ids(t, c)
	if calls.Load() != 1 || len(slept) != 0 {
		t.Errorf("calls=%d sleeps=%d, want 1 and 0", calls.Load(), len(slept))
	}
}

func TestRunningContainers_SecondCallDoesNotWait(t *testing.T) {
	var calls atomic.Int32
	srv := selfServer(t, 0, &calls)
	c := newTestClient(srv)
	c.selfID = selfTestID
	c.Log = slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
	var slept []time.Duration
	w := fakeWait(&slept)
	w.limit = 400 * time.Millisecond
	var clock time.Time
	w.now = func() time.Time { return clock }
	w.sleep = func(ctx context.Context, d time.Duration) error {
		slept = append(slept, d)
		clock = clock.Add(d)
		if clock.Sub(time.Time{}) >= w.limit {
			return context.DeadlineExceeded
		}
		return nil
	}
	c.selfWait = w

	ids(t, c)
	firstCalls, firstSleeps := calls.Load(), len(slept)
	ids(t, c)
	if calls.Load() != firstCalls+1 || len(slept) != firstSleeps {
		t.Errorf("second call: calls %d->%d sleeps %d->%d, want exactly one more call and no sleep",
			firstCalls, calls.Load(), firstSleeps, len(slept))
	}
}

// stallServer answers the calls numbered in stallOn only when the client
// gives up; the others list one container that is not self.
func stallServer(t *testing.T, stallOn map[int32]bool, calls *atomic.Int32) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if stallOn[calls.Add(1)] {
			<-r.Context().Done()
			return
		}
		json.NewEncoder(w).Encode([]rawContainer{{Id: strings.Repeat("cd", 32), Image: "other:1", Names: []string{"/other"}}})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func realTimeClient(srv *httptest.Server, limit time.Duration) (*Client, *bytes.Buffer) {
	c := newTestClient(srv)
	c.selfID = selfTestID
	var buf bytes.Buffer
	c.Log = slog.New(slog.NewTextHandler(&buf, nil))
	c.selfWait = defaultSelfWait()
	c.selfWait.limit = limit
	c.selfWait.interval = 10 * time.Millisecond
	return c, &buf
}

func TestRunningContainers_FirstCallStallsReturnsError(t *testing.T) {
	var calls atomic.Int32
	c, _ := realTimeClient(stallServer(t, map[int32]bool{1: true}, &calls), 150*time.Millisecond)
	start := time.Now()
	cs, err := c.RunningContainers(context.Background())
	if err == nil {
		t.Fatalf("want the listing error, got %v", cs)
	}
	if el := time.Since(start); el > 2*time.Second {
		t.Errorf("took %v, want bounded by the limit", el)
	}
	if calls.Load() != 1 {
		t.Errorf("calls = %d, want 1 (no re-call with the parent context)", calls.Load())
	}
}

func TestRunningContainers_RelistStallsReturnsLastListWithWarning(t *testing.T) {
	var calls atomic.Int32
	c, buf := realTimeClient(stallServer(t, map[int32]bool{2: true}, &calls), 150*time.Millisecond)
	start := time.Now()
	cs, err := c.RunningContainers(context.Background())
	if err != nil || len(cs) != 1 {
		t.Fatalf("got %v, %v; want the first list", cs, err)
	}
	if el := time.Since(start); el > 2*time.Second {
		t.Errorf("took %v, want bounded by the limit", el)
	}
	if !strings.Contains(buf.String(), "level=WARN") || !strings.Contains(buf.String(), selfTestID[:12]) {
		t.Errorf("warning missing: %s", buf.String())
	}
}

func TestRunningContainers_ParentCancelDuringWait(t *testing.T) {
	var calls atomic.Int32
	c, buf := realTimeClient(stallServer(t, map[int32]bool{2: true}, &calls), 10*time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(80*time.Millisecond, cancel)
	start := time.Now()
	if _, err := c.RunningContainers(ctx); err == nil {
		t.Fatal("want an error when the caller cancels")
	}
	if el := time.Since(start); el > 2*time.Second {
		t.Errorf("took %v after cancel", el)
	}
	if strings.Contains(buf.String(), "level=WARN") {
		t.Errorf("a cancelled call must not log the self-wait warning: %s", buf.String())
	}
}
