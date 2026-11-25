package imagefs

import (
	"errors"
	"io"
	"sync"
	"time"
)

// Defaults of Limits.
const (
	DefaultRegistryBytesPerCycle = 2 << 30
	DefaultDockerBytesPerCycle   = 8 << 30
	DefaultMaxLayerBytes         = 4 << 30
	DefaultImageTimeout          = 10 * time.Minute
	DefaultMaxSummaryBytes       = 32 << 20
	DefaultMaxEntries            = 500000
	DefaultMaxReleaseBytes       = 16 << 10
	DefaultMaxJSONBytes          = 4 << 20
)

// Limits bound what a read may cost. A zero field selects its default. The
// values are part of the key of a "cannot complete" record: a record made
// under other limits is not used.
type Limits struct {
	// RegistryBytesPerCycle and DockerBytesPerCycle are the sizes of the
	// budgets of one cycle (see NewBudget): compressed bytes from registries,
	// bytes of the Docker export stream.
	RegistryBytesPerCycle int64 `json:"registry_bytes_per_cycle"`
	DockerBytesPerCycle   int64 `json:"docker_bytes_per_cycle"`
	// MaxLayerBytes caps the decompressed size of one layer.
	MaxLayerBytes int64 `json:"max_layer_bytes"`
	// ImageTimeout is the time one image may take.
	ImageTimeout time.Duration `json:"image_timeout"`
	// MaxSummaryBytes and MaxEntries cap one layer's summary.
	MaxSummaryBytes int64 `json:"max_summary_bytes"`
	MaxEntries      int   `json:"max_entries"`
	// MaxReleaseBytes is the largest release file whose content is kept.
	MaxReleaseBytes int64 `json:"max_release_bytes"`
	// MaxJSONBytes is the largest JSON blob kept from a Docker export.
	MaxJSONBytes int64 `json:"max_json_bytes"`
}

func (l Limits) withDefaults() Limits {
	def := func(v *int64, d int64) {
		if *v <= 0 {
			*v = d
		}
	}
	def(&l.RegistryBytesPerCycle, DefaultRegistryBytesPerCycle)
	def(&l.DockerBytesPerCycle, DefaultDockerBytesPerCycle)
	def(&l.MaxLayerBytes, DefaultMaxLayerBytes)
	def(&l.MaxSummaryBytes, DefaultMaxSummaryBytes)
	def(&l.MaxReleaseBytes, DefaultMaxReleaseBytes)
	def(&l.MaxJSONBytes, DefaultMaxJSONBytes)
	if l.ImageTimeout <= 0 {
		l.ImageTimeout = DefaultImageTimeout
	}
	if l.MaxEntries <= 0 {
		l.MaxEntries = DefaultMaxEntries
	}
	return l
}

// DefaultLimits returns the default limits.
func DefaultLimits() Limits { return Limits{}.withDefaults() }

// Budget holds the bytes a cycle may still read, from registries and from
// Docker, shared by every Read of the cycle. A cycle makes a new one.
type Budget struct {
	mu                      sync.Mutex
	regTotal, regLeft       int64
	dockerTotal, dockerLeft int64
}

// NewBudget returns a budget of the sizes the limits give.
func NewBudget(l Limits) *Budget {
	l = l.withDefaults()
	return &Budget{regTotal: l.RegistryBytesPerCycle, regLeft: l.RegistryBytesPerCycle,
		dockerTotal: l.DockerBytesPerCycle, dockerLeft: l.DockerBytesPerCycle}
}

// RegistryLeft and DockerLeft are the bytes still available.
func (b *Budget) RegistryLeft() int64 { return b.left(&b.regLeft) }
func (b *Budget) DockerLeft() int64   { return b.left(&b.dockerLeft) }

func (b *Budget) left(p *int64) int64 {
	if b == nil {
		return 1 << 62
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return *p
}

// take consumes up to n bytes of *p and returns how many it consumed.
func (b *Budget) take(p *int64, n int64) int64 {
	if b == nil {
		return n
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if n > *p {
		n = *p
	}
	*p -= n
	return n
}

var errBudget = errors.New("imagefs: cycle budget used up")

// budgetReader passes bytes through and charges them to a budget; when the
// budget cannot cover what was read it fails with errBudget.
type budgetReader struct {
	r    io.Reader
	b    *Budget
	left func(b *Budget) *int64
	read int64 // bytes charged through this reader
}

func (r *budgetReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	if n > 0 {
		var got int64
		if r.b == nil {
			got = int64(n)
		} else {
			got = r.b.take(r.left(r.b), int64(n))
		}
		r.read += got
		if got < int64(n) {
			return int(got), errBudget
		}
	}
	return n, err
}

func registryLeft(b *Budget) *int64 { return &b.regLeft }
func dockerLeft(b *Budget) *int64   { return &b.dockerLeft }
