package registry

import "sync"

// Budget caps how many HTTP requests a client may send. The caller creates one
// per cycle and shares it; every request, including token requests and
// redirects, consumes one. A nil *Budget is unlimited.
type Budget struct {
	mu        sync.Mutex
	remaining int
	used      int
	reserved  int
}

// NewBudget returns a budget of n requests.
func NewBudget(n int) *Budget {
	if n < 0 {
		n = 0
	}
	return &Budget{remaining: n}
}

// Reserve keeps n requests for later work: until it is called again with 0,
// a request that finds n or fewer left is refused with ErrBudgetReserved
// and consumes nothing.
func (b *Budget) Reserve(n int) {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.reserved = max(n, 0)
}

// Reserved returns how many requests are kept for later work.
func (b *Budget) Reserved() int {
	if b == nil {
		return 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.reserved
}

// take consumes one request, or returns ErrBudgetExhausted, or
// ErrBudgetReserved when what is left is kept for later work.
func (b *Budget) take() error {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.remaining <= 0 {
		return ErrBudgetExhausted
	}
	if b.reserved > 0 && b.remaining <= b.reserved {
		return ErrBudgetReserved
	}
	b.remaining--
	b.used++
	return nil
}

// Used returns how many requests have been consumed.
func (b *Budget) Used() int {
	if b == nil {
		return 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.used
}

// Remaining returns how many requests are left.
func (b *Budget) Remaining() int {
	if b == nil {
		return -1
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.remaining
}
