package cache

import "sync"

// Lazy is a single-value memo: it computes a value on first read, serves the
// cached result to every later read, and recomputes only after Invalidate.
//
// It is the degenerate case of [TTLCache] — one key, no expiry — and shares
// nothing with it but the package name. Reach for Lazy when a value is
// expensive to compute, read on a hot path, and invalidated by an explicit
// event rather than by the clock: a parsed configuration field, a resolved
// host capability. Reach for TTLCache when entries are keyed or should age out
// on their own.
//
// [sync.OnceValue] covers the load-once half of this and is the better choice
// when the value never changes. Lazy exists for the half OnceValue cannot
// express, which is invalidation.
//
// The zero value is not usable; construct with [NewLazy].
type Lazy[T any] struct {
	mu    sync.Mutex
	val   T
	valid bool
	load  func() T
}

// NewLazy returns a Lazy that calls load to compute the value on first access
// and after each Invalidate.
func NewLazy[T any](load func() T) *Lazy[T] {
	return &Lazy[T]{load: load}
}

// Get returns the cached value, calling load if the cache is invalid.
// Concurrent callers serialize on the mutex, so only the first invokes load
// and the rest see its result. load runs while the mutex is held: a load that
// calls back into Get on the same Lazy deadlocks.
func (v *Lazy[T]) Get() T {
	v.mu.Lock()
	defer v.mu.Unlock()
	if !v.valid {
		v.val = v.load()
		v.valid = true
	}
	return v.val
}

// Invalidate drops the cached value so the next Get re-runs load. The stored
// value is zeroed rather than merely marked stale, so a pointer the cache held
// does not keep its referent alive until the next Get.
func (v *Lazy[T]) Invalidate() {
	var zero T
	v.mu.Lock()
	v.val = zero
	v.valid = false
	v.mu.Unlock()
}
