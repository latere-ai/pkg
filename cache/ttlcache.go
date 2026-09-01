package cache

import (
	"container/list"
	"sync"
	"time"
)

// entry holds a cached value along with its expiration metadata.
type entry[V any] struct {
	value     V
	permanent bool          // permanent entries never expire by TTL
	expiresAt time.Time     // zero for permanent entries
	elem      *list.Element // position in the LRU list; the element holds the key
}

// TTLCache is a generic thread-safe key-value cache with per-entry
// expiration. Entries stored with [TTLCache.Set] expire after the default
// TTL; entries stored with [TTLCache.SetPermanent] never expire by TTL. Both
// kinds count against MaxSize when it is set, and the least recently used
// entry of either kind is evicted when the cap is exceeded. A Get promotes
// the entry to most recently used.
type TTLCache[K comparable, V any] struct {
	mu         sync.Mutex
	entries    map[K]entry[V]
	lru        *list.List // front = least recently used, back = most recently used
	defaultTTL time.Duration
	maxSize    int // max entries of any kind (0 = unlimited)
	now        func() time.Time
}

// sweepThreshold is the entry-count high-water mark above which Set
// opportunistically reclaims expired non-permanent entries. Below it the
// map is small enough that lazy eviction on Get is sufficient.
const sweepThreshold = 256

// sweepBudget caps how many entries a single Set scans for expiry, so the
// hot insert path stays O(1) amortized rather than O(n) per call.
const sweepBudget = 8

// Option configures a [TTLCache].
type Option[K comparable, V any] func(*TTLCache[K, V])

// WithClock sets an injectable time source (default: time.Now).
func WithClock[K comparable, V any](now func() time.Time) Option[K, V] {
	return func(c *TTLCache[K, V]) { c.now = now }
}

// WithMaxSize caps the number of entries, TTL and permanent alike. When a
// store would exceed n, the least recently used entry is evicted first. 0
// means unlimited. A TTL cache keyed by caller-supplied values needs this
// cap: without it every distinct key holds a map slot until it is read
// again or the sweep reaches it.
func WithMaxSize[K comparable, V any](n int) Option[K, V] {
	return func(c *TTLCache[K, V]) { c.maxSize = n }
}

// New creates a TTLCache with the given default TTL and options.
func New[K comparable, V any](defaultTTL time.Duration, opts ...Option[K, V]) *TTLCache[K, V] {
	c := &TTLCache[K, V]{
		entries:    make(map[K]entry[V]),
		lru:        list.New(),
		defaultTTL: defaultTTL,
		now:        time.Now,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// Get returns the value and true if the key exists and has not expired. An
// expired entry is removed on access. A hit promotes the entry to most
// recently used.
func (c *TTLCache[K, V]) Get(key K) (V, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok {
		var zero V
		return zero, false
	}
	if !e.permanent && c.now().After(e.expiresAt) {
		c.removeLocked(key, e)
		var zero V
		return zero, false
	}
	c.lru.MoveToBack(e.elem)
	return e.value, true
}

// Set stores a value with the cache's default TTL. Storing over a permanent
// key makes it a TTL entry.
func (c *TTLCache[K, V]) Set(key K, value V) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sweepExpiredLocked()
	c.putLocked(key, entry[V]{value: value, expiresAt: c.now().Add(c.defaultTTL)})
}

// SetPermanent stores a value that never expires by TTL. It still counts
// against MaxSize and can be evicted as least recently used.
func (c *TTLCache[K, V]) SetPermanent(key K, value V) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.putLocked(key, entry[V]{value: value, permanent: true})
}

// putLocked stores e under key, reusing the key's LRU position when it is
// already present and evicting the least recently used entry when the cap
// is exceeded. The caller must hold c.mu.
func (c *TTLCache[K, V]) putLocked(key K, e entry[V]) {
	if old, ok := c.entries[key]; ok {
		e.elem = old.elem
		c.lru.MoveToBack(e.elem)
	} else {
		e.elem = c.lru.PushBack(key)
	}
	c.entries[key] = e
	if c.maxSize > 0 && c.lru.Len() > c.maxSize {
		front := c.lru.Front()
		// The list holds keys and nothing else; PushBack above is the only writer.
		evict := front.Value.(K) //nolint:errcheck // the LRU list holds keys only
		c.removeLocked(evict, c.entries[evict])
	}
}

// removeLocked drops key from the map and the LRU list. The caller must hold
// c.mu.
func (c *TTLCache[K, V]) removeLocked(key K, e entry[V]) {
	c.lru.Remove(e.elem)
	delete(c.entries, key)
}

// sweepExpiredLocked opportunistically reclaims expired non-permanent entries
// so their map slots do not leak when the same key is never read again. It is
// bounded: it does nothing until the map exceeds sweepThreshold, and it scans
// at most sweepBudget entries per call, keeping the insert path O(1) amortized.
// Permanent and live entries are left untouched. The caller must hold c.mu.
func (c *TTLCache[K, V]) sweepExpiredLocked() {
	if len(c.entries) <= sweepThreshold {
		return
	}
	now := c.now()
	scanned := 0
	for k, e := range c.entries {
		if scanned >= sweepBudget {
			break
		}
		scanned++
		if !e.permanent && now.After(e.expiresAt) {
			c.removeLocked(k, e)
		}
	}
}

// Len returns the current number of entries (both live and not-yet-reclaimed
// expired non-permanent entries). Intended for tests and diagnostics.
func (c *TTLCache[K, V]) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

// Invalidate removes an entry regardless of its TTL or permanence.
func (c *TTLCache[K, V]) Invalidate(key K) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.entries[key]; ok {
		c.removeLocked(key, e)
	}
}
