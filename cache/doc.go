// Package cache provides a thread-safe in-memory TTL cache with optional
// bounded LRU eviction, plus [Lazy] for the single-value case.
//
// [TTLCache] supports generic key-value storage with per-entry expiration,
// permanent entries that bypass TTL, and an optional maximum size that evicts
// the least recently used entries when exceeded. A pluggable clock interface
// enables deterministic testing without real time delays.
//
// [Lazy] holds one value instead of a keyed set: it computes on first read and
// recomputes only after an explicit Invalidate, with no clock involved.
//
// # Usage
//
//	c := cache.New[string, []byte](5 * time.Minute)
//	c.Set("key", data)
//	if val, ok := c.Get("key"); ok { ... }
//	c.Invalidate("key")
//
//	v := cache.NewLazy(func() int { return expensiveCompute() })
//	n := v.Get()
//	v.Invalidate()
package cache
