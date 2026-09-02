// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// Package cache provides a thread-safe in-memory TTL cache with optional
// bounded LRU eviction.
//
// [TTLCache] supports generic key-value storage with per-entry expiration,
// permanent entries that bypass TTL, and an optional maximum size that evicts
// the least recently used entries when exceeded. A pluggable clock interface
// enables deterministic testing without real time delays.
//
// # Usage
//
//	c := cache.New[string, []byte](5 * time.Minute)
//	c.Set("key", data)
//	if val, ok := c.Get("key"); ok { ... }
//	c.Invalidate("key")
package cache
