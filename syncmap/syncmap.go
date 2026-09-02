// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package syncmap

import (
	"iter"
	"sync"
)

// Map is a type-safe concurrent map. The zero value is ready to use.
type Map[K comparable, V any] struct {
	m sync.Map
}

// Store sets the value for a key.
func (m *Map[K, V]) Store(key K, val V) {
	m.m.Store(key, val)
}

// Load returns the value stored under key and whether it was found.
// Returns the zero value of V when the key is absent.
func (m *Map[K, V]) Load(key K) (V, bool) {
	v, ok := m.m.Load(key)
	if !ok {
		var zero V
		return zero, false
	}
	// Store is the only writer and takes a V, so this holds by construction.
	// A panic here would mean the invariant broke, which is worth hearing about.
	return v.(V), true //nolint:errcheck // Store is the only writer, and it takes a V
}

// Delete removes the entry for key.
// LoadOrStore returns the value stored under key, storing and returning val
// when the key is absent. loaded reports whether the value was already
// present. It is the primitive behind a per-key mutex: LoadOrStore(key,
// &sync.Mutex{}) hands every caller of the same key the same lock.
func (m *Map[K, V]) LoadOrStore(key K, val V) (actual V, loaded bool) {
	v, loaded := m.m.LoadOrStore(key, val)
	return v.(V), loaded //nolint:errcheck // Store and LoadOrStore are the only writers, and both take a V
}

func (m *Map[K, V]) Delete(key K) {
	m.m.Delete(key)
}

// All returns an iterator over all key-value pairs.
func (m *Map[K, V]) All() iter.Seq2[K, V] {
	return func(yield func(K, V) bool) {
		m.m.Range(func(k, v any) bool {
			// Same invariant as Load: only Store writes here, with typed arguments.
			return yield(k.(K), v.(V)) //nolint:errcheck // only Store writes, with a K and a V
		})
	}
}
