// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package egress

import "sync"

// Registry is the in-memory store of per-principal substitution maps. The
// control plane pushes a principal's map through the ingest API at create,
// start, and rotation; the egress path looks it up by principal on each
// request. The real secrets live only here, in memory, only for live
// principals: never on disk, never inside the workload. On restart the maps
// are empty until the control plane pushes again. Safe for concurrent use.
type Registry struct {
	mu   sync.RWMutex
	maps map[string]*Map
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{maps: make(map[string]*Map)}
}

// Set replaces the substitution map for a principal. Passing no entries
// stores an empty map (the principal is known but substitutes nothing), which
// is distinct from Delete (the principal is unknown). Entries are compiled
// once here.
func (r *Registry) Set(principal string, entries []Entry) {
	m := NewMap(entries)
	r.mu.Lock()
	r.maps[principal] = m
	r.mu.Unlock()
}

// Get returns the principal's map, or an empty (non-nil) map if the principal
// is unknown, so callers can always call SubstituteValue without a nil check.
// found reports whether the principal was actually registered, which the
// gateway uses to decide inspect-vs-passthrough before terminating TLS.
func (r *Registry) Get(principal string) (m *Map, found bool) {
	r.mu.RLock()
	m, found = r.maps[principal]
	r.mu.RUnlock()
	if !found {
		return &Map{}, false
	}
	return m, true
}

// Delete drops a principal's map. Missing principals are a no-op.
func (r *Registry) Delete(principal string) {
	r.mu.Lock()
	delete(r.maps, principal)
	r.mu.Unlock()
}

// Len reports how many principals are registered (for metrics and tests).
func (r *Registry) Len() int {
	r.mu.RLock()
	n := len(r.maps)
	r.mu.RUnlock()
	return n
}
