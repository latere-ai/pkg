// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package egress

import (
	"strconv"
	"sync"
	"testing"
)

func TestRegistry_SetGetDelete(t *testing.T) {
	r := NewRegistry()
	if r.Len() != 0 {
		t.Fatal("new registry should be empty")
	}
	// Unknown principal → empty non-nil map, found=false.
	m, found := r.Get("p-unknown")
	if found || m == nil || !m.Empty() {
		t.Fatalf("unknown: found=%v empty=%v", found, m.Empty())
	}

	r.Set("p-1", []Entry{{Placeholder: []byte("cph_x"), Secret: []byte("S"), AllowedHosts: []string{"h"}}})
	m, found = r.Get("p-1")
	if !found {
		t.Fatal("p-1 should be found")
	}
	if v, ok := m.SubstituteValue("h", "cph_x"); !ok || v != "S" {
		t.Fatalf("map not usable: %q %v", v, ok)
	}
	if r.Len() != 1 {
		t.Fatalf("len=%d", r.Len())
	}

	// Known-but-empty (no entries) is distinct from unknown.
	r.Set("p-2", nil)
	m, found = r.Get("p-2")
	if !found || !m.Empty() {
		t.Fatalf("p-2 should be found and empty: found=%v empty=%v", found, m.Empty())
	}

	r.Delete("p-1")
	if _, found := r.Get("p-1"); found {
		t.Fatal("p-1 should be gone after Delete")
	}
	r.Delete("p-missing") // no-op
}

func TestRegistry_Concurrent(t *testing.T) {
	r := NewRegistry()
	var wg sync.WaitGroup
	for i := range 50 {
		wg.Go(func() {
			id := "p-" + strconv.Itoa(i%8)
			r.Set(id, []Entry{{Placeholder: []byte("cph_x"), Secret: []byte("S"), AllowedHosts: []string{"h"}}})
			_, _ = r.Get(id)
			if i%3 == 0 {
				r.Delete(id)
			}
			_ = r.Len()
		})
	}
	wg.Wait()
}
