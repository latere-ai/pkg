// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package dag

import (
	"cmp"
	"errors"
	"slices"
	"testing"
)

// assertTopo checks the ordering invariant: for every edge a→b, a comes
// before b, and every node appears exactly once.
func assertTopo[K comparable](t *testing.T, adj map[K][]K, order []K) {
	t.Helper()
	pos := make(map[K]int, len(order))
	for i, n := range order {
		if _, dup := pos[n]; dup {
			t.Fatalf("node %v appears twice in %v", n, order)
		}
		pos[n] = i
	}
	for from, tos := range adj {
		if _, ok := pos[from]; !ok {
			t.Fatalf("node %v missing from %v", from, order)
		}
		for _, to := range tos {
			if _, ok := pos[to]; !ok {
				t.Fatalf("edge target %v missing from %v", to, order)
			}
			if pos[from] >= pos[to] {
				t.Fatalf("edge %v→%v violated in %v", from, to, order)
			}
		}
	}
}

func TestTopoSort(t *testing.T) {
	tests := []struct {
		name string
		adj  map[string][]string
		want []string // exact expected order, or nil to check only the invariant
	}{
		{"empty", map[string][]string{}, []string{}},
		{"single", map[string][]string{"a": nil}, []string{"a"}},
		{"linear", map[string][]string{"a": {"b"}, "b": {"c"}, "c": nil}, []string{"a", "b", "c"}},
		{"linear reversed keys", map[string][]string{"c": {"b"}, "b": {"a"}}, []string{"c", "b", "a"}},
		{"diamond", map[string][]string{"a": {"b", "c"}, "b": {"d"}, "c": {"d"}}, []string{"a", "b", "c", "d"}},
		{"disconnected sorted by key", map[string][]string{"z": nil, "m": nil, "a": nil}, []string{"a", "m", "z"}},
		{"target absent from keys", map[string][]string{"a": {"x"}}, []string{"a", "x"}},
		{"tie-break prefers smaller ready node", map[string][]string{"b": {"a"}, "c": nil}, []string{"b", "a", "c"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := TopoSort(tc.adj)
			if err != nil {
				t.Fatalf("TopoSort: %v", err)
			}
			assertTopo(t, tc.adj, got)
			if tc.want != nil && !slices.Equal(got, tc.want) {
				t.Errorf("order = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestTopoSort_IsDeterministic(t *testing.T) {
	adj := map[string][]string{"r": {"e", "d", "c", "b", "a"}}
	first, _ := TopoSort(adj)
	for range 50 {
		got, _ := TopoSort(adj)
		if !slices.Equal(got, first) {
			t.Fatalf("order varied: %v vs %v", got, first)
		}
	}
	if want := []string{"r", "a", "b", "c", "d", "e"}; !slices.Equal(first, want) {
		t.Errorf("order = %v, want %v", first, want)
	}
}

func TestTopoSort_Cycle(t *testing.T) {
	tests := []struct {
		name        string
		adj         map[string][]string
		wantOrdered []string // nodes that are still orderable, in order
	}{
		{"self loop", map[string][]string{"a": {"a"}}, []string{}},
		{"two cycle", map[string][]string{"a": {"b"}, "b": {"a"}}, []string{}},
		{"cycle with upstream and downstream", map[string][]string{
			"root": {"a"}, "a": {"b"}, "b": {"a", "c"}, "c": nil, "free": nil,
		}, []string{"free", "root"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := TopoSort(tc.adj)
			if !errors.Is(err, ErrCycle) {
				t.Fatalf("err = %v, want ErrCycle", err)
			}
			if !slices.Equal(got, tc.wantOrdered) {
				t.Errorf("partial order = %v, want %v", got, tc.wantOrdered)
			}
		})
	}
}

func TestTopoSortFunc_IntKeysWithCustomOrder(t *testing.T) {
	adj := map[int][]int{0: {2}, 1: nil, 2: nil}
	// Descending tie-break: 1 is ready with 0 at the start and must come first.
	got, err := TopoSortFunc(adj, func(a, b int) int { return cmp.Compare(b, a) })
	if err != nil {
		t.Fatal(err)
	}
	assertTopo(t, adj, got)
	if want := []int{1, 0, 2}; !slices.Equal(got, want) {
		t.Errorf("order = %v, want %v", got, want)
	}
}

func TestLongestPath(t *testing.T) {
	tests := []struct {
		name  string
		adj   map[string][]string
		start string
		want  int
	}{
		{"leaf", map[string][]string{"a": nil}, "a", 1},
		{"absent node", map[string][]string{}, "ghost", 1},
		{"linear from head", map[string][]string{"a": {"b"}, "b": {"c"}}, "a", 3},
		{"linear from middle", map[string][]string{"a": {"b"}, "b": {"c"}}, "b", 2},
		{"diamond", map[string][]string{"a": {"b", "c"}, "b": {"d"}, "c": {"d"}}, "a", 3},
		{"branches of unequal length", map[string][]string{"a": {"b", "c"}, "b": {"d"}}, "a", 3},
		{"shared suffix memoised", map[string][]string{
			"a": {"b", "c"}, "b": {"x"}, "c": {"x"}, "x": {"y"}, "y": {"z"},
		}, "a", 5},
		{"self loop ignored", map[string][]string{"a": {"a"}}, "a", 1},
		{"two cycle terminates", map[string][]string{"a": {"b"}, "b": {"a"}}, "a", 2},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := LongestPath(tc.adj, tc.start); got != tc.want {
				t.Errorf("LongestPath(%s) = %d, want %d", tc.start, got, tc.want)
			}
		})
	}
}

func TestLongestPath_AgreesWithTopoOrderDP(t *testing.T) {
	// A wider DAG: the memoised DFS must match a reference DP over the
	// topological order for every node.
	adj := map[int][]int{
		1: {2, 3}, 2: {4}, 3: {4, 5}, 4: {6}, 5: {6}, 6: {7}, 7: nil, 8: {3},
	}
	order, err := TopoSort(adj)
	if err != nil {
		t.Fatal(err)
	}
	ref := make(map[int]int)
	for _, n := range slices.Backward(order) {
		best := 0
		for _, next := range adj[n] {
			best = max(best, ref[next])
		}
		ref[n] = 1 + best
	}
	for n, want := range ref {
		if got := LongestPath(adj, n); got != want {
			t.Errorf("LongestPath(%d) = %d, want %d", n, got, want)
		}
	}
}
