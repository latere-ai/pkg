// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// Package dag provides generic operations on directed acyclic graphs
// represented as adjacency lists.
package dag

import (
	"cmp"
	"errors"
	"slices"
)

// ReverseEdges inverts all edges in an adjacency list.
// For every edge a→b in adj, the result contains b→a.
func ReverseEdges[K comparable](adj map[K][]K) map[K][]K {
	rev := make(map[K][]K)
	for from, tos := range adj {
		for _, to := range tos {
			rev[to] = append(rev[to], from)
		}
		// Ensure every node appears as a key even if it has no reverse edges.
		if _, ok := rev[from]; !ok {
			rev[from] = nil
		}
	}
	return rev
}

// DetectCycles finds all cycles in a directed graph using DFS with coloring.
// Returns a slice of cycles, where each cycle is an ordered path that loops
// back to its start (e.g., [A, B, C, A]).
func DetectCycles[K comparable](adj map[K][]K) [][]K {
	type color int
	const (
		white color = iota
		gray
		black
	)

	colors := make(map[K]color)
	parent := make(map[K]K)
	var cycles [][]K

	var dfs func(node K)
	dfs = func(node K) {
		colors[node] = gray
		for _, next := range adj[node] {
			switch colors[next] {
			case white:
				parent[next] = node
				dfs(next)
			case gray:
				// Back edge — cycle found. Reconstruct path.
				cycle := []K{next, node}
				cur := node
				for cur != next {
					cur = parent[cur]
					cycle = append(cycle, cur)
				}
				slices.Reverse(cycle)
				cycles = append(cycles, cycle)
			}
		}
		colors[node] = black
	}

	for node := range adj {
		if colors[node] == white {
			dfs(node)
		}
	}
	return cycles
}

// Reachable returns the set of all nodes transitively reachable from start
// via BFS through adj. The start node itself is not included in the result.
func Reachable[K comparable](adj map[K][]K, start K) map[K]bool {
	visited := map[K]bool{start: true}
	queue := []K{start}
	result := make(map[K]bool)

	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, next := range adj[cur] {
			if visited[next] {
				continue
			}
			visited[next] = true
			result[next] = true
			queue = append(queue, next)
		}
	}
	return result
}

// ErrCycle is returned by [TopoSort] and [TopoSortFunc] when adj contains a
// cycle.
var ErrCycle = errors.New("dag: cycle")

// TopoSort returns the nodes of adj in an order where every edge a→b has a
// before b. The node set is every key in adj plus every edge target. Among
// nodes ready at the same step, the smallest is emitted first, so the order
// is a function of the input alone.
//
// On a cycle the result holds every node that could be ordered and err is
// [ErrCycle]. The nodes absent from the result lie on or downstream of a
// cycle; [DetectCycles] names the cycles themselves.
func TopoSort[K cmp.Ordered](adj map[K][]K) ([]K, error) {
	return TopoSortFunc(adj, cmp.Compare[K])
}

// TopoSortFunc is [TopoSort] for a key type without a natural order. compare
// breaks ties among nodes ready at the same step; it must be a strict weak
// ordering, as for [slices.SortFunc].
func TopoSortFunc[K comparable](adj map[K][]K, compare func(a, b K) int) ([]K, error) {
	indeg := make(map[K]int, len(adj))
	for from, tos := range adj {
		if _, ok := indeg[from]; !ok {
			indeg[from] = 0
		}
		for _, to := range tos {
			indeg[to]++
		}
	}

	ready := make([]K, 0, len(indeg))
	for node, d := range indeg {
		if d == 0 {
			ready = append(ready, node)
		}
	}
	slices.SortFunc(ready, compare)

	order := make([]K, 0, len(indeg))
	for len(ready) > 0 {
		cur := ready[0]
		ready = ready[1:]
		order = append(order, cur)
		for _, next := range adj[cur] {
			indeg[next]--
			if indeg[next] == 0 {
				i, _ := slices.BinarySearchFunc(ready, next, compare)
				ready = slices.Insert(ready, i, next)
			}
		}
	}
	if len(order) != len(indeg) {
		return order, ErrCycle
	}
	return order, nil
}

// LongestPath returns the number of nodes on the longest path that starts
// at start, following edges in adj. A node with no out-edges scores 1, so
// a→b→c scores 3 from a and 1 from c. A node absent from adj scores 1.
//
// adj is expected to be acyclic. On cyclic input an edge back to a node on
// the current path is ignored, so the call terminates, but the result may
// under-count. A caller with untrusted input runs [DetectCycles] first.
func LongestPath[K comparable](adj map[K][]K, start K) int {
	memo := make(map[K]int)
	onPath := make(map[K]bool)
	var visit func(K) int
	visit = func(node K) int {
		if v, ok := memo[node]; ok {
			return v
		}
		if onPath[node] {
			return 0
		}
		onPath[node] = true
		best := 0
		for _, next := range adj[node] {
			best = max(best, visit(next))
		}
		onPath[node] = false
		memo[node] = 1 + best
		return memo[node]
	}
	return visit(start)
}
