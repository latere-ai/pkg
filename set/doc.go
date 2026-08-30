// Package set provides a generic unordered set backed by a map.
//
// [Set] offers Add, Has, and Len over a map[T]struct{}, which is the shape this
// replaces at each call site that tracks unique items and tests membership.
//
// # Usage
//
//	s := set.New("a", "b", "c")
//	s.Add("d")
//	if s.Has("a") { ... }
package set
