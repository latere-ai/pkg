// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// Package uniq removes duplicates from a slice while keeping the first
// occurrence and the original order. [slices.Compact] removes adjacent
// duplicates only, and sorting first destroys an order the caller chose.
package uniq

import (
	"errors"
	"fmt"
	"strings"
)

// Of returns the elements of s without duplicates. The first occurrence of
// each value is kept and the order is preserved. The result is a new,
// never-nil slice.
func Of[T comparable](s []T) []T {
	return By(s, func(v T) T { return v })
}

// By returns the elements of s whose key has not been seen before. The
// first element for each key is kept and the order is preserved. The result
// is a new, never-nil slice.
func By[T any, K comparable](s []T, key func(T) K) []T {
	seen := make(map[K]struct{}, len(s))
	out := make([]T, 0, len(s))
	for _, v := range s {
		k := key(v)
		if _, dup := seen[k]; dup {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, v)
	}
	return out
}

// Strings trims each element, drops the empties, and removes duplicates
// with the first occurrence kept in place. It is [Normalized] with
// [strings.TrimSpace].
func Strings(s []string) []string {
	return Normalized(s, strings.TrimSpace)
}

// Normalized applies norm to each element, drops the elements norm made
// empty, and removes duplicates with the first occurrence kept in place. The
// result holds the normalised forms. It does not sort: a caller whose order
// is meaningful keeps it, and one that wants sorted output sorts the result.
func Normalized(s []string, norm func(string) string) []string {
	seen := make(map[string]struct{}, len(s))
	out := make([]string, 0, len(s))
	for _, raw := range s {
		v := norm(raw)
		if v == "" {
			continue
		}
		if _, dup := seen[v]; dup {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

// ErrDuplicate is the error [Merge] wraps when a key repeats.
var ErrDuplicate = errors.New("uniq: duplicate key")

// Merge returns base followed by extra, in order, when every key across
// both is unique. A repeated key, whether an element of extra shadowing one
// of base or a repeat within either slice, is an error wrapping
// [ErrDuplicate] and naming the key. Merge does not deduplicate: it is for a
// catalog where a collision is a mistake the caller must surface, such as a
// user-authored item shadowing a built-in one.
func Merge[T any, K comparable](base, extra []T, key func(T) K) ([]T, error) {
	seen := make(map[K]struct{}, len(base)+len(extra))
	out := make([]T, 0, len(base)+len(extra))
	for _, s := range [][]T{base, extra} {
		for _, v := range s {
			k := key(v)
			if _, dup := seen[k]; dup {
				return nil, fmt.Errorf("%w: %v", ErrDuplicate, k)
			}
			seen[k] = struct{}{}
			out = append(out, v)
		}
	}
	return out, nil
}
