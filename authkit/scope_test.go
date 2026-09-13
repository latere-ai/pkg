// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package authkit

import (
	"reflect"
	"testing"
)

func TestSplitScopes(t *testing.T) {
	tests := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"   ", nil},
		{"a b c", []string{"a", "b", "c"}},
		{"a,b,c", []string{"a", "b", "c"}},
		{"a b a c b", []string{"a", "b", "c"}}, // dedup, order-preserving
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := SplitScopes(tt.in); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("SplitScopes(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func FuzzSplitScopes(f *testing.F) {
	f.Add("a b,c")
	f.Add("")
	f.Fuzz(func(t *testing.T, in string) {
		got := SplitScopes(in)
		seen := map[string]bool{}
		for _, s := range got {
			if s == "" || seen[s] {
				t.Fatalf("SplitScopes(%q) = %v: empty or duplicate element", in, got)
			}
			seen[s] = true
		}
	})
}
