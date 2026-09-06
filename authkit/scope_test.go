// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package authkit

import (
	"reflect"
	"testing"
)

func TestHasScope(t *testing.T) {
	const adminScope = "admin:sandbox"
	cases := []struct {
		name  string
		id    Identity
		want  string
		admin string
		ok    bool
	}{
		{"superadmin bypasses", Identity{IsSuperadmin: true}, "read:x", adminScope, true},
		{"exact match", Identity{Scopes: []string{"read:x"}}, "read:x", adminScope, true},
		{"admin implies other", Identity{Scopes: []string{adminScope}}, "write:x", adminScope, true},
		{"no match", Identity{Scopes: []string{"read:x"}}, "write:x", adminScope, false},
		{"empty identity", Identity{}, "read:x", adminScope, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := HasScope(tc.id, tc.want, tc.admin)
			if got != tc.ok {
				t.Fatalf("HasScope(%q, %q) = %v, want %v", tc.want, tc.admin, got, tc.ok)
			}
		})
	}
}

func TestHasScopeCustomAdmin(t *testing.T) {
	// Verify that the admin parameter is truly parameterized —
	// "admin:topos" implies "write:x" only when passed as admin, not as want.
	id := Identity{Scopes: []string{"admin:topos"}}
	if !HasScope(id, "write:x", "admin:topos") {
		t.Fatal("admin:topos should imply write:x when admin=admin:topos")
	}
	// But "admin:sandbox" does NOT imply "write:x" when admin is "admin:topos".
	id2 := Identity{Scopes: []string{"admin:sandbox"}}
	if HasScope(id2, "write:x", "admin:topos") {
		t.Fatal("admin:sandbox should NOT imply write:x when admin=admin:topos")
	}
}

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
