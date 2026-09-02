// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package authkit

import "testing"

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
