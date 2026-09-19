// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package placeholder

import (
	"errors"
	"strings"
	"testing"
)

func isTokenChar(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '_' || b == '-'
}

func TestMint_ShapeAndEntropy(t *testing.T) {
	seen := map[string]struct{}{}
	for i := range 1000 {
		p := Mint()
		if !strings.HasPrefix(p, Prefix) {
			t.Fatalf("missing prefix: %q", p)
		}
		if !Is(p) {
			t.Fatalf("Is false for freshly minted %q", p)
		}
		if len(p) != len(Prefix)+32 {
			t.Fatalf("width %d, want %d: %q", len(p), len(Prefix)+32, p)
		}
		// Every char must be a token char so the substitution engine's
		// whole-token match treats the placeholder as one token.
		for j := range len(p) {
			if !isTokenChar(p[j]) {
				t.Fatalf("non-token char %q in placeholder %q", p[j], p)
			}
		}
		if _, dup := seen[p]; dup {
			t.Fatalf("collision after %d mints: %q", i, p)
		}
		seen[p] = struct{}{}
	}
}

// A failing entropy source must never yield a low-entropy placeholder.
func TestMint_PanicsWithoutEntropy(t *testing.T) {
	prev := randRead
	randRead = func([]byte) (int, error) { return 0, errors.New("no entropy") }
	t.Cleanup(func() { randRead = prev })
	defer func() {
		if recover() == nil {
			t.Fatal("Mint must panic when crypto/rand fails")
		}
	}()
	Mint()
}

func TestIs(t *testing.T) {
	if good := Mint(); !Is(good) {
		t.Fatalf("minted placeholder should pass: %q", good)
	}
	for _, bad := range []string{
		"",
		"sk-real",
		Prefix,
		Prefix + "tooshort",
		Prefix + strings.Repeat("a", 33),
		"CPH_" + strings.Repeat("a", 32),
	} {
		if Is(bad) {
			t.Errorf("Is(%q) = true, want false", bad)
		}
	}
}

func FuzzIs(f *testing.F) {
	f.Add("")
	f.Add(Prefix)
	f.Add(Mint())
	f.Fuzz(func(t *testing.T, s string) {
		if Is(s) && (!strings.HasPrefix(s, Prefix) || len(s) != len(Prefix)+32) {
			t.Fatalf("Is accepted a malformed value %q", s)
		}
	})
}
