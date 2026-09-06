// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package egress

import (
	"errors"
	"strings"
	"testing"
)

func TestMintPlaceholder_ShapeAndEntropy(t *testing.T) {
	seen := map[string]struct{}{}
	for i := range 1000 {
		p := MintPlaceholder()
		if !strings.HasPrefix(p, PlaceholderPrefix) {
			t.Fatalf("missing prefix: %q", p)
		}
		if !IsPlaceholder(p) {
			t.Fatalf("IsPlaceholder false for freshly minted %q", p)
		}
		// Every char must be a token char so the engine's whole-token match
		// treats the placeholder as one token.
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
func TestMintPlaceholder_PanicsWithoutEntropy(t *testing.T) {
	prev := randRead
	randRead = func([]byte) (int, error) { return 0, errors.New("no entropy") }
	t.Cleanup(func() { randRead = prev })
	defer func() {
		if recover() == nil {
			t.Fatal("MintPlaceholder must panic when crypto/rand fails")
		}
	}()
	MintPlaceholder()
}

func TestIsPlaceholder(t *testing.T) {
	good := MintPlaceholder()
	if !IsPlaceholder(good) {
		t.Fatalf("minted placeholder should pass: %q", good)
	}
	bad := []string{
		"",
		"sk-real",
		PlaceholderPrefix, // prefix only, wrong width
		PlaceholderPrefix + "tooshort",
		"CPH_" + strings.Repeat("a", 32), // wrong prefix case
	}
	for _, b := range bad {
		if IsPlaceholder(b) {
			t.Fatalf("IsPlaceholder should be false for %q", b)
		}
	}
}

// IsPlaceholder accepts exactly the prefix plus the minted token width, and
// never panics on arbitrary input.
func FuzzIsPlaceholder(f *testing.F) {
	f.Add(MintPlaceholder())
	f.Add(PlaceholderPrefix)
	f.Add("")
	f.Fuzz(func(t *testing.T, s string) {
		got := IsPlaceholder(s)
		want := strings.HasPrefix(s, PlaceholderPrefix) && len(s) == len(PlaceholderPrefix)+32
		if got != want {
			t.Fatalf("IsPlaceholder(%q) = %v want %v", s, got, want)
		}
	})
}

// A minted placeholder must round-trip through the substitution engine.
func TestMintPlaceholder_SubstitutesEndToEnd(t *testing.T) {
	ph := MintPlaceholder()
	m := NewMap([]Entry{{
		Placeholder:  []byte(ph),
		Secret:       []byte("sk-real"),
		AllowedHosts: []string{"api.provider.example"},
	}})
	v, ok := m.SubstituteValue("api.provider.example", "Bearer "+ph)
	if !ok {
		t.Fatal("minted placeholder did not substitute")
	}
	if v != "Bearer sk-real" {
		t.Fatalf("got %q", v)
	}
}
