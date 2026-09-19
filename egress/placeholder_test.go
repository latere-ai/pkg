// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package egress

import (
	"testing"

	"latere.ai/x/pkg/egress/placeholder"
)

// The gateway's MintPlaceholder and IsPlaceholder are the subpackage's Mint
// and Is; the shape and entropy tests live there. This pins that a
// placeholder minted through either import substitutes end to end.
func TestPlaceholder_DelegatesToSubpackage(t *testing.T) {
	p := MintPlaceholder()
	if !placeholder.Is(p) || !IsPlaceholder(placeholder.Mint()) {
		t.Fatalf("egress and placeholder disagree on %q", p)
	}
	if PlaceholderPrefix != placeholder.Prefix {
		t.Fatalf("prefix %q != %q", PlaceholderPrefix, placeholder.Prefix)
	}
}

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
