// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package egress

import "testing"

func TestRebuildMap_JoinsByName(t *testing.T) {
	phA := MintPlaceholder()
	phB := MintPlaceholder()
	placeholders := map[string]string{"A": phA, "B": phB}
	secrets := map[string]CredSecret{
		"A": {Secret: []byte("sk-a"), Hosts: []string{"api.a.example"}},
		"B": {Secret: []byte("sk-b"), Hosts: []string{"api.b.example"}},
	}
	entries := RebuildMap(placeholders, secrets)
	if len(entries) != 2 {
		t.Fatalf("want 2 entries, got %d", len(entries))
	}
	// The exact live placeholder is preserved (not re-minted), so a request from
	// the workload matches.
	byPh := map[string]IngestEntry{}
	for _, e := range entries {
		byPh[e.Placeholder] = e
	}
	if _, ok := byPh[phA]; !ok {
		t.Errorf("entry must carry the workload's live placeholder %q", phA)
	}
}

func TestRebuildMap_SkipsUnmatchedOrBadPlaceholders(t *testing.T) {
	ph := MintPlaceholder()
	placeholders := map[string]string{
		"A":    ph,                  // matched
		"B":    MintPlaceholder(),   // no secret → skipped
		"junk": "not-a-placeholder", // not a cph_ token → skipped
		"C":    "",                  // empty → skipped
	}
	secrets := map[string]CredSecret{"A": {Secret: []byte("s"), Hosts: []string{"h"}}}
	entries := RebuildMap(placeholders, secrets)
	if len(entries) != 1 || entries[0].Placeholder != ph {
		t.Fatalf("only the matched real placeholder should survive, got %+v", entries)
	}
}

func TestRebuildMap_Empty(t *testing.T) {
	if got := RebuildMap(nil, nil); len(got) != 0 {
		t.Fatalf("empty inputs → no entries, got %v", got)
	}
}
