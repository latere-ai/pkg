// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package egress

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
)

func staticResolver(secret string) func(context.Context) ([]byte, error) {
	return func(context.Context) ([]byte, error) { return []byte(secret), nil }
}

func TestNewMapStrict_ReportsDropped(t *testing.T) {
	m, dropped := NewMapStrict([]Entry{
		{Placeholder: ph(""), Secret: ph("S"), AllowedHosts: []string{"h"}},
		{Placeholder: ph("cph_nohost"), Secret: ph("S")},
		{Placeholder: ph("cph_cr"), Secret: ph("a\rb"), AllowedHosts: []string{"h"}},
		{Placeholder: ph("cph_lf"), Secret: ph("a\nb"), AllowedHosts: []string{"h"}},
		{Placeholder: ph("cph_ok"), Secret: ph("S"), AllowedHosts: []string{"h"}},
		// A resolver entry ignores Secret, so a line break there is not a
		// static-secret injection and is checked at resolve time instead.
		{Placeholder: ph("cph_dyn"), Secret: ph("x\ny"), AllowedHosts: []string{"h"}, Resolve: staticResolver("t")},
	})
	if len(m.entries) != 2 {
		t.Fatalf("usable entries = %d, want 2", len(m.entries))
	}
	want := []struct {
		idx int
		ph  string
		err error
	}{
		{0, "", ErrEmptyPlaceholder},
		{1, "cph_nohost", ErrNoAllowedHosts},
		{2, "cph_cr", ErrSecretLineBreak},
		{3, "cph_lf", ErrSecretLineBreak},
	}
	if len(dropped) != len(want) {
		t.Fatalf("dropped = %v", dropped)
	}
	for i, w := range want {
		d := dropped[i]
		if d.Index != w.idx || d.Placeholder != w.ph || !errors.Is(d, w.err) {
			t.Errorf("dropped[%d] = %+v, want %+v", i, d, w)
		}
		if !strings.Contains(d.Error(), w.err.Error()) {
			t.Errorf("Error() = %q lacks reason", d.Error())
		}
	}
	// NewMap keeps its shape and drops the same entries silently.
	if got := len(NewMap(nil).entries); got != 0 {
		t.Errorf("NewMap(nil) entries = %d", got)
	}
	if _, dropped := NewMapStrict([]Entry{{Placeholder: ph("cph_ok"), Secret: ph("S"), AllowedHosts: []string{"h"}}}); dropped != nil {
		t.Errorf("clean input reported dropped = %v", dropped)
	}
}

func TestSubstituteValue_SkipsResolverEntries(t *testing.T) {
	m := mkMap(
		Entry{Placeholder: ph("cph_static"), Secret: ph("S"), AllowedHosts: []string{"h"}},
		Entry{Placeholder: ph("cph_dyn"), AllowedHosts: []string{"h"}, Resolve: staticResolver("T")},
	)
	got, ok := m.SubstituteValue("h", "cph_static cph_dyn")
	if !ok || got != "S cph_dyn" {
		t.Fatalf("SubstituteValue = %q, %v", got, ok)
	}
	got, ok = m.SubstituteValue("h", "cph_dyn")
	if ok || got != "cph_dyn" {
		t.Fatalf("resolver-only value must pass through: %q, %v", got, ok)
	}
}

func TestSubstituteValueContext_ResolvesAndScopes(t *testing.T) {
	var calls atomic.Int32
	m := mkMap(
		Entry{Placeholder: ph("cph_static"), Secret: ph("S"), AllowedHosts: []string{"h"}},
		Entry{Placeholder: ph("cph_dyn"), AllowedHosts: []string{"h"}, Resolve: func(context.Context) ([]byte, error) {
			calls.Add(1)
			return []byte("T"), nil
		}},
	)
	got, ok, err := m.SubstituteValueContext(context.Background(), "h", "Bearer cph_dyn cph_static")
	if err != nil || !ok || got != "Bearer T S" {
		t.Fatalf("got %q, %v, %v", got, ok, err)
	}
	// Out-of-scope host: the resolver is never consulted.
	got, ok, err = m.SubstituteValueContext(context.Background(), "other", "cph_dyn")
	if err != nil || ok || got != "cph_dyn" {
		t.Fatalf("out of scope: %q, %v, %v", got, ok, err)
	}
	// Placeholder absent: the resolver is never consulted.
	if _, _, err := m.SubstituteValueContext(context.Background(), "h", "cph_static"); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatalf("resolver calls = %d, want 1", calls.Load())
	}
}

func TestSubstituteValueContext_ErrorLeavesValueUnchanged(t *testing.T) {
	boom := errors.New("boom")
	m := mkMap(
		Entry{Placeholder: ph("cph_static"), Secret: ph("S"), AllowedHosts: []string{"h"}},
		Entry{Placeholder: ph("cph_dyn"), AllowedHosts: []string{"h"}, Resolve: func(context.Context) ([]byte, error) {
			return nil, boom
		}},
	)
	in := "cph_static cph_dyn"
	got, ok, err := m.SubstituteValueContext(context.Background(), "h", in)
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v", err)
	}
	if ok || got != in {
		t.Fatalf("value must be returned as given on error: %q, %v", got, ok)
	}
	if !strings.Contains(err.Error(), "cph_dyn") {
		t.Errorf("error should name the placeholder: %v", err)
	}
}

func TestSubstituteValueContext_ResolvedLineBreakRejected(t *testing.T) {
	m := mkMap(Entry{Placeholder: ph("cph_dyn"), AllowedHosts: []string{"h"}, Resolve: staticResolver("a\r\nInjected: x")})
	got, _, err := m.SubstituteValueContext(context.Background(), "h", "cph_dyn")
	if !errors.Is(err, ErrSecretLineBreak) {
		t.Fatalf("err = %v", err)
	}
	if got != "cph_dyn" {
		t.Fatalf("value = %q", got)
	}
}

func TestSubstituteValueContext_EmptyMapAndNoPrefix(t *testing.T) {
	got, ok, err := (&Map{}).SubstituteValueContext(context.Background(), "h", "cph_x")
	if err != nil || ok || got != "cph_x" {
		t.Fatal("empty map must be a no-op")
	}
	m := mkMap(Entry{Placeholder: ph("cph_x"), Secret: ph("S"), AllowedHosts: []string{"h"}})
	got, ok, err = m.SubstituteValueContext(context.Background(), "h", "plain")
	if err != nil || ok || got != "plain" {
		t.Fatal("value without prefix must be a no-op")
	}
}
