// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package uniq

import (
	"slices"
	"strings"
	"testing"
)

func TestOf(t *testing.T) {
	got := Of([]int{3, 1, 3, 2, 1})
	if !slices.Equal(got, []int{3, 1, 2}) {
		t.Fatalf("Of = %v", got)
	}
	if got := Of[string](nil); got == nil || len(got) != 0 {
		t.Fatalf("Of(nil) = %#v, want empty non-nil", got)
	}
}

func TestOfDoesNotAliasInput(t *testing.T) {
	in := []int{1, 2}
	out := Of(in)
	out[0] = 9
	if in[0] != 1 {
		t.Fatal("Of shares the input's backing array")
	}
}

func TestBy(t *testing.T) {
	type item struct{ ID, Name string }
	in := []item{{"a", "first"}, {"b", "second"}, {"a", "third"}}
	got := By(in, func(i item) string { return i.ID })
	want := []item{{"a", "first"}, {"b", "second"}}
	if !slices.Equal(got, want) {
		t.Fatalf("By = %v, want %v", got, want)
	}
}

func TestStrings(t *testing.T) {
	in := []string{" a ", "", "b", "a", "  ", "b ", "c"}
	got := Strings(in)
	if !slices.Equal(got, []string{"a", "b", "c"}) {
		t.Fatalf("Strings = %q", got)
	}
	if got := Strings(nil); got == nil || len(got) != 0 {
		t.Fatalf("Strings(nil) = %#v, want empty non-nil", got)
	}
}

func TestNormalizedKeepsNormalisedForm(t *testing.T) {
	in := []string{"Foo", " foo", "BAR", "bar", ""}
	got := Normalized(in, func(s string) string { return strings.ToLower(strings.TrimSpace(s)) })
	if !slices.Equal(got, []string{"foo", "bar"}) {
		t.Fatalf("Normalized = %q", got)
	}
}

func FuzzStrings(f *testing.F) {
	f.Add("a, b,a, ,c")
	f.Add("")
	f.Add(" x x ")
	f.Fuzz(func(t *testing.T, joined string) {
		in := strings.Split(joined, ",")
		out := Strings(in)
		seen := map[string]bool{}
		for _, v := range out {
			if v == "" || v != strings.TrimSpace(v) {
				t.Fatalf("output %q is empty or untrimmed", v)
			}
			if seen[v] {
				t.Fatalf("duplicate %q in %q", v, out)
			}
			seen[v] = true
		}
		// out is a subsequence of the trimmed input.
		i := 0
		for _, raw := range in {
			if i < len(out) && strings.TrimSpace(raw) == out[i] {
				i++
			}
		}
		if i != len(out) {
			t.Fatalf("%q is not a subsequence of trimmed %q", out, in)
		}
	})
}
