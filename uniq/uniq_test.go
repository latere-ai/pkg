// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package uniq

import (
	"errors"
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

type catalogItem struct{ Slug string }

func TestMerge(t *testing.T) {
	slug := func(i catalogItem) string { return i.Slug }
	tests := []struct {
		name    string
		base    []catalogItem
		extra   []catalogItem
		want    []string
		wantDup string // key named in the error, empty for success
	}{
		{"both empty", nil, nil, []string{}, ""},
		{"base only", []catalogItem{{"a"}, {"b"}}, nil, []string{"a", "b"}, ""},
		{"extra only", nil, []catalogItem{{"c"}}, []string{"c"}, ""},
		{"base then extra", []catalogItem{{"a"}, {"b"}}, []catalogItem{{"c"}}, []string{"a", "b", "c"}, ""},
		{"extra shadows base", []catalogItem{{"a"}}, []catalogItem{{"a"}}, nil, "a"},
		{"repeat within extra", []catalogItem{{"a"}}, []catalogItem{{"b"}, {"b"}}, nil, "b"},
		{"repeat within base", []catalogItem{{"a"}, {"a"}}, nil, nil, "a"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Merge(tc.base, tc.extra, slug)
			if tc.wantDup != "" {
				if !errors.Is(err, ErrDuplicate) {
					t.Fatalf("err = %v, want ErrDuplicate", err)
				}
				if !strings.Contains(err.Error(), tc.wantDup) {
					t.Errorf("err = %q, want it to name %q", err, tc.wantDup)
				}
				if got != nil {
					t.Errorf("result = %v, want nil on error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("Merge: %v", err)
			}
			if got == nil {
				t.Fatal("result is nil, want a non-nil slice")
			}
			slugs := make([]string, len(got))
			for i, v := range got {
				slugs[i] = v.Slug
			}
			if !slices.Equal(slugs, tc.want) {
				t.Errorf("order = %v, want %v", slugs, tc.want)
			}
		})
	}
}

func TestMergeDoesNotAliasInput(t *testing.T) {
	base := []int{1, 2}
	got, err := Merge(base, []int{3}, func(v int) int { return v })
	if err != nil {
		t.Fatal(err)
	}
	got[0] = 99
	if base[0] != 1 {
		t.Error("Merge result aliases base")
	}
}
