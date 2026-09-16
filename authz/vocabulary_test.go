// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package authz_test

import (
	"slices"
	"strings"
	"testing"

	"latere.ai/x/pkg/authz"
)

// origo is the four-row table of Origo spec 028, the smallest real
// vocabulary, and lux stands in for a table over several kinds.
var (
	origo = []authz.Action{
		{Name: "repo.read", Kind: "Repository"},
		{Name: "repo.write", Kind: "Repository"},
		{Name: "repo.admin", Kind: "Repository"},
		{Name: "repo.list", Kind: "Repository"},
	}
	lux = []authz.Action{
		{Name: "provider.create", Kind: "Provider"},
		{Name: "provider.list", Kind: "Provider"},
		{Name: "model.read", Kind: "Model"},
		{Name: "usage.read", Kind: "Usage"},
	}
)

func TestNewVocabularyRefusesATableThatIsNoMap(t *testing.T) {
	for _, tc := range []struct {
		name    string
		core    string
		actions []authz.Action
		want    string
	}{
		{"no core name", "", origo, "names the core"},
		{"a blank core name", "   ", origo, "names the core"},
		{"no action", "origo", nil, "names no action"},
		{"an action with no name", "origo", []authz.Action{{Kind: "Repository"}}, "action 0 has no name"},
		{"an action with no kind", "origo", []authz.Action{{Name: "repo.read"}}, `"repo.read" names no resource kind`},
		{"a name twice on one kind", "origo", []authz.Action{
			{Name: "repo.read", Kind: "Repository"}, {Name: "repo.read", Kind: "Repository"},
		}, `names "repo.read" twice`},
		{"a name twice on two kinds", "lux", []authz.Action{
			{Name: "read", Kind: "Provider"}, {Name: "read", Kind: "Model"},
		}, `names "read" twice`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v, err := authz.NewVocabulary(tc.core, tc.actions...)
			if err == nil {
				t.Fatalf("NewVocabulary(%q, %v) built %+v; it is refused", tc.core, tc.actions, v)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %q; it names %q", err, tc.want)
			}
			if len(v.Actions) != 0 || v.Core != "" {
				t.Fatalf("a refused vocabulary is the zero value; got %+v", v)
			}
		})
	}
}

func TestNewVocabularyKeepsTheTablesOrderAndCopiesIt(t *testing.T) {
	actions := slices.Clone(origo)
	v, err := authz.NewVocabulary("origo", actions...)
	if err != nil {
		t.Fatal(err)
	}
	if v.Core != "origo" {
		t.Fatalf("Core = %q", v.Core)
	}
	if !slices.Equal(v.Actions, origo) {
		t.Fatalf("Actions = %+v; the table keeps its order", v.Actions)
	}
	actions[0].Name = "repo.rewritten"
	if v.Actions[0].Name != "repo.read" {
		t.Fatalf("the caller's slice reached the vocabulary: %+v", v.Actions[0])
	}
}

func TestKnownAndKind(t *testing.T) {
	v, err := authz.NewVocabulary("lux", lux...)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		action string
		kind   string
		known  bool
	}{
		{"provider.create", "Provider", true},
		{"model.read", "Model", true},
		{"usage.read", "Usage", true},
		{"provider.delete", "", false},
		{"", "", false},
		{"Provider.Create", "", false},
	} {
		t.Run(tc.action, func(t *testing.T) {
			kind, ok := v.Kind(tc.action)
			if ok != tc.known || kind != tc.kind {
				t.Fatalf("Kind(%q) = %q, %v; want %q, %v", tc.action, kind, ok, tc.kind, tc.known)
			}
			if got := v.Known(tc.action); got != tc.known {
				t.Fatalf("Known(%q) = %v; want %v", tc.action, got, tc.known)
			}
		})
	}
}

func TestTheZeroVocabularyNamesNothing(t *testing.T) {
	var v authz.Vocabulary
	if v.Known("repo.read") {
		t.Fatal("the zero vocabulary knows an action")
	}
	if kind, ok := v.Kind("repo.read"); ok || kind != "" {
		t.Fatalf("Kind = %q, %v", kind, ok)
	}
	if kinds := v.Kinds(); kinds != nil {
		t.Fatalf("Kinds = %v", kinds)
	}
}

func TestKindsListsEachKindOnceInTheTablesOrder(t *testing.T) {
	for _, tc := range []struct {
		name    string
		actions []authz.Action
		want    []string
	}{
		{"one kind over four actions", origo, []string{"Repository"}},
		{"three kinds in the order they appear", lux, []string{"Provider", "Model", "Usage"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v, err := authz.NewVocabulary("core", tc.actions...)
			if err != nil {
				t.Fatal(err)
			}
			if got := v.Kinds(); !slices.Equal(got, tc.want) {
				t.Fatalf("Kinds() = %v; want %v", got, tc.want)
			}
		})
	}
}

func TestIsList(t *testing.T) {
	for _, tc := range []struct {
		action string
		want   bool
	}{
		{"repo.list", true},
		{"provider.list", true},
		{"repo.read", false},
		{"list", false},
		{"", false},
		{"repo.listing", false},
	} {
		t.Run(tc.action, func(t *testing.T) {
			if got := authz.IsList(tc.action); got != tc.want {
				t.Fatalf("IsList(%q) = %v; want %v", tc.action, got, tc.want)
			}
		})
	}
}

func FuzzVocabularyKind(f *testing.F) {
	v, err := authz.NewVocabulary("lux", lux...)
	if err != nil {
		f.Fatal(err)
	}
	for _, s := range []string{"provider.create", "", "provider.", ".list", "repo.read"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, action string) {
		kind, ok := v.Kind(action)
		if ok != v.Known(action) {
			t.Fatalf("Kind(%q) and Known(%q) disagree", action, action)
		}
		if ok && !slices.Contains(v.Kinds(), kind) {
			t.Fatalf("Kind(%q) = %q, which Kinds() does not list", action, kind)
		}
		if !ok && kind != "" {
			t.Fatalf("an unknown action carries the kind %q", kind)
		}
	})
}
