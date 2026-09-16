// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package authz

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

// A core's action list is read in four places: by the core when it builds
// a request, by the control plane when it validates one, by the
// conformance suite when it drives its cases, and by a self-hoster
// writing an endpoint. Vocabulary is that list as data, so the four read
// one table rather than four copies of it.

// Action is one entry of a core's vocabulary: the action name and the
// resource kind it acts on. An action names exactly one kind, so a core
// that acts on two kinds names two actions.
type Action struct {
	Name string
	Kind string
}

// Vocabulary is a core's whole action table. The zero value names no
// action and [Vocabulary.Known] refuses every string, which is why a
// consumer that validates against a vocabulary asks for a built one.
type Vocabulary struct {
	// Core is the core the table belongs to, for a message: "cella",
	// "lux", "origo".
	Core string
	// Actions is the table in the order the core's spec writes it.
	Actions []Action
}

// NewVocabulary builds a core's table and refuses one that cannot be read
// as a map from action to kind: no core name, no action, an entry with no
// name or no kind, or a name that appears twice, whatever the two kinds
// are. A vocabulary is declared once in a package a core publishes, so
// the error is read by whoever wrote that declaration and never at run
// time.
func NewVocabulary(core string, actions ...Action) (Vocabulary, error) {
	if strings.TrimSpace(core) == "" {
		return Vocabulary{}, errors.New("authz: a vocabulary names the core it belongs to")
	}
	if len(actions) == 0 {
		return Vocabulary{}, fmt.Errorf("authz: %s's vocabulary names no action", core)
	}
	seen := make(map[string]struct{}, len(actions))
	for i, a := range actions {
		switch {
		case a.Name == "":
			return Vocabulary{}, fmt.Errorf("authz: %s's vocabulary: action %d has no name", core, i)
		case a.Kind == "":
			return Vocabulary{}, fmt.Errorf("authz: %s's vocabulary: action %q names no resource kind", core, a.Name)
		}
		if _, dup := seen[a.Name]; dup {
			return Vocabulary{}, fmt.Errorf("authz: %s's vocabulary names %q twice; an action acts on one kind", core, a.Name)
		}
		seen[a.Name] = struct{}{}
	}
	return Vocabulary{Core: core, Actions: slices.Clone(actions)}, nil
}

// Known reports whether action is one of the table's.
func (v Vocabulary) Known(action string) bool {
	_, ok := v.Kind(action)
	return ok
}

// Kind is the resource kind an action acts on. ok is false for a string
// the table does not name, which is the one case a caller tells apart
// from a kind it does not recognise.
func (v Vocabulary) Kind(action string) (string, bool) {
	for _, a := range v.Actions {
		if a.Name == action {
			return a.Kind, true
		}
	}
	return "", false
}

// Kinds lists every resource kind the table names, each once, in the
// order the actions first name it.
func (v Vocabulary) Kinds() []string {
	var out []string
	for _, a := range v.Actions {
		if !slices.Contains(out, a.Kind) {
			out = append(out, a.Kind)
		}
	}
	return out
}

// IsList reports whether an action's verb is list — repo.list,
// provider.list — an action that names no object but the kind it ranges
// over. It is the vocabulary's naming convention and not a routing rule:
// a list action answers a [Decision] like every other, and
// [Decision.Filter] is how an authorizer narrows the core's own list.
//
// An action whose answer is a page of the core's own shape instead, with
// fields and a cursor the contract does not fix, is the exception a core
// declares by name in authz/server's Options.PageActions.
func IsList(action string) bool { return strings.HasSuffix(action, ".list") }
