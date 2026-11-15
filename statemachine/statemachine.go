// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// Package statemachine declares a stored record's lifecycle as one table:
// the states a record may start in and the successors of each state. The
// table is the only place a lifecycle is written down. Code consults it
// before every write of the state, tests hold the writers to it, and
// [latere.ai/x/pkg/statemachine/statemachinetest] renders it into a Lean
// model and a TLA+ model that lateregate checks.
//
// A table guards a write only when the state it is checked against is the
// state the write lands on. Either read the current state under a row lock
// in the transaction that writes it and call [Table.Check], or write with
// the sources as the condition and require one affected row:
//
//	UPDATE invitations SET status = $2
//	 WHERE id = $1 AND status = ANY($3)  -- $3 = table.Sources(to)
//
// A state read earlier, outside that transaction, may be stale by the time
// the write lands, and a check against it lets two writers move one record
// along steps the table does not have.
package statemachine

import (
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
)

// ErrIllegalTransition is what [Table.Check] and [Table.CheckStart] wrap
// when the table has no such step or start.
var ErrIllegalTransition = errors.New("illegal transition")

var (
	nameRE  = regexp.MustCompile(`^[A-Z][A-Za-z0-9]*$`)
	stateRE = regexp.MustCompile(`^[a-z][a-z0-9_-]*$`)
)

// reservedNames are the module names the rendered models use themselves.
var reservedNames = []string{"Machines", "Proofs", "Statemachine", "Transition"}

// Table is a validated transition table over the state type S. The zero
// value is not usable; build one with [New]. A Table is immutable and safe
// for concurrent use.
type Table[S ~string] struct {
	name    string
	states  []S
	initial []S
	next    map[S][]S
}

// New validates and builds the table named name, in which a record starts
// in one of initial and moves from each state to the states next lists for
// it. Every state is a key of next, a terminal state with no successors,
// so a typo in a target is an error rather than a state nothing leaves.
//
// The name is the model's name in the rendered Lean and TLA+ files: an
// upper-case letter, then letters and digits. A state is a lower-case
// letter, then lower-case letters, digits, '_' and '-'. New refuses a
// table with no initial state, a successor or initial state that is not a
// key, a state listed as its own successor or twice in one list, and a
// state no path from an initial state reaches.
func New[S ~string](name string, initial []S, next map[S][]S) (*Table[S], error) {
	if !nameRE.MatchString(name) || slices.Contains(reservedNames, name) {
		return nil, fmt.Errorf("statemachine: name %q is not an upper-case identifier other than %v", name, reservedNames)
	}
	if len(initial) == 0 {
		return nil, fmt.Errorf("statemachine %s: no initial state", name)
	}
	t := &Table[S]{name: name, next: make(map[S][]S, len(next))}
	for s, succ := range next {
		if !stateRE.MatchString(string(s)) {
			return nil, fmt.Errorf("statemachine %s: state %q is not a lower-case identifier", name, s)
		}
		for _, to := range succ {
			if _, ok := next[to]; !ok {
				return nil, fmt.Errorf("statemachine %s: %s lists %q, which is not a state", name, s, to)
			}
			if to == s {
				return nil, fmt.Errorf("statemachine %s: %s lists itself", name, s)
			}
		}
		sorted := slices.Sorted(slices.Values(succ))
		if len(slices.Compact(slices.Clone(sorted))) != len(sorted) {
			return nil, fmt.Errorf("statemachine %s: %s lists a successor twice", name, s)
		}
		t.next[s] = sorted
	}
	for _, s := range initial {
		if _, ok := next[s]; !ok {
			return nil, fmt.Errorf("statemachine %s: initial state %q is not a state", name, s)
		}
	}
	t.states = slices.Sorted(maps.Keys(next))
	t.initial = slices.Compact(slices.Sorted(slices.Values(initial)))
	reached := t.reach(t.initial)
	for _, s := range t.states {
		if !reached[s] {
			return nil, fmt.Errorf("statemachine %s: no path from an initial state reaches %s", name, s)
		}
	}
	return t, nil
}

// Must returns t, and panics when err is not nil. It is for tables declared
// as package variables, where an invalid table is a programming error.
func Must[S ~string](t *Table[S], err error) *Table[S] {
	if err != nil {
		panic(err)
	}
	return t
}

func (t *Table[S]) reach(from []S) map[S]bool {
	seen := map[S]bool{}
	queue := slices.Clone(from)
	for len(queue) > 0 {
		s := queue[0]
		queue = queue[1:]
		if seen[s] {
			continue
		}
		seen[s] = true
		queue = append(queue, t.next[s]...)
	}
	return seen
}

// Name is the table's name.
func (t *Table[S]) Name() string { return t.name }

// States lists every state, sorted.
func (t *Table[S]) States() []S { return slices.Clone(t.states) }

// Initial lists the states a record may start in, sorted.
func (t *Table[S]) Initial() []S { return slices.Clone(t.initial) }

// Next lists the successors of s, sorted: none for a terminal state or one
// the table does not have.
func (t *Table[S]) Next(s S) []S { return slices.Clone(t.next[s]) }

// Sources lists, sorted, the states with a step to to: the condition of a
// write of to that checks the state it lands on.
func (t *Table[S]) Sources(to S) []S {
	var out []S
	for _, s := range t.states {
		if slices.Contains(t.next[s], to) {
			out = append(out, s)
		}
	}
	return out
}

// Can reports whether the table has the step from to to.
func (t *Table[S]) Can(from, to S) bool { return slices.Contains(t.next[from], to) }

// Terminal reports whether s is a state of the table with no successor.
func (t *Table[S]) Terminal(s S) bool {
	succ, ok := t.next[s]
	return ok && len(succ) == 0
}

// Check returns nil when the table has the step from to to, and otherwise
// an error wrapping [ErrIllegalTransition] that names the table and both
// states. from must be the state the write lands on; see the package
// documentation.
func (t *Table[S]) Check(from, to S) error {
	if t.Can(from, to) {
		return nil
	}
	return fmt.Errorf("%w: %s %s -> %s", ErrIllegalTransition, t.name, from, to)
}

// CheckStart returns nil when a record may start in s, and otherwise an
// error wrapping [ErrIllegalTransition].
func (t *Table[S]) CheckStart(s S) error {
	if slices.Contains(t.initial, s) {
		return nil
	}
	return fmt.Errorf("%w: %s cannot start in %s", ErrIllegalTransition, t.name, s)
}

// Graph is the table with its states as strings, for code that handles
// tables of different state types together, such as the model renderer.
func (t *Table[S]) Graph() Graph {
	g := Graph{Name: t.name, Next: make(map[string][]string, len(t.next))}
	for _, s := range t.states {
		g.States = append(g.States, string(s))
		succ := make([]string, 0, len(t.next[s]))
		for _, to := range t.next[s] {
			succ = append(succ, string(to))
		}
		g.Next[string(s)] = succ
	}
	for _, s := range t.initial {
		g.Initial = append(g.Initial, string(s))
	}
	return g
}

// Graph is a validated table with string states, as [Table.Graph] returns
// it. States, Initial and every successor list are sorted.
type Graph struct {
	Name    string
	States  []string
	Initial []string
	Next    map[string][]string
}
