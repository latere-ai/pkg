// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// Package statemachinetest holds a service's code and its formal models to
// the transition tables of [latere.ai/x/pkg/statemachine].
//
// Three links keep the code, the table and the models in step, and each one
// fails a test or a gate when it breaks:
//
//   - [Exhaustive] and [Race] drive the service's real writers, against its
//     real store, through every pair of states and every pair of racing
//     steps, and fail when a writer allows a step the table lacks, refuses
//     one it has, or lets two concurrent writers leave it.
//   - [Models] renders each table into a Lean model and a TLA+ model and
//     fails when the committed models differ from the tables, so a table
//     cannot change without its models.
//   - lateregate's lean gate builds the Lean project, proving the generic
//     lemmas and every claim written about a table by hand, and its tla
//     gate model-checks each table under concurrent writers with TLC.
package statemachinetest

import (
	"errors"
	"fmt"
	"sync"
	"testing"

	"latere.ai/x/pkg/statemachine"
)

// Driver is how the checks reach a service's records and writers.
type Driver[S ~string] struct {
	// Enter stores a fresh record in state s, however the service stores
	// it, and returns the key Move and State take.
	Enter func(t *testing.T, s S) string
	// Move runs the service's own writer that takes the record to to. A
	// refusal wraps statemachine.ErrIllegalTransition, including for a
	// state no writer moves a record to. Two Moves of one record may run
	// at once.
	Move func(key string, to S) error
	// State reads the record's state back.
	State func(t *testing.T, key string) S
}

// Exhaustive tries every ordered pair of distinct states of table: it puts
// a record in the first and asks Move for the second. A step the table has
// must succeed and land; any other must be refused with
// statemachine.ErrIllegalTransition and leave the record where it was.
func Exhaustive[S ~string](t *testing.T, table *statemachine.Table[S], d Driver[S]) {
	t.Helper()
	for _, from := range table.States() {
		for _, to := range table.States() {
			if from == to {
				continue
			}
			t.Run(fmt.Sprintf("%s->%s", from, to), func(t *testing.T) {
				key := d.Enter(t, from)
				err := d.Move(key, to)
				if msg := checkStep(table, from, to, err, d.State(t, key)); msg != "" {
					t.Error(msg)
				}
			})
		}
	}
}

// checkStep is Exhaustive's verdict on one Move: empty when it agrees with
// the table, and otherwise what went wrong.
func checkStep[S ~string](table *statemachine.Table[S], from, to S, err error, got S) string {
	if table.Can(from, to) {
		if err != nil || got != to {
			return fmt.Sprintf("%s %s -> %s is a step: Move = %v, state now %s", table.Name(), from, to, err, got)
		}
		return ""
	}
	if !errors.Is(err, statemachine.ErrIllegalTransition) || got != from {
		return fmt.Sprintf("%s %s -> %s is not a step: Move = %v, state now %s; want it refused with ErrIllegalTransition",
			table.Name(), from, to, err, got)
	}
	return ""
}

// raceRounds is how many times Race repeats each pair of writers.
const raceRounds = 4

// Race starts two writers at once on a record in each state with a step,
// for every pair of its successors, the same one twice included, and
// checks that the record followed the table: the writers that succeeded
// took it along steps the table has, in some order, to where it ended, and
// a refused writer was refused with statemachine.ErrIllegalTransition.
func Race[S ~string](t *testing.T, table *statemachine.Table[S], d Driver[S]) {
	t.Helper()
	for _, from := range table.States() {
		next := table.Next(from)
		for i, a := range next {
			for _, b := range next[i:] {
				t.Run(fmt.Sprintf("%s->%s|%s", from, a, b), func(t *testing.T) {
					for range raceRounds {
						race(t, table, d, from, a, b)
					}
				})
			}
		}
	}
}

func race[S ~string](t *testing.T, table *statemachine.Table[S], d Driver[S], from, a, b S) {
	t.Helper()
	key := d.Enter(t, from)
	var errA, errB error
	var wg sync.WaitGroup
	start := make(chan struct{})
	wg.Go(func() { <-start; errA = d.Move(key, a) })
	wg.Go(func() { <-start; errB = d.Move(key, b) })
	close(start)
	wg.Wait()
	if msg := checkRace(table, from, a, b, errA, errB, d.State(t, key)); msg != "" {
		t.Fatal(msg)
	}
}

// checkRace is Race's verdict on one pair of writers: empty when the
// outcome follows the table, and otherwise what went wrong.
func checkRace[S ~string](table *statemachine.Table[S], from, a, b S, errA, errB error, got S) string {
	for _, err := range []error{errA, errB} {
		if err != nil && !errors.Is(err, statemachine.ErrIllegalTransition) {
			return fmt.Sprintf("%s %s -> %s | %s: a writer failed with %v, want success or ErrIllegalTransition",
				table.Name(), from, a, b, err)
		}
	}
	var legal bool
	switch {
	case errA == nil && errB == nil:
		legal = table.Can(a, b) && got == b || table.Can(b, a) && got == a
	case errA == nil:
		legal = got == a
	case errB == nil:
		legal = got == b
	}
	if !legal {
		return fmt.Sprintf("%s %s -> %s | %s: writers answered %v and %v and left the record in %s, which no order of the table's steps explains",
			table.Name(), from, a, b, errA, errB, got)
	}
	return ""
}
