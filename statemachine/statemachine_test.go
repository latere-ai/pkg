// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package statemachine

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

type status string

const (
	pending  status = "pending"
	approved status = "approved"
	denied   status = "denied"
	expired  status = "expired"
)

func device(t *testing.T) *Table[status] {
	t.Helper()
	tab, err := New("Device", []status{pending}, map[status][]status{
		pending:  {expired, approved, denied},
		approved: {expired},
		denied:   nil,
		expired:  {},
	})
	if err != nil {
		t.Fatal(err)
	}
	return tab
}

func TestTableAnswersFromItsSteps(t *testing.T) {
	tab := device(t)
	if tab.Name() != "Device" {
		t.Errorf("Name = %q", tab.Name())
	}
	if got := tab.States(); !slices.Equal(got, []status{approved, denied, expired, pending}) {
		t.Errorf("States = %v, want sorted", got)
	}
	if got := tab.Initial(); !slices.Equal(got, []status{pending}) {
		t.Errorf("Initial = %v", got)
	}
	if got := tab.Next(pending); !slices.Equal(got, []status{approved, denied, expired}) {
		t.Errorf("Next(pending) = %v, want sorted", got)
	}
	if got := tab.Next("unknown"); got != nil {
		t.Errorf("Next(unknown) = %v, want nil", got)
	}
	if got := tab.Sources(expired); !slices.Equal(got, []status{approved, pending}) {
		t.Errorf("Sources(expired) = %v", got)
	}
	if got := tab.Sources(pending); got != nil {
		t.Errorf("Sources(pending) = %v, want none", got)
	}
	if !tab.Can(pending, approved) || tab.Can(approved, pending) || tab.Can(pending, pending) {
		t.Error("Can disagrees with the table")
	}
	if !tab.Terminal(denied) || tab.Terminal(pending) || tab.Terminal("unknown") {
		t.Error("Terminal disagrees with the table")
	}
}

func TestReturnedSlicesAreCopies(t *testing.T) {
	tab := device(t)
	tab.Next(pending)[0] = denied
	tab.States()[0] = denied
	tab.Initial()[0] = denied
	if !tab.Can(pending, approved) || tab.States()[0] != approved || tab.Initial()[0] != pending {
		t.Error("a caller's change to a returned slice reached the table")
	}
}

func TestNewCopiesTheMap(t *testing.T) {
	next := map[status][]status{pending: {approved}, approved: nil}
	tab, err := New("Copy", []status{pending}, next)
	if err != nil {
		t.Fatal(err)
	}
	next[pending][0] = pending
	next[approved] = []status{pending}
	if !tab.Can(pending, approved) || tab.Can(approved, pending) {
		t.Error("a caller's change to the map reached the table")
	}
}

func TestCheck(t *testing.T) {
	tab := device(t)
	if err := tab.Check(pending, approved); err != nil {
		t.Errorf("pending -> approved: %v", err)
	}
	err := tab.Check(denied, approved)
	if !errors.Is(err, ErrIllegalTransition) {
		t.Fatalf("denied -> approved: %v, want ErrIllegalTransition", err)
	}
	if !strings.Contains(err.Error(), "Device denied -> approved") {
		t.Errorf("error %q does not name the table and the step", err)
	}
	if err := tab.CheckStart(pending); err != nil {
		t.Errorf("start in pending: %v", err)
	}
	if err := tab.CheckStart(approved); !errors.Is(err, ErrIllegalTransition) {
		t.Errorf("start in approved: %v, want ErrIllegalTransition", err)
	}
}

func TestGraph(t *testing.T) {
	g := device(t).Graph()
	if g.Name != "Device" || !slices.Equal(g.States, []string{"approved", "denied", "expired", "pending"}) ||
		!slices.Equal(g.Initial, []string{"pending"}) {
		t.Errorf("Graph = %+v", g)
	}
	if !slices.Equal(g.Next["pending"], []string{"approved", "denied", "expired"}) {
		t.Errorf("Graph.Next[pending] = %v", g.Next["pending"])
	}
	if s, ok := g.Next["denied"]; !ok || s == nil || len(s) != 0 {
		t.Errorf("Graph.Next[denied] = %#v, want an empty list", s)
	}
}

func TestNewAcceptsMixedCase(t *testing.T) {
	tab, err := New("Tunnel", []status{"NotConnected"}, map[status][]status{
		"NotConnected": {"Starting"},
		"Starting":     {"Online", "Offline"},
		"Online":       {"Offline"},
		"Offline":      {"Starting"},
	})
	if err != nil {
		t.Fatalf("New refused a mixed-case table: %v", err)
	}
	if err := tab.Check("Starting", "Online"); err != nil {
		t.Errorf("Check(Starting, Online) = %v, want a step", err)
	}
	if tab.Can("Online", "Starting") {
		t.Error("Online -> Starting is not a step")
	}
}

func TestNewRefuses(t *testing.T) {
	cases := []struct {
		name    string
		label   string
		initial []status
		next    map[status][]status
		want    string
	}{
		{"lower-case name", "device", []status{pending}, map[status][]status{pending: nil}, "not an upper-case identifier"},
		{"reserved name", "Transition", []status{pending}, map[status][]status{pending: nil}, "not an upper-case identifier"},
		{"no initial", "Device", nil, map[status][]status{pending: nil}, "no initial state"},
		{"empty state", "Device", []status{""}, map[status][]status{"": nil}, "is not an identifier"},
		{"leading digit", "Device", []status{"1x"}, map[status][]status{"1x": nil}, "is not an identifier"},
		{"space", "Device", []status{"a b"}, map[status][]status{"a b": nil}, "is not an identifier"},
		{"closing guillemet", "Device", []status{"x»"}, map[status][]status{"x»": nil}, "is not an identifier"},
		{"case collision", "Device", []status{"Ready"}, map[status][]status{"Ready": {"ready"}, "ready": nil}, `states "Ready" and "ready" differ only in case`},
		{"undeclared target", "Device", []status{pending}, map[status][]status{pending: {"approvd"}}, `lists "approvd", which is not a state`},
		{"self step", "Device", []status{pending}, map[status][]status{pending: {pending}}, "lists itself"},
		{"repeated step", "Device", []status{pending}, map[status][]status{pending: {approved, approved}, approved: nil}, "a successor twice"},
		{"undeclared initial", "Device", []status{"new"}, map[status][]status{pending: nil}, `initial state "new" is not a state`},
		{"unreachable", "Device", []status{pending}, map[status][]status{pending: {approved}, approved: nil, denied: nil}, "reaches denied"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := New(c.label, c.initial, c.next)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("New = %v, want an error containing %q", err, c.want)
			}
		})
	}
}

func TestMust(t *testing.T) {
	tab := Must(New("Device", []status{pending}, map[status][]status{pending: nil}))
	if tab.Name() != "Device" {
		t.Errorf("Must returned %v", tab)
	}
	defer func() {
		if recover() == nil {
			t.Error("Must did not panic on an invalid table")
		}
	}()
	Must(New("Device", nil, map[status][]status{pending: nil}))
}

func TestRepeatedInitialCollapses(t *testing.T) {
	tab := Must(New("Device", []status{pending, pending}, map[status][]status{pending: nil}))
	if got := tab.Initial(); !slices.Equal(got, []status{pending}) {
		t.Errorf("Initial = %v", got)
	}
}

// FuzzNew holds New to its promise for any state names: it either refuses
// the table or returns one whose every state is reached and whose answers
// agree with the map it was given.
func FuzzNew(f *testing.F) {
	f.Add("pending", "approved", "denied")
	f.Add("a", "a", "b")
	f.Add("", "x-y", "z_1")
	f.Fuzz(func(t *testing.T, a, b, c string) {
		next := map[status][]status{status(a): {status(b)}, status(b): {status(c)}, status(c): nil}
		tab, err := New("Fuzz", []status{status(a)}, next)
		if err != nil {
			return
		}
		for _, s := range tab.States() {
			for _, to := range tab.Next(s) {
				if !tab.Can(s, to) || tab.Check(s, to) != nil || !slices.Contains(tab.Sources(to), s) {
					t.Fatalf("%s -> %s is listed but not answered", s, to)
				}
			}
		}
	})
}
