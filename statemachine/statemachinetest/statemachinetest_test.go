// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package statemachinetest

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"latere.ai/x/pkg/statemachine"
)

var update = flag.Bool("update", false, "rewrite the example formal models under testdata/formal")

type status string

// device is the example table: a device sign-in that is approved or denied
// while pending, lapses unless consumed, and is consumed once approved.
var device = statemachine.Must(statemachine.New("Device", []status{"pending"}, map[status][]status{
	"pending":  {"approved", "denied", "expired"},
	"approved": {"consumed", "expired"},
	"denied":   nil,
	"expired":  nil,
	"consumed": nil,
}))

// tunnel is the example table with mixed-case states, as a column that
// stores them keeps them.
var tunnel = statemachine.Must(statemachine.New("Tunnel", []status{"NotConnected"}, map[status][]status{
	"NotConnected": {"Starting"},
	"Starting":     {"Online", "Offline"},
	"Online":       {"Offline"},
	"Offline":      {"Starting", "Retired"},
	"Retired":      nil,
}))

// TestExampleModels keeps testdata/formal, which the lean and tla gates
// check in this repository, rendered from the example tables.
func TestExampleModels(t *testing.T) {
	Models(t, filepath.Join("testdata", "formal"), *update, device.Graph(), tunnel.Graph())
}

// store is an in-memory service whose writer checks the table against the
// state it lands on, under the lock that also guards the write.
type store struct {
	mu   sync.Mutex
	rows map[string]status
	n    int
}

func (s *store) driver() Driver[status] {
	return Driver[status]{
		Enter: func(t *testing.T, st status) string {
			s.mu.Lock()
			defer s.mu.Unlock()
			s.n++
			key := fmt.Sprint(s.n)
			s.rows[key] = st
			return key
		},
		Move: func(key string, to status) error {
			s.mu.Lock()
			defer s.mu.Unlock()
			if err := device.Check(s.rows[key], to); err != nil {
				return err
			}
			s.rows[key] = to
			return nil
		},
		State: func(t *testing.T, key string) status {
			s.mu.Lock()
			defer s.mu.Unlock()
			return s.rows[key]
		},
	}
}

func TestAGuardedWriterPasses(t *testing.T) {
	s := &store{rows: map[string]status{}}
	Exhaustive(t, device, s.driver())
	Race(t, device, s.driver())
}

func TestCheckStep(t *testing.T) {
	refused := fmt.Errorf("wrapped: %w", statemachine.ErrIllegalTransition)
	cases := []struct {
		name     string
		from, to status
		err      error
		got      status
		want     string
	}{
		{"step lands", "pending", "approved", nil, "approved", ""},
		{"step refused", "pending", "approved", refused, "pending", "is a step"},
		{"step reports success but does not land", "pending", "approved", nil, "pending", "is a step"},
		{"non-step refused", "denied", "approved", refused, "denied", ""},
		{"non-step allowed", "denied", "approved", nil, "approved", "is not a step"},
		{"non-step refused with another error", "denied", "approved", errors.New("boom"), "denied", "is not a step"},
		{"non-step refused but moved", "denied", "approved", refused, "approved", "is not a step"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			msg := checkStep(device, c.from, c.to, c.err, c.got)
			if c.want == "" && msg != "" || c.want != "" && !strings.Contains(msg, c.want) {
				t.Errorf("checkStep = %q, want %q", msg, c.want)
			}
		})
	}
}

func TestCheckRace(t *testing.T) {
	refused := fmt.Errorf("wrapped: %w", statemachine.ErrIllegalTransition)
	cases := []struct {
		name       string
		a, b       status
		errA, errB error
		got        status
		bad        bool
	}{
		{"one wins", "approved", "denied", nil, refused, "approved", false},
		{"the other wins", "approved", "denied", refused, nil, "denied", false},
		{"both win along a path", "approved", "expired", nil, nil, "expired", false},
		{"both win along the reverse path", "expired", "approved", nil, nil, "expired", false},
		{"both win with no path between", "approved", "denied", nil, nil, "denied", true},
		{"the same step twice", "approved", "approved", nil, nil, "approved", true},
		{"both refused", "approved", "denied", refused, refused, "pending", true},
		{"winner did not land", "approved", "denied", nil, refused, "denied", true},
		{"a writer broke", "approved", "denied", errors.New("connection reset"), nil, "denied", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			msg := checkRace(device, "pending", c.a, c.b, c.errA, c.errB, c.got)
			if (msg != "") != c.bad {
				t.Errorf("checkRace = %q, want a failure: %v", msg, c.bad)
			}
		})
	}
}

// fakeTB records failures instead of failing the test that runs it.
type fakeTB struct {
	testing.TB
	errs  []string
	fatal bool
}

func (f *fakeTB) Helper() {}
func (f *fakeTB) Errorf(format string, args ...any) {
	f.errs = append(f.errs, fmt.Sprintf(format, args...))
}
func (f *fakeTB) Fatal(args ...any) { f.fatal = true; f.errs = append(f.errs, fmt.Sprint(args...)) }

func TestModelsWritesAndChecks(t *testing.T) {
	dir := t.TempDir()
	Models(t, dir, true, device.Graph())
	for _, p := range []string{"lakefile.toml", "lean-toolchain", "Statemachine.lean", "Transition.tla",
		"Machines/Device.lean", "Device.tla", "Device.cfg", "Device.stale.cfg"} {
		if _, err := os.Stat(filepath.Join(dir, p)); err != nil {
			t.Errorf("%s not written: %v", p, err)
		}
	}
	f := &fakeTB{TB: t}
	Models(f, dir, false, device.Graph())
	if len(f.errs) > 0 {
		t.Fatalf("fresh models reported %v", f.errs)
	}

	changed := statemachine.Must(statemachine.New("Device", []status{"pending"}, map[status][]status{
		"pending": {"approved"}, "approved": nil,
	}))
	f = &fakeTB{TB: t}
	Models(f, dir, false, changed.Graph())
	if len(f.errs) != 1 || !strings.Contains(f.errs[0], "Machines/Device.lean differs from its table") ||
		!strings.Contains(f.errs[0], "Device.stale.cfg is generated but no table produces it") {
		t.Fatalf("a changed table reported %v", f.errs)
	}

	if err := os.Remove(filepath.Join(dir, "Device.tla")); err != nil {
		t.Fatal(err)
	}
	f = &fakeTB{TB: t}
	Models(f, dir, false, device.Graph())
	if len(f.errs) != 1 || !strings.Contains(f.errs[0], "Device.tla is missing") {
		t.Fatalf("a missing model reported %v", f.errs)
	}

	Models(t, dir, true, changed.Graph())
	if _, err := os.Stat(filepath.Join(dir, "Device.stale.cfg")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("update left the stale configuration nothing produces: %v", err)
	}
}

func TestModelsBuildsProofsOnceThereAreAny(t *testing.T) {
	dir := t.TempDir()
	Models(t, dir, true, device.Graph())
	lake, err := os.ReadFile(filepath.Join(dir, "lakefile.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(lake), "Proofs") {
		t.Errorf("lakefile names Proofs with no proof file:\n%s", lake)
	}
	if err := os.MkdirAll(filepath.Join(dir, "Proofs"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "Proofs", "Device.lean"), []byte("import Machines.Device\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	f := &fakeTB{TB: t}
	Models(f, dir, false, device.Graph())
	if len(f.errs) != 1 || !strings.Contains(f.errs[0], "lakefile.toml differs") {
		t.Fatalf("a first proof file reported %v", f.errs)
	}
	Models(t, dir, true, device.Graph())
	f = &fakeTB{TB: t}
	Models(f, dir, false, device.Graph())
	if len(f.errs) > 0 {
		t.Fatalf("after update: %v", f.errs)
	}
}

func TestModelsRefusesTwoTablesOfOneName(t *testing.T) {
	f := &fakeTB{TB: t}
	Models(f, t.TempDir(), false, device.Graph(), device.Graph())
	if !f.fatal || !strings.Contains(f.errs[0], "two tables are named Device") {
		t.Fatalf("Models = %v", f.errs)
	}
}

func TestModelsOfAnAbsentDirectoryAreMissing(t *testing.T) {
	f := &fakeTB{TB: t}
	Models(f, filepath.Join(t.TempDir(), "absent"), false, device.Graph())
	if len(f.errs) != 1 || !strings.Contains(f.errs[0], "lakefile.toml is missing") {
		t.Fatalf("Models = %v", f.errs)
	}
}

func TestLeanEscapesNamesThatAreNotPlain(t *testing.T) {
	g := statemachine.Must(statemachine.New("Odd", []status{"in-progress"}, map[status][]status{
		"in-progress": {"end"}, "end": nil,
	})).Graph()
	out := lean(g)
	for _, want := range []string{"| «in-progress»", "| .«in-progress» => [.«end»]", "theorem terminal_end"} {
		if !strings.Contains(out, want) {
			t.Errorf("lean output lacks %q:\n%s", want, out)
		}
	}
	h := statemachine.Must(statemachine.New("Odd", []status{"go"}, map[status][]status{
		"go": {"in-progress"}, "in-progress": nil,
	})).Graph()
	if out := lean(h); !strings.Contains(out, "theorem «terminal_in-progress»") {
		t.Errorf("lean output does not escape the theorem name:\n%s", out)
	}
}

func TestTLAOfATableWithNoStep(t *testing.T) {
	g := statemachine.Must(statemachine.New("Single", []status{"done"}, map[status][]status{"done": nil})).Graph()
	if out := tla(g); !strings.Contains(out, `MCSucc == [s \in MCStates |-> {}]`) {
		t.Errorf("tla output:\n%s", out)
	}
}

func TestStaleBreaks(t *testing.T) {
	cases := []struct {
		name string
		next map[status][]status
		want bool
	}{
		{"one step", map[status][]status{"a": {"b"}, "b": nil}, false},
		{"a chain", map[status][]status{"a": {"b"}, "b": {"c"}, "c": nil}, true},
		{"a fork", map[status][]status{"a": {"b", "c"}, "b": nil, "c": nil}, true},
		{"a fork that rejoins: a writer that read a writes b over c", map[status][]status{"a": {"b", "c"}, "b": {"c"}, "c": nil}, true},
		{"a cycle", map[status][]status{"a": {"b"}, "b": {"a"}}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := statemachine.Must(statemachine.New("Case", []status{"a"}, c.next)).Graph()
			if got := staleBreaks(g); got != c.want {
				t.Errorf("staleBreaks = %v, want %v", got, c.want)
			}
		})
	}
}
