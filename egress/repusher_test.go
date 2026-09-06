// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package egress

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"
)

type fakeLister struct {
	ids []string
	err error
}

func (f *fakeLister) CredentialedPrincipals(context.Context) ([]string, error) { return f.ids, f.err }

type fakePlaceholders struct{ m map[string]map[string]string }

func (f *fakePlaceholders) Placeholders(_ context.Context, id string) (map[string]string, error) {
	return f.m[id], nil
}

type fakeSecrets struct {
	m map[string]map[string]CredSecret
}

func (f *fakeSecrets) Secrets(_ context.Context, id string) (map[string]CredSecret, error) {
	return f.m[id], nil
}

type fakePusher struct {
	pushed map[string]int
	err    error
}

func (f *fakePusher) PushMapAllReplicas(_ context.Context, id string, entries []IngestEntry) error {
	if f.err != nil {
		return f.err
	}
	if f.pushed == nil {
		f.pushed = map[string]int{}
	}
	f.pushed[id] = len(entries)
	return nil
}

func TestRePusher_ReconcileRebuildsAndPushes(t *testing.T) {
	phA := MintPlaceholder()
	push := &fakePusher{}
	r := &RePusher{
		List:         &fakeLister{ids: []string{"p-1", "p-empty", "p-orphan"}},
		Placeholders: &fakePlaceholders{m: map[string]map[string]string{"p-1": {"A": phA}, "p-orphan": {"Z": MintPlaceholder()}}},
		Secrets:      &fakeSecrets{m: map[string]map[string]CredSecret{"p-1": {"A": {Secret: []byte("s"), Hosts: []string{"h"}}}}},
		Push:         push,
	}
	n, err := r.Reconcile(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// p-1 pushed (1 entry); p-empty skipped (no placeholders); p-orphan skipped
	// (placeholder with no secret rebuilds to nothing).
	if n != 1 || push.pushed["p-1"] != 1 {
		t.Fatalf("pushed=%d map=%v want p-1:1", n, push.pushed)
	}
	for _, skipped := range []string{"p-empty", "p-orphan"} {
		if _, ok := push.pushed[skipped]; ok {
			t.Errorf("%s must be skipped", skipped)
		}
	}
}

type errPlaceholders struct{ err error }

func (e *errPlaceholders) Placeholders(context.Context, string) (map[string]string, error) {
	return nil, e.err
}

type errSecrets struct{ err error }

func (e *errSecrets) Secrets(context.Context, string) (map[string]CredSecret, error) {
	return nil, e.err
}

// A per-principal resolution or push failure (workload gone, store miss,
// gateway down) is logged, not silently dropped, so an outage that empties
// the re-push loop is visible.
func TestRePusher_ReconcileLogsResolutionErrors(t *testing.T) {
	var buf strings.Builder
	log := slog.New(slog.NewTextHandler(&buf, nil))

	r := &RePusher{
		List:         &fakeLister{ids: []string{"p-1"}},
		Placeholders: &errPlaceholders{err: errors.New("exec failed")},
		Secrets:      &errSecrets{err: errors.New("store miss")},
		Push:         &fakePusher{},
		Log:          log,
	}
	if _, err := r.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "egress re-push placeholders") {
		t.Fatalf("placeholder error not logged: %q", buf.String())
	}

	buf.Reset()
	phA := MintPlaceholder()
	r.Placeholders = &fakePlaceholders{m: map[string]map[string]string{"p-1": {"A": phA}}}
	if _, err := r.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "egress re-push secrets") {
		t.Fatalf("secret error not logged: %q", buf.String())
	}

	buf.Reset()
	r.Secrets = &fakeSecrets{m: map[string]map[string]CredSecret{"p-1": {"A": {Secret: []byte("s"), Hosts: []string{"h"}}}}}
	r.Push = &fakePusher{err: errors.New("gateway down")}
	if n, err := r.Reconcile(context.Background()); err != nil || n != 0 {
		t.Fatalf("push failure: n=%d err=%v", n, err)
	}
	if !strings.Contains(buf.String(), "gateway down") {
		t.Fatalf("push error not logged: %q", buf.String())
	}
}

// Without a logger every failure path is silent and still non-fatal.
func TestRePusher_ReconcileWithoutLogger(t *testing.T) {
	r := &RePusher{
		List:         &fakeLister{ids: []string{"p-1"}},
		Placeholders: &fakePlaceholders{m: map[string]map[string]string{"p-1": {"A": MintPlaceholder()}}},
		Secrets:      &fakeSecrets{m: map[string]map[string]CredSecret{"p-1": {"A": {Secret: []byte("s"), Hosts: []string{"h"}}}}},
		Push:         &fakePusher{err: errors.New("gateway down")},
	}
	if n, err := r.Reconcile(context.Background()); err != nil || n != 0 {
		t.Fatalf("n=%d err=%v", n, err)
	}
}

// chanPusher signals each push over a channel (safe to observe from Run's
// goroutine).
type chanPusher struct{ ch chan string }

func (c *chanPusher) PushMapAllReplicas(_ context.Context, id string, _ []IngestEntry) error {
	c.ch <- id
	return nil
}

// Run reconciles once immediately, so a fresh leader repopulates gateway
// replicas without waiting a full interval, and logs the pass.
func TestRePusher_RunReconcilesImmediately(t *testing.T) {
	phA := MintPlaceholder()
	push := &chanPusher{ch: make(chan string, 1)}
	logs := &syncBuffer{}
	r := &RePusher{
		List:         &fakeLister{ids: []string{"p-1"}},
		Placeholders: &fakePlaceholders{m: map[string]map[string]string{"p-1": {"A": phA}}},
		Secrets:      &fakeSecrets{m: map[string]map[string]CredSecret{"p-1": {"A": {Secret: []byte("s"), Hosts: []string{"h"}}}}},
		Push:         push,
		Interval:     time.Hour,
		Log:          slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { r.Run(ctx); close(done) }()
	select {
	case id := <-push.ch:
		if id != "p-1" {
			t.Fatalf("pushed %q want p-1", id)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not reconcile before the first tick")
	}
	cancel()
	<-done
	if !strings.Contains(logs.String(), "pushed=1") {
		t.Fatalf("successful pass not logged: %q", logs.String())
	}
}

// Run logs a list failure and keeps going until cancelled, using the default
// interval when none is configured.
func TestRePusher_RunLogsListError(t *testing.T) {
	logs := &syncBuffer{}
	r := &RePusher{List: &fakeLister{err: errors.New("down")}, Log: slog.New(slog.NewTextHandler(logs, nil))}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { r.Run(ctx); close(done) }()
	deadline := time.Now().Add(2 * time.Second)
	for !strings.Contains(logs.String(), "egress re-push reconcile") {
		if time.Now().After(deadline) {
			t.Fatalf("list error not logged: %q", logs.String())
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
}

func TestRePusher_ListErrorPropagates(t *testing.T) {
	r := &RePusher{List: &fakeLister{err: errors.New("down")}}
	if _, err := r.Reconcile(context.Background()); err == nil {
		t.Fatal("list error must propagate")
	}
}
