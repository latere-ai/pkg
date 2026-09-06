// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package egress

import (
	"context"
	"log/slog"
	"time"

	"latere.ai/x/pkg/wait"
)

// The re-push controller keeps every gateway replica's substitution maps warm
// so the deployment can run >1 replica behind a service without a restarted or
// scaled-out replica ever serving a live principal an empty map. It
// periodically re-derives each credentialed principal's map (RebuildMap) and
// pushes it to ALL replicas. Secrets flow one-directional (control plane →
// gateway) exactly as at create: no vending endpoint, no shared secret store,
// and never on disk.

// PrincipalLister lists the live principals that carry credentials and so
// need a substitution map.
type PrincipalLister interface {
	CredentialedPrincipals(ctx context.Context) ([]string, error)
}

// PlaceholderReader reads credName→placeholder back from a running workload's
// environment (the only place the random per-create placeholder survives).
type PlaceholderReader interface {
	Placeholders(ctx context.Context, principal string) (map[string]string, error)
}

// SecretResolver re-projects credName→secret+hosts for a principal from the
// credential store (the secret is never retained by the control plane; it is
// re-derived here).
type SecretResolver interface {
	Secrets(ctx context.Context, principal string) (map[string]CredSecret, error)
}

// MapPusher pushes a principal's map to every gateway replica (fan-out over
// the headless service's endpoints: a push to one replica does not populate
// the others).
type MapPusher interface {
	PushMapAllReplicas(ctx context.Context, principal string, entries []IngestEntry) error
}

// RePusher runs the re-push reconcile loop.
type RePusher struct {
	List         PrincipalLister
	Placeholders PlaceholderReader
	Secrets      SecretResolver
	Push         MapPusher
	Interval     time.Duration
	Log          *slog.Logger
}

// Reconcile runs one re-push pass over every credentialed principal. A
// per-principal error (workload gone, store miss) is logged and skipped so
// one bad principal does not stall the rest.
func (r *RePusher) Reconcile(ctx context.Context) (int, error) {
	ids, err := r.List.CredentialedPrincipals(ctx)
	if err != nil {
		return 0, err
	}
	pushed := 0
	for _, id := range ids {
		ph, err := r.Placeholders.Placeholders(ctx, id)
		if err != nil {
			if r.Log != nil {
				r.Log.Warn("egress re-push placeholders", "principal", id, "err", err)
			}
			continue
		}
		if len(ph) == 0 {
			continue
		}
		sec, err := r.Secrets.Secrets(ctx, id)
		if err != nil {
			if r.Log != nil {
				r.Log.Warn("egress re-push secrets", "principal", id, "err", err)
			}
			continue
		}
		entries := RebuildMap(ph, sec)
		if len(entries) == 0 {
			continue
		}
		if err := r.Push.PushMapAllReplicas(ctx, id, entries); err != nil {
			if r.Log != nil {
				r.Log.Warn("egress re-push", "principal", id, "err", err)
			}
			continue
		}
		pushed++
	}
	return pushed, nil
}

// Run drives Reconcile until ctx is cancelled: once immediately (so a fresh
// leader repopulates gateway replicas without waiting a full interval), then on
// a ticker. Call it under the controller leader lease. Default interval 60s.
func (r *RePusher) Run(ctx context.Context) {
	interval := r.Interval
	if interval <= 0 {
		interval = 60 * time.Second
	}
	step := func(ctx context.Context) {
		if n, err := r.Reconcile(ctx); err != nil && r.Log != nil {
			r.Log.Error("egress re-push reconcile", "err", err)
		} else if r.Log != nil && n > 0 {
			r.Log.Debug("egress re-push reconcile", "pushed", n)
		}
	}
	step(ctx)
	wait.Every(ctx, interval, step)
}
