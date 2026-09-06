// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// Package health serves the probe surface every Latere service carries on
// its internal listener: /livez, /readyz, /version, and /metrics where
// the service has some.
//
// The four paths are the fleet's decision, recorded in docs/health.md at
// the module root. /livez and /readyz are Kubernetes' own probe
// semantics: liveness failing means restart me, readiness failing means
// take me out of rotation. A single /healthz conflates the two, so a
// dependency outage restarts a process that was fine. /version is the
// build identity the release smoke checks; /metrics is the Prometheus
// text exposition a scraper reads.
//
// The registers: /livez and /version never carry an error text or a
// secret. /readyz carries the failing check's name and error in its body,
// which is the developer register, read by whoever is debugging why a
// replica left rotation.
package health

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// Options configures Handler. The zero value serves /livez and /readyz
// always 200, /version with empty fields, and no /metrics.
type Options struct {
	// Ready answers whether the process can serve. Nil means always ready.
	// Compose several checks with Checks.
	Ready func(context.Context) error
	// Timeout bounds one Ready call. Zero means the request's own context.
	Timeout time.Duration
	// Metrics, when not nil, is mounted at /metrics.
	Metrics http.Handler
	// Version, Commit, and BuildTime are the build identity /version
	// reports. Version is what the release smoke compares with the tag.
	Version   string
	Commit    string
	BuildTime string
	// LegacyHealthz mounts /healthz as an alias of /livez, so a manifest
	// that still probes the old path keeps working for one release while
	// it is moved.
	LegacyHealthz bool
}

// Check is one named readiness condition.
type Check struct {
	Name string
	Run  func(context.Context) error
}

// Checks folds several readiness checks into one Ready. Every check runs,
// in order, and each failure is reported with its name, so /readyz says
// which dependency is down rather than that one is.
func Checks(checks ...Check) func(context.Context) error {
	return func(ctx context.Context) error {
		var errs []error
		for _, c := range checks {
			if err := c.Run(ctx); err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", c.Name, err))
			}
		}
		return errors.Join(errs...)
	}
}

// Build is the body of /version.
type Build struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildTime string `json:"build_time"`
}

// Handler serves the probes. It is mounted whole on the internal
// listener, or path by path on a public mux when a service exposes some
// of the probes through its ingress.
func Handler(o Options) http.Handler {
	mux := http.NewServeMux()
	live := func(w http.ResponseWriter, _ *http.Request) { ok(w) }
	mux.HandleFunc("GET /livez", live)
	if o.LegacyHealthz {
		mux.HandleFunc("GET /healthz", live)
	}
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		if o.Ready != nil {
			ctx := r.Context()
			if o.Timeout > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, o.Timeout)
				defer cancel()
			}
			if err := o.Ready(ctx); err != nil {
				w.Header().Set("Content-Type", "text/plain; charset=utf-8")
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = w.Write([]byte("not ready: " + err.Error() + "\n"))
				return
			}
		}
		ok(w)
	})
	mux.HandleFunc("GET /version", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(Build{Version: o.Version, Commit: o.Commit, BuildTime: o.BuildTime})
	})
	if o.Metrics != nil {
		mux.Handle("GET /metrics", o.Metrics)
	}
	return mux
}

func ok(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("ok\n"))
}
