// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// Package metrics provides a lightweight Prometheus-compatible metrics registry
// without external dependencies.
//
// It supports labeled counters, histograms with configurable buckets, and
// scrape-time gauge callbacks. The registry is thread-safe and writes its
// contents in the Prometheus text exposition format, which keeps a service
// scrapable without linking the full Prometheus client library.
//
// Define a metric where it is recorded and pass the registry through, rather
// than reaching for a package-level default.
//
// # Usage
//
//	reg := metrics.NewRegistry()
//	counter := reg.Counter("http_requests_total", "Total HTTP requests")
//	counter.Inc(map[string]string{"method": "GET", "path": "/api/tasks"})
//	hist := reg.Histogram("request_duration_seconds", "Request latency", metrics.DefaultDurationBuckets)
//	hist.Observe(nil, elapsed.Seconds())
//	reg.WritePrometheus(w)
package metrics
