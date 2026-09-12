// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"bytes"
	"strings"
	"sync"
	"testing"
)

func TestHistogramInitExposesZeroSeries(t *testing.T) {
	r := NewRegistry()
	h := r.Histogram("latency", "Latency", []float64{1, 5})
	labels := map[string]string{"op": "read"}
	h.Init(labels)
	labels["op"] = "mutated"
	var out bytes.Buffer
	r.WritePrometheus(&out)
	for _, line := range []string{
		`latency_bucket{le="1",op="read"} 0`,
		`latency_bucket{le="5",op="read"} 0`,
		`latency_bucket{le="+Inf",op="read"} 0`,
		`latency_count{op="read"} 0`,
		`latency_sum{op="read"} 0`,
	} {
		if !strings.Contains(out.String(), line+"\n") {
			t.Errorf("missing %s in %s", line, out.String())
		}
	}
	labels = map[string]string{"op": "read"}
	h.Observe(labels, 3)
	h.Init(labels)
	if h.Count(labels) != 1 {
		t.Fatal("Init changed observations")
	}
	out.Reset()
	r.WritePrometheus(&out)
	if !strings.Contains(out.String(), `latency_sum{op="read"} 3`) {
		t.Fatal("Init reset sum")
	}
}

func TestHistogramConcurrentInitObserve(t *testing.T) {
	h := NewRegistry().Histogram("h", "H", nil)
	var wg sync.WaitGroup
	for range 100 {
		wg.Go(func() { h.Init(nil); h.Observe(nil, 1); h.Init(nil) })
	}
	wg.Wait()
	if h.Count(nil) != 100 {
		t.Fatal("Init lost observations")
	}
}
