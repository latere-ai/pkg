// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package ratelimit

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestIndependentKeysRefillAndIdle(t *testing.T) {
	now := time.Unix(100, 0)
	b := New(Config{PerMinute: 60, Burst: 2, Idle: time.Second, Now: func() time.Time { return now }})
	for range 2 {
		if !b.Allow("a").OK {
			t.Fatal("burst denied")
		}
	}
	if a := b.Allow("a"); a.OK || a.Retry != time.Second || a.Remaining != 0 {
		t.Fatalf("allowance=%+v", a)
	}
	if !b.Allow("b").OK || b.Len() != 2 {
		t.Fatal("keys share quota")
	}
	now = now.Add(500 * time.Millisecond)
	if a := b.Allow("a"); a.OK || a.Retry != 500*time.Millisecond {
		t.Fatalf("fractional refill=%+v", a)
	}
	now = now.Add(500 * time.Millisecond)
	if !b.Allow("a").OK {
		t.Fatal("refill denied")
	}
	now = now.Add(2 * time.Second)
	if removed := b.Sweep(); removed != 2 || b.Len() != 0 {
		t.Fatalf("removed=%d len=%d", removed, b.Len())
	}
	if !b.Allow("a").OK {
		t.Fatal("expired key not recreated")
	}
}

func TestIdleCannotResetDepletedQuota(t *testing.T) {
	now := time.Unix(100, 0)
	b := New(Config{PerMinute: 1, Burst: 1, Idle: time.Second, Now: func() time.Time { return now }})
	b.Allow("a")
	now = now.Add(2 * time.Second)
	if b.Sweep() != 0 || b.Allow("a").OK {
		t.Fatal("idle expiry bypassed rate")
	}
	now = now.Add(-time.Hour)
	if b.Allow("a").OK {
		t.Fatal("backward clock refilled quota")
	}
}

func TestRateUpdatesAndAnonymousAfterIdle(t *testing.T) {
	now := time.Unix(100, 0)
	b := New(Config{PerMinute: 60, Burst: 60, Idle: time.Second, Now: func() time.Time { return now }})
	b.SetRate("anonymous", 1)
	if a := b.Allow("anonymous"); !a.OK || a.PerMinute != 1 {
		t.Fatal(a)
	}
	b.SetRate("anonymous", 1)
	if b.Allow("anonymous").OK {
		t.Fatal("identical rate replenished tokens")
	}
	now = now.Add(2 * time.Minute)
	b.SetRate("anonymous", 1)
	if a := b.Allow("anonymous"); a.PerMinute != 1 || !a.OK {
		t.Fatalf("override lost after idle: %+v", a)
	}
	b.SetRate("anonymous", 2)
	if b.Rate("anonymous") != 2 {
		t.Fatal("override missing")
	}
	for range 2 {
		if !b.Allow("anonymous").OK {
			t.Fatal("increased rate did not fill burst")
		}
	}
	b.SetRate("anonymous", 1)
	if b.Allow("anonymous").OK {
		t.Fatal("decreasing rate refilled tokens")
	}
	b.SetRate("anonymous", 0)
	if b.Rate("anonymous") != 1 || b.Rate("unknown") != 60 {
		t.Fatal("default or no-op override wrong")
	}
}

func TestConcurrentAdmission(t *testing.T) {
	b := New(Config{PerMinute: 60, Burst: 10, Now: func() time.Time { return time.Unix(100, 0) }})
	var accepted atomic.Int32
	var wg sync.WaitGroup
	for range 100 {
		wg.Go(func() {
			if b.Allow("a").OK {
				accepted.Add(1)
			}
			b.Rate("a")
			b.Len()
		})
	}
	wg.Wait()
	if accepted.Load() != 10 {
		t.Fatalf("accepted=%d", accepted.Load())
	}
}

func TestDefaultsAndDisabled(t *testing.T) {
	for _, b := range []*Buckets{nil, New(Config{}), New(Config{PerMinute: -1})} {
		b.SetRate("a", 1)
		if !b.Allow("a").OK || b.Len() != 0 || b.Rate("a") != 0 || b.Sweep() != 0 {
			t.Fatal("disabled limiter enforced")
		}
	}
	b := New(Config{PerMinute: 1})
	if !b.Allow("a").OK || b.Allow("a").OK {
		t.Fatal("default burst wrong")
	}
}

func FuzzKeys(f *testing.F) {
	f.Add("subject")
	f.Add("")
	f.Fuzz(func(t *testing.T, key string) {
		b := New(Config{PerMinute: 1, Burst: 1, Now: func() time.Time { return time.Unix(100, 0) }})
		if !b.Allow(key).OK || b.Allow(key).OK {
			t.Fatal("key changed admission semantics")
		}
	})
}
