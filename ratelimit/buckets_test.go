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
	remaining := b.Len() // b may already have expired during the prior admission.
	if removed := b.Sweep(); removed != remaining || b.Len() != 0 {
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
	for _, b := range []*Buckets{nil, New(Config{PerMinute: -1})} {
		b.SetRate("a", 1)
		b.Adjust("a", -100)
		if !b.Allow("a").OK || !b.AllowN("a", 1000).OK || b.Len() != 0 || b.Rate("a") != 0 || b.Sweep() != 0 {
			t.Fatal("disabled limiter enforced")
		}
	}
	b := New(Config{PerMinute: 1})
	if !b.Allow("a").OK || b.Allow("a").OK {
		t.Fatal("default burst wrong")
	}
}

// TestAllowNIsAllOrNothing: n tokens leave at once or none do, Retry is
// the wait for all n, and n above the burst is never admitted.
func TestAllowNIsAllOrNothing(t *testing.T) {
	now := time.Unix(100, 0)
	b := New(Config{PerMinute: 60, Burst: 10, Now: func() time.Time { return now }})
	if a := b.AllowN("a", 4); !a.OK || a.Remaining != 6 || a.PerMinute != 60 {
		t.Fatalf("AllowN(4) = %+v", a)
	}
	// Seven of six: refused, nothing taken, one token's wait.
	if a := b.AllowN("a", 7); a.OK || a.Remaining != 6 || a.Retry != time.Second {
		t.Fatalf("AllowN(7) with 6 = %+v", a)
	}
	if a := b.AllowN("a", 6); !a.OK || a.Remaining != 0 {
		t.Fatalf("AllowN(6) with 6 = %+v", a)
	}
	// A charge of nothing is allowed and takes nothing.
	if a := b.AllowN("a", 0); !a.OK || a.Remaining != 0 {
		t.Fatalf("AllowN(0) = %+v", a)
	}
	if a := b.AllowN("a", -3); !a.OK || a.Remaining != 0 {
		t.Fatalf("AllowN(-3) = %+v", a)
	}
	// Allow is AllowN of one: refused now, with the wait for one token.
	if a := b.Allow("a"); a.OK || a.Retry != time.Second {
		t.Fatalf("Allow on empty = %+v", a)
	}
	now = now.Add(time.Minute)
	if a := b.AllowN("a", 11); a.OK || a.Remaining != 10 || a.Retry != time.Second {
		t.Fatalf("AllowN above the burst = %+v", a)
	}
	if a := b.AllowN("a", 10); !a.OK || a.Remaining != 0 {
		t.Fatalf("AllowN of the whole burst = %+v", a)
	}
}

// TestAdjustSettlesAReservation is Lux spec 007's rate window: a
// reservation of estimated tokens settled to the measured count, refunded
// when the estimate was high, debited into a deficit when it was low, and
// refunded whole on a later refusal.
func TestAdjustSettlesAReservation(t *testing.T) {
	now := time.Unix(100, 0)
	b := New(Config{PerMinute: 60, Burst: 10, Idle: time.Second, Now: func() time.Time { return now }})
	// Reserve 8, measure 5: refund 3, leaving 5.
	b.AllowN("a", 8)
	b.Adjust("a", 3)
	if a := b.AllowN("a", 5); !a.OK || a.Remaining != 0 {
		t.Fatalf("after a refund of 3: %+v", a)
	}
	// Reserve the whole burst, measure 15: debit 5 more, into a deficit.
	b.AllowN("b", 10)
	b.Adjust("b", -5)
	if a := b.Allow("b"); a.OK || a.Remaining != 0 || a.Retry != 6*time.Second {
		t.Fatalf("in a deficit of 5: %+v", a)
	}
	// The deficit is covered by the refill before a token is admitted, and
	// a bucket in deficit is never evicted as replenished.
	now = now.Add(2 * time.Second)
	if removed := b.Sweep(); removed != 0 || b.Len() != 2 {
		t.Fatalf("sweep in deficit removed %d, len %d", removed, b.Len())
	}
	if a := b.Allow("b"); a.OK || a.Retry != 4*time.Second {
		t.Fatalf("deficit after 2 s: %+v", a)
	}
	now = now.Add(4 * time.Second)
	if a := b.Allow("b"); !a.OK || a.Remaining != 0 {
		t.Fatalf("deficit covered: %+v", a)
	}
	// A refund is capped at the burst, and a refund of nothing does nothing.
	b.Adjust("b", 1000)
	b.Adjust("c", 0)
	if a := b.AllowN("b", 10); !a.OK || a.Remaining != 0 || b.Allow("b").OK || b.Len() != 2 {
		t.Fatalf("refund past the burst: %+v, len %d", a, b.Len())
	}
	// A refund whole of a refused request: the tokens are back.
	b.AllowN("a", 5)
	b.Adjust("a", 5)
	if a := b.AllowN("a", 5); !a.OK {
		t.Fatalf("refunded whole: %+v", a)
	}
}

// TestPerKeyModeHasNoDefaultBucket: PerMinute zero limits only the keys
// SetRate names and leaves every other key unlimited, rather than
// disabling the limiter.
func TestPerKeyModeHasNoDefaultBucket(t *testing.T) {
	now := time.Unix(100, 0)
	b := New(Config{Idle: time.Second, Now: func() time.Time { return now }})
	if a := b.Allow("x"); !a.OK || a.PerMinute != 0 || b.Len() != 0 || b.Rate("x") != 0 {
		t.Fatalf("an unknown key: %+v, len %d, rate %d", a, b.Len(), b.Rate("x"))
	}
	b.Adjust("x", -100)
	if !b.AllowN("x", 1000).OK || b.Len() != 0 {
		t.Fatal("an unlimited key was charged")
	}
	b.SetRate("x", 2)
	if b.Rate("x") != 2 || b.Len() != 1 {
		t.Fatalf("rate %d, len %d after SetRate", b.Rate("x"), b.Len())
	}
	if a := b.Allow("x"); !a.OK || a.PerMinute != 2 || a.Remaining != 1 {
		t.Fatalf("first of two: %+v", a)
	}
	if a := b.Allow("x"); !a.OK || a.Remaining != 0 {
		t.Fatalf("second of two: %+v", a)
	}
	if a := b.Allow("x"); a.OK || a.Retry != 30*time.Second {
		t.Fatalf("third of two: %+v", a)
	}
	// A settlement applies to a limited key and nobody else.
	b.Adjust("x", 1)
	if !b.Allow("x").OK || !b.Allow("y").OK || b.Len() != 1 {
		t.Fatal("adjust in per-key mode")
	}
	// Once idle and full the key is evicted, rate and all, and is
	// unlimited again until the next SetRate.
	now = now.Add(2 * time.Minute)
	if removed := b.Sweep(); removed != 1 || b.Rate("x") != 0 {
		t.Fatalf("sweep removed %d, rate %d", removed, b.Rate("x"))
	}
	for range 5 {
		if !b.Allow("x").OK {
			t.Fatal("an evicted key stayed limited")
		}
	}
}

// FuzzAllowNAdjust: whatever the key, the charge and the settlement, a
// charge is all or nothing, the bucket never holds more than the burst,
// and a deficit reports no remaining tokens.
func FuzzAllowNAdjust(f *testing.F) {
	f.Add("subject", 3, -2)
	f.Add("", 11, 100)
	f.Add("k", 0, -1000)
	f.Fuzz(func(t *testing.T, key string, n, delta int) {
		const burst = 10
		b := New(Config{PerMinute: 60, Burst: burst, Now: func() time.Time { return time.Unix(100, 0) }})
		a := b.AllowN(key, n)
		switch {
		case n <= 0 && (!a.OK || a.Remaining != burst):
			t.Fatalf("a charge of %d: %+v", n, a)
		case n > burst && (a.OK || a.Remaining != burst):
			t.Fatalf("a charge above the burst: %+v", a)
		case n > 0 && n <= burst && (!a.OK || a.Remaining != burst-n):
			t.Fatalf("a charge of %d: %+v", n, a)
		}
		b.Adjust(key, delta)
		after := b.AllowN(key, 0)
		if after.Remaining > burst || after.Remaining < 0 {
			t.Fatalf("after Adjust(%d): %+v", delta, after)
		}
	})
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
