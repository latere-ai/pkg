// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// Package ratelimit provides keyed token buckets with idle eviction.
//
// A bucket holds up to Burst tokens and refills at PerMinute. Allow takes
// one token, AllowN takes n at once or none, and Adjust gives tokens back
// or takes more, which is how a caller that must charge before it knows
// the cost settles: it reserves an estimate with AllowN, measures, and
// Adjusts by the difference, a refund when it over-estimated and a further
// debit, into a deficit the refill must cover first, when it under-
// estimated.
//
// Config.PerMinute selects one of three modes. Positive is a default
// bucket for every key, with SetRate overriding one key's rate. Zero is no
// default bucket: a key with no SetRate is unlimited and a key with one is
// limited to it, which is a limiter whose rates arrive per key from
// elsewhere. Negative disables the limiter: every key is unlimited and
// SetRate is ignored.
package ratelimit

import (
	"math"
	"sync"
	"time"
)

// Config controls the default quota. Each accepted call consumes one token.
type Config struct {
	// PerMinute is the default refill rate. Zero means no default bucket: a
	// key is unlimited until SetRate gives it a rate. Negative disables the
	// limiter.
	PerMinute int
	// Burst is the default capacity, defaulting to PerMinute when
	// nonpositive. A key with its own rate has that rate as its burst, so
	// Burst is unused when PerMinute is zero.
	Burst int
	// Idle is the quiet period before eviction; nonpositive defaults to ten
	// minutes. A depleted bucket is retained until fully refilled, so eviction
	// cannot reset a quota. This bounds retention, not peak key cardinality.
	Idle time.Duration
	// Now supplies a clock, defaulting to time.Now. Calls are serialized.
	Now func() time.Time
}

// Allowance is the decision and quota snapshot from one admission check.
type Allowance struct {
	OK        bool
	Retry     time.Duration // until the tokens asked for are available, rounded up to a nanosecond
	PerMinute int           // zero when the key is unlimited
	Remaining int           // whole tokens remaining after the decision; zero in a deficit
}

type bucket struct {
	tokens           float64
	updated, touched time.Time
	rate             int
}

// Buckets is safe for concurrent use. A nil receiver is disabled; the zero
// value has no default bucket and limits only the keys SetRate names.
// Expiry runs opportunistically on admission and updates, or explicitly via
// Sweep; it uses no background goroutine. Keys are opaque strings.
type Buckets struct {
	mu          sync.Mutex
	config      Config
	entries     map[string]*bucket
	last, swept time.Time
}

// New creates a keyed limiter with initially full buckets.
func New(config Config) *Buckets {
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.Burst <= 0 {
		config.Burst = max(config.PerMinute, 1)
	}
	if config.Idle <= 0 {
		config.Idle = 10 * time.Minute
	}
	return &Buckets{config: config, entries: make(map[string]*bucket)}
}

// disabled reports a limiter that admits everything: a nil receiver or a
// negative PerMinute.
func (b *Buckets) disabled() bool { return b == nil || b.config.PerMinute < 0 }

// perKey reports the mode with no default bucket, PerMinute zero.
func (b *Buckets) perKey() bool { return b.config.PerMinute == 0 }

// clock reads a monotonic view of the supplied clock while holding b.mu.
func (b *Buckets) clock() time.Time {
	now := b.config.Now()
	if now.Before(b.last) {
		return b.last
	}
	b.last = now
	return now
}

func (b *Buckets) quota(e *bucket) (int, int) {
	if e.rate > 0 {
		return e.rate, e.rate
	}
	return b.config.PerMinute, b.config.Burst
}

func (b *Buckets) refill(e *bucket, now time.Time) {
	rate, burst := b.quota(e)
	e.tokens = min(float64(burst), e.tokens+now.Sub(e.updated).Minutes()*float64(rate))
	e.updated = now
}

func (b *Buckets) entry(key string, now time.Time) *bucket {
	e, ok := b.entries[key]
	if !ok {
		e = &bucket{tokens: float64(b.config.Burst), updated: now}
		b.entries[key] = e
	}
	b.refill(e, now)
	e.touched = now
	return e
}

// bucketFor is key's bucket for an admission or a settlement: the default
// one, created for an unknown key, or nil when the key is unlimited
// because the per-key mode has no default bucket to create.
func (b *Buckets) bucketFor(key string, now time.Time) *bucket {
	if b.perKey() {
		if _, ok := b.entries[key]; !ok {
			return nil
		}
	}
	return b.entry(key, now)
}

func (b *Buckets) sweep(now time.Time) int {
	removed := 0
	for key, e := range b.entries {
		if now.Sub(e.touched) < b.config.Idle {
			continue
		}
		b.refill(e, now)
		_, burst := b.quota(e)
		if e.tokens >= float64(burst) {
			delete(b.entries, key)
			removed++
		}
	}
	b.swept = now
	return removed
}

func (b *Buckets) sweepIdle(now time.Time) {
	if now.Sub(b.swept) >= b.config.Idle {
		b.sweep(now)
	}
}

// Allow consumes one token for key, or reports the wait until the next token.
func (b *Buckets) Allow(key string) Allowance { return b.AllowN(key, 1) }

// AllowN consumes n tokens for key at once, all or nothing, or consumes
// nothing and reports the wait until n are available. n of 1 is Allow; n
// below 1 consumes nothing and is allowed. n above the burst is refused on
// every call, Retry the time n tokens would take to accrue, because the
// bucket never holds that many; a caller that reserves an estimate bounds
// it by Rate.
func (b *Buckets) AllowN(key string, n int) Allowance {
	if b.disabled() {
		return Allowance{OK: true}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.clock()
	b.sweepIdle(now)
	e := b.bucketFor(key, now)
	if e == nil {
		return Allowance{OK: true}
	}
	rate, _ := b.quota(e)
	result := Allowance{PerMinute: rate}
	want := float64(max(n, 0))
	if e.tokens >= want {
		e.tokens -= want
		result.OK = true
	} else {
		ns := math.Ceil((want - e.tokens) * float64(time.Minute) / float64(rate))
		result.Retry = time.Duration(max(ns, 1))
	}
	result.Remaining = max(int(e.tokens), 0)
	return result
}

// Adjust adds delta tokens to key's bucket, which is how a reservation is
// settled: a negative delta debits past zero into a deficit that later
// refills cover before the next Allow succeeds, and a positive one refunds
// up to the burst. An unlimited key is left alone, and so is a disabled
// limiter.
func (b *Buckets) Adjust(key string, delta int) {
	if b.disabled() || delta == 0 {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.clock()
	b.sweepIdle(now)
	e := b.bucketFor(key, now)
	if e == nil {
		return
	}
	_, burst := b.quota(e)
	e.tokens = min(float64(burst), e.tokens+float64(delta))
}

// SetRate overrides key's refill rate and burst with perMinute; in the
// per-key mode it is what makes a key limited at all. Nonpositive values
// are ignored. Reapplying the same rate does not replenish tokens;
// increasing it fills the new burst, decreasing it preserves accrued tokens
// up to the new burst. Rate updates count as activity for idle eviction,
// and an evicted key's rate goes with it, so a caller whose rates arrive
// per request sets the rate before each Allow.
func (b *Buckets) SetRate(key string, perMinute int) {
	if b.disabled() || perMinute <= 0 {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.clock()
	b.sweepIdle(now)
	e := b.entry(key, now)
	if e.rate == perMinute {
		return
	}
	oldRate, _ := b.quota(e)
	if e.rate == 0 || perMinute > oldRate {
		e.tokens = float64(perMinute)
	} else {
		e.tokens = min(e.tokens, float64(perMinute))
	}
	e.rate = perMinute
}

// Rate reports key's override or the default refill rate, zero when the
// key is unlimited.
func (b *Buckets) Rate(key string) int {
	if b.disabled() {
		return 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if e, ok := b.entries[key]; ok {
		rate, _ := b.quota(e)
		return rate
	}
	return b.config.PerMinute
}

// Sweep evicts idle, fully replenished entries and returns their count.
func (b *Buckets) Sweep() int {
	if b.disabled() {
		return 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.sweep(b.clock())
}

// Len reports the current number of retained keys without triggering eviction.
func (b *Buckets) Len() int {
	if b.disabled() {
		return 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.entries)
}
