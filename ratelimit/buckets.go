// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// Package ratelimit provides keyed token buckets with idle eviction.
package ratelimit

import (
	"math"
	"sync"
	"time"
)

// Config controls the default quota. Each accepted call consumes one token.
type Config struct {
	// PerMinute is the refill rate. Nonpositive values disable admission limits.
	PerMinute int
	// Burst is the capacity, defaulting to PerMinute when nonpositive.
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
	Retry     time.Duration // until one token is available, rounded up to a nanosecond
	PerMinute int           // zero when disabled
	Remaining int           // whole tokens remaining after the decision
}

type bucket struct {
	tokens           float64
	updated, touched time.Time
	rate             int
}

// Buckets is safe for concurrent use. A nil receiver or zero value is disabled.
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

func (b *Buckets) enabled() bool { return b != nil && b.config.PerMinute > 0 }

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
func (b *Buckets) Allow(key string) Allowance {
	if !b.enabled() {
		return Allowance{OK: true}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.clock()
	b.sweepIdle(now)
	e := b.entry(key, now)
	rate, _ := b.quota(e)
	result := Allowance{PerMinute: rate}
	if e.tokens >= 1 {
		e.tokens--
		result.OK = true
	} else {
		ns := math.Ceil((1 - e.tokens) * float64(time.Minute) / float64(rate))
		result.Retry = time.Duration(max(ns, 1))
	}
	result.Remaining = int(e.tokens)
	return result
}

// SetRate overrides key's refill rate and burst with perMinute. Nonpositive
// values are ignored. Reapplying the same rate does not replenish tokens;
// increasing it fills the new burst, decreasing it preserves accrued tokens
// up to the new burst. Rate updates count as activity for idle eviction.
func (b *Buckets) SetRate(key string, perMinute int) {
	if !b.enabled() || perMinute <= 0 {
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

// Rate reports key's override or the default refill rate, zero when disabled.
func (b *Buckets) Rate(key string) int {
	if !b.enabled() {
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
	if !b.enabled() {
		return 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.sweep(b.clock())
}

// Len reports the current number of retained keys without triggering eviction.
func (b *Buckets) Len() int {
	if !b.enabled() {
		return 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.entries)
}
