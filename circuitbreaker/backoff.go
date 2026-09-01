package circuitbreaker

import (
	"sync"
	"time"

	"latere.ai/x/pkg/retry"
)

// BackoffConfig configures a [BackoffBreaker].
type BackoffConfig struct {
	BaseDelay time.Duration    // initial backoff delay (default: 30s)
	MaxDelay  time.Duration    // maximum backoff delay cap (default: 5min)
	Now       func() time.Time // injectable clock (default: time.Now)
}

// BackoffBreaker is a mutex-based circuit breaker with exponential backoff.
// It is simpler than [Breaker] and suited for per-feature fault isolation
// where lock-free performance is not required.
type BackoffBreaker struct {
	mu        sync.Mutex
	failures  int
	openUntil time.Time // zero means closed (healthy)
	policy    retry.Policy
	now       func() time.Time
}

// NewBackoff creates a BackoffBreaker with the given configuration.
// Zero-valued fields use their defaults.
func NewBackoff(cfg BackoffConfig) *BackoffBreaker {
	if cfg.BaseDelay <= 0 {
		cfg.BaseDelay = 30 * time.Second
	}
	if cfg.MaxDelay <= 0 {
		cfg.MaxDelay = 5 * time.Minute
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &BackoffBreaker{
		// Jitter is off: a breaker's RetryAt is a promise callers schedule
		// against, and the schedule is what its tests pin.
		policy: retry.Policy{Base: cfg.BaseDelay, Max: cfg.MaxDelay, Jitter: -1},
		now:    cfg.Now,
	}
}

// IsOpen reports whether the breaker is currently open (blocking operations).
func (b *BackoffBreaker) IsOpen() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return !b.openUntil.IsZero() && b.now().Before(b.openUntil)
}

// RecordFailure increments the failure counter and opens the breaker for the
// delay [retry.Policy.Delay] gives that failure count: doubling from
// BaseDelay up to MaxDelay. Returns the updated failure count.
func (b *BackoffBreaker) RecordFailure() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.failures++
	b.openUntil = b.now().Add(b.policy.Delay(b.failures))
	return b.failures
}

// RecordSuccess resets the failure counter and closes the breaker.
func (b *BackoffBreaker) RecordSuccess() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.failures = 0
	b.openUntil = time.Time{}
}

// Failures returns the current failure count.
func (b *BackoffBreaker) Failures() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.failures
}

// RetryAt returns the time when the breaker will close and allow retries.
// The bool is false when the breaker is already closed (healthy).
func (b *BackoffBreaker) RetryAt() (time.Time, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.openUntil.IsZero() || !b.now().Before(b.openUntil) {
		return time.Time{}, false
	}
	return b.openUntil, true
}
