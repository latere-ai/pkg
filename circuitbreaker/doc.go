// Package circuitbreaker provides two fault isolation implementations for
// protecting against cascading failures.
//
// [Breaker] is a lock-free, three-state (closed/open/half-open) circuit breaker
// using atomic operations for high-throughput paths. [BackoffBreaker] is a
// simpler mutex-based implementation with exponential backoff for cases where
// per-caller isolation is needed. Both track consecutive failures and
// temporarily block operations when the failure threshold is exceeded.
//
// # Usage
//
//	cb := circuitbreaker.New(5, 30*time.Second)
//	if cb.Allow() {
//	    err := launch()
//	    if err != nil { cb.RecordFailure() } else { cb.RecordSuccess() }
//	}
package circuitbreaker
