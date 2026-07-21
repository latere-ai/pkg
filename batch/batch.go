// Package batch provides a generic, non-blocking batching pump: producers
// Add items without ever blocking (a full intake buffer drops the item and
// reports it), while a single Run goroutine accumulates items and hands them to
// a caller-supplied flush function in batches — either when the batch reaches a
// size threshold, at a fixed interval, or as a final drain when Run's context
// is cancelled.
//
// It centralizes a batching loop whose correctness is easy to get subtly wrong:
// the drain-on-shutdown path that still flushes the tail after cancellation, the
// size-vs-interval-vs-drain select, and the drop-on-full intake. The flush
// function receives Run's context so it can carry request values, detach from
// cancellation (context.WithoutCancel), and apply its own per-flush timeout; the
// batcher itself stays oblivious to what a flush does.
//
// A Batcher is safe for many concurrent producers calling Add; Run must be
// called exactly once.
package batch

import (
	"context"
	"sync"
	"time"
)

// Config parameterizes a Batcher. Flush is required; the rest default.
type Config[T any] struct {
	// BufferSize is the capacity of the intake buffer. Add drops items when it
	// is full. A non-positive value yields an unbuffered intake.
	BufferSize int
	// BatchSize flushes the accumulated batch once it reaches this many items.
	// A value below 1 is treated as 1 (flush every item).
	BatchSize int
	// FlushInterval flushes a non-empty batch at least this often. A
	// non-positive value disables time-based flushing (flush only on batch
	// size or final drain).
	FlushInterval time.Duration
	// Flush hands one batch to the caller. It is never called with an empty
	// batch. The context is Run's context (already cancelled during the final
	// drain); the callback decides how to handle that.
	//
	// The batch slice is only valid for the duration of the call: Run reuses
	// its backing array for the next batch. A Flush that retains the slice
	// beyond the call (e.g. hands it to a goroutine) must copy it first.
	Flush func(ctx context.Context, batch []T)
}

// Batcher accumulates items added via Add and flushes them in batches from its
// Run loop. The zero value is not usable; construct one with New.
type Batcher[T any] struct {
	ch       chan T
	batchN   int
	flushInt time.Duration
	flush    func(ctx context.Context, batch []T)
	done     chan struct{}
	intakeMu sync.Mutex
	stopped  bool
}

// New builds a Batcher from cfg. It panics if cfg.Flush is nil, which is always
// a programming error.
func New[T any](cfg Config[T]) *Batcher[T] {
	if cfg.Flush == nil {
		panic("batch: Config.Flush must be set")
	}
	if cfg.BatchSize < 1 {
		cfg.BatchSize = 1
	}
	if cfg.BufferSize < 0 {
		cfg.BufferSize = 0
	}
	return &Batcher[T]{
		ch:       make(chan T, cfg.BufferSize),
		batchN:   cfg.BatchSize,
		flushInt: cfg.FlushInterval,
		flush:    cfg.Flush,
		done:     make(chan struct{}),
	}
}

// Add enqueues item without waiting for buffer capacity. It returns false if
// the intake buffer is full or shutdown has begun.
func (b *Batcher[T]) Add(item T) bool {
	b.intakeMu.Lock()
	defer b.intakeMu.Unlock()
	if b.stopped {
		return false
	}
	select {
	case b.ch <- item:
		return true
	default:
		return false
	}
}

// Run consumes items until ctx is cancelled, flushing on batch size or
// interval, then drains the buffer and performs a final flush. It closes the
// done channel on return (see Wait) and must be called exactly once.
func (b *Batcher[T]) Run(ctx context.Context) {
	defer close(b.done)
	var tick <-chan time.Time
	if b.flushInt > 0 {
		t := time.NewTicker(b.flushInt)
		defer t.Stop()
		tick = t.C
	}
	batch := make([]T, 0, b.batchN)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		b.flush(ctx, batch)
		batch = batch[:0]
	}
	for {
		select {
		case <-ctx.Done():
			b.intakeMu.Lock()
			b.stopped = true
			b.intakeMu.Unlock()
			for {
				select {
				case item := <-b.ch:
					batch = append(batch, item)
					if len(batch) >= b.batchN {
						flush()
					}
				default:
					flush()
					return
				}
			}
		case item := <-b.ch:
			batch = append(batch, item)
			if len(batch) >= b.batchN {
				flush()
			}
		case <-tick:
			flush()
		}
	}
}

// Wait blocks until Run has returned (after its final flush).
func (b *Batcher[T]) Wait() { <-b.done }
