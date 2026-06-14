package batch

import (
	"context"
	"sync"
	"testing"
	"time"
)

type sink struct {
	mu      sync.Mutex
	batches [][]int
}

func (s *sink) flush(_ context.Context, batch []int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := append([]int(nil), batch...)
	s.batches = append(s.batches, cp)
}

func (s *sink) total() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, b := range s.batches {
		n += len(b)
	}
	return n
}

func TestNew_PanicsOnNilFlush(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("New should panic when Flush is nil")
		}
	}()
	_ = New(Config[int]{})
}

func TestNew_AppliesDefaults(t *testing.T) {
	b := New(Config[int]{BatchSize: 0, BufferSize: -1, Flush: func(context.Context, []int) {}})
	if b.batchN != 1 {
		t.Fatalf("BatchSize<1 should default to 1, got %d", b.batchN)
	}
	if cap(b.ch) != 0 {
		t.Fatalf("BufferSize<0 should default to 0, got cap %d", cap(b.ch))
	}
}

func TestBatcher_DrainFlushesWhenBatchFills(t *testing.T) {
	s := &sink{}
	// Small batch, no interval: the cancel-drain loop must itself flush once
	// it has accumulated batchN items, not only at the very end.
	b := New(Config[int]{BufferSize: 10, BatchSize: 2, Flush: s.flush})
	ctx, cancel := context.WithCancel(context.Background())
	for i := range 4 {
		b.Add(i)
	}
	go b.Run(ctx)
	cancel()
	b.Wait()
	if s.total() != 4 {
		t.Fatalf("drain should flush all 4 items, got %d", s.total())
	}
}

func TestBatcher_FlushesOnBatchSize(t *testing.T) {
	s := &sink{}
	b := New(Config[int]{BufferSize: 10, BatchSize: 3, Flush: s.flush})
	ctx, cancel := context.WithCancel(context.Background())
	go b.Run(ctx)
	for i := range 3 {
		b.Add(i)
	}
	// Wait for the size-triggered flush.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) && s.total() < 3 {
		time.Sleep(2 * time.Millisecond)
	}
	cancel()
	b.Wait()
	if s.total() != 3 {
		t.Fatalf("want 3 items flushed, got %d", s.total())
	}
}

func TestBatcher_FlushesOnInterval(t *testing.T) {
	s := &sink{}
	b := New(Config[int]{BufferSize: 10, BatchSize: 100, FlushInterval: 10 * time.Millisecond, Flush: s.flush})
	ctx, cancel := context.WithCancel(context.Background())
	go b.Run(ctx)
	b.Add(1)
	b.Add(2)
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) && s.total() < 2 {
		time.Sleep(2 * time.Millisecond)
	}
	cancel()
	b.Wait()
	if s.total() != 2 {
		t.Fatalf("interval flush: want 2 items, got %d", s.total())
	}
}

func TestBatcher_DrainsTailOnCancel(t *testing.T) {
	s := &sink{}
	b := New(Config[int]{BufferSize: 10, BatchSize: 100, Flush: s.flush})
	ctx, cancel := context.WithCancel(context.Background())
	go b.Run(ctx)
	b.Add(1)
	b.Add(2)
	cancel() // no size/interval trigger; only the final drain can flush these
	b.Wait()
	if s.total() != 2 {
		t.Fatalf("drain-on-cancel: want 2 items, got %d", s.total())
	}
}

func TestBatcher_DropsWhenFull(t *testing.T) {
	// Buffer of 1, never Run: the second Add has nowhere to go.
	b := New(Config[int]{BufferSize: 1, BatchSize: 100, Flush: func(context.Context, []int) {}})
	if !b.Add(1) {
		t.Fatal("first Add should succeed")
	}
	if b.Add(2) {
		t.Fatal("second Add should be dropped when buffer is full")
	}
}
