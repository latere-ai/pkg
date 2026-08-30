// Package keyedmu provides a per-key mutex map for fine-grained locking.
//
// When goroutines operate on different entities concurrently, a single global
// mutex creates unnecessary contention. [Map] maintains a separate sync.Mutex
// per key, so operations on different keys proceed in parallel while operations
// on the same key serialize. It replaces the sync.Map +
// LoadOrStore(&sync.Mutex{}) pattern with a type-safe generic wrapper. The zero
// value is ready to use.
//
// # Usage
//
//	var mu keyedmu.Map[string]
//	mu.Lock(taskID)
//	defer mu.Unlock(taskID)
//	// exclusive access for this taskID
package keyedmu
