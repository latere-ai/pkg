// Package tail provides a generic function for retaining the last N elements
// of a slice.
//
// Bounded history fields (edit history, retry records) need older entries
// trimmed while the most recent are kept. [Of] returns a sub-slice of the last
// n elements, or the slice unchanged when it is already shorter, so callers do
// not repeat the bounds check.
//
// # Usage
//
//	recent := tail.Of(allRecords, 10) // last 10 records
package tail
