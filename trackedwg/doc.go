// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// Package trackedwg provides a sync.WaitGroup wrapper that tracks in-flight
// goroutine labels for observability.
//
// A plain WaitGroup reports how many goroutines are outstanding but not which,
// so a server blocked in graceful shutdown cannot say what it is waiting on.
// [WaitGroup] attaches a string label to each goroutine and [WaitGroup.Pending]
// reports them, formatted as "label×N" when several share a label.
// [WaitGroup.Go] launches a tracked goroutine in one call.
//
// # Usage
//
//	var wg trackedwg.WaitGroup
//	wg.Go("title-gen", func() { generateTitle(taskID) })
//	wg.Go("oversight", func() { generateOversight(taskID) })
//	pending := wg.Pending() // ["oversight", "title-gen"]
//	wg.Wait()
package trackedwg
