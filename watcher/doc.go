// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// Package watcher provides a reusable event loop for background goroutines that
// react to wake signals and/or periodic tickers.
//
// Automation goroutines share one shape: wait for a wake signal or a timer tick,
// optionally settle before acting, run an action, and clean up on cancellation.
// [Start] encapsulates it behind a [Config], so a caller supplies the action
// rather than another select/timer/context block. The [WakeSource] interface is
// satisfied by a [pubsub.Hub] wake subscription.
//
// # Usage
//
//	watcher.Start(ctx, watcher.Config{
//	    Wake:        hub,
//	    Interval:    5 * time.Minute,
//	    SettleDelay: 2 * time.Second,
//	    Action:      func(ctx context.Context) { promoteNextTask() },
//	})
package watcher
