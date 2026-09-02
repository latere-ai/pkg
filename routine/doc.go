// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// Package routine schedules periodic fire-and-forget callbacks keyed by UUID.
//
// Each routine owns one [time.AfterFunc] timer, arms it according to a
// [Schedule], and invokes a caller-supplied [FireFunc] when the timer elapses.
// One timer per routine replaces the singleton cronjob loop this generalizes,
// so routines with unrelated periods do not share a tick.
//
// The package is stateless with respect to persistence: it knows nothing about
// what a routine does or where it is stored. A caller reconciles the engine
// with external state through [Engine.Register] and [Engine.Unregister], and
// adds new [Schedule] implementations (cron expressions, time-of-day) without
// changing this package.
package routine
