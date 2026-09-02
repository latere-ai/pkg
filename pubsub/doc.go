// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// Package pubsub provides a generic fan-out pub/sub hub with a bounded replay
// buffer for reconnecting subscribers.
//
// A publisher hands a value to the [Hub], which fans it out to every current
// subscriber. The replay buffer lets a client that dropped its connection catch
// up on what it missed via [Hub.Since] using monotonic sequence numbers, which
// is what makes the hub usable behind Server-Sent Events. Wake-only subscribers
// ([Hub.SubscribeWake]) receive a signal without the payload, for consumers that
// re-read state themselves rather than consuming the message.
//
// # Usage
//
//	hub := pubsub.NewHub[Delta](pubsub.WithReplayCapacity[Delta](100))
//	hub.Publish(delta)
//	id, ch := hub.Subscribe()
//	defer hub.Unsubscribe(id)
//	for msg := range ch { ... }
package pubsub
