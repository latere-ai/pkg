// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// Package s3 is a client for the S3 REST API in the standard library,
// signed with Signature Version 4 and checked against the signing
// documentation's published vectors. It carries exactly the primitives
// Latere services use against an S3 compatible store and nothing more:
// put, create-if-absent, get with If-None-Match, head, delete, a prefixed
// listing, and presigned GET and PUT URLs. A service that needs another
// call adds it here rather than a cloud SDK.
//
// # What the providers honour
//
// The primitives were verified on MinIO and on Spaces; the report is
// docs/spikes/2026-09-06-conditional-writes.md in the origo repository.
// What it found that a caller must design around:
//
//   - PUT If-Match is not portable. MinIO honours it; Spaces answers 412
//     to every If-Match, including one carrying the ETag it returned a
//     moment earlier. This package has no If-Match on PUT, and its s3test
//     fake answers 412 to one, so a design that needs compare-and-swap
//     fails in the unit suite rather than on one provider. Linearize
//     writers with [Client.CreateObject] on an immutable key instead.
//   - PUT If-None-Match: * is portable: a 412 means the key existed and
//     the object is untouched, on both providers and under a race of many
//     writers per key.
//   - A conditional GET answers 304 and a HEAD of an absent key answers
//     404 on both providers, and the HEAD is the cheapest round trip.
//   - A write whose response is lost in transport may have been applied.
//     Under load a 412 can close a pooled connection while another
//     request is in flight on it; that request fails on the client side
//     though the store applied exactly one write. A caller that needs to
//     know reads the key back after a transport error on
//     [Client.CreateObject].
//   - ETag values are returned as the provider sends them, with quotes on
//     MinIO. Compare them with the quotes trimmed.
//
// # Errors
//
// A refused request is an [*Error] with the status and the code the XML
// body carried. Three outcomes the callers branch on are sentinels that
// [errors.Is] matches: [ErrNotFound], [ErrPreconditionFailed], and
// [ErrNotModified]. A 5xx or a transport failure is retried under the
// policy given to [WithRetry]; a 4xx is never retried.
//
// # Telemetry
//
// The client sends through the [http.Client] given to [WithHTTPClient],
// so a service passes its instrumented client. The default is a client
// over a clone of [http.DefaultTransport].
package s3
