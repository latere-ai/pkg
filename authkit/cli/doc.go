// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// Package cli holds the client side of Latere authentication: the pieces a
// command-line or desktop process needs to obtain a token and keep it
// between runs. A server never imports this package, and it is the only
// package in the authkit tree that opens a browser or touches the home
// directory.
//
//   - [DeviceCodeClient] drives the RFC 8628 device-authorization flow
//     against an [oidc.Client] and stores the result.
//   - [TokenStore] and [FileTokenStore] persist an OAuth2 token on disk.
//
// Typical usage:
//
//	store, _ := cli.NewFileTokenStore(path)
//	dev := cli.NewDeviceCodeClient(oidc.New(cfg), store)
//	if err := dev.Login(ctx); err != nil { ... }
package cli
