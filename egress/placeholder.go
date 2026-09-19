// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package egress

import "latere.ai/x/pkg/egress/placeholder"

// MintPlaceholder returns a fresh placeholder. It is placeholder.Mint, kept
// here so the gateway's callers mint and substitute through one import; a
// package that must not depend on the gateway imports the subpackage.
func MintPlaceholder() string { return placeholder.Mint() }

// IsPlaceholder reports whether s has the placeholder shape. It is
// placeholder.Is; see MintPlaceholder.
func IsPlaceholder(s string) bool { return placeholder.Is(s) }
