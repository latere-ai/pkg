// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// Package pagination provides a generic cursor-based pagination helper for
// pre-sorted slices.
//
// Cursors stay stable as items are added, which offset-based pagination does
// not: an offset shifts under any insertion ahead of it, so a client walking an
// event timeline sees duplicates or gaps. [Paginate] takes a sorted slice,
// applies cursor positioning, filtering, and limit clamping, and returns a
// [Page] with items, next cursor, and total count.
//
// # Usage
//
//	page := pagination.Paginate(items, cursor, afterCursor, limit, 50, 200, nil)
//	// page.Items, page.NextCursor, page.HasMore, page.TotalFiltered
package pagination
