// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package drive

// Mode is the access mode of a workspace attachment.
type Mode string

// RO grants a read-only snapshot; RW acquires the exclusive writer.
const (
	RO Mode = "ro"
	RW Mode = "rw"
)

// Valid reports whether the mode is RO or RW.
func (m Mode) Valid() bool { return m == RO || m == RW }
