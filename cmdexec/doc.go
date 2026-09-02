// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// Package cmdexec provides a fluent command builder and transactional command
// sequencer with rollback and deferred cleanup.
//
// [Cmd] wraps os/exec.Cmd with a builder pattern for common operations: setting
// the working directory, capturing stdout/stderr, and running with context. The
// [Git] constructor provides a shorthand for git -C commands. [Tx] sequences
// multiple commands with optional per-step rollback and LIFO deferred cleanup,
// ensuring that partial operations are unwound on failure.
//
// # Usage
//
//	out, err := cmdexec.Git(repoDir, "status", "--porcelain").Output()
//	tx := cmdexec.NewTx()
//	tx.Add(cmdexec.Git(dir, "checkout", "-b", branch))
//	tx.AddWithRollback(cmd, rollbackCmd)
//	tx.Defer(cleanupCmd)
//	err = tx.Run()
package cmdexec
