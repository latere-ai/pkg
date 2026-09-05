// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// Package relpath answers one question: does a caller-supplied path stay
// under the directory it is meant for. A traversal ("../x"), an absolute
// path, or an embedded NUL must not escape the base, and a symlink inside the
// base must not point out of it. Path validation is security-sensitive and
// was re-derived per caller with slightly different coverage; this is the
// single source of truth.
package relpath

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"syscall"
)

// Clean validates a forward-slash relative path and returns its cleaned
// forward-slash form. It rejects an empty path, an embedded NUL, an absolute
// path, and any path that escapes its root through "..". A caller that needs
// an on-disk location joins the result under a base with [Join].
func Clean(rel string) (string, error) {
	switch {
	case rel == "":
		return "", errors.New("relpath: empty path")
	case strings.IndexByte(rel, 0) >= 0:
		return "", fmt.Errorf("relpath: %q contains NUL", rel)
	case path.IsAbs(rel):
		return "", fmt.Errorf("relpath: %q is absolute", rel)
	}
	clean := path.Clean(rel)
	if clean == ".." || strings.HasPrefix(clean, "../") {
		return "", fmt.Errorf("relpath: %q escapes its root", rel)
	}
	return clean, nil
}

// Join joins rel under base and verifies lexically that the result stays
// under base. rel is OS-native, so a forward-slash value from [Clean] goes
// through [filepath.FromSlash] first. The check is defence in depth for a
// rel that was validated by Clean and a hard guard for one that was not.
func Join(base, rel string) (string, error) {
	base = filepath.Clean(base)
	target := filepath.Join(base, rel)
	if !containsLexically(base, target) {
		return "", fmt.Errorf("relpath: %q escapes %q", rel, base)
	}
	return target, nil
}

// Contains reports whether target is root or lies inside root once both are
// absolute and symlinks are resolved. root must exist. target need not: the
// longest existing prefix of target is resolved and the rest is appended
// unchanged, so a file about to be created is judged by the directory it
// will land in. An unresolved symlink returns an error, even if its target
// does not exist, because discarding the link would hide an escape.
//
// On macOS /tmp is a symlink to /private/tmp, so a lexical prefix test
// against an unresolved root is wrong in both directions. Contains resolves
// both sides.
func Contains(root, target string) (bool, error) {
	r, err := filepath.Abs(root)
	if err != nil {
		return false, err
	}
	r, err = filepath.EvalSymlinks(r)
	if err != nil {
		return false, err
	}
	t, err := filepath.Abs(target)
	if err != nil {
		return false, err
	}
	t, err = resolveExisting(t)
	if err != nil {
		return false, err
	}
	return containsLexically(r, t), nil
}

func containsLexically(root, target string) bool {
	rel, err := filepath.Rel(root, target)
	return err == nil && filepath.IsLocal(rel)
}

// resolveExisting resolves symlinks in the longest existing prefix of the
// absolute path p and re-attaches the remainder unchanged.
func resolveExisting(p string) (string, error) {
	rest := ""
	for {
		resolved, err := filepath.EvalSymlinks(p)
		if err == nil {
			return filepath.Join(resolved, rest), nil
		}
		if !errors.Is(err, fs.ErrNotExist) && !errors.Is(err, syscall.ENOTDIR) {
			return "", err
		}
		// EvalSymlinks also reports ENOENT for a dangling link. It is an
		// existing path component, so never strip it as if it were absent.
		info, statErr := os.Lstat(p)
		if statErr == nil && info.Mode()&fs.ModeSymlink != 0 {
			return "", err
		}
		if statErr != nil && !errors.Is(statErr, fs.ErrNotExist) && !errors.Is(statErr, syscall.ENOTDIR) {
			return "", statErr
		}
		parent := filepath.Dir(p)
		if parent == p {
			return "", err
		}
		rest = filepath.Join(filepath.Base(p), rest)
		p = parent
	}
}
