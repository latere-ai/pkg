// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

func TestNewFileTokenStore_EmptyPath(t *testing.T) {
	if _, err := NewFileTokenStore(""); err == nil {
		t.Fatal("expected error for empty path")
	}
}

func TestNewFileTokenStore_Valid(t *testing.T) {
	s, err := NewFileTokenStore(filepath.Join(t.TempDir(), "tok.json"))
	if err != nil {
		t.Fatal(err)
	}
	if s.Path == "" {
		t.Fatal("Path empty")
	}
}

func TestDefaultFileTokenStorePath(t *testing.T) {
	got, err := DefaultFileTokenStorePath()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(got, filepath.Join("latere", "token.json")) {
		t.Fatalf("path = %q, want suffix latere/token.json", got)
	}
}

func TestDefaultFileTokenStorePath_NoConfigDir(t *testing.T) {
	// Clearing every variable os.UserConfigDir consults across platforms
	// drives it to report an error. Skip if the platform still resolves
	// (e.g. Windows %AppData% lookups fall back to default registry paths).
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("HOME", "")
	t.Setenv("AppData", "")
	t.Setenv("LocalAppData", "")
	_, err := DefaultFileTokenStorePath()
	if err == nil {
		t.Skip("platform still resolves UserConfigDir without env vars")
	}
}

func TestFileTokenStore_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "token.json") // sub dir is created lazily
	s, _ := NewFileTokenStore(path)

	want := &oauth2.Token{
		AccessToken:  "at-1",
		RefreshToken: "rt-1",
		TokenType:    "Bearer",
		Expiry:       time.Now().Add(1 * time.Hour).UTC().Truncate(time.Second),
	}
	if err := s.Save(want); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := s.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got == nil {
		t.Fatal("Load returned nil")
	}
	if got.AccessToken != want.AccessToken ||
		got.RefreshToken != want.RefreshToken ||
		got.TokenType != want.TokenType ||
		!got.Expiry.Equal(want.Expiry) {
		t.Fatalf("token mismatch: got %+v want %+v", got, want)
	}
}

func TestFileTokenStore_Permissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "token.json")
	s, _ := NewFileTokenStore(path)
	if err := s.Save(&oauth2.Token{AccessToken: "x"}); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm() & 0o077; got != 0 {
		t.Fatalf("token file is group/other-readable: mode %v", info.Mode().Perm())
	}

	parent, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if got := parent.Mode().Perm() & 0o077; got != 0 {
		t.Fatalf("token parent dir is group/other-accessible: mode %v", parent.Mode().Perm())
	}
}

func TestFileTokenStore_LoadMissing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nope.json")
	s, _ := NewFileTokenStore(path)
	tok, err := s.Load()
	if err != nil {
		t.Fatalf("Load on missing: %v", err)
	}
	if tok != nil {
		t.Fatalf("Load on missing returned %+v, want nil", tok)
	}
}

func TestFileTokenStore_LoadEmpty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.json")
	if err := os.WriteFile(path, []byte{}, 0o600); err != nil {
		t.Fatal(err)
	}
	s, _ := NewFileTokenStore(path)
	tok, err := s.Load()
	if err != nil {
		t.Fatalf("Load on empty: %v", err)
	}
	if tok != nil {
		t.Fatalf("Load on empty returned %+v, want nil", tok)
	}
}

func TestFileTokenStore_LoadCorrupt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(path, []byte("not-json"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, _ := NewFileTokenStore(path)
	if _, err := s.Load(); err == nil {
		t.Fatal("expected parse error")
	}
}

func TestFileTokenStore_LoadUnreadable(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o000); err != nil {
		t.Skip("cannot chmod tempdir on this platform")
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	s, _ := NewFileTokenStore(filepath.Join(dir, "x.json"))
	_, err := s.Load()
	if err == nil {
		// Some platforms (windows in CI) still allow the read; accept either.
		return
	}
	if errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected non-NotExist error, got %v", err)
	}
}

func TestFileTokenStore_SaveNil(t *testing.T) {
	s, _ := NewFileTokenStore(filepath.Join(t.TempDir(), "x.json"))
	if err := s.Save(nil); err == nil {
		t.Fatal("expected error saving nil")
	}
}

func TestFileTokenStore_Clear(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tok.json")
	s, _ := NewFileTokenStore(path)
	if err := s.Save(&oauth2.Token{AccessToken: "x"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Clear(); err != nil {
		t.Fatal(err)
	}
	tok, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if tok != nil {
		t.Fatalf("Load after Clear returned %+v, want nil", tok)
	}
	// idempotent
	if err := s.Clear(); err != nil {
		t.Fatalf("Clear on missing: %v", err)
	}
}

func TestFileTokenStore_SaveDirCreateFails(t *testing.T) {
	// Point at a path whose "parent" is actually a file → MkdirAll fails.
	tmp := t.TempDir()
	blocker := filepath.Join(tmp, "blocker")
	if err := os.WriteFile(blocker, []byte("file-not-dir"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, _ := NewFileTokenStore(filepath.Join(blocker, "deep", "token.json"))
	if err := s.Save(&oauth2.Token{AccessToken: "x"}); err == nil {
		t.Fatal("expected MkdirAll error")
	}
}

func TestFileTokenStore_SaveRenameFails(t *testing.T) {
	// The target path is a non-empty directory, so the atomic rename of the
	// temp file onto it fails and the temp file is cleaned up.
	tmp := t.TempDir()
	target := filepath.Join(tmp, "token.json")
	if err := os.MkdirAll(filepath.Join(target, "child"), 0o700); err != nil {
		t.Fatal(err)
	}
	s, _ := NewFileTokenStore(target)
	if err := s.Save(&oauth2.Token{AccessToken: "x"}); err == nil {
		t.Fatal("expected rename error")
	}
	entries, err := os.ReadDir(tmp)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".token-") {
			t.Fatalf("temp file %s left behind", e.Name())
		}
	}
}

func TestFileTokenStore_SaveTempCreateFails(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	tmp := t.TempDir()
	dir := filepath.Join(tmp, "ro")
	if err := os.Mkdir(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	s, _ := NewFileTokenStore(filepath.Join(dir, "token.json"))
	if err := s.Save(&oauth2.Token{AccessToken: "x"}); err == nil {
		t.Fatal("expected temp-file creation error in a read-only dir")
	}
}

func TestFileTokenStore_ClearRemoveFails(t *testing.T) {
	// A non-empty directory at the token path cannot be removed with
	// os.Remove, and that is not a not-exist condition.
	tmp := t.TempDir()
	target := filepath.Join(tmp, "token.json")
	if err := os.MkdirAll(filepath.Join(target, "child"), 0o700); err != nil {
		t.Fatal(err)
	}
	s, _ := NewFileTokenStore(target)
	if err := s.Clear(); err == nil {
		t.Fatal("expected remove error")
	}
}
