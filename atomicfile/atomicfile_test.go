// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package atomicfile

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

// swapHook replaces a package-level function variable for the duration of a
// test and restores it on cleanup. Returns a pointer so the caller can
// replace the value inline.
func swapHook[T any](t *testing.T, ptr *T, val T) {
	t.Helper()
	orig := *ptr
	*ptr = val
	t.Cleanup(func() { *ptr = orig })
}

// TestWrite_Success validates the happy path: data is written to the target
// path and the temporary file is cleaned up afterward.
func TestWrite_Success(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.txt")
	data := []byte("hello world")

	if err := Write(path, data, 0644); err != nil {
		t.Fatalf("Write: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != string(data) {
		t.Fatalf("got %q, want %q", got, data)
	}

	// Temp file must not remain.
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("temp file should not exist after successful write")
	}
}

// TestWrite_DirNotExist verifies that Write returns an error when the
// parent directory does not exist.
func TestWrite_DirNotExist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "no-such-dir", "file.txt")
	if err := Write(path, []byte("x"), 0644); err == nil {
		t.Fatal("expected error for nonexistent directory")
	}
}

// TestWriteJSON_Success verifies that WriteJSON marshals a value as indented
// JSON and the result can be read back and unmarshaled correctly.
func TestWriteJSON_Success(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "data.json")
	v := map[string]int{"a": 1, "b": 2}

	if err := WriteJSON(path, v, 0644); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var result map[string]int
	if err := json.Unmarshal(got, &result); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if result["a"] != 1 || result["b"] != 2 {
		t.Fatalf("unexpected result: %v", result)
	}
}

// TestWriteJSON_MarshalError verifies that WriteJSON returns an error for
// unmarshalable types (channels) and does not leave a file on disk.
func TestWriteJSON_MarshalError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	// Channels cannot be marshaled to JSON.
	if err := WriteJSON(path, make(chan int), 0644); err == nil {
		t.Fatal("expected marshal error")
	}
	// File must not exist.
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("file should not exist after marshal error")
	}
}

// TestWrite_Overwrite verifies that a second Write to the same path
// atomically replaces the file content.
func TestWrite_Overwrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "file.txt")

	if err := Write(path, []byte("first"), 0644); err != nil {
		t.Fatalf("first Write: %v", err)
	}
	if err := Write(path, []byte("second"), 0644); err != nil {
		t.Fatalf("second Write: %v", err)
	}

	got, _ := os.ReadFile(path)
	if string(got) != "second" {
		t.Fatalf("got %q, want %q", got, "second")
	}
}

// TestWrite_WriteError verifies that a write error is returned and the
// temp file is cleaned up.
func TestWrite_WriteError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.txt")
	injected := errors.New("injected write error")
	swapHook(t, &writeFile, func(_ *os.File, _ []byte) (int, error) {
		return 0, injected
	})

	err := Write(path, []byte("data"), 0644)
	if !errors.Is(err, injected) {
		t.Fatalf("expected injected write error, got %v", err)
	}
	// Target must not exist.
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("target file should not exist after write error")
	}
	// No leftover temp files.
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".tmp-") {
			t.Fatalf("temp file %q was not cleaned up", e.Name())
		}
	}
}

// TestWriteSync_SyncsBeforeRename verifies that WriteSync fsyncs the temp file
// before renaming, so a crash right after the atomic rename cannot leave a
// renamed-but-empty file. The spec.readme writer relies on this durability.
func TestWriteSync_SyncsBeforeRename(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.txt")

	synced := false
	swapHook(t, &syncFile, func(f *os.File) error {
		synced = true
		// Confirm the rename has NOT happened yet: target must be absent.
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Error("rename happened before fsync")
		}
		return f.Sync()
	})

	if err := WriteSync(path, []byte("durable"), 0644); err != nil {
		t.Fatalf("WriteSync: %v", err)
	}
	if !synced {
		t.Fatal("expected the temp file to be fsynced before rename")
	}
	data, _ := os.ReadFile(path)
	if string(data) != "durable" {
		t.Fatalf("content = %q, want %q", data, "durable")
	}
}

// TestWrite_DoesNotSync verifies that the plain Write path (used by the
// append-heavy event/task callers) does NOT fsync, keeping that hot path cheap.
func TestWrite_DoesNotSync(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.txt")

	synced := false
	swapHook(t, &syncFile, func(f *os.File) error {
		synced = true
		return f.Sync()
	})

	if err := Write(path, []byte("fast"), 0644); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if synced {
		t.Fatal("Write should not fsync the temp file")
	}
}

// TestWriteSync_SyncError verifies that an fsync error is returned and the temp
// file is cleaned up (no renamed target).
func TestWriteSync_SyncError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.txt")
	injected := errors.New("injected sync error")
	swapHook(t, &syncFile, func(_ *os.File) error {
		return injected
	})

	err := WriteSync(path, []byte("data"), 0644)
	if !errors.Is(err, injected) {
		t.Fatalf("expected injected sync error, got %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("target file should not exist after sync error")
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".tmp-") {
			t.Fatalf("temp file %q was not cleaned up", e.Name())
		}
	}
}

// TestWrite_CloseError verifies that a close error is returned and the
// temp file is cleaned up.
func TestWrite_CloseError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.txt")
	injected := errors.New("injected close error")
	swapHook(t, &closeFile, func(f *os.File) error {
		_ = f.Close() // actually close the fd to avoid leaks
		return injected
	})

	err := Write(path, []byte("data"), 0644)
	if !errors.Is(err, injected) {
		t.Fatalf("expected injected close error, got %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("target file should not exist after close error")
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".tmp-") {
			t.Fatalf("temp file %q was not cleaned up", e.Name())
		}
	}
}

// TestWrite_ChmodError verifies that a chmod error is returned and the
// temp file is cleaned up.
func TestWrite_ChmodError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.txt")
	injected := errors.New("injected chmod error")
	swapHook(t, &chmodPath, func(string, os.FileMode) error { return injected })

	err := Write(path, []byte("data"), 0644)
	if !errors.Is(err, injected) {
		t.Fatalf("expected injected chmod error, got %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("target file should not exist after chmod error")
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".tmp-") {
			t.Fatalf("temp file %q was not cleaned up", e.Name())
		}
	}
}

// TestWrite_RenameError verifies that a rename error is returned and the
// temp file is cleaned up.
func TestWrite_RenameError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.txt")
	injected := errors.New("injected rename error")
	swapHook(t, &renamePath, func(string, string) error { return injected })

	err := Write(path, []byte("data"), 0644)
	if !errors.Is(err, injected) {
		t.Fatalf("expected injected rename error, got %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("target file should not exist after rename error")
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".tmp-") {
			t.Fatalf("temp file %q was not cleaned up", e.Name())
		}
	}
}

// TestWrite_Concurrent verifies that concurrent writes to the same path
// do not corrupt the file -- exactly one writer's content should survive.
func TestWrite_Concurrent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "concurrent.txt")
	const n = 20
	var wg sync.WaitGroup
	wg.Add(n)
	for i := range n {
		go func(i int) {
			defer wg.Done()
			data := []byte{byte('A' + i)}
			_ = Write(path, data, 0644)
		}(i)
	}
	wg.Wait()

	// File must contain exactly one byte (one of the writers won).
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 byte, got %d", len(got))
	}
}

// WriteSync's contract is durability, not just atomicity. Syncing the temp file
// alone is not enough: until the containing directory is synced the rename can
// be recovered away, which is exactly the loss the fsync was meant to prevent.
func TestWriteSyncSyncsTheContainingDirectory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "durable.txt")

	var synced []string
	orig := syncDirAt
	syncDirAt = func(d string) error {
		synced = append(synced, d)
		return nil
	}
	t.Cleanup(func() { syncDirAt = orig })

	if err := WriteSync(path, []byte("payload"), 0o644); err != nil {
		t.Fatalf("WriteSync: %v", err)
	}
	if len(synced) != 1 || synced[0] != dir {
		t.Fatalf("directories synced = %v, want exactly [%s]", synced, dir)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "payload" {
		t.Fatalf("ReadFile = %q, %v", got, err)
	}
}

// Write is the throughput path and deliberately trades durability away, so it
// must not pay for a directory fsync it does not promise.
func TestWriteDoesNotSyncTheContainingDirectory(t *testing.T) {
	dir := t.TempDir()

	called := false
	orig := syncDirAt
	syncDirAt = func(string) error {
		called = true
		return nil
	}
	t.Cleanup(func() { syncDirAt = orig })

	if err := Write(filepath.Join(dir, "fast.txt"), []byte("payload"), 0o644); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if called {
		t.Fatal("Write fsynced the directory; that cost belongs to WriteSync only")
	}
}

// A directory sync that fails leaves a file that exists but may not survive a
// crash. That is worth reporting, and the file is deliberately left in place:
// the write did happen.
func TestWriteSyncReportsDirectorySyncFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "durable.txt")

	orig := syncDirAt
	syncDirAt = func(string) error { return errors.New("no space left on device") }
	t.Cleanup(func() { syncDirAt = orig })

	err := WriteSync(path, []byte("payload"), 0o644)
	if err == nil {
		t.Fatal("expected the directory-sync failure to be reported")
	}
	if !strings.Contains(err.Error(), "no space left") {
		t.Fatalf("err = %v, want the underlying sync error", err)
	}
	if got, rerr := os.ReadFile(path); rerr != nil || string(got) != "payload" {
		t.Fatalf("file should still be in place: ReadFile = %q, %v", got, rerr)
	}
}

// The real syncDir must work against an ordinary directory on this platform.
// On Windows it is a documented no-op and still returns nil.
func TestSyncDirOnRealDirectory(t *testing.T) {
	if err := syncDir(t.TempDir()); err != nil {
		t.Fatalf("syncDir on a real directory: %v", err)
	}
}

// A directory that cannot be opened is reported rather than being mistaken for
// a successful sync. (No-op on Windows, where syncDir never opens anything.)
func TestSyncDirOnMissingDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("syncDir is a documented no-op on Windows")
	}
	err := syncDir(filepath.Join(t.TempDir(), "does-not-exist"))
	if err == nil {
		t.Fatal("expected an error for a directory that cannot be opened")
	}
}
