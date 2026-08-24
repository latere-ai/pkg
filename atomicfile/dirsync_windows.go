//go:build windows

package atomicfile

// syncDir is a no-op on Windows.
//
// There is no portable equivalent of fsync on a directory handle here:
// opening a directory for the purpose and calling Sync fails rather than
// flushing metadata. Making the durable-rename guarantee hold on Windows
// would mean reaching for MoveFileEx with MOVEFILE_WRITE_THROUGH instead of
// os.Rename, which is a different change from this one.
//
// Callers on Windows therefore get [WriteSync]'s temp-file fsync but not the
// directory-entry guarantee. That is weaker than the POSIX behaviour, and it
// is stated rather than papered over.
func syncDir(string) error { return nil }
