package pgxmigrate

import (
	"errors"
	"testing"

	"github.com/golang-migrate/migrate/v4"
)

// fakeMigrator records whether Close was called and returns a configured Up error.
type fakeMigrator struct {
	upErr  error
	closed bool
}

func (f *fakeMigrator) Up() error                       { return f.upErr }
func (f *fakeMigrator) Close() (sourceErr, dbErr error) { f.closed = true; return nil, nil }

// TestRunUpClosesOnSuccess reproduces the connection leak the shared package
// exists to prevent: migrate opens its own *sql.DB and must be closed after Up.
func TestRunUpClosesOnSuccess(t *testing.T) {
	f := &fakeMigrator{}
	if err := runUp(f); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !f.closed {
		t.Fatal("migrator was not closed — leaks the migrate-owned *sql.DB")
	}
}

// TestRunUpNoChange confirms ErrNoChange is treated as success and the migrator
// is still closed.
func TestRunUpNoChange(t *testing.T) {
	f := &fakeMigrator{upErr: migrate.ErrNoChange}
	if err := runUp(f); err != nil {
		t.Fatalf("ErrNoChange must be success, got: %v", err)
	}
	if !f.closed {
		t.Fatal("migrator was not closed")
	}
}

// TestRunUpClosesOnError confirms the migrator is closed even when Up fails, so
// the temp pool is not leaked on a failed startup, and the error is wrapped.
func TestRunUpClosesOnError(t *testing.T) {
	boom := errors.New("boom")
	f := &fakeMigrator{upErr: boom}
	err := runUp(f)
	if err == nil {
		t.Fatal("expected error from failed Up")
	}
	if !errors.Is(err, boom) {
		t.Fatalf("error %v does not wrap the cause %v", err, boom)
	}
	if !f.closed {
		t.Fatal("migrator was not closed on the error path")
	}
}
