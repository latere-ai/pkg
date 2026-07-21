package pgxmigrate

import (
	"errors"
	"testing"
	"testing/fstest"
	"time"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/source"
)

// stubOpen replaces the migrator constructor for the duration of a test and
// restores it afterward, so the retry loop can be exercised without a database.
func stubOpen(t *testing.T, fn func(source.Driver, string) (migrator, error)) {
	t.Helper()
	prev := newMigrator
	newMigrator = fn
	t.Cleanup(func() { newMigrator = prev })
	prevSleep := sleep
	sleep = func(time.Duration) {} // no real waiting in tests
	t.Cleanup(func() { sleep = prevSleep })
}

// oneMigration is the smallest source iofs accepts, so Up reaches the database
// open, which is the step under test.
var oneMigration = fstest.MapFS{
	"1_init.up.sql":   {Data: []byte("SELECT 1;")},
	"1_init.down.sql": {Data: []byte("SELECT 1;")},
}

// TestUpRetriesTransientDatabaseOpen reproduces the production boot crash:
// during a rolling deploy the outgoing pod still holds its pool, so the
// incoming pod's migrate connection can lose the race for the last free slot
// and Postgres answers
//
//	pq: remaining connection slots are reserved for roles with the SUPERUSER attribute
//
// That is transient by definition (the old pod is seconds from exiting), but a
// single-shot open turned it into a crashed pod that only survived because the
// restart happened to win the next slot. The open must be retried.
func TestUpRetriesTransientDatabaseOpen(t *testing.T) {
	slots := errors.New("pq: remaining connection slots are reserved for roles with the SUPERUSER attribute")
	attempts := 0
	f := &fakeMigrator{}
	stubOpen(t, func(source.Driver, string) (migrator, error) {
		attempts++
		if attempts < 3 {
			return nil, slots
		}
		return f, nil
	})

	if err := Up("postgres://ignored", oneMigration, "."); err != nil {
		t.Fatalf("transient open failures must be retried, got: %v", err)
	}
	if attempts != 3 {
		t.Errorf("open attempts = %d, want 3", attempts)
	}
	if !f.closed {
		t.Error("migrator was not closed after a retried open")
	}
}

// TestUpGivesUpOnPersistentOpenFailure keeps the retry bounded: a database that
// is genuinely unreachable must still crash the process (so Kubernetes
// backs off and the failure is visible) rather than hang forever.
func TestUpGivesUpOnPersistentOpenFailure(t *testing.T) {
	boom := errors.New("connection refused")
	attempts := 0
	stubOpen(t, func(source.Driver, string) (migrator, error) {
		attempts++
		return nil, boom
	})

	err := Up("postgres://ignored", oneMigration, ".")
	if err == nil {
		t.Fatal("a permanently unreachable database must fail startup")
	}
	if !errors.Is(err, boom) {
		t.Errorf("error %v does not wrap the cause %v", err, boom)
	}
	if attempts != openAttempts {
		t.Errorf("open attempts = %d, want the bounded %d", attempts, openAttempts)
	}
}

// fakeMigrator records whether Close was called and returns a configured Up error.
type fakeMigrator struct {
	upErr     error
	sourceErr error
	dbErr     error
	closed    bool
}

func (f *fakeMigrator) Up() error { return f.upErr }
func (f *fakeMigrator) Close() (sourceErr, dbErr error) {
	f.closed = true
	return f.sourceErr, f.dbErr
}

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

func TestRunUpReturnsCloseErrors(t *testing.T) {
	sourceErr := errors.New("source close")
	dbErr := errors.New("database close")
	err := runUp(&fakeMigrator{sourceErr: sourceErr, dbErr: dbErr})
	if !errors.Is(err, sourceErr) || !errors.Is(err, dbErr) {
		t.Fatalf("close error = %v, want both source and database causes", err)
	}
}

func TestRunUpJoinsMigrationAndCloseErrors(t *testing.T) {
	upErr := errors.New("migration failed")
	dbErr := errors.New("database close")
	err := runUp(&fakeMigrator{upErr: upErr, dbErr: dbErr})
	if !errors.Is(err, upErr) || !errors.Is(err, dbErr) {
		t.Fatalf("joined error = %v, want migration and close causes", err)
	}
}
