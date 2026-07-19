// Package pgxmigrate runs embedded golang-migrate migrations against a database
// and reliably closes migrate's own connection pool afterward.
//
// Every latere service that owns a Postgres schema ran the same bring-up dance
// (open an iofs source, build a migrate instance, defer-close it, apply Up,
// treat ErrNoChange as success). The defer-close is load-bearing:
// migrate.NewWithSourceInstance opens its own database/sql pool, separate from
// any pgxpool the caller keeps, and skipping the close leaks idle connections
// for the process lifetime. This package is that dance, in one place.
package pgxmigrate

import (
	"fmt"
	"io/fs"
	"time"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/source"
	"github.com/golang-migrate/migrate/v4/source/iofs"
)

// Bounds on the database-open retry. A rolling deploy overlaps the outgoing and
// incoming pods for a few seconds, so the incoming pod's migrate connection can
// briefly find no free slot; ~10s of retries outlasts that window while still
// crashing promptly when the database is actually down.
const (
	openAttempts   = 6
	openRetryDelay = 2 * time.Second
)

// newMigrator opens the migrate instance (and, through the database driver, a
// connection). It is a variable so the retry loop is testable without a
// database. sleep is likewise stubbed to keep those tests instant.
var (
	newMigrator = func(d source.Driver, dsn string) (migrator, error) {
		m, err := migrate.NewWithSourceInstance("iofs", d, dsn)
		if err != nil {
			return nil, err
		}
		return m, nil
	}
	sleep = time.Sleep
)

// Up applies all pending migrations from src (rooted at dir, e.g. "." or
// "migrations") to the database identified by dsn, then closes migrate's own
// database/sql pool. migrate.ErrNoChange (no pending migrations) is success.
//
// The dsn scheme selects the golang-migrate database driver, so the CALLER must
// blank-import the matching driver and pass a dsn whose scheme it registers:
//
//	import _ "github.com/golang-migrate/migrate/v4/database/postgres" // postgres://
//	import _ "github.com/golang-migrate/migrate/v4/database/pgx/v5"   // pgx5://
//
// This package intentionally imports no database driver, so each caller picks
// its own; importing one here would force it on every consumer and break
// services that use a different driver.
func Up(dsn string, src fs.FS, dir string) error {
	d, err := iofs.New(src, dir)
	if err != nil {
		return fmt.Errorf("pgxmigrate: open source: %w", err)
	}
	m, err := open(d, dsn)
	if err != nil {
		return err
	}
	return runUp(m)
}

// open builds the migrate instance, retrying the database connection it opens.
// Only the open is retried: a failure inside Up leaves golang-migrate's dirty
// flag set, so re-running it can only report "Dirty database version" and would
// mask a real migration bug.
func open(d source.Driver, dsn string) (migrator, error) {
	var err error
	for attempt := 1; attempt <= openAttempts; attempt++ {
		var m migrator
		if m, err = newMigrator(d, dsn); err == nil {
			return m, nil
		}
		if attempt < openAttempts {
			sleep(openRetryDelay)
		}
	}
	return nil, fmt.Errorf("pgxmigrate: init: %w", err)
}

// migrator is the subset of *migrate.Migrate that runUp needs, so the
// always-close behavior can be tested without a live database.
type migrator interface {
	Up() error
	Close() (sourceErr error, dbErr error)
}

// runUp applies migrations and always closes the migrator, even on failure, so
// the migrate-owned connection pool is never leaked on a failed startup.
func runUp(m migrator) error {
	defer m.Close()
	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		return fmt.Errorf("pgxmigrate: up: %w", err)
	}
	return nil
}
