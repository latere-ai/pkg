// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// Package pgxmigrate runs embedded golang-migrate migrations against a database
// and reliably closes migrate's own connection pool afterward.
//
// Every service that owns a Postgres schema ran the same bring-up dance
// (open an iofs source, build a migrate instance, defer-close it, apply Up,
// treat ErrNoChange as success). migrate.NewWithSourceInstance opens its own
// database/sql pool, separate from any pgxpool the caller keeps, so skipping
// the defer-close leaks idle connections for the process lifetime. This package
// is that dance, in one place.
//
// A caller must not read the schema version itself before Up or To. While one
// process runs a migration golang-migrate marks the schema dirty, so a second
// process that reads schema_migrations outside migrate's advisory lock sees a
// healthy migration in progress as a failed one and refuses to start. Up and To
// read the version and the dirty flag under that lock, waiting up to
// LockTimeout for another process to finish, and report what they find as
// ErrDirty and ErrNewer.
package pgxmigrate

import (
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/source"
	"github.com/golang-migrate/migrate/v4/source/iofs"
)

// LockTimeout is how long a migration waits for the advisory lock another
// process holds while it migrates. It outlasts a long migration, so a replica
// that starts meanwhile waits and then finds nothing to do, instead of failing
// after golang-migrate's 15 second default.
const LockTimeout = 5 * time.Minute

var (
	// ErrDirty means a migration failed halfway and left the schema at
	// neither version. An operator repairs it; running migrations again would
	// only report the same failure with less to go on.
	ErrDirty = errors.New("pgxmigrate: the schema is dirty")

	// ErrNewer means the database is at a version above the highest one the
	// source carries: an older binary met a newer schema, and statements run
	// against it would address tables the binary does not know.
	ErrNewer = errors.New("pgxmigrate: the schema is newer than the migrations")
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
		m.LockTimeout = LockTimeout
		return m, nil
	}
	sleep = time.Sleep
)

// Up applies all pending migrations from src (rooted at dir, e.g. "." or
// "migrations") to the database identified by dsn, then closes migrate's own
// database/sql pool. migrate.ErrNoChange (no pending migrations) is success.
// An error wraps ErrDirty when the schema is dirty and ErrNewer when the
// database is above the highest version src carries.
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
	return run(dsn, src, dir, "up", (migrator).Up)
}

// To migrates the database identified by dsn up or down to exactly version,
// with the same open retry, close and error classification as Up.
// migrate.ErrNoChange (already at version) is success.
func To(dsn string, src fs.FS, dir string, version uint) error {
	return run(dsn, src, dir, "migrate", func(m migrator) error { return m.Migrate(version) })
}

func run(dsn string, src fs.FS, dir, what string, op func(migrator) error) error {
	d, err := iofs.New(src, dir)
	if err != nil {
		return fmt.Errorf("pgxmigrate: open source: %w", err)
	}
	m, err := open(d, dsn)
	if err != nil {
		return err
	}
	return finish(m, what, op, func() (uint, error) { return HighestOf(src, dir) })
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

// migrator is the subset of *migrate.Migrate that finish needs, so the
// always-close behavior can be tested without a live database.
type migrator interface {
	Up() error
	Migrate(version uint) error
	Version() (version uint, dirty bool, err error)
	Close() (sourceErr error, dbErr error)
}

// finish runs op and always closes the migrator, even on failure, so the
// migrate-owned connection pool is never leaked on a failed startup.
func finish(m migrator, what string, op func(migrator) error, highest func() (uint, error)) error {
	var runErr error
	if err := op(m); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		runErr = classify(m, what, err, highest)
	}
	sourceErr, dbErr := m.Close()
	if sourceErr != nil {
		sourceErr = fmt.Errorf("pgxmigrate: close source: %w", sourceErr)
	}
	if dbErr != nil {
		dbErr = fmt.Errorf("pgxmigrate: close database: %w", dbErr)
	}
	return errors.Join(runErr, sourceErr, dbErr)
}

// classify turns a failed run into ErrDirty or ErrNewer where it is one. The
// version is read after the failure, so a database above the source is told
// apart from any other reason the source has no migration for it.
func classify(m migrator, what string, err error, highest func() (uint, error)) error {
	var dirty migrate.ErrDirty
	if errors.As(err, &dirty) {
		return fmt.Errorf("pgxmigrate: %s: %w at version %d: %w", what, ErrDirty, dirty.Version, err)
	}
	if v, _, verr := m.Version(); verr == nil {
		if top, herr := highest(); herr == nil && v > top {
			return fmt.Errorf("pgxmigrate: %s: %w: the database is at version %d and the source carries %d: %w", what, ErrNewer, v, top, err)
		}
	}
	return fmt.Errorf("pgxmigrate: %s: %w", what, err)
}

// HighestOf returns the highest migration version in dir of src, read from the
// number each file name starts with (N_name.up.sql, N_name.down.sql). Files
// whose names have no underscore are ignored. It is an error for a file to
// start with something other than a number, and for dir to hold no migration.
func HighestOf(src fs.FS, dir string) (uint, error) {
	entries, err := fs.ReadDir(src, dir)
	if err != nil {
		return 0, fmt.Errorf("pgxmigrate: read migrations: %w", err)
	}
	var highest uint
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		number, _, found := strings.Cut(e.Name(), "_")
		if !found {
			continue
		}
		n, err := strconv.ParseUint(number, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("pgxmigrate: the migration %q does not start with a number", e.Name())
		}
		highest = max(highest, uint(n))
	}
	if highest == 0 {
		return 0, errors.New("pgxmigrate: no migration found")
	}
	return highest, nil
}

// DriverURL returns the URL golang-migrate's pgx/v5 driver reads for raw, a
// postgres:// or postgresql:// URL: the scheme becomes pgx5, and every query
// parameter named pool_* is dropped. Those are pgx pool settings; the driver
// forwards parameters it does not know to the server as settings, and the
// server then refuses the session. Everything else in the URL is unchanged.
// Any other scheme is refused, and the error never echoes raw, which can carry
// a password.
func DriverURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", errors.New("pgxmigrate: the database URL does not parse")
	}
	if u.Scheme != "postgres" && u.Scheme != "postgresql" {
		return "", errors.New("pgxmigrate: the database URL scheme must be postgres or postgresql")
	}
	u.Scheme = "pgx5"
	if u.RawQuery != "" {
		var kept []string
		for pair := range strings.SplitSeq(u.RawQuery, "&") {
			name, _, _ := strings.Cut(pair, "=")
			if decoded, err := url.QueryUnescape(name); err == nil {
				name = decoded
			}
			if !strings.HasPrefix(name, "pool_") {
				kept = append(kept, pair)
			}
		}
		u.RawQuery = strings.Join(kept, "&")
	}
	return u.String(), nil
}
