// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package pgxmigrate

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/source"
)

var threeMigrations = fstest.MapFS{
	"1_a.up.sql": {}, "1_a.down.sql": {},
	"2_b.up.sql": {}, "2_b.down.sql": {},
	"3_c.up.sql": {}, "3_c.down.sql": {},
}

func TestUpReportsADirtySchema(t *testing.T) {
	f := &fakeMigrator{upErr: migrate.ErrDirty{Version: 2}}
	stubOpen(t, func(source.Driver, string) (migrator, error) { return f, nil })
	err := Up("postgres://ignored", threeMigrations, ".")
	if !errors.Is(err, ErrDirty) {
		t.Fatalf("error %v should wrap ErrDirty", err)
	}
	if !strings.Contains(err.Error(), "version 2") {
		t.Errorf("error %v should name the version", err)
	}
	if errors.Is(err, ErrNewer) {
		t.Error("a dirty schema is not a newer one")
	}
	if !f.closed {
		t.Error("migrator was not closed")
	}
}

func TestUpReportsANewerSchema(t *testing.T) {
	cause := fmt.Errorf("no migration found for version 9")
	f := &fakeMigrator{upErr: cause, version: 9}
	stubOpen(t, func(source.Driver, string) (migrator, error) { return f, nil })
	err := Up("postgres://ignored", threeMigrations, ".")
	if !errors.Is(err, ErrNewer) || !errors.Is(err, cause) {
		t.Fatalf("error %v should wrap ErrNewer and the cause", err)
	}
	if !f.closed {
		t.Error("migrator was not closed")
	}
}

func TestUpFailureWithinTheSourceIsNotNewer(t *testing.T) {
	cause := errors.New("syntax error")
	cases := map[string]*fakeMigrator{
		"version at the highest": {upErr: cause, version: 3},
		"version unreadable":     {upErr: cause, versErr: migrate.ErrNilVersion},
	}
	for name, f := range cases {
		t.Run(name, func(t *testing.T) {
			stubOpen(t, func(source.Driver, string) (migrator, error) { return f, nil })
			err := Up("postgres://ignored", threeMigrations, ".")
			if !errors.Is(err, cause) || errors.Is(err, ErrNewer) || errors.Is(err, ErrDirty) {
				t.Fatalf("error = %v, want the plain cause", err)
			}
		})
	}
}

func TestUpFailureWithUnreadableSourceKeepsTheCause(t *testing.T) {
	cause := errors.New("boom")
	f := &fakeMigrator{upErr: cause, version: 9}
	stubOpen(t, func(source.Driver, string) (migrator, error) { return f, nil })
	// iofs accepts the directory; HighestOf then finds a bad file name.
	bad := fstest.MapFS{"1_a.up.sql": {}, "x_b.up.sql": {}}
	if err := Up("postgres://ignored", bad, "."); !errors.Is(err, cause) || errors.Is(err, ErrNewer) {
		t.Fatalf("error = %v, want the plain cause", err)
	}
}

func TestToMigratesToTheVersion(t *testing.T) {
	f := &fakeMigrator{}
	stubOpen(t, func(source.Driver, string) (migrator, error) { return f, nil })
	if err := To("postgres://ignored", threeMigrations, ".", 2); err != nil {
		t.Fatal(err)
	}
	if f.migrated != 2 || !f.closed {
		t.Errorf("migrated = %d, closed = %v", f.migrated, f.closed)
	}
}

func TestToTreatsNoChangeAsSuccess(t *testing.T) {
	f := &fakeMigrator{migErr: migrate.ErrNoChange}
	stubOpen(t, func(source.Driver, string) (migrator, error) { return f, nil })
	if err := To("postgres://ignored", threeMigrations, ".", 3); err != nil {
		t.Fatalf("ErrNoChange must be success, got %v", err)
	}
}

func TestToClassifiesFailures(t *testing.T) {
	f := &fakeMigrator{migErr: migrate.ErrDirty{Version: 3}}
	stubOpen(t, func(source.Driver, string) (migrator, error) { return f, nil })
	if err := To("postgres://ignored", threeMigrations, ".", 1); !errors.Is(err, ErrDirty) {
		t.Fatalf("error %v should wrap ErrDirty", err)
	}
	f = &fakeMigrator{migErr: errors.New("no migration found"), version: 7}
	if err := To("postgres://ignored", threeMigrations, ".", 1); !errors.Is(err, ErrNewer) {
		t.Fatalf("error %v should wrap ErrNewer", err)
	}
}

func TestToRejectsASourceItCannotOpen(t *testing.T) {
	if err := To("postgres://ignored", threeMigrations, "missing", 1); err == nil {
		t.Fatal("a missing directory must fail")
	}
}

func TestToReportsAnOpenFailure(t *testing.T) {
	boom := errors.New("down")
	stubOpen(t, func(source.Driver, string) (migrator, error) { return nil, boom })
	if err := To("postgres://ignored", threeMigrations, ".", 1); !errors.Is(err, boom) {
		t.Fatalf("error = %v", err)
	}
}

func TestLockTimeoutOutlastsTheDefault(t *testing.T) {
	if LockTimeout <= migrate.DefaultLockTimeout {
		t.Fatalf("LockTimeout %v must exceed migrate's default %v", LockTimeout, migrate.DefaultLockTimeout)
	}
}

func TestHighestOf(t *testing.T) {
	got, err := HighestOf(threeMigrations, ".")
	if err != nil || got != 3 {
		t.Fatalf("HighestOf = %d, %v", got, err)
	}
	sub := fstest.MapFS{
		"m/000010_x.up.sql": {}, "m/000002_y.up.sql": {}, "m/README.md": {}, "m/dir/20_z.up.sql": {},
	}
	if got, err := HighestOf(sub, "m"); err != nil || got != 10 {
		t.Fatalf("HighestOf = %d, %v, want 10", got, err)
	}
}

func TestHighestOfErrors(t *testing.T) {
	cases := map[string]struct {
		fs  fstest.MapFS
		dir string
	}{
		"empty":       {fstest.MapFS{"m/README.md": {}}, "m"},
		"missing":     {fstest.MapFS{}, "m"},
		"not numeric": {fstest.MapFS{"m/abc_x.up.sql": {}}, "m"},
		"zero only":   {fstest.MapFS{"m/0_x.up.sql": {}}, "m"},
	}
	for name, c := range cases {
		if _, err := HighestOf(c.fs, c.dir); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}

func TestDriverURL(t *testing.T) {
	cases := []struct{ in, want string }{
		{"postgres://u:p@h:5432/db", "pgx5://u:p@h:5432/db"},
		{"postgresql://u@h/db?sslmode=require", "pgx5://u@h/db?sslmode=require"},
		{"postgres://u@h/db?pool_max_conns=4&sslmode=disable&pool_min_conns=1", "pgx5://u@h/db?sslmode=disable"},
		{"postgres://u@h/db?pool_max_conns=4", "pgx5://u@h/db"},
		{"postgres://u@h/db?options=-c%20search_path%3Dx&application_name=a+b", "pgx5://u@h/db?options=-c%20search_path%3Dx&application_name=a+b"},
		{"postgres://u@h/db?%70ool_x=1&a=b", "pgx5://u@h/db?a=b"},
	}
	for _, c := range cases {
		got, err := DriverURL(c.in)
		if err != nil || got != c.want {
			t.Errorf("DriverURL(%q) = %q, %v, want %q", c.in, got, err, c.want)
		}
	}
}

func TestDriverURLRefusesWithoutEchoing(t *testing.T) {
	for _, in := range []string{
		"mysql://user:hunter2@h/db",
		"pgx5://user:hunter2@h/db",
		"user:hunter2@h/db",
		"postgres://user:hunter2@h:notaport/db",
	} {
		_, err := DriverURL(in)
		if err == nil {
			t.Errorf("DriverURL(%q) must fail", in)
			continue
		}
		if strings.Contains(err.Error(), "hunter2") {
			t.Errorf("error %q echoes the password", err)
		}
	}
}

func FuzzDriverURL(f *testing.F) {
	for _, s := range []string{
		"postgres://u:p@h:5432/db", "postgresql://u@h/db?pool_max_conns=4&a=b", "mysql://u:secret@h/db",
		"", "postgres://", "postgres://u@h/db?%zz=1&pool_x", "postgres://u@h/db?&&=&pool_=", "://", "postgres://u@h/db#pool_x=1",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		got, err := DriverURL(raw)
		if err != nil {
			if strings.Contains(raw, "@") && strings.Contains(err.Error(), raw) {
				t.Fatalf("error echoes the URL: %q", err)
			}
			return
		}
		u, perr := url.Parse(got)
		if perr != nil {
			t.Fatalf("output %q does not parse: %v", got, perr)
		}
		if u.Scheme != "pgx5" {
			t.Fatalf("scheme = %q", u.Scheme)
		}
		for pair := range strings.SplitSeq(u.RawQuery, "&") {
			name, _, _ := strings.Cut(pair, "=")
			if d, err := url.QueryUnescape(name); err == nil {
				name = d
			}
			if strings.HasPrefix(name, "pool_") {
				t.Fatalf("output %q keeps %q", got, name)
			}
		}
	})
}
