// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package health

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func get(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

func TestProbesWithoutAReadiness(t *testing.T) {
	h := Handler(Options{})
	for _, p := range []string{"/livez", "/readyz"} {
		if rec := get(t, h, p); rec.Code != http.StatusOK || rec.Body.String() != "ok\n" || rec.Header().Get("Content-Type") != "text/plain; charset=utf-8" {
			t.Errorf("%s: %d %q", p, rec.Code, rec.Body.String())
		}
	}
	for _, p := range []string{"/metrics", "/healthz"} {
		if rec := get(t, h, p); rec.Code != http.StatusNotFound {
			t.Errorf("%s without an option must be 404, got %d", p, rec.Code)
		}
	}
}

func TestReadyzCarriesTheErrorAndLivezNever(t *testing.T) {
	h := Handler(Options{Ready: func(context.Context) error { return errors.New("database: refused") }})
	rec := get(t, h, "/readyz")
	if rec.Code != http.StatusServiceUnavailable || rec.Body.String() != "not ready: database: refused\n" {
		t.Fatalf("%d %q", rec.Code, rec.Body.String())
	}
	if rec := get(t, h, "/livez"); rec.Code != http.StatusOK || rec.Body.String() != "ok\n" {
		t.Fatalf("liveness is independent of readiness: %d %q", rec.Code, rec.Body.String())
	}
	ok := Handler(Options{Ready: func(context.Context) error { return nil }})
	if rec := get(t, ok, "/readyz"); rec.Code != http.StatusOK {
		t.Fatalf("a nil readiness error must be 200, got %d", rec.Code)
	}
}

func TestChecksNameEveryFailingCheck(t *testing.T) {
	var ran []string
	mk := func(name string, err error) Check {
		return Check{Name: name, Run: func(context.Context) error { ran = append(ran, name); return err }}
	}
	ready := Checks(mk("storage", errors.New("dial: refused")), mk("disk", nil), mk("peer", errors.New("timeout")))
	err := ready(context.Background())
	if err == nil || err.Error() != "storage: dial: refused\npeer: timeout" {
		t.Fatalf("err = %v", err)
	}
	if strings.Join(ran, ",") != "storage,disk,peer" {
		t.Fatalf("ran %v: every check runs", ran)
	}
	if err := Checks(mk("disk", nil))(context.Background()); err != nil {
		t.Fatalf("all passing: %v", err)
	}
	if err := Checks()(context.Background()); err != nil {
		t.Fatalf("no checks: %v", err)
	}
	rec := get(t, Handler(Options{Ready: ready}), "/readyz")
	if rec.Code != http.StatusServiceUnavailable || rec.Body.String() != "not ready: storage: dial: refused\npeer: timeout\n" {
		t.Fatalf("%d %q", rec.Code, rec.Body.String())
	}
}

func TestTimeoutBoundsTheReadyCall(t *testing.T) {
	var deadline bool
	h := Handler(Options{Timeout: time.Millisecond, Ready: func(ctx context.Context) error {
		_, deadline = ctx.Deadline()
		<-ctx.Done()
		return ctx.Err()
	}})
	rec := get(t, h, "/readyz")
	if rec.Code != http.StatusServiceUnavailable || !deadline || !strings.Contains(rec.Body.String(), "deadline exceeded") {
		t.Fatalf("%d %q deadline %v", rec.Code, rec.Body.String(), deadline)
	}
	var hasDeadline bool
	h = Handler(Options{Ready: func(ctx context.Context) error { _, hasDeadline = ctx.Deadline(); return nil }})
	if rec := get(t, h, "/readyz"); rec.Code != http.StatusOK || hasDeadline {
		t.Fatalf("without a timeout the request context is used as is: %d %v", rec.Code, hasDeadline)
	}
}

func TestVersionIsTheBuildIdentityAndNothingElse(t *testing.T) {
	rec := get(t, Handler(Options{Version: "v1.2.3", Commit: "abc1234", BuildTime: "2026-09-06T00:00:00Z"}), "/version")
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("%d %s", rec.Code, rec.Header().Get("Content-Type"))
	}
	var got map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got["version"] != "v1.2.3" || got["commit"] != "abc1234" || got["build_time"] != "2026-09-06T00:00:00Z" {
		t.Fatalf("got %v", got)
	}
}

func TestMetricsIsMountedWhenGiven(t *testing.T) {
	m := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("x_total 1\n")) })
	rec := get(t, Handler(Options{Metrics: m}), "/metrics")
	if rec.Code != http.StatusOK || rec.Body.String() != "x_total 1\n" {
		t.Fatalf("%d %q", rec.Code, rec.Body.String())
	}
}

func TestLegacyHealthzAliasesLivez(t *testing.T) {
	h := Handler(Options{LegacyHealthz: true, Ready: func(context.Context) error { return errors.New("down") }})
	if rec := get(t, h, "/healthz"); rec.Code != http.StatusOK || rec.Body.String() != "ok\n" {
		t.Fatalf("/healthz: %d %q", rec.Code, rec.Body.String())
	}
}

func TestOnlyGetIsServed(t *testing.T) {
	rec := httptest.NewRecorder()
	Handler(Options{}).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/livez", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST /livez: %d", rec.Code)
	}
}
