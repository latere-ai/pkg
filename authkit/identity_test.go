// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package authkit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"
)

// ── IdentityFromContext / WithIdentity ───────────────────────────────────────

func TestIdentityContextRoundTrip(t *testing.T) {
	id := Identity{Sub: "u-1", OrgID: "org-1", Email: "a@b.com"}
	ctx := WithIdentity(context.Background(), id)
	got := IdentityFromContext(ctx)
	if got.Sub != id.Sub || got.OrgID != id.OrgID || got.Email != id.Email {
		t.Fatalf("roundtrip mismatch: got %+v", got)
	}
}

func TestIdentityFromContextMissing(t *testing.T) {
	got := IdentityFromContext(context.Background())
	if got.Sub != "" {
		t.Fatalf("expected zero Identity, got %+v", got)
	}
}

// ── Middleware ───────────────────────────────────────────────────────────────

type fixedAuth struct {
	id  Identity
	err error
}

func (f *fixedAuth) Authenticate(*http.Request) (Identity, error) { return f.id, f.err }

func TestMiddlewareSuccess(t *testing.T) {
	id := Identity{Sub: "u-1"}
	var capturedID Identity
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedID = IdentityFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})
	h := Middleware(inner, &fixedAuth{id: id})

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	h.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if capturedID.Sub != "u-1" {
		t.Fatalf("identity not propagated: %+v", capturedID)
	}
}

func TestMiddlewareUnauthorized(t *testing.T) {
	h := Middleware(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }),
		&fixedAuth{err: ErrUnauthenticated},
	)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	h.ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
	if !strings.Contains(w.Body.String(), "unauthorized") {
		t.Fatalf("body missing 'unauthorized': %s", w.Body.String())
	}
}

func TestMiddlewareDoesNotLeakInternalError(t *testing.T) {
	// Authenticator errors can wrap internal detail (tokeninfo HTTP bodies,
	// backend topology). The 401 body must not echo that to the client.
	secret := "tokeninfo: 500 upstream: db-host-7 connection refused"
	h := Middleware(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }),
		&fixedAuth{err: errors.New(secret)},
	)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
	body := w.Body.String()
	if strings.Contains(body, "db-host-7") || strings.Contains(body, "tokeninfo") {
		t.Errorf("401 body leaked internal error detail: %s", body)
	}
	if !strings.Contains(body, "unauthorized") {
		t.Errorf("401 body missing generic code: %s", body)
	}
}

// ── Chain ────────────────────────────────────────────────────────────────────

func TestChainEmptyReturnsErrUnauthenticated(t *testing.T) {
	var c Chain
	_, err := c.Authenticate(httptest.NewRequest(http.MethodGet, "/", nil))
	if !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("empty chain: got %v, want ErrUnauthenticated", err)
	}
}

func TestChainFirstSucceeds(t *testing.T) {
	id := Identity{Sub: "u-1"}
	c := Chain{
		&fixedAuth{err: ErrUnauthenticated},
		&fixedAuth{id: id},
	}
	got, err := c.Authenticate(httptest.NewRequest(http.MethodGet, "/", nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Sub != "u-1" {
		t.Fatalf("got %+v", got)
	}
}

func TestChainAllFail(t *testing.T) {
	sentinel := errors.New("my error")
	c := Chain{
		&fixedAuth{err: ErrUnauthenticated},
		&fixedAuth{err: sentinel},
	}
	_, err := c.Authenticate(httptest.NewRequest(http.MethodGet, "/", nil))
	if !errors.Is(err, sentinel) {
		t.Fatalf("all fail: got %v, want sentinel", err)
	}
}

func TestChainSingleSuccess(t *testing.T) {
	id := Identity{Sub: "only"}
	c := Chain{&fixedAuth{id: id}}
	got, err := c.Authenticate(httptest.NewRequest(http.MethodGet, "/", nil))
	if err != nil {
		t.Fatal(err)
	}
	if got.Sub != "only" {
		t.Fatalf("got %+v", got)
	}
}

func TestWriteUnauthorized(t *testing.T) {
	rr := httptest.NewRecorder()
	WriteUnauthorized(rr, "test message")

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q", ct)
	}
	var body map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("WriteUnauthorized must emit JSON: %v", err)
	}
	if body["error"] != "unauthorized" || body["message"] != "test message" {
		t.Errorf("body = %v", body)
	}
}

// TestAuthkitIsLeaf pins the dependency direction of the auth tree: this
// package is imported by jwt, oidc, and cli, so it must not import any
// of them, or anything else in pkg that does.
func TestAuthkitIsLeaf(t *testing.T) {
	out, err := exec.Command("go", "list", "-f", "{{join .Imports \"\\n\"}}", ".").Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	allowed := map[string]bool{
		"latere.ai/x/pkg/bearer":   true,
		"latere.ai/x/pkg/envutil":  true,
		"latere.ai/x/pkg/httpjson": true,
	}
	for imp := range strings.SplitSeq(strings.TrimSpace(string(out)), "\n") {
		if strings.HasPrefix(imp, "latere.ai/x/pkg/") && !allowed[imp] {
			t.Errorf("authkit imports %s; the root of the auth tree must stay a leaf", imp)
		}
	}
}

// failingResponseWriter fails every body write, which is what a client that
// hangs up between the status line and the body looks like to a handler.
type failingResponseWriter struct {
	hdr    http.Header
	status int
}

func (f *failingResponseWriter) Header() http.Header { return f.hdr }

func (f *failingResponseWriter) Write([]byte) (int, error) {
	return 0, errors.New("connection reset by peer")
}

func (f *failingResponseWriter) WriteHeader(status int) { f.status = status }

// TestWriteUnauthorized_BodyWriteFails asserts that a 401 whose body never
// reached the client is recorded rather than discarded: without it a dropped
// response is indistinguishable from a delivered one in the logs.
func TestWriteUnauthorized_BodyWriteFails(t *testing.T) {
	var logged bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logged, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	w := &failingResponseWriter{hdr: make(http.Header)}
	WriteUnauthorized(w, "test message")

	if w.status != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.status)
	}
	if !strings.Contains(logged.String(), "write json") {
		t.Errorf("write failure was not logged: %q", logged.String())
	}
}
