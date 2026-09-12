// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package drive

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// fakeDrive is a scriptable stand-in for drive's mount API. Each test installs a
// handler; the fake records the last request's method, path, auth header, and
// decoded JSON body so tests can assert the client speaks the contract exactly.
type fakeDrive struct {
	srv     *httptest.Server
	handler func(w http.ResponseWriter, r *http.Request)

	lastMethod string
	lastPath   string
	lastQuery  string
	lastAuth   string
	lastBody   map[string]any
}

func newFakeDrive(t *testing.T) *fakeDrive {
	t.Helper()
	f := &fakeDrive{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.lastMethod, f.lastPath, f.lastQuery = r.Method, r.URL.Path, r.URL.RawQuery
		f.lastAuth = r.Header.Get("Authorization")
		if b, _ := io.ReadAll(r.Body); len(b) > 0 {
			f.lastBody = map[string]any{}
			_ = json.Unmarshal(b, &f.lastBody)
		}
		f.handler(w, r)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeDrive) client(t *testing.T, tok string) *Client {
	c := NewClient(f.srv.URL, TokenSourceFunc(func(context.Context) (string, error) { return tok, nil }))
	if c == nil {
		t.Fatal("NewClient returned nil")
	}
	return c.WithHTTPClient(f.srv.Client())
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func TestNewClient(t *testing.T) {
	ts := TokenSourceFunc(func(context.Context) (string, error) { return "t", nil })
	if NewClient("", ts) != nil {
		t.Error("empty baseURL should give nil")
	}
	if NewClient("https://drive.test", nil) != nil {
		t.Error("nil TokenSource should give nil")
	}
	if c := NewClient("https://drive.test/", ts); c == nil || c.baseURL != "https://drive.test" {
		t.Errorf("baseURL not trimmed: %+v", c)
	}
	if c := NewClient("  https://drive.test/  ", ts); c == nil || c.baseURL != "https://drive.test" {
		t.Errorf("baseURL whitespace not trimmed: %q", c.baseURL)
	}
}

// TestDecodeError: a 2xx body that is not valid JSON surfaces a decode error
// rather than a zero-value result.
func TestDecodeError(t *testing.T) {
	f := newFakeDrive(t)
	f.handler = func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not json"))
	}
	c := f.client(t, "t")
	if _, err := c.Materialize(context.Background(), "ws", "att"); err == nil || !strings.Contains(err.Error(), "decode") {
		t.Errorf("materialize decode err = %v", err)
	}
	if _, err := c.Sync(context.Background(), "ws", "att", nil); err == nil || !strings.Contains(err.Error(), "decode") {
		t.Errorf("sync decode err = %v", err)
	}
	if _, err := c.Renew(context.Background(), "ws", "att", 0); err == nil || !strings.Contains(err.Error(), "decode") {
		t.Errorf("renew decode err = %v", err)
	}
}

func TestAttachRW(t *testing.T) {
	f := newFakeDrive(t)
	exp := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	f.handler = func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusCreated, map[string]any{
			"id": "att-1", "workspace_id": "ws-1", "mode": "rw",
			"expires_at": exp.Format(time.RFC3339),
		})
	}
	att, err := f.client(t, "tok-123").Attach(context.Background(), "ws-1", "sbx-1", RW, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if att.ID != "att-1" || att.Mode != "rw" {
		t.Fatalf("attachment = %+v", att)
	}
	if !att.ExpiresAt.Equal(exp) {
		t.Errorf("expires_at = %v, want %v", att.ExpiresAt, exp)
	}
	// Contract wire-check: path, auth, and body.
	if f.lastMethod != "POST" || f.lastPath != "/v1/workspaces/ws-1/attach" {
		t.Errorf("request = %s %s", f.lastMethod, f.lastPath)
	}
	if f.lastAuth != "Bearer tok-123" {
		t.Errorf("auth = %q", f.lastAuth)
	}
	if f.lastBody["sandbox_id"] != "sbx-1" || f.lastBody["mode"] != "rw" || f.lastBody["ttl_seconds"] != float64(3600) {
		t.Errorf("body = %v", f.lastBody)
	}
}

func TestAttachWriterHeld(t *testing.T) {
	f := newFakeDrive(t)
	f.handler = func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "writer_held", "holder_sandbox_id": "other-sbx"})
	}
	_, err := f.client(t, "t").Attach(context.Background(), "ws-1", "sbx-1", RW, 0)
	if !errors.Is(err, ErrWriterHeld) {
		t.Fatalf("err = %v, want ErrWriterHeld", err)
	}
	var held *WriterHeldError
	if !errors.As(err, &held) || held.HolderSandboxID != "other-sbx" {
		t.Fatalf("holder not surfaced: %v", err)
	}
	if held.Error() == "" || !strings.Contains(held.Error(), "other-sbx") {
		t.Errorf("WriterHeldError message = %q", held.Error())
	}
	// No ttl in body when zero.
	if _, ok := f.lastBody["ttl_seconds"]; ok {
		t.Error("ttl_seconds should be omitted when zero")
	}
}

func TestAttachNotFound(t *testing.T) {
	f := newFakeDrive(t)
	f.handler = func(w http.ResponseWriter, r *http.Request) { writeJSON(w, http.StatusNotFound, map[string]any{}) }
	_, err := f.client(t, "t").Attach(context.Background(), "ws-x", "sbx", RO, 0)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestMaterialize(t *testing.T) {
	f := newFakeDrive(t)
	f.handler = func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"root": "workspaces/proj/", "pinned_at": "2026-07-18T00:00:00Z",
			"files": []map[string]any{{"path": "a.txt", "checksum": "ab", "size": 2, "url": "https://s3/a"}},
		})
	}
	m, err := f.client(t, "t").Materialize(context.Background(), "ws-1", "att-1")
	if err != nil {
		t.Fatal(err)
	}
	if m.Root != "workspaces/proj/" || len(m.Files) != 1 || m.Files[0].URL != "https://s3/a" || m.Files[0].Path != "a.txt" {
		t.Fatalf("materialization = %+v", m)
	}
	if f.lastPath != "/v1/workspaces/ws-1/materialize" || f.lastQuery != "attachment=att-1" {
		t.Errorf("request = %s?%s", f.lastPath, f.lastQuery)
	}
}

// TestMaterializeLargeBody: a Materialization for a big workspace exceeds 1 MiB
// of JSON. The client must decode the whole body, not truncate it mid-JSON.
func TestMaterializeLargeBody(t *testing.T) {
	f := newFakeDrive(t)
	const n = 4000 // ~4000 files * (path+checksum+presigned URL) >> 1 MiB
	files := make([]map[string]any, n)
	for i := range files {
		files[i] = map[string]any{
			"path":     "dir/subdir/file-" + strconv.Itoa(i) + ".txt",
			"checksum": strings.Repeat("a", 64),
			"size":     123,
			"url":      "https://s3.example.com/bucket/object-" + strings.Repeat("x", 200) + "-" + strconv.Itoa(i),
		}
	}
	f.handler = func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"root": "workspaces/big/", "pinned_at": "2026-07-18T00:00:00Z", "files": files,
		})
	}
	m, err := f.client(t, "t").Materialize(context.Background(), "ws-1", "att-1")
	if err != nil {
		t.Fatalf("decode large materialize: %v", err)
	}
	if len(m.Files) != n {
		t.Fatalf("files = %d, want %d", len(m.Files), n)
	}
	if m.Files[n-1].Path != "dir/subdir/file-"+strconv.Itoa(n-1)+".txt" {
		t.Errorf("last file truncated: %+v", m.Files[n-1])
	}
}

func TestMaterializeGone(t *testing.T) {
	f := newFakeDrive(t)
	f.handler = func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusGone) }
	_, err := f.client(t, "t").Materialize(context.Background(), "ws-1", "att-1")
	if !errors.Is(err, ErrAttachmentGone) {
		t.Fatalf("err = %v, want ErrAttachmentGone", err)
	}
}

func TestSync(t *testing.T) {
	f := newFakeDrive(t)
	f.handler = func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"synced_files": 3, "deleted_files": 1, "last_sync": "2026-07-18T00:00:00Z"})
	}
	res, err := f.client(t, "t").Sync(context.Background(), "ws-1", "att-1",
		[]ManifestEntry{{Path: "a", Checksum: "x", Size: 1}})
	if err != nil {
		t.Fatal(err)
	}
	if res.SyncedFiles != 3 || res.DeletedFiles != 1 {
		t.Fatalf("result = %+v", res)
	}
	if f.lastBody["attachment_id"] != "att-1" {
		t.Errorf("body = %v", f.lastBody)
	}
	if files, ok := f.lastBody["files"].([]any); !ok || len(files) != 1 {
		t.Errorf("files body = %v", f.lastBody["files"])
	}
}

func TestSyncManifestIncomplete(t *testing.T) {
	f := newFakeDrive(t)
	f.handler = func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "manifest_incomplete", "missing": []string{"b.txt", "c.txt"}})
	}
	_, err := f.client(t, "t").Sync(context.Background(), "ws-1", "att-1", nil)
	var inc *ManifestIncompleteError
	if !errors.As(err, &inc) || len(inc.Missing) != 2 {
		t.Fatalf("err = %v, want ManifestIncompleteError with 2 missing", err)
	}
	if !strings.Contains(inc.Error(), "2 file") {
		t.Errorf("ManifestIncompleteError message = %q", inc.Error())
	}
	// nil files must serialize as [] not null.
	if _, ok := f.lastBody["files"].([]any); !ok {
		t.Errorf("nil files should serialize as [], got %v", f.lastBody["files"])
	}
}

func TestSyncConflictOther(t *testing.T) {
	f := newFakeDrive(t)
	f.handler = func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "writer_lock_lost"})
	}
	_, err := f.client(t, "t").Sync(context.Background(), "ws-1", "att-1", nil)
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Status != http.StatusConflict {
		t.Fatalf("err = %v, want APIError 409", err)
	}
}

func TestRenew(t *testing.T) {
	f := newFakeDrive(t)
	exp := time.Now().Add(2 * time.Hour).UTC().Truncate(time.Second)
	f.handler = func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"id": "att-1", "expires_at": exp.Format(time.RFC3339)})
	}
	got, err := f.client(t, "t").Renew(context.Background(), "ws-1", "att-1", 30*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(exp) {
		t.Fatalf("expires = %v, want %v", got, exp)
	}
	if f.lastPath != "/v1/workspaces/ws-1/attach/att-1/renew" || f.lastBody["ttl_seconds"] != float64(1800) {
		t.Errorf("request = %s body=%v", f.lastPath, f.lastBody)
	}
}

func TestRelease(t *testing.T) {
	f := newFakeDrive(t)
	f.handler = func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }
	if err := f.client(t, "t").Release(context.Background(), "ws-1", "att-1"); err != nil {
		t.Fatal(err)
	}
	if f.lastMethod != "DELETE" || f.lastPath != "/v1/workspaces/ws-1/attach/att-1" {
		t.Errorf("request = %s %s", f.lastMethod, f.lastPath)
	}
}

func TestTokenSourceError(t *testing.T) {
	f := newFakeDrive(t)
	f.handler = func(w http.ResponseWriter, r *http.Request) { t.Fatal("must not reach drive when token fails") }
	c := NewClient(f.srv.URL, TokenSourceFunc(func(context.Context) (string, error) {
		return "", errors.New("mint failed")
	})).WithHTTPClient(f.srv.Client())
	if _, err := c.Attach(context.Background(), "ws", "sbx", RO, 0); err == nil {
		t.Fatal("expected token error")
	}
}

// TestConnectionError: when drive is unreachable, every method returns the
// transport error rather than panicking or masking it as success.
func TestConnectionError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close() // now nothing listens on that port
	c := NewClient(url, TokenSourceFunc(func(context.Context) (string, error) { return "t", nil }))
	ctx := context.Background()
	if _, err := c.Attach(ctx, "ws", "sbx", RO, 0); err == nil {
		t.Error("Attach should fail")
	}
	if _, err := c.Materialize(ctx, "ws", "att"); err == nil {
		t.Error("Materialize should fail")
	}
	if _, err := c.Sync(ctx, "ws", "att", nil); err == nil {
		t.Error("Sync should fail")
	}
	if _, err := c.Renew(ctx, "ws", "att", 0); err == nil {
		t.Error("Renew should fail")
	}
	if err := c.Release(ctx, "ws", "att"); err == nil {
		t.Error("Release should fail")
	}
}

func TestServerError(t *testing.T) {
	f := newFakeDrive(t)
	f.handler = func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "boom"})
	}
	_, err := f.client(t, "t").Materialize(context.Background(), "ws-1", "att-1")
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Status != 500 {
		t.Fatalf("err = %v, want APIError 500", err)
	}
	if apiErr.Error() == "" {
		t.Error("APIError message empty")
	}
}

// TestListWorkspaces: the client hits GET /v1/workspaces with the bearer
// and decodes drive's {entries:[...]} page into []Workspace.
func TestListWorkspaces(t *testing.T) {
	f := newFakeDrive(t)
	last := "2026-07-19T00:00:00Z"
	f.handler = func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"entries": []map[string]any{
			{"id": "ws1", "owner": "u-me", "kind": "workspace", "slug": "api-service", "locked": false, "last_sync": last, "agent_access": "visible"},
			{"id": "ws2", "owner": "u-me", "kind": "repo", "slug": "notes", "locked": true, "agent_access": "hidden"},
		}})
	}
	ws, err := f.client(t, "user-jwt").ListWorkspaces(context.Background(), ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if f.lastMethod != http.MethodGet || f.lastPath != "/v1/workspaces" {
		t.Fatalf("request = %s %s", f.lastMethod, f.lastPath)
	}
	if f.lastAuth != "Bearer user-jwt" {
		t.Errorf("auth = %q, want the session bearer", f.lastAuth)
	}
	if len(ws) != 2 || ws[0].Slug != "api-service" || ws[0].Kind != "workspace" || ws[0].Locked {
		t.Fatalf("workspaces = %+v", ws)
	}
	if ws[0].LastSync == nil || *ws[0].LastSync != last {
		t.Errorf("last_sync = %v", ws[0].LastSync)
	}
	if !ws[1].Locked {
		t.Errorf("ws2 should be locked (writer held)")
	}
}
