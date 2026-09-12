// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package drive

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestClientMethodFailures(t *testing.T) {
	actions := []struct {
		name   string
		status int
		call   func(*Client) error
	}{
		{"attach", 201, func(c *Client) error { _, e := c.Attach(t.Context(), "ws", "sb", RO, 0); return e }},
		{"materialize", 200, func(c *Client) error { _, e := c.Materialize(t.Context(), "ws", "att"); return e }},
		{"sync", 200, func(c *Client) error { _, e := c.Sync(t.Context(), "ws", "att", nil); return e }},
		{"renew", 200, func(c *Client) error { _, e := c.Renew(t.Context(), "ws", "att", 0); return e }},
		{"release", 204, func(c *Client) error { return c.Release(t.Context(), "ws", "att") }},
		{"put", 200, func(c *Client) error {
			return c.PutFile(t.Context(), "u-a", "workspaces/s/", "x", strings.NewReader("x"), 1)
		}},
		{"create", 201, func(c *Client) error { _, e := c.CreateWorkspace(t.Context(), "me", "workspace", "s"); return e }},
		{"get", 200, func(c *Client) error { _, e := c.GetWorkspace(t.Context(), "ws"); return e }},
		{"page", 200, func(c *Client) error { _, e := c.ListWorkspacesPage(t.Context(), ListOptions{}); return e }},
		{"list", 200, func(c *Client) error { _, e := c.ListWorkspaces(t.Context(), ListOptions{}); return e }},
	}
	boom := errors.New("transport unavailable")
	for _, action := range actions {
		t.Run(action.name, func(t *testing.T) {
			ts := TokenSourceFunc(func(context.Context) (string, error) { return "token", nil })
			tokenFailure := NewClient("https://drive.test", TokenSourceFunc(func(context.Context) (string, error) { return "", boom }))
			if err := action.call(tokenFailure); !errors.Is(err, boom) {
				t.Fatalf("token failure: %v", err)
			}
			client := NewClient("https://drive.test", ts).WithHTTPClient(&http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, boom })})
			if err := action.call(client); !errors.Is(err, boom) {
				t.Fatalf("transport failure: %v", err)
			}
			if err := action.call(NewClient("http://%zz", ts)); err == nil {
				t.Fatal("accepted malformed URL")
			}
			for _, scenario := range []string{"success", "status", "decode"} {
				if scenario == "decode" && (action.name == "release" || action.name == "put") {
					continue
				}
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Header.Get("Authorization") != "Bearer token" {
						t.Error("missing bearer")
					}
					status := action.status
					if scenario == "status" {
						status = 503
					}
					w.WriteHeader(status)
					if scenario == "decode" {
						_, _ = io.WriteString(w, "bad json")
					} else {
						_, _ = io.WriteString(w, `{}`)
					}
				}))
				err := action.call(NewClient(server.URL, ts))
				server.Close()
				if (err != nil) != (scenario != "success") {
					t.Fatalf("%s: %v", scenario, err)
				}
			}
		})
	}
}

func TestWorkspacePagination(t *testing.T) {
	const cursor = "next/page?with=+space #"
	tokens := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("kind") != "workspace" || q.Get("scope") != "all" || q.Get("limit") != "7" {
			t.Errorf("lost filters: %v", q)
		}
		if q.Get("cursor") == "" {
			writeJSON(w, 200, WorkspacePage{Entries: []Workspace{{ID: "first"}}, NextCursor: cursor})
		} else if q.Get("cursor") == cursor {
			writeJSON(w, 200, WorkspacePage{Entries: []Workspace{{ID: "second", Owner: "u-a"}}})
		} else {
			t.Errorf("unexpected cursor: %q", q.Get("cursor"))
			w.WriteHeader(400)
		}
	}))
	t.Cleanup(srv.Close)
	client := NewClient(srv.URL, TokenSourceFunc(func(context.Context) (string, error) { tokens++; return "token", nil }))
	got, err := client.ListWorkspaces(t.Context(), ListOptions{Kind: "workspace", Scope: "all", Limit: 7})
	if err != nil || len(got) != 2 || got[1].ID != "second" || tokens != 2 {
		t.Fatalf("pages: %+v %v tokens=%d", got, err, tokens)
	}
}

func TestWorkspacePaginationRejectsIncompleteResults(t *testing.T) {
	for _, scenario := range []string{"repeat", "cycle", "failure"} {
		t.Run(scenario, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				cursor := r.URL.Query().Get("cursor")
				if cursor != "" && scenario == "failure" {
					w.WriteHeader(500)
					return
				}
				next := "a"
				if cursor == "a" && scenario == "cycle" {
					next = "b"
				}
				writeJSON(w, 200, WorkspacePage{Entries: []Workspace{{ID: cursor}}, NextCursor: next})
			}))
			t.Cleanup(srv.Close)
			c := NewClient(srv.URL, TokenSourceFunc(func(context.Context) (string, error) { return "t", nil }))
			got, err := c.ListWorkspaces(t.Context(), ListOptions{})
			if err == nil || got != nil {
				t.Fatalf("partial result accepted: %+v %v", got, err)
			}
		})
	}
}

func TestWorkspaceCreateAndGet(t *testing.T) {
	f := newFakeDrive(t)
	f.handler = func(w http.ResponseWriter, r *http.Request) {
		status := 200
		if r.Method == http.MethodPost {
			status = 201
		}
		writeJSON(w, status, Workspace{ID: "ws", Owner: "u-a", Slug: "s", RootPrefix: "workspaces/s", AgentAccess: "visible"})
	}
	c := f.client(t, "token")
	created, err := c.CreateWorkspace(t.Context(), "me", "workspace", "s")
	if err != nil || created.ID != "ws" || f.lastBody["owner"] != "me" || f.lastBody["kind"] != "workspace" || f.lastBody["slug"] != "s" {
		t.Fatalf("create: %+v %v body=%v", created, err, f.lastBody)
	}
	got, err := c.GetWorkspace(t.Context(), "ws")
	if err != nil || got.Owner != "u-a" || got.RootPrefix != "workspaces/s" {
		t.Fatalf("get: %+v %v", got, err)
	}
}

type brokenBody struct{}

func (brokenBody) Read(p []byte) (int, error) { return copy(p, `{}`), io.ErrUnexpectedEOF }
func (brokenBody) Close() error               { return nil }

func TestClientRejectsResponseReadFailure(t *testing.T) {
	c := NewClient("https://drive.test", TokenSourceFunc(func(context.Context) (string, error) { return "t", nil }))
	c.WithHTTPClient(&http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: brokenBody{}, Request: r}, nil
	})})
	if _, err := c.GetWorkspace(t.Context(), "ws"); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("read error lost: %v", err)
	}
}

func TestClientOptionsAndErrors(t *testing.T) {
	var missing *Client
	if missing.WithHTTPClient(nil) != nil {
		t.Fatal("nil client changed")
	}
	c := NewClient("\n https://drive.test/ \t", TokenSourceFunc(func(context.Context) (string, error) { return "t", nil }))
	if c.WithHTTPClient(nil) != c || c.http.Transport == nil || c.http.Timeout != 30*time.Second {
		t.Fatal("invalid client defaults")
	}
	if _, err := c.do(t.Context(), "POST", c.baseURL, make(chan int)); err == nil {
		t.Fatal("unencodable body accepted")
	}
	if _, err := c.do(t.Context(), "bad method", c.baseURL, nil); err == nil {
		t.Fatal("invalid method accepted")
	}
	if !RO.Valid() || !RW.Valid() || Mode("").Valid() || Mode("other").Valid() {
		t.Fatal("invalid mode validation")
	}
	held := &WriterHeldError{HolderSandboxID: "sb"}
	if !errors.Is(held, ErrWriterHeld) || errors.Is(held, ErrNotFound) || !strings.Contains(held.Error(), "sb") {
		t.Fatal("writer error mapping")
	}
	incomplete := &ManifestIncompleteError{Missing: []string{"file"}}
	if !strings.Contains(incomplete.Error(), "1 file") {
		t.Fatal("incomplete error")
	}
	api := &APIError{Method: "GET", Path: "/v1/workspaces", Status: 500, Body: "failed"}
	if !strings.Contains(api.Error(), "500: failed") {
		t.Fatal("API error")
	}
}

func FuzzAttachmentURL(f *testing.F) {
	f.Add("workspace", "attachment")
	f.Add("w/#? %", "a/#? %")
	f.Fuzz(func(t *testing.T, workspace, attachment string) {
		c := NewClient("https://drive.test", TokenSourceFunc(func(context.Context) (string, error) { return "token", nil }))
		c.WithHTTPClient(&http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			want := "/v1/workspaces/" + url.PathEscape(workspace) + "/attach/" + url.PathEscape(attachment)
			if r.URL.EscapedPath() != want || r.URL.RawQuery != "" || r.URL.Fragment != "" {
				t.Fatalf("escaped path=%s, want %s", r.URL.EscapedPath(), want)
			}
			return &http.Response{StatusCode: 204, Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
		})})
		if err := c.Release(t.Context(), workspace, attachment); err != nil {
			t.Fatal(err)
		}
	})
}

func TestResponseBounds(t *testing.T) {
	for _, tc := range []struct {
		body      string
		limit     int64
		wantError bool
	}{
		{`{"id":"w"}`, 10, false},
		{`{"id":"w"} `, 10, true},
	} {
		raw := &http.Response{Body: io.NopCloser(strings.NewReader(tc.body))}
		var workspace Workspace
		err := newResponse(raw).decodeLimit(&workspace, tc.limit)
		if (err != nil) != tc.wantError {
			t.Fatalf("limit %d body %q: %v", tc.limit, tc.body, err)
		}
	}
	raw := &http.Response{Body: io.NopCloser(strings.NewReader(strings.Repeat("x", maxErrorBody+1)))}
	response := newResponse(raw)
	if len(response.bytes()) != maxErrorBody {
		t.Fatal("diagnostic bound changed")
	}
	if string(response.bytes()[:3]) != "xxx" {
		t.Fatal("cached diagnostic content changed")
	}
}

func TestPutFilePreservesSpecialCharacters(t *testing.T) {
	f := newFakeDrive(t)
	f.handler = func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/files/u-a/workspaces/s/a#b?c%.txt" || r.URL.RawQuery != "" || r.URL.Fragment != "" {
			t.Errorf("file URL = %s", r.URL)
		}
		w.WriteHeader(200)
	}
	if err := f.client(t, "t").PutFile(t.Context(), "u-a", "workspaces/s/", "a#b?c%.txt", strings.NewReader("x"), 1); err != nil {
		t.Fatal(err)
	}
}

func FuzzWorkspacePage(f *testing.F) {
	f.Add(`{"entries":[{"id":"w","owner":"u-a"}],"next_cursor":"next"}`)
	f.Add(`bad json`)
	f.Fuzz(func(t *testing.T, body string) {
		c := NewClient("https://drive.test", TokenSourceFunc(func(context.Context) (string, error) { return "t", nil }))
		c.WithHTTPClient(&http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
		})})
		_, _ = c.ListWorkspacesPage(t.Context(), ListOptions{})
	})
}
