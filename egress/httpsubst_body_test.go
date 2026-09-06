// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package egress

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
)

const bodyHost = "api.provider.example"

func bodyMap() *Map {
	return NewMap([]Entry{
		{Placeholder: ph("cph_body"), Secret: ph("sk-body"), AllowedHosts: []string{bodyHost}, SubstituteBody: true},
		{Placeholder: ph("cph_hdr"), Secret: ph("sk-hdr"), AllowedHosts: []string{bodyHost}},
	})
}

// bodyReq builds a POST with a fixed-length body, as http.ReadRequest would
// deliver it from the wire: ContentLength set and the header present.
func bodyReq(t *testing.T, contentType, body string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, "https://"+bodyHost+"/v1", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Content-Length", strconv.Itoa(len(body)))
	return req
}

func readBody(t *testing.T, req *http.Request) string {
	t.Helper()
	b, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestSubstituteHTTPRequestContext_BodyRewritten(t *testing.T) {
	for _, ct := range []string{
		"application/json",
		"application/json; charset=utf-8",
		"application/vnd.api+json",
		"application/x-www-form-urlencoded",
		"text/plain",
		"text/csv; header=present",
	} {
		t.Run(ct, func(t *testing.T) {
			req := bodyReq(t, ct, `{"key":"cph_body","other":"cph_hdr"}`)
			changed, err := SubstituteHTTPRequestContext(context.Background(), bodyHost, req, bodyMap())
			if err != nil || !changed {
				t.Fatalf("changed=%v err=%v", changed, err)
			}
			// Only the opted-in entry rewrites the body; cph_hdr stays.
			want := `{"key":"sk-body","other":"cph_hdr"}`
			if got := readBody(t, req); got != want {
				t.Fatalf("body = %q, want %q", got, want)
			}
			if req.ContentLength != int64(len(want)) || req.Header.Get("Content-Length") != strconv.Itoa(len(want)) {
				t.Fatalf("framing not updated: %d %q", req.ContentLength, req.Header.Get("Content-Length"))
			}
			rc, err := req.GetBody()
			if err != nil {
				t.Fatal(err)
			}
			if b, _ := io.ReadAll(rc); string(b) != want {
				t.Fatalf("GetBody = %q", b)
			}
		})
	}
}

func TestSubstituteHTTPRequestContext_BodyLeftAlone(t *testing.T) {
	const body = `{"key":"cph_body"}`
	cases := map[string]func(*http.Request){
		"binary":      func(r *http.Request) { r.Header.Set("Content-Type", "application/octet-stream") },
		"multipart":   func(r *http.Request) { r.Header.Set("Content-Type", "multipart/form-data; boundary=x") },
		"no type":     func(r *http.Request) { r.Header.Del("Content-Type") },
		"bad type":    func(r *http.Request) { r.Header.Set("Content-Type", "/") },
		"chunked":     func(r *http.Request) { r.ContentLength = -1; r.Header.Del("Content-Length") },
		"too large":   func(r *http.Request) { r.ContentLength = DefaultMaxBodyBytes + 1 },
		"wrong host":  nil,
		"limit zero":  nil,
		"no body":     func(r *http.Request) { r.Body = http.NoBody; r.ContentLength = 0 },
		"nil body":    func(r *http.Request) { r.Body = nil; r.ContentLength = 0 },
		"static-only": nil,
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			req := bodyReq(t, "application/json", body)
			if mutate != nil {
				mutate(req)
			}
			host := bodyHost
			var opts []SubstituteOption
			var changed bool
			var err error
			switch name {
			case "wrong host":
				host = "other.example"
			case "limit zero":
				opts = append(opts, WithMaxBodyBytes(0))
			}
			if name == "static-only" {
				changed = SubstituteHTTPRequest(host, req, bodyMap())
			} else {
				changed, err = SubstituteHTTPRequestContext(context.Background(), host, req, bodyMap(), opts...)
			}
			if err != nil || changed {
				t.Fatalf("changed=%v err=%v", changed, err)
			}
			if req.Body != nil && req.Body != http.NoBody {
				if got := readBody(t, req); got != body {
					t.Fatalf("body = %q, want untouched %q", got, body)
				}
			}
		})
	}
}

func TestSubstituteHTTPRequestContext_BodyLimitOption(t *testing.T) {
	body := `k=cph_body`
	req := bodyReq(t, "application/x-www-form-urlencoded", body)
	if _, err := SubstituteHTTPRequestContext(context.Background(), bodyHost, req, bodyMap(), WithMaxBodyBytes(int64(len(body)))); err != nil {
		t.Fatal(err)
	}
	if got := readBody(t, req); got != "k=sk-body" {
		t.Fatalf("body = %q", got)
	}
	req = bodyReq(t, "application/x-www-form-urlencoded", body)
	if _, err := SubstituteHTTPRequestContext(context.Background(), bodyHost, req, bodyMap(), WithMaxBodyBytes(int64(len(body))-1)); err != nil {
		t.Fatal(err)
	}
	if got := readBody(t, req); got != body {
		t.Fatalf("body over the limit was rewritten: %q", got)
	}
}

// A body shorter than Content-Length declares is left as delivered: what was
// read is put back in front of what remains.
func TestSubstituteHTTPRequestContext_ShortBody(t *testing.T) {
	req := bodyReq(t, "application/json", "cph_body")
	req.ContentLength = 100
	changed, err := SubstituteHTTPRequestContext(context.Background(), bodyHost, req, bodyMap())
	if err != nil || changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	if got := readBody(t, req); got != "cph_body" {
		t.Fatalf("body = %q", got)
	}
}

type failingBody struct{ closed bool }

func (b *failingBody) Read([]byte) (int, error) { return 0, errors.New("read failed") }
func (b *failingBody) Close() error             { b.closed = true; return nil }

func TestSubstituteHTTPRequestContext_BodyReadError(t *testing.T) {
	req := bodyReq(t, "application/json", "cph_body")
	fb := &failingBody{}
	req.Body = fb
	changed, err := SubstituteHTTPRequestContext(context.Background(), bodyHost, req, bodyMap())
	if err != nil || changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	if _, err := io.ReadAll(req.Body); err == nil {
		t.Fatal("the read error must reach the caller")
	}
	if err := req.Body.Close(); err != nil || !fb.closed {
		t.Fatal("close must reach the original body")
	}
}

// Content-Length is rewritten only when the request carried the header; a
// request built in-process keeps relying on ContentLength alone.
func TestSubstituteHTTPRequestContext_NoContentLengthHeader(t *testing.T) {
	req := bodyReq(t, "application/json", "cph_body")
	req.Header.Del("Content-Length")
	if _, err := SubstituteHTTPRequestContext(context.Background(), bodyHost, req, bodyMap()); err != nil {
		t.Fatal(err)
	}
	if _, ok := req.Header["Content-Length"]; ok {
		t.Fatal("header must not be added")
	}
	if req.ContentLength != int64(len("sk-body")) {
		t.Fatalf("ContentLength = %d", req.ContentLength)
	}
}

// One resolver call serves the header and the body of the same request, and
// a failing resolver leaves the whole request as given.
func TestSubstituteHTTPRequestContext_ResolverOncePerRequest(t *testing.T) {
	var calls atomic.Int32
	fail := atomic.Bool{}
	m := NewMap([]Entry{{
		Placeholder: ph("cph_dyn"), AllowedHosts: []string{bodyHost}, SubstituteBody: true,
		Resolve: func(context.Context) ([]byte, error) {
			calls.Add(1)
			if fail.Load() {
				return nil, errors.New("mint failed")
			}
			return []byte("tok"), nil
		},
	}})
	req := bodyReq(t, "application/json", `{"t":"cph_dyn"}`)
	req.URL.RawQuery = "t=cph_dyn"
	req.Header.Set("Authorization", "Bearer cph_dyn")
	req.Header.Add("X-Also", "cph_dyn")
	changed, err := SubstituteHTTPRequestContext(context.Background(), bodyHost, req, m)
	if err != nil || !changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	if calls.Load() != 1 {
		t.Fatalf("resolver calls = %d, want 1", calls.Load())
	}
	if req.Header.Get("Authorization") != "Bearer tok" || req.Header.Get("X-Also") != "tok" || req.URL.RawQuery != "t=tok" || readBody(t, req) != `{"t":"tok"}` {
		t.Fatalf("request not fully rewritten: %+v", req)
	}

	fail.Store(true)
	req = bodyReq(t, "application/json", `{"t":"cph_dyn"}`)
	req.URL.RawQuery = "t=cph_dyn"
	req.Header.Set("Authorization", "Bearer cph_dyn")
	changed, err = SubstituteHTTPRequestContext(context.Background(), bodyHost, req, m)
	if err == nil || changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	if req.Header.Get("Authorization") != "Bearer cph_dyn" || req.URL.RawQuery != "t=cph_dyn" || readBody(t, req) != `{"t":"cph_dyn"}` {
		t.Fatalf("request mutated on error: %+v", req)
	}
}

func TestSubstituteHTTPRequestContext_ErrorInQueryAndHeader(t *testing.T) {
	m := NewMap([]Entry{{
		Placeholder: ph("cph_dyn"), AllowedHosts: []string{bodyHost},
		Resolve: func(context.Context) ([]byte, error) { return nil, errors.New("no") },
	}})
	req, _ := http.NewRequest(http.MethodGet, "https://"+bodyHost+"/?k=cph_dyn", nil)
	if _, err := SubstituteHTTPRequestContext(context.Background(), bodyHost, req, m); err == nil {
		t.Fatal("query resolver error must surface")
	}
	req, _ = http.NewRequest(http.MethodGet, "https://"+bodyHost+"/", nil)
	req.Header.Set("Authorization", "cph_dyn")
	if _, err := SubstituteHTTPRequestContext(context.Background(), bodyHost, req, m); err == nil {
		t.Fatal("header resolver error must surface")
	}
	if _, err := SubstituteHTTPRequestContext(context.Background(), bodyHost, nil, m); err != nil {
		t.Fatal("nil request must be a no-op")
	}
}

func TestSubstituteHTTPRequest_ExcludedHeaders(t *testing.T) {
	excluded := []string{
		"Content-Length", "Transfer-Encoding", "TE", "Trailer", "Connection",
		"Keep-Alive", "Upgrade", "Proxy-Connection", "Proxy-Authorization",
		"X-Forwarded-For", "X-Forwarded-Host", "x-forwarded-proto", "X-FORWARDED-ANYTHING",
	}
	for _, name := range excluded {
		req, _ := http.NewRequest(http.MethodGet, "https://"+bodyHost+"/", nil)
		req.Header.Set(name, "cph_hdr")
		lower := strings.ToLower("X-Lower-Case-Key") // a non-canonical key still substitutes
		req.Header[lower] = []string{"cph_hdr"}
		if changed := SubstituteHTTPRequest(bodyHost, req, bodyMap()); !changed {
			t.Fatalf("%s: the unrelated header must still change", name)
		}
		if got := req.Header.Get(name); got != "cph_hdr" {
			t.Errorf("%s rewritten to %q", name, got)
		}
		if got := req.Header[lower][0]; got != "sk-hdr" {
			t.Errorf("non-canonical key not rewritten: %q", got)
		}
		changed, err := SubstituteHTTPRequestContext(context.Background(), bodyHost, req, bodyMap())
		if err != nil || changed {
			t.Errorf("%s: second pass changed=%v err=%v", name, changed, err)
		}
	}
	if !substitutableHeader("Authorization") || !substitutableHeader("X-Forward") || substitutableHeader("te") {
		t.Fatal("substitutableHeader misclassifies")
	}
}

func FuzzSubstituteBody(f *testing.F) {
	f.Add("application/json", `{"k":"cph_body"}`, true)
	f.Add("text/plain", "cph_body cph_hdr cph_bodyx", true)
	f.Add("application/octet-stream", "cph_body", true)
	f.Add("application/x-www-form-urlencoded", "a=cph_body&b=cph_body", false)
	f.Add("", "", true)
	f.Fuzz(func(t *testing.T, contentType, body string, allowed bool) {
		host := "other.example"
		if allowed {
			host = bodyHost
		}
		req, err := http.NewRequest(http.MethodPost, "https://"+bodyHost+"/", strings.NewReader(body))
		if err != nil {
			t.Skip()
		}
		req.Header.Set("Content-Type", contentType)
		req.Header.Set("Content-Length", strconv.Itoa(len(body)))
		m := bodyMap()
		changed, err := SubstituteHTTPRequestContext(context.Background(), host, req, m)
		if err != nil {
			t.Fatalf("static map errored: %v", err)
		}
		got, err := io.ReadAll(req.Body)
		if err != nil {
			t.Fatal(err)
		}
		if req.ContentLength != int64(len(got)) {
			t.Fatalf("ContentLength %d != body %d", req.ContentLength, len(got))
		}
		if !allowed || !substitutableMediaType(contentType) {
			if !bytes.Equal(got, []byte(body)) {
				t.Fatalf("body changed when it must not: %q -> %q", body, got)
			}
			return
		}
		want, wantChanged := replaceToken(body, "cph_body", "sk-body")
		if string(got) != want {
			t.Fatalf("body = %q, want %q", got, want)
		}
		if wantChanged && !changed {
			t.Fatal("changed not reported")
		}
		// The header-only entry never touches the body.
		if strings.Contains(string(got), "sk-hdr") {
			t.Fatal("header-only secret leaked into the body")
		}
	})
}
