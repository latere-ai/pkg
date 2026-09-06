// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package s3test

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"latere.ai/x/pkg/s3"
)

// recorder captures Errorf so the fake's own refusals can be asserted
// from inside a passing test.
type recorder struct {
	testing.TB
	errors []string
}

func (r *recorder) Helper() {}

func (r *recorder) Errorf(format string, args ...any) {
	r.errors = append(r.errors, fmt.Sprintf(format, args...))
}

func TestSeedingAndInspectionBypassTheWire(t *testing.T) {
	s := New(t, "b")
	s.Put("b/1", []byte("one"))
	s.Put("a/1", []byte("two"))
	if got, ok := s.Get("b/1"); !ok || string(got) != "one" {
		t.Fatalf("get: %q %v", got, ok)
	}
	if _, ok := s.Get("nope"); ok {
		t.Fatal("absent key present")
	}
	if got := strings.Join(s.Keys(), ","); got != "a/1,b/1" {
		t.Fatalf("keys = %s", got)
	}
	c := s.Client(true)
	rc, o, err := c.GetObject(context.Background(), "a/1", "")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(rc)
	_ = rc.Close()
	if string(b) != "two" || o.Size != 3 {
		t.Fatalf("seeded object over the wire: %q %+v", b, o)
	}
	if n := len(s.Requests()); n != 1 || s.Requests()[0].Method != http.MethodGet {
		t.Fatalf("requests: %+v", s.Requests())
	}
}

func TestIfMatchIsRefusedLikeSpaces(t *testing.T) {
	s := New(t, "b")
	s.Put("k", []byte("v"))
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPut, s.URL()+"/b/k", strings.NewReader("w"))
	req.ContentLength = 1
	req.Header.Set("If-Match", `"anything"`)
	s.signer.Sign(req, "UNSIGNED-PAYLOAD", time.Now())
	resp, err := s.HTTPClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusPreconditionFailed {
		t.Fatalf("If-Match answered %d", resp.StatusCode)
	}
	if got, _ := s.Get("k"); string(got) != "v" {
		t.Fatalf("object changed to %q", got)
	}
}

func TestVerificationFailuresAreReportedAndRefused(t *testing.T) {
	rec := &recorder{TB: t}
	s := New(rec, "b")
	hc := s.HTTPClient()
	do := func(req *http.Request) int {
		t.Helper()
		resp, err := hc.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	// No signature at all.
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, s.URL()+"/b/k", nil)
	if code := do(req); code != http.StatusForbidden {
		t.Fatalf("unsigned: %d", code)
	}
	// A wrong Content-MD5 and a wrong SHA-256.
	for name, hash := range map[string]string{"md5": "UNSIGNED-PAYLOAD", "sha256": strings.Repeat("0", 64)} {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodPut, s.URL()+"/b/k", strings.NewReader("v"))
		req.ContentLength = 1
		if name == "md5" {
			req.Header.Set("Content-MD5", "AAAAAAAAAAAAAAAAAAAAAA==")
		}
		s.signer.Sign(req, hash, time.Now())
		if code := do(req); code != http.StatusBadRequest {
			t.Fatalf("%s: %d", name, code)
		}
	}
	if len(rec.errors) != 3 {
		t.Fatalf("reported %d failures: %q", len(rec.errors), rec.errors)
	}
	// A body that ends before its Content-Length, sent on a raw connection
	// because the standard client refuses to send one.
	req, _ = http.NewRequestWithContext(context.Background(), http.MethodPut, s.URL()+"/b/k", nil)
	req.ContentLength = 3
	s.signer.Sign(req, "UNSIGNED-PAYLOAD", time.Now())
	conn, err := net.Dial("tcp", strings.TrimPrefix(s.URL(), "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	fmt.Fprintf(conn, "PUT /b/k HTTP/1.1\r\nHost: %s\r\nContent-Length: 3\r\n", req.Host)
	for k, v := range req.Header {
		fmt.Fprintf(conn, "%s: %s\r\n", k, v[0])
	}
	fmt.Fprint(conn, "\r\nv")
	_ = conn.(*net.TCPConn).CloseWrite()
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("short body: %d", resp.StatusCode)
	}
	if _, ok := s.Get("k"); ok {
		t.Fatal("a refused PUT stored the object")
	}
}

func TestPresignedURLExpiresOnTheServerClock(t *testing.T) {
	s := New(t, "b")
	s.Put("k", []byte("v"))
	c := s.Client(true)
	u, err := c.PresignGet("k", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	s.SetClock(func() time.Time { return time.Now().Add(2 * time.Minute) })
	resp, err := s.HTTPClient().Get(u)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expired presigned URL answered %d", resp.StatusCode)
	}
}

func TestUnknownMethodAndVirtualHostKeys(t *testing.T) {
	s := New(t, "b")
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, s.URL()+"/b/k", nil)
	s.signer.Sign(req, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", time.Now())
	resp, err := s.HTTPClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("POST answered %d", resp.StatusCode)
	}
	c := s.Client(false)
	if _, err := c.PutObject(context.Background(), "v/k", s3.BytesBody([]byte("x"))); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Get("v/k"); !ok {
		t.Fatalf("virtual-host key not stored: %v", s.Keys())
	}
	res, err := c.ListObjects(context.Background(), s3.ListOptions{Prefix: "v/"})
	if err != nil || len(res.Objects) != 1 {
		t.Fatalf("virtual-host list: %+v, %v", res, err)
	}
}

func TestFailInjectsAfterVerification(t *testing.T) {
	s := New(t, "b")
	c := s.Client(true, s3.WithRetry(fastRetry))
	s.Fail(3, http.StatusBadGateway)
	_, _, err := c.GetObject(context.Background(), "k", "")
	var se *s3.Error
	if !errors.As(err, &se) || se.Status != 502 || se.Code != "InternalError" {
		t.Fatalf("injected failure: %v", err)
	}
	if s.Count(http.MethodGet) != 3 {
		t.Fatalf("%d GETs", s.Count(http.MethodGet))
	}
}

func TestClientFatalsOnABadEndpoint(t *testing.T) {
	rec := &fataler{TB: t}
	s := New(rec, "")
	s.Client(true)
	if !rec.fatal {
		t.Fatal("an empty bucket built a client")
	}
}

type fataler struct {
	testing.TB
	fatal bool
}

func (f *fataler) Helper()           {}
func (f *fataler) Fatal(args ...any) { f.fatal = true }

func TestListingAndConditionalReadsMatchTheProviders(t *testing.T) {
	s := New(t, "b")
	for _, k := range []string{"r/a/1", "r/a/2", "r/b/1", "r/c", "x"} {
		s.Put(k, []byte(k))
	}
	c := s.Client(true)
	ctx := context.Background()
	res, err := c.ListObjects(ctx, s3.ListOptions{Prefix: "r/", Delimiter: "/", MaxKeys: 2})
	if err != nil || !res.Truncated || strings.Join(res.Prefixes, ",") != "r/a/,r/b/" || len(res.Objects) != 0 {
		t.Fatalf("grouped page: %+v, %v", res, err)
	}
	res, err = c.ListObjects(ctx, s3.ListOptions{Prefix: "r/", Delimiter: "/", StartAfter: "r/b/1"})
	if err != nil || res.Truncated || len(res.Prefixes) != 0 || len(res.Objects) != 1 || res.Objects[0].Key != "r/c" {
		t.Fatalf("last page: %+v, %v", res, err)
	}
	res, err = c.ListObjects(ctx, s3.ListOptions{Prefix: "r/", MaxKeys: 3})
	if err != nil || !res.Truncated || len(res.Objects) != 3 {
		t.Fatalf("flat page: %+v, %v", res, err)
	}
	o, err := c.HeadObject(ctx, "x")
	if err != nil || o.Size != 1 {
		t.Fatalf("head: %+v, %v", o, err)
	}
	if _, _, err := c.GetObject(ctx, "x", strings.Trim(o.ETag, `"`)); !errors.Is(err, s3.ErrNotModified) {
		t.Fatalf("unquoted etag did not match: %v", err)
	}
	if _, err := c.HeadObject(ctx, "absent"); !errors.Is(err, s3.ErrNotFound) {
		t.Fatalf("head absent: %v", err)
	}
	if err := c.DeleteObject(ctx, "x"); err != nil || len(s.Keys()) != 4 {
		t.Fatalf("delete: %v, %v", err, s.Keys())
	}
}
