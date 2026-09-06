// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package s3_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"latere.ai/x/pkg/retry"
	"latere.ai/x/pkg/s3"
	"latere.ai/x/pkg/s3/s3test"
)

func TestPrimitivesOverBothAddressingStyles(t *testing.T) {
	for _, pathStyle := range []bool{true, false} {
		t.Run(map[bool]string{true: "path-style", false: "virtual-host"}[pathStyle], func(t *testing.T) {
			runPrimitives(t, func(t *testing.T) *s3.Client {
				return s3test.New(t, "bucket").Client(pathStyle)
			})
		})
	}
}

// runPrimitives is the contract every store the family runs on was
// verified to share; a consumer's integration tier runs the same shape.
func runPrimitives(t *testing.T, newClient func(t *testing.T) *s3.Client) {
	t.Helper()
	ctx := context.Background()

	t.Run("create refuses an existing key and leaves it untouched", func(t *testing.T) {
		c := newClient(t)
		etag, err := c.CreateObject(ctx, "idx/1", s3.BytesBody([]byte("a")))
		if err != nil || etag == "" {
			t.Fatalf("create: %q, %v", etag, err)
		}
		_, err = c.CreateObject(ctx, "idx/1", s3.BytesBody([]byte("b")))
		if !errors.Is(err, s3.ErrPreconditionFailed) {
			t.Fatalf("second create: %v", err)
		}
		var se *s3.Error
		if !errors.As(err, &se) || se.Status != 412 || se.Code != "PreconditionFailed" {
			t.Fatalf("error detail: %#v", err)
		}
		if got := read(ctx, t, c, "idx/1"); got != "a" {
			t.Fatalf("content = %q after a refused create", got)
		}
	})

	t.Run("put overwrites and the etag changes", func(t *testing.T) {
		c := newClient(t)
		e1, err := c.PutObject(ctx, "hint", s3.BytesBody([]byte("1")))
		if err != nil {
			t.Fatal(err)
		}
		e2, err := c.PutObject(ctx, "hint", s3.BytesBody([]byte("2")))
		if err != nil || e1 == e2 {
			t.Fatalf("etags %q %q, %v", e1, e2, err)
		}
		if got := read(ctx, t, c, "hint"); got != "2" {
			t.Fatalf("content = %q", got)
		}
	})

	t.Run("head answers 404 or the etag get reports", func(t *testing.T) {
		c := newClient(t)
		if _, err := c.HeadObject(ctx, "absent"); !errors.Is(err, s3.ErrNotFound) {
			t.Fatalf("head absent: %v", err)
		}
		if _, _, err := c.GetObject(ctx, "absent", ""); !errors.Is(err, s3.ErrNotFound) {
			t.Fatalf("get absent: %v", err)
		}
		if _, err := c.CreateObject(ctx, "k", s3.BytesBody([]byte("body"))); err != nil {
			t.Fatal(err)
		}
		h, err := c.HeadObject(ctx, "k")
		if err != nil || h.Size != 4 || h.ETag == "" || h.LastModified.IsZero() || h.Key != "k" {
			t.Fatalf("head: %+v, %v", h, err)
		}
		rc, o, err := c.GetObject(ctx, "k", "")
		if err != nil {
			t.Fatal(err)
		}
		_ = rc.Close()
		if o.ETag != h.ETag || o.Size != 4 {
			t.Fatalf("get object %+v, head %+v", o, h)
		}
	})

	t.Run("content type is sent on put and create and answered on get and head", func(t *testing.T) {
		c := newClient(t)
		typed := s3.BytesBody([]byte("{}"))
		typed.ContentType = "application/json"
		if _, err := c.PutObject(ctx, "put", typed); err != nil {
			t.Fatal(err)
		}
		if _, err := c.CreateObject(ctx, "create", typed); err != nil {
			t.Fatal(err)
		}
		if _, err := c.PutObject(ctx, "plain", s3.BytesBody([]byte("{}"))); err != nil {
			t.Fatal(err)
		}
		for key, want := range map[string]string{"put": "application/json", "create": "application/json", "plain": s3test.DefaultContentType} {
			h, err := c.HeadObject(ctx, key)
			if err != nil || h.ContentType != want {
				t.Errorf("head %s: %q, %v, want %q", key, h.ContentType, err, want)
			}
			rc, o, err := c.GetObject(ctx, key, "")
			if err != nil {
				t.Fatal(err)
			}
			_ = rc.Close()
			if o.ContentType != want {
				t.Errorf("get %s: %q, want %q", key, o.ContentType, want)
			}
		}
	})

	t.Run("conditional get answers 304 for the current etag and 200 for a stale one", func(t *testing.T) {
		c := newClient(t)
		etag, err := c.CreateObject(ctx, "k", s3.BytesBody([]byte("body")))
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := c.GetObject(ctx, "k", etag); !errors.Is(err, s3.ErrNotModified) {
			t.Fatalf("get current: %v", err)
		}
		rc, _, err := c.GetObject(ctx, "k", `"0123456789abcdef0123456789abcdef"`)
		if err != nil {
			t.Fatalf("get stale: %v", err)
		}
		b, _ := io.ReadAll(rc)
		_ = rc.Close()
		if string(b) != "body" {
			t.Fatalf("body = %q", b)
		}
	})

	t.Run("list is lexical with prefix, start-after, max-keys, and delimiter", func(t *testing.T) {
		c := newClient(t)
		for _, k := range []string{"r/a/index/000000000002", "r/a/index/000000000001", "r/a/index/latest", "r/b/meta", "r/a/wal/x"} {
			if _, err := c.PutObject(ctx, k, s3.BytesBody([]byte(k))); err != nil {
				t.Fatal(err)
			}
		}
		res, err := c.ListObjects(ctx, s3.ListOptions{Prefix: "r/a/index/0"})
		if err != nil {
			t.Fatal(err)
		}
		if keys(res) != "r/a/index/000000000001,r/a/index/000000000002" || res.Truncated {
			t.Fatalf("list = %q truncated %v", keys(res), res.Truncated)
		}
		if o := res.Objects[0]; o.Size != int64(len(o.Key)) || o.ETag == "" || o.LastModified.IsZero() {
			t.Fatalf("listed object: %+v", o)
		}
		res, err = c.ListObjects(ctx, s3.ListOptions{Prefix: "r/a/", MaxKeys: 2})
		if err != nil || !res.Truncated || keys(res) != "r/a/index/000000000001,r/a/index/000000000002" {
			t.Fatalf("page 1 = %q truncated %v, %v", keys(res), res.Truncated, err)
		}
		res, err = c.ListObjects(ctx, s3.ListOptions{Prefix: "r/a/", MaxKeys: 2, StartAfter: res.Objects[1].Key})
		if err != nil || keys(res) != "r/a/index/latest,r/a/wal/x" {
			t.Fatalf("page 2 = %q, %v", keys(res), err)
		}
		res, err = c.ListObjects(ctx, s3.ListOptions{Prefix: "r/", Delimiter: "/"})
		if err != nil || len(res.Objects) != 0 || strings.Join(res.Prefixes, ",") != "r/a/,r/b/" {
			t.Fatalf("prefixes = %q objects %d, %v", res.Prefixes, len(res.Objects), err)
		}
	})

	t.Run("delete is idempotent", func(t *testing.T) {
		c := newClient(t)
		if _, err := c.PutObject(ctx, "k", s3.BytesBody([]byte("x"))); err != nil {
			t.Fatal(err)
		}
		if err := c.DeleteObject(ctx, "k"); err != nil {
			t.Fatal(err)
		}
		if err := c.DeleteObject(ctx, "k"); err != nil {
			t.Fatalf("second delete: %v", err)
		}
		if _, err := c.HeadObject(ctx, "k"); !errors.Is(err, s3.ErrNotFound) {
			t.Fatalf("head after delete: %v", err)
		}
	})

	t.Run("16 writers race to create one key for 20 rounds, exactly one wins each", func(t *testing.T) {
		c := newClient(t)
		const writers, rounds = 16, 20
		for round := range rounds {
			key := fmt.Sprintf("race/%012d", round)
			var wg sync.WaitGroup
			wins := make([]int, writers)
			for w := range writers {
				wg.Go(func() {
					_, err := c.CreateObject(ctx, key, s3.BytesBody(fmt.Appendf(nil, "writer-%d", w)))
					switch {
					case err == nil:
						wins[w] = 1
					case errors.Is(err, s3.ErrPreconditionFailed):
					default:
						t.Errorf("round %d writer %d: %v", round, w, err)
					}
				})
			}
			wg.Wait()
			winner, total := -1, 0
			for w, n := range wins {
				total += n
				if n == 1 {
					winner = w
				}
			}
			if total != 1 {
				t.Fatalf("round %d: %d winners", round, total)
			}
			if got := read(ctx, t, c, key); got != fmt.Sprintf("writer-%d", winner) {
				t.Fatalf("round %d: stored %q, winner %d", round, got, winner)
			}
		}
	})

	t.Run("presigned get and put reach the object without a credential", func(t *testing.T) {
		c := newClient(t)
		hc := &http.Client{Transport: http.DefaultTransport.(*http.Transport).Clone()}
		put, err := c.PresignPut("up/loaded", time.Minute, 5)
		if err != nil {
			t.Fatal(err)
		}
		req, _ := http.NewRequestWithContext(ctx, http.MethodPut, put, strings.NewReader("hello"))
		req.ContentLength = 5
		resp, err := hc.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("presigned put: %d", resp.StatusCode)
		}
		get, err := c.PresignGet("up/loaded", time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		resp, err = hc.Get(get)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != 200 || string(b) != "hello" {
			t.Fatalf("presigned get: %d %q", resp.StatusCode, b)
		}
	})
}

func read(ctx context.Context, t *testing.T, c *s3.Client, key string) string {
	t.Helper()
	rc, _, err := c.GetObject(ctx, key, "")
	if err != nil {
		t.Fatalf("get %s: %v", key, err)
	}
	defer func() { _ = rc.Close() }()
	b, err := io.ReadAll(rc)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func keys(res s3.ListResult) string {
	var b []string
	for _, o := range res.Objects {
		b = append(b, o.Key)
	}
	return strings.Join(b, ",")
}

func TestNewRejectsBadParameters(t *testing.T) {
	for name, args := range map[string][5]string{
		"relative endpoint": {"minio:9000", "r", "b", "k", "s"},
		"no bucket":         {"http://minio:9000", "r", "", "k", "s"},
		"no region":         {"http://minio:9000", "", "b", "k", "s"},
		"no secret":         {"http://minio:9000", "r", "b", "k", ""},
	} {
		if _, err := s3.New(args[0], args[1], args[2], args[3], args[4]); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	c, err := s3.New("http://minio:9000", "r", "b", "k", "s")
	if err != nil || c == nil {
		t.Fatalf("default client: %v", err)
	}
}

func TestRetriesServerFailuresAndNotClientOnes(t *testing.T) {
	ctx := context.Background()
	f := s3test.New(t, "b")
	c := f.Client(true)
	f.Fail(2, http.StatusServiceUnavailable)
	if _, err := c.PutObject(ctx, "k", s3.BytesBody([]byte("v"))); err != nil {
		t.Fatalf("put after two 503s: %v", err)
	}
	if n := f.Count(http.MethodPut); n != 3 {
		t.Fatalf("%d PUTs, want 3", n)
	}
	f.Fail(3, http.StatusInternalServerError)
	_, err := c.HeadObject(ctx, "k")
	if err == nil || !strings.Contains(err.Error(), "after 3 attempts") {
		t.Fatalf("head after three 500s: %v", err)
	}
	f.Fail(3, http.StatusInternalServerError)
	_, _, err = c.GetObject(ctx, "k", "")
	var se *s3.Error
	if err == nil || !errors.As(err, &se) || se.Status != 500 || se.Code != "InternalError" || se.Message != "injected" {
		t.Fatalf("get after three 500s: %v", err)
	}
	f.Fail(1, http.StatusTooManyRequests)
	if _, err := c.HeadObject(ctx, "k"); err != nil {
		t.Fatalf("head after a 429: %v", err)
	}
	f.Fail(1, http.StatusForbidden)
	if _, _, err := c.GetObject(ctx, "k", ""); err == nil || !strings.Contains(err.Error(), "403") || strings.Contains(err.Error(), "attempts") {
		t.Fatalf("get with a 403: %v", err)
	}
	if n := f.Count(http.MethodHead); n != 5 || f.Count(http.MethodGet) != 4 {
		t.Fatalf("%d HEADs, want 5", n)
	}
	broken := s3.Body{Open: func() (io.ReadCloser, error) { return nil, errors.New("no body") }, Size: 1}
	if _, err := c.PutObject(ctx, "k2", broken); err == nil || !strings.Contains(err.Error(), "no body") || strings.Contains(err.Error(), "attempts") {
		t.Fatalf("broken body: %v", err)
	}
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	f.Fail(2, http.StatusInternalServerError)
	if _, err := c.HeadObject(cctx, "k"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled head: %v", err)
	}
}

func TestErrorsWithoutAnXMLBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("plain text"))
	}))
	defer srv.Close()
	c, _ := s3.New(srv.URL, "r", "b", "k", "s", s3.WithPathStyle(), s3.WithHTTPClient(srv.Client()))
	_, _, err := c.GetObject(context.Background(), "k", "")
	var se *s3.Error
	if err == nil || !errors.As(err, &se) || se.Body != "plain text" || err.Error() != "s3: 400: plain text" {
		t.Fatalf("err = %v", err)
	}
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("<not xml"))
	}))
	defer bad.Close()
	c, _ = s3.New(bad.URL, "r", "b", "k", "s", s3.WithPathStyle(), s3.WithHTTPClient(bad.Client()))
	if _, err := c.ListObjects(context.Background(), s3.ListOptions{}); err == nil {
		t.Fatal("malformed listing accepted")
	}
	empty := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))
	defer empty.Close()
	c, _ = s3.New(empty.URL, "r", "b", "k", "s", s3.WithPathStyle(), s3.WithHTTPClient(empty.Client()))
	if err := c.DeleteObject(context.Background(), "k"); err == nil || err.Error() != "s3: 418" {
		t.Fatalf("empty body: %v", err)
	}
	// A transport failure is retried and then reported.
	c, _ = s3.New("http://127.0.0.1:1", "r", "b", "k", "s", s3.WithPathStyle(),
		s3.WithRetry(retry.Policy{MaxAttempts: 2, Base: time.Nanosecond, Max: time.Nanosecond}))
	if _, err := c.HeadObject(context.Background(), "k"); err == nil || !strings.Contains(err.Error(), "after 2 attempts") {
		t.Fatalf("unreachable endpoint: %v", err)
	}
}

func TestListingReadsTheBodyWhole(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "100")
		_, _ = w.Write([]byte("<ListBucketResult>"))
	}))
	defer srv.Close()
	c, _ := s3.New(srv.URL, "r", "b", "k", "s", s3.WithPathStyle(), s3.WithHTTPClient(srv.Client()))
	if _, err := c.ListObjects(context.Background(), s3.ListOptions{}); err == nil {
		t.Fatal("truncated listing accepted")
	}
}

func TestPresignRefusesWhatTheStoreWould(t *testing.T) {
	c := s3test.New(t, "b").Client(true)
	if _, err := c.PresignGet("", time.Minute); err == nil {
		t.Error("empty key")
	}
	if _, err := c.PresignGet("k", 0); err == nil {
		t.Error("zero expiry")
	}
	if _, err := c.PresignGet("k", 8*24*time.Hour); err == nil {
		t.Error("eight days")
	}
	if _, err := c.PresignPut("k", time.Minute, -1); err == nil {
		t.Error("negative length")
	}
}

func TestBodies(t *testing.T) {
	b := s3.BytesBody([]byte("abc"))
	if b.Size != 3 || b.SHA256 != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" || b.MD5 != "kAFQmDzST7DWlj99KOF/cg==" {
		t.Fatalf("bytes body: %+v", b)
	}
	data, err := b.ReadAll()
	if err != nil || string(data) != "abc" {
		t.Fatalf("read all: %q, %v", data, err)
	}
	path := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(path, []byte("abc"), 0o600); err != nil {
		t.Fatal(err)
	}
	fb, err := s3.FileBody(path)
	if err != nil || fb.Size != 3 || fb.SHA256 != b.SHA256 || fb.MD5 != b.MD5 {
		t.Fatalf("file body: %+v, %v", fb, err)
	}
	if data, err := fb.ReadAll(); err != nil || string(data) != "abc" {
		t.Fatalf("file read all: %q, %v", data, err)
	}
	if _, err := s3.FileBody(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing file")
	}
	if _, err := s3.FileBody(t.TempDir()); err == nil {
		t.Fatal("a directory hashed")
	}
	broken := s3.Body{Open: func() (io.ReadCloser, error) { return nil, errors.New("no") }}
	if _, err := broken.ReadAll(); err == nil {
		t.Fatal("broken body read")
	}
	// An unsigned payload without Content-MD5 is accepted by the store.
	c := s3test.New(t, "b").Client(true)
	plain := s3.Body{Open: b.Open, Size: 3}
	if _, err := c.PutObject(context.Background(), "k", plain); err != nil {
		t.Fatalf("unsigned payload: %v", err)
	}
}

func TestErrorIsMatchesOnlyItsStatus(t *testing.T) {
	e := &s3.Error{Status: 404}
	if !errors.Is(e, s3.ErrNotFound) || errors.Is(e, s3.ErrNotModified) || errors.Is(e, s3.ErrPreconditionFailed) || errors.Is(e, io.EOF) {
		t.Fatal("Is")
	}
	if e.Error() != "s3: 404" {
		t.Fatal(e.Error())
	}
}

// recorder captures the fake's Errorf so a deliberately wrong request
// can be asserted from a passing test.
type recorder struct {
	testing.TB
	errors int
}

func (r *recorder) Helper()               {}
func (r *recorder) Errorf(string, ...any) { r.errors++ }

func TestPresignedPutIsBoundToItsContentLength(t *testing.T) {
	rec := &recorder{TB: t}
	c := s3test.New(rec, "b").Client(true)
	put, err := c.PresignPut("k", time.Minute, 5)
	if err != nil {
		t.Fatal(err)
	}
	hc := &http.Client{Transport: http.DefaultTransport.(*http.Transport).Clone()}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPut, put, strings.NewReader("hello!"))
	req.ContentLength = 6
	resp, err := hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 403 || rec.errors != 1 {
		t.Fatalf("presigned put of another length: %d, %d reports", resp.StatusCode, rec.errors)
	}
}

// A Content-Type of any shape either reaches the store and comes back on
// HEAD as sent, or is refused by the transport before it is sent. Go's
// transport refuses a value with a control byte, and the server side
// trims the spaces and tabs around a value, so those are the two
// departures from identity the fuzz allows.
func FuzzContentTypeRoundTrip(f *testing.F) {
	f.Add("text/plain")
	f.Add("  application/json; charset=utf-8\t")
	f.Add("")
	f.Add(" ")
	f.Add("a\nb")
	f.Add("\xc2\x85x")
	tb := &fuzzTB{TB: f}
	c := s3test.New(tb, "b").Client(true)
	f.Fuzz(func(t *testing.T, ct string) {
		tb.enter(t)
		defer tb.leave()
		body := s3.BytesBody([]byte("v"))
		body.ContentType = ct
		_, err := c.PutObject(context.Background(), "k", body)
		if !validHeaderValue(ct) {
			if err == nil {
				t.Fatalf("Content-Type %q with a control byte was sent", ct)
			}
			return
		}
		if err != nil {
			t.Fatalf("put with Content-Type %q: %v", ct, err)
		}
		want := strings.Trim(ct, " \t")
		if want == "" {
			want = s3test.DefaultContentType
		}
		h, err := c.HeadObject(context.Background(), "k")
		if err != nil || h.ContentType != want {
			t.Fatalf("head after Content-Type %q: %q, %v, want %q", ct, h.ContentType, err, want)
		}
	})
}

// validHeaderValue is the transport's rule: any byte but a control
// character other than tab.
func validHeaderValue(v string) bool {
	for i := range len(v) {
		if b := v[i]; b < ' ' && b != '\t' || b == 0x7f {
			return false
		}
	}
	return true
}

// fuzzTB is one server for a whole fuzz function: a listener per input
// exhausts the ephemeral ports. Setup runs on the F; a report from
// inside the fuzz target reaches the input's own T, since an F refuses
// to fail from there.
type fuzzTB struct {
	testing.TB
	mu  sync.Mutex
	cur testing.TB
}

func (w *fuzzTB) enter(t testing.TB) { w.mu.Lock(); w.cur = t; w.mu.Unlock() }
func (w *fuzzTB) leave()             { w.mu.Lock(); w.cur = nil; w.mu.Unlock() }

func (w *fuzzTB) target() testing.TB {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.cur != nil {
		return w.cur
	}
	return w.TB
}

func (w *fuzzTB) Helper()                        {}
func (w *fuzzTB) Errorf(format string, a ...any) { w.target().Errorf(format, a...) }
func (w *fuzzTB) Fatal(a ...any)                 { w.target().Fatal(a...) }
