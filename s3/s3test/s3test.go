// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// Package s3test is an in-process S3 endpoint for a consumer's tests. It
// serves the primitives the parent package sends, over a map, with the
// semantics the providers were verified to share: create-if-absent
// refuses an existing key with 412 and leaves it untouched, a conditional
// GET answers 304, a HEAD of an absent key answers 404, a listing is
// lexical, and a delete of a missing key succeeds.
//
// It behaves like the least capable provider where they differ: a PUT
// with If-Match answers 412 whatever the ETag, the way Spaces does, so a
// design that relies on compare-and-swap fails here rather than in one
// region.
//
// Every request is verified the way a real endpoint verifies it: the
// signature is recomputed from what arrived on the wire, a body is
// checked against its Content-MD5 and its signed SHA-256, and a
// presigned URL is refused after it expires. A verification failure is
// reported on the test and answered with the status the provider would
// send.
//
// An object keeps the Content-Type its PUT carried and answers it on GET
// and HEAD. A PUT without one stores [DefaultContentType], the way MinIO
// does, so a consumer's test reads back what a provider would send.
package s3test

import (
	"bytes"
	"crypto/md5" //nolint:gosec // the ETag S3 reports for a single-part object
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"latere.ai/x/pkg/s3"
	"latere.ai/x/pkg/s3/internal/sigv4"
)

// The credential every Server accepts.
const (
	Key    = "AKIDEXAMPLE"
	Secret = "secret"
	Region = "us-east-1"
)

// DefaultContentType is stored for a PUT that carries no Content-Type.
const DefaultContentType = "application/octet-stream"

// Server is one bucket behind an httptest listener.
type Server struct {
	t      testing.TB
	srv    *httptest.Server
	bucket string
	signer sigv4.Signer

	mu       sync.Mutex
	objects  map[string]object
	requests []Request
	failNext int
	failCode int
	now      func() time.Time
}

type object struct {
	data        []byte
	etag        string
	contentType string
	modified    time.Time
}

// Request is one request the server saw.
type Request struct {
	Method string
	Path   string
	Header http.Header
}

// New starts a server for bucket and stops it when the test ends.
func New(t testing.TB, bucket string) *Server {
	t.Helper()
	s := &Server{
		t: t, bucket: bucket, objects: map[string]object{}, now: time.Now,
		signer:   sigv4.Signer{Key: Key, Secret: Secret, Region: Region},
		failCode: http.StatusInternalServerError,
	}
	s.srv = httptest.NewServer(s)
	t.Cleanup(s.srv.Close)
	return s
}

// URL is the endpoint for path-style addressing.
func (s *Server) URL() string { return s.srv.URL }

// VirtualHostURL is the endpoint for virtual-host addressing: the
// listener under a name whose sub-labels resolve to the loopback
// address, so bucket.localhost reaches it.
func (s *Server) VirtualHostURL() string {
	return strings.Replace(s.srv.URL, "127.0.0.1", "localhost", 1)
}

// HTTPClient is the client that reaches the listener.
func (s *Server) HTTPClient() *http.Client { return s.srv.Client() }

// Client returns a parent-package client on this server, path-style
// unless the caller adds virtual-host addressing through the endpoint.
// The retry policy waits nothing between attempts, so a test of the
// retry path runs at once; a consumer passes s3.WithRetry to change it.
func (s *Server) Client(pathStyle bool, opts ...s3.Option) *s3.Client {
	s.t.Helper()
	endpoint := s.URL()
	all := []s3.Option{s3.WithHTTPClient(s.HTTPClient()), s3.WithRetry(fastRetry)}
	if pathStyle {
		all = append(all, s3.WithPathStyle())
	} else {
		endpoint = s.VirtualHostURL()
	}
	all = append(all, opts...)
	c, err := s3.New(endpoint, Region, s.bucket, Key, Secret, all...)
	if err != nil {
		s.t.Fatal(err)
	}
	return c
}

// SetClock replaces the clock that stamps LastModified and judges a
// presigned URL's expiry.
func (s *Server) SetClock(now func() time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.now = now
}

// Fail makes the next n requests answer status with an XML error body,
// after their signature is verified. It is how a consumer tests the
// retry path.
func (s *Server) Fail(n, status int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failNext, s.failCode = n, status
}

// Requests reports every request seen so far, in order.
func (s *Server) Requests() []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Request(nil), s.requests...)
}

// Count reports how many requests used method.
func (s *Server) Count(method string) int {
	n := 0
	for _, r := range s.Requests() {
		if r.Method == method {
			n++
		}
	}
	return n
}

// Put seeds key with data under DefaultContentType, bypassing the wire.
func (s *Server) Put(key string, data []byte) {
	s.PutWithContentType(key, data, "")
}

// PutWithContentType seeds key with data and contentType, bypassing the
// wire. An empty contentType stores DefaultContentType.
func (s *Server) PutWithContentType(key string, data []byte, contentType string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.store(key, data, contentType)
}

// Get reads key, bypassing the wire.
func (s *Server) Get(key string) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	o, ok := s.objects[key]
	return append([]byte(nil), o.data...), ok
}

// ContentType reports the Content-Type stored for key, and whether the
// key exists. It is what a GET or HEAD of the key answers.
func (s *Server) ContentType(key string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	o, ok := s.objects[key]
	return o.contentType, ok
}

// Keys reports every key in lexical order.
func (s *Server) Keys() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sortedKeys()
}

func (s *Server) sortedKeys() []string {
	keys := make([]string, 0, len(s.objects))
	for k := range s.objects {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func (s *Server) store(key string, data []byte, contentType string) string {
	sum := md5.Sum(data) //nolint:gosec // ETag
	etag := `"` + hex.EncodeToString(sum[:]) + `"`
	if contentType == "" {
		contentType = DefaultContentType
	}
	s.objects[key] = object{data: data, etag: etag, contentType: contentType, modified: s.now()}
	return etag
}

// ServeHTTP is the endpoint.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.requests = append(s.requests, Request{Method: r.Method, Path: r.URL.RequestURI(), Header: r.Header.Clone()})
	fail := s.failNext > 0
	if fail {
		s.failNext--
	}
	code := s.failCode
	now := s.now
	s.mu.Unlock()

	if err := s.signer.Verify(r); err != nil {
		s.t.Errorf("s3test: %s %s: %v", r.Method, r.URL.RequestURI(), err)
		s.refuse(w, http.StatusForbidden, "SignatureDoesNotMatch", err.Error())
		return
	}
	if q := r.URL.Query(); q.Get("X-Amz-Signature") != "" {
		at, _ := time.Parse(sigv4.DateFormat, q.Get("X-Amz-Date"))
		expires, _ := strconv.ParseInt(q.Get("X-Amz-Expires"), 10, 64)
		if now().After(at.Add(time.Duration(expires) * time.Second)) {
			s.refuse(w, http.StatusForbidden, "AccessDenied", "Request has expired")
			return
		}
	}
	if fail {
		s.refuse(w, code, "InternalError", "injected")
		return
	}
	if r.Header.Get("If-Match") != "" {
		// Spaces answers 412 to every If-Match; the fake does the same so
		// a compare-and-swap fails in the unit suite.
		s.refuse(w, http.StatusPreconditionFailed, "PreconditionFailed", "If-Match is not honoured; see the s3 package documentation")
		return
	}
	key := s.key(r)
	switch {
	case r.Method == http.MethodGet && key == "" && r.URL.Query().Get("list-type") == "2":
		s.list(w, r)
	case r.Method == http.MethodPut:
		s.put(w, r, key)
	case r.Method == http.MethodGet, r.Method == http.MethodHead:
		s.get(w, r, key)
	case r.Method == http.MethodDelete:
		s.mu.Lock()
		delete(s.objects, key)
		s.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	default:
		s.refuse(w, http.StatusMethodNotAllowed, "MethodNotAllowed", r.Method)
	}
}

// key extracts the object key under either addressing style.
func (s *Server) key(r *http.Request) string {
	p := strings.TrimPrefix(r.URL.Path, "/")
	if strings.HasPrefix(r.Host, s.bucket+".") {
		return p
	}
	return strings.TrimPrefix(strings.TrimPrefix(p, s.bucket), "/")
}

func (s *Server) refuse(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(status)
	_ = xml.NewEncoder(w).Encode(struct {
		XMLName xml.Name `xml:"Error"`
		Code    string   `xml:"Code"`
		Message string   `xml:"Message"`
	}{Code: code, Message: message})
}

func (s *Server) put(w http.ResponseWriter, r *http.Request, key string) {
	data, err := io.ReadAll(r.Body)
	if err != nil {
		s.refuse(w, http.StatusBadRequest, "IncompleteBody", err.Error())
		return
	}
	if want := r.Header.Get("Content-MD5"); want != "" {
		sum := md5.Sum(data) //nolint:gosec // Content-MD5
		if got := base64.StdEncoding.EncodeToString(sum[:]); got != want {
			s.t.Errorf("s3test: PUT %s: Content-MD5 %s, body has %s", key, want, got)
			s.refuse(w, http.StatusBadRequest, "BadDigest", "The Content-MD5 you specified did not match what we received")
			return
		}
	}
	if want := r.Header.Get("x-amz-content-sha256"); want != "" && want != sigv4.UnsignedPayload {
		sum := sha256.Sum256(data)
		if got := hex.EncodeToString(sum[:]); got != want {
			s.t.Errorf("s3test: PUT %s: x-amz-content-sha256 %s, body has %s", key, want, got)
			s.refuse(w, http.StatusBadRequest, "XAmzContentSHA256Mismatch", "The provided x-amz-content-sha256 header does not match what was computed")
			return
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.objects[key]; exists && r.Header.Get("If-None-Match") == "*" {
		s.refuse(w, http.StatusPreconditionFailed, "PreconditionFailed", "At least one of the pre-conditions you specified did not hold")
		return
	}
	w.Header().Set("ETag", s.store(key, data, r.Header.Get("Content-Type")))
	w.WriteHeader(http.StatusOK)
}

func (s *Server) get(w http.ResponseWriter, r *http.Request, key string) {
	s.mu.Lock()
	o, ok := s.objects[key]
	s.mu.Unlock()
	if !ok {
		s.refuse(w, http.StatusNotFound, "NoSuchKey", "The specified key does not exist.")
		return
	}
	if inm := r.Header.Get("If-None-Match"); inm != "" && strings.Trim(inm, `"`) == strings.Trim(o.etag, `"`) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("ETag", o.etag)
	w.Header().Set("Last-Modified", o.modified.UTC().Format(http.TimeFormat))
	w.Header().Set("Content-Length", strconv.Itoa(len(o.data)))
	w.Header().Set("Content-Type", o.contentType)
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		_, _ = io.Copy(w, bytes.NewReader(o.data))
	}
}

type listing struct {
	XMLName     xml.Name `xml:"ListBucketResult"`
	IsTruncated bool     `xml:"IsTruncated"`
	Contents    []struct {
		Key          string    `xml:"Key"`
		Size         int64     `xml:"Size"`
		ETag         string    `xml:"ETag"`
		LastModified time.Time `xml:"LastModified"`
	} `xml:"Contents"`
	CommonPrefixes []struct {
		Prefix string `xml:"Prefix"`
	} `xml:"CommonPrefixes"`
}

func (s *Server) list(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	prefix, startAfter, delimiter := q.Get("prefix"), q.Get("start-after"), q.Get("delimiter")
	limit, _ := strconv.Atoi(q.Get("max-keys"))
	if limit <= 0 || limit > 1000 {
		limit = 1000
	}
	var out listing
	seen := map[string]bool{}
	count := 0
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, key := range s.sortedKeys() {
		if !strings.HasPrefix(key, prefix) || key <= startAfter {
			continue
		}
		if delimiter != "" {
			rest := key[len(prefix):]
			if i := strings.Index(rest, delimiter); i >= 0 {
				p := prefix + rest[:i+len(delimiter)]
				if !seen[p] {
					if count == limit {
						out.IsTruncated = true
						break
					}
					seen[p] = true
					out.CommonPrefixes = append(out.CommonPrefixes, struct {
						Prefix string `xml:"Prefix"`
					}{p})
					count++
				}
				continue
			}
		}
		if count == limit {
			out.IsTruncated = true
			break
		}
		o := s.objects[key]
		out.Contents = append(out.Contents, struct {
			Key          string    `xml:"Key"`
			Size         int64     `xml:"Size"`
			ETag         string    `xml:"ETag"`
			LastModified time.Time `xml:"LastModified"`
		}{key, int64(len(o.data)), o.etag, o.modified.UTC()})
		count++
	}
	w.Header().Set("Content-Type", "application/xml")
	_ = xml.NewEncoder(w).Encode(out)
}
