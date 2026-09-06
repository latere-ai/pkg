// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// Package sigv4 signs HTTP requests with Signature Version 4 for the S3
// service, in the standard library. It is shared by the client in the
// parent package and by the s3test fake, which verifies every request the
// way a real endpoint does: by recomputing the signature from what
// arrived on the wire.
package sigv4

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	// EmptyPayloadHash is the SHA-256 of zero bytes, the payload hash of a
	// request without a body.
	EmptyPayloadHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	// UnsignedPayload is the payload hash of a body the signature does not
	// cover; a presigned URL always uses it.
	UnsignedPayload = "UNSIGNED-PAYLOAD"
	// DateFormat is the layout of the x-amz-date header and query value.
	DateFormat = "20060102T150405Z"

	algorithm = "AWS4-HMAC-SHA256"
	service   = "s3"
)

// Signer holds one credential for one region.
type Signer struct {
	Key, Secret, Region string
}

// Escape percent-encodes everything but the unreserved characters, as the
// signing specification requires; url.PathEscape leaves more alone, and a
// request line that disagrees with the canonical URI fails verification.
func Escape(s string) string {
	var b strings.Builder
	for i := range len(s) {
		c := s[i]
		switch {
		case 'A' <= c && c <= 'Z', 'a' <= c && c <= 'z', '0' <= c && c <= '9', c == '-', c == '_', c == '.', c == '~':
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// CanonicalQuery renders q sorted by key with every key and value escaped
// the way the signature expects. It is what a request's RawQuery must be
// for the signature to verify.
func CanonicalQuery(q url.Values) string {
	if len(q) == 0 {
		return ""
	}
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		for _, v := range q[k] {
			parts = append(parts, Escape(k)+"="+Escape(v))
		}
	}
	return strings.Join(parts, "&")
}

// Sign adds the x-amz-date, x-amz-content-sha256, and Authorization headers
// to req. Every header already on the request is signed, so a caller
// cannot hand the endpoint a header the signature does not cover.
func (s Signer) Sign(req *http.Request, payloadHash string, at time.Time) {
	amzDate := at.UTC().Format(DateFormat)
	req.Header.Set("x-amz-date", amzDate)
	req.Header.Set("x-amz-content-sha256", payloadHash)
	if req.Host == "" {
		req.Host = req.URL.Host
	}
	names, canonHeaders := canonicalHeaders(req)
	signedHeaders := strings.Join(names, ";")
	scope := amzDate[:8] + "/" + s.Region + "/" + service + "/aws4_request"
	signature := s.signature(req.Method, canonicalPath(req.URL), req.URL.RawQuery, canonHeaders, signedHeaders, payloadHash, amzDate, scope)
	req.Header.Set("Authorization", fmt.Sprintf(
		"%s Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		algorithm, s.Key, scope, signedHeaders, signature))
}

// Presign returns req's URL with the signature carried in the query, valid
// for expires from at. The headers on req are the ones the sender must
// repeat exactly: host always, and any other the caller set, which is how
// a presigned PUT binds its Content-Length. The payload is unsigned.
func (s Signer) Presign(req *http.Request, at time.Time, expires time.Duration) string {
	amzDate := at.UTC().Format(DateFormat)
	if req.Host == "" {
		req.Host = req.URL.Host
	}
	names, canonHeaders := canonicalHeaders(req)
	signedHeaders := strings.Join(names, ";")
	scope := amzDate[:8] + "/" + s.Region + "/" + service + "/aws4_request"

	q := req.URL.Query()
	q.Set("X-Amz-Algorithm", algorithm)
	q.Set("X-Amz-Credential", s.Key+"/"+scope)
	q.Set("X-Amz-Date", amzDate)
	q.Set("X-Amz-Expires", strconv.FormatInt(int64(expires/time.Second), 10))
	q.Set("X-Amz-SignedHeaders", signedHeaders)
	rawQuery := CanonicalQuery(q)
	signature := s.signature(req.Method, canonicalPath(req.URL), rawQuery, canonHeaders, signedHeaders, UnsignedPayload, amzDate, scope)

	u := *req.URL
	u.RawQuery = rawQuery + "&X-Amz-Signature=" + signature
	return u.String()
}

// Verify recomputes the signature of a request as it arrived and reports
// whether it matches the one carried in the Authorization header or the
// X-Amz-Signature query value. It is what an endpoint does.
func (s Signer) Verify(r *http.Request) error {
	if sig := r.URL.Query().Get("X-Amz-Signature"); sig != "" {
		return s.verifyPresigned(r, sig)
	}
	auth := r.Header.Get("Authorization")
	prefix := algorithm + " Credential=" + s.Key + "/"
	if !strings.HasPrefix(auth, prefix) {
		return fmt.Errorf("sigv4: Authorization %q does not name key %s", auth, s.Key)
	}
	var signed, sig string
	for part := range strings.SplitSeq(auth[len(algorithm)+1:], ", ") {
		if v, ok := strings.CutPrefix(part, "SignedHeaders="); ok {
			signed = v
		}
		if v, ok := strings.CutPrefix(part, "Signature="); ok {
			sig = v
		}
	}
	at, err := time.Parse(DateFormat, r.Header.Get("x-amz-date"))
	if err != nil {
		return fmt.Errorf("sigv4: x-amz-date: %w", err)
	}
	c := cloneForVerify(r, signed)
	s.Sign(c, r.Header.Get("x-amz-content-sha256"), at)
	if want := c.Header.Get("Authorization"); !strings.HasSuffix(want, "Signature="+sig) {
		return fmt.Errorf("sigv4: signature %s does not verify; expected %s", sig, want[strings.LastIndex(want, "=")+1:])
	}
	return nil
}

func (s Signer) verifyPresigned(r *http.Request, sig string) error {
	q := r.URL.Query()
	at, err := time.Parse(DateFormat, q.Get("X-Amz-Date"))
	if err != nil {
		return fmt.Errorf("sigv4: X-Amz-Date: %w", err)
	}
	expires, err := strconv.ParseInt(q.Get("X-Amz-Expires"), 10, 64)
	if err != nil {
		return fmt.Errorf("sigv4: X-Amz-Expires: %w", err)
	}
	c := cloneForVerify(r, q.Get("X-Amz-SignedHeaders"))
	q.Del("X-Amz-Algorithm")
	q.Del("X-Amz-Credential")
	q.Del("X-Amz-Date")
	q.Del("X-Amz-Expires")
	q.Del("X-Amz-SignedHeaders")
	q.Del("X-Amz-Signature")
	u := *r.URL
	u.RawQuery = CanonicalQuery(q)
	c.URL = &u
	want := s.Presign(c, at, time.Duration(expires)*time.Second)
	if !strings.HasSuffix(want, "&X-Amz-Signature="+sig) {
		return fmt.Errorf("sigv4: presigned signature %s does not verify; expected %s", sig, want[strings.LastIndex(want, "=")+1:])
	}
	return nil
}

// cloneForVerify copies method, URL, host, and exactly the signed headers,
// so a header the client did not sign cannot change the recomputation.
func cloneForVerify(r *http.Request, signedHeaders string) *http.Request {
	c := &http.Request{Method: r.Method, URL: r.URL, Host: r.Host, Header: http.Header{}}
	for name := range strings.SplitSeq(signedHeaders, ";") {
		switch name {
		case "host", "":
		case "content-length":
			c.Header.Set(name, strconv.FormatInt(r.ContentLength, 10))
		default:
			c.Header.Set(name, r.Header.Get(name))
		}
	}
	return c
}

func canonicalHeaders(req *http.Request) ([]string, string) {
	names := []string{"host"}
	values := map[string]string{"host": req.Host}
	for name, vs := range req.Header {
		lower := strings.ToLower(name)
		names = append(names, lower)
		values[lower] = strings.TrimSpace(strings.Join(vs, ","))
	}
	sort.Strings(names)
	var b strings.Builder
	for _, n := range names {
		b.WriteString(n + ":" + values[n] + "\n")
	}
	return names, b.String()
}

func canonicalPath(u *url.URL) string {
	if u.RawPath != "" {
		return u.RawPath
	}
	return u.EscapedPath()
}

func (s Signer) signature(method, path, query, canonHeaders, signedHeaders, payloadHash, amzDate, scope string) string {
	canonical := strings.Join([]string{method, path, query, canonHeaders, signedHeaders, payloadHash}, "\n")
	toSign := strings.Join([]string{algorithm, amzDate, scope, hexSHA256([]byte(canonical))}, "\n")
	k := hmacSHA256([]byte("AWS4"+s.Secret), amzDate[:8])
	k = hmacSHA256(k, s.Region)
	k = hmacSHA256(k, service)
	k = hmacSHA256(k, "aws4_request")
	return hex.EncodeToString(hmacSHA256(k, toSign))
}

func hmacSHA256(key []byte, msg string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(msg))
	return m.Sum(nil)
}

func hexSHA256(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
