// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package sigv4

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

var (
	vectorSigner = Signer{Key: "AKIAIOSFODNN7EXAMPLE", Secret: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", Region: "us-east-1"}
	vectorTime   = time.Date(2013, 5, 24, 0, 0, 0, 0, time.UTC)
)

// The GET Object example from the Signature Version 4 documentation for
// S3, with its published signature.
func TestSignMatchesTheDocumentedVector(t *testing.T) {
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://examplebucket.s3.amazonaws.com/test.txt", nil)
	req.Header.Set("Range", "bytes=0-9")
	vectorSigner.Sign(req, EmptyPayloadHash, vectorTime)
	want := "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
	if got := req.Header.Get("Authorization"); got != want {
		t.Fatalf("Authorization =\n%s\nwant\n%s", got, want)
	}
	if err := vectorSigner.Verify(req); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

// The presigned GET Object example from the same documentation.
func TestPresignMatchesTheDocumentedVector(t *testing.T) {
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://examplebucket.s3.amazonaws.com/test.txt", nil)
	got := vectorSigner.Presign(req, vectorTime, 24*time.Hour)
	want := "https://examplebucket.s3.amazonaws.com/test.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20130524T000000Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host&X-Amz-Signature=aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404"
	if got != want {
		t.Fatalf("presigned =\n%s\nwant\n%s", got, want)
	}
	back, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, got, nil)
	back.Host = back.URL.Host
	if err := vectorSigner.Verify(back); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestPresignBindsTheHeadersOnTheRequest(t *testing.T) {
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPut, "https://b.example.test/k", nil)
	req.Header.Set("Content-Length", "12")
	u := vectorSigner.Presign(req, vectorTime, time.Hour)
	if !strings.Contains(u, "X-Amz-SignedHeaders=content-length%3Bhost") {
		t.Fatalf("signed headers: %s", u)
	}
	good, _ := http.NewRequestWithContext(context.Background(), http.MethodPut, u, nil)
	good.Host, good.ContentLength = good.URL.Host, 12
	if err := vectorSigner.Verify(good); err != nil {
		t.Fatalf("matching length: %v", err)
	}
	bad, _ := http.NewRequestWithContext(context.Background(), http.MethodPut, u, nil)
	bad.Host, bad.ContentLength = bad.URL.Host, 13
	if err := vectorSigner.Verify(bad); err == nil {
		t.Fatal("a different Content-Length verified")
	}
}

func TestVerifyRefusesWhatItCannotRecompute(t *testing.T) {
	mk := func(u string) *http.Request {
		r, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, u, nil)
		r.Host = r.URL.Host
		return r
	}
	cases := map[string]*http.Request{}
	r := mk("https://b.example.test/k")
	cases["no authorization"] = r
	r = mk("https://b.example.test/k")
	r.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/x, SignedHeaders=host, Signature=00")
	r.Header.Set("x-amz-date", "not-a-date")
	cases["bad date"] = r
	r = mk("https://b.example.test/k")
	vectorSigner.Sign(r, EmptyPayloadHash, vectorTime)
	r.URL.Path = "/other"
	cases["tampered path"] = r
	cases["presigned bad date"] = mk("https://b.example.test/k?X-Amz-Signature=00&X-Amz-Date=nope")
	cases["presigned bad expires"] = mk("https://b.example.test/k?X-Amz-Signature=00&X-Amz-Date=20130524T000000Z&X-Amz-Expires=x")
	cases["presigned tampered"] = mk("https://b.example.test/k?X-Amz-Signature=00&X-Amz-Date=20130524T000000Z&X-Amz-Expires=60&X-Amz-SignedHeaders=host")
	for name, r := range cases {
		if err := vectorSigner.Verify(r); err == nil {
			t.Errorf("%s: verified", name)
		}
	}
}

func TestEscapeAndCanonicalQuery(t *testing.T) {
	if got := Escape("o w/s+l~ug"); got != "o%20w%2Fs%2Bl~ug" {
		t.Fatalf("escape = %s", got)
	}
	q := url.Values{"prefix": {"a b"}, "list-type": {"2"}, "z": {"2", "1"}}
	if got := CanonicalQuery(q); got != "list-type=2&prefix=a%20b&z=2&z=1" {
		t.Fatalf("query = %s", got)
	}
	if CanonicalQuery(nil) != "" {
		t.Fatal("empty query rendered")
	}
}

func TestSignUsesRawPathWhenPresent(t *testing.T) {
	u, _ := url.Parse("https://b.example.test/")
	u.Path, u.RawPath = "/a b", "/a%20b"
	req := &http.Request{Method: http.MethodGet, URL: u, Header: http.Header{}}
	vectorSigner.Sign(req, EmptyPayloadHash, vectorTime)
	if err := vectorSigner.Verify(req); err != nil {
		t.Fatal(err)
	}
}

func FuzzEscape(f *testing.F) {
	f.Add("plain")
	f.Add("o w/s+l~ug")
	f.Add("\x00\xff")
	f.Fuzz(func(t *testing.T, s string) {
		e := Escape(s)
		for i := range len(e) {
			c := e[i]
			if c == '%' || 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '-' || c == '_' || c == '.' || c == '~' {
				continue
			}
			t.Fatalf("Escape(%q) = %q carries %q", s, e, c)
		}
		if back, err := url.PathUnescape(e); err != nil || back != s {
			t.Fatalf("Escape(%q) = %q does not round-trip: %q, %v", s, e, back, err)
		}
	})
}

// The PUT Object example from the same documentation: a caller header,
// x-amz-storage-class, and a signed payload.
func TestSignMatchesTheDocumentedPutVector(t *testing.T) {
	req := putVectorRequest()
	vectorSigner.Sign(req, putVectorPayloadHash, vectorTime)
	want := "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=date;host;x-amz-content-sha256;x-amz-date;x-amz-storage-class, Signature=98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd"
	if got := req.Header.Get("Authorization"); got != want {
		t.Fatalf("Authorization =\n%s\nwant\n%s", got, want)
	}
	if err := vectorSigner.Verify(req); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

const putVectorPayloadHash = "44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072"

// putVectorRequest is the documented PUT Object request before signing.
// The key carries a dollar sign, which the canonical URI escapes and Go's
// path escaping does not, so RawPath is set the way the client sets it.
func putVectorRequest() *http.Request {
	u, _ := url.Parse("https://examplebucket.s3.amazonaws.com/")
	u.Path, u.RawPath = "/test$file.text", "/test%24file.text"
	req := &http.Request{Method: http.MethodPut, URL: u, Header: http.Header{}}
	req.Header.Set("Date", "Fri, 24 May 2013 00:00:00 GMT")
	req.Header.Set("x-amz-storage-class", "REDUCED_REDUNDANCY")
	return req
}

// The published vectors carry no Content-Type. These two are the
// documented PUT vector with Content-Type: text/plain added, and a
// presigned PUT binding Content-Length and Content-Type, with signatures
// computed independently of this package from the canonical request the
// specification prescribes. A signature that drifts from them means the
// header left the signature or its canonical form changed.
func TestContentTypeIsInTheSignature(t *testing.T) {
	req := putVectorRequest()
	req.Header.Set("Content-Type", "text/plain")
	vectorSigner.Sign(req, putVectorPayloadHash, vectorTime)
	want := "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=content-type;date;host;x-amz-content-sha256;x-amz-date;x-amz-storage-class, Signature=f093977030bf8d8069918f1b3546fd02cf697d43e763c40d58c109a2e197bdac"
	if got := req.Header.Get("Authorization"); got != want {
		t.Fatalf("Authorization =\n%s\nwant\n%s", got, want)
	}
	if err := vectorSigner.Verify(req); err != nil {
		t.Fatalf("verify: %v", err)
	}
	req.Header.Set("Content-Type", "text/html")
	if err := vectorSigner.Verify(req); err == nil {
		t.Fatal("another Content-Type verified")
	}

	p := putVectorRequest()
	p.Header = http.Header{}
	p.Header.Set("Content-Length", "12")
	p.Header.Set("Content-Type", "text/plain")
	got := vectorSigner.Presign(p, vectorTime, time.Hour)
	want = "https://examplebucket.s3.amazonaws.com/test%24file.text?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20130524T000000Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=content-length%3Bcontent-type%3Bhost&X-Amz-Signature=2d2950388956fba80de33459411a13a91ae8305eadbd8ebbf93f58a3a54a000b"
	if got != want {
		t.Fatalf("presigned =\n%s\nwant\n%s", got, want)
	}
	good, _ := http.NewRequestWithContext(context.Background(), http.MethodPut, got, nil)
	good.Host, good.ContentLength = good.URL.Host, 12
	good.Header.Set("Content-Type", "text/plain")
	if err := vectorSigner.Verify(good); err != nil {
		t.Fatalf("matching type: %v", err)
	}
	for name, ct := range map[string]string{"another type": "text/html", "no type": ""} {
		bad, _ := http.NewRequestWithContext(context.Background(), http.MethodPut, got, nil)
		bad.Host, bad.ContentLength = bad.URL.Host, 12
		if ct != "" {
			bad.Header.Set("Content-Type", ct)
		}
		if err := vectorSigner.Verify(bad); err == nil {
			t.Errorf("%s verified", name)
		}
	}
}

// A header value of any shape signs, verifies as sent, and stops
// verifying once it changes, through both the header and the presigned
// form.
func FuzzSignVerifyHeaderRoundTrip(f *testing.F) {
	f.Add("text/plain")
	f.Add("  application/json; charset=utf-8 ")
	f.Add("")
	f.Add("a\tb")
	f.Add("\xc2\x85x")
	f.Fuzz(func(t *testing.T, ct string) {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodPut, "https://b.example.test/k", nil)
		req.Header.Set("Content-Type", ct)
		vectorSigner.Sign(req, UnsignedPayload, vectorTime)
		if !strings.Contains(req.Header.Get("Authorization"), "SignedHeaders=content-type;host;") {
			t.Fatalf("Content-Type not signed: %s", req.Header.Get("Authorization"))
		}
		if err := vectorSigner.Verify(req); err != nil {
			t.Fatalf("Sign then Verify of %q: %v", ct, err)
		}
		req.Header.Set("Content-Type", ct+"x")
		if err := vectorSigner.Verify(req); err == nil {
			t.Fatalf("a changed Content-Type %q verified", ct)
		}

		p := &http.Request{Method: http.MethodPut, URL: req.URL, Header: http.Header{}}
		p.Header.Set("Content-Type", ct)
		u := vectorSigner.Presign(p, vectorTime, time.Hour)
		back, _ := http.NewRequestWithContext(context.Background(), http.MethodPut, u, nil)
		back.Host = back.URL.Host
		back.Header.Set("Content-Type", ct)
		if err := vectorSigner.Verify(back); err != nil {
			t.Fatalf("Presign then Verify of %q: %v", ct, err)
		}
		back.Header.Set("Content-Type", ct+"x")
		if err := vectorSigner.Verify(back); err == nil {
			t.Fatalf("a changed presigned Content-Type %q verified", ct)
		}
	})
}
