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
