// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package agentweb

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// documentHandlers builds each document handler with the given
// Cache-Control, so one table covers all four.
func documentHandlers(cc string) map[string]func() (http.Handler, error) {
	return map[string]func() (http.Handler, error){
		"robots.txt": func() (http.Handler, error) {
			return RobotsHandler(Robots{Groups: []Group{{UserAgents: []string{"*"}, Allow: []string{"/"}}}, CacheControl: cc})
		},
		"sitemap.xml": func() (http.Handler, error) {
			return SitemapHandler(bookIndex(), SitemapOptions{CacheControl: cc})
		},
		"llms.txt": func() (http.Handler, error) {
			return LLMsTxtHandler(bookIndex(), LLMsOptions{Lang: "en", CacheControl: cc})
		},
		"llms-full.txt": func() (http.Handler, error) {
			return LLMsFullHandler(bookIndex(), FSOpener(bookFS()), LLMsOptions{Lang: "en", CacheControl: cc})
		},
	}
}

// Every document states its freshness. Without Cache-Control a CDN in front
// of the site applies its own default, and one held a replaced robots.txt for
// four hours after a deploy.
func TestDocumentsSendCacheControl(t *testing.T) {
	for _, tc := range []struct{ configured, want string }{
		{"", DefaultCacheControl},
		{"no-cache", "no-cache"},
	} {
		for name, build := range documentHandlers(tc.configured) {
			h, err := build()
			if err != nil {
				t.Fatalf("%s: build: %v", name, err)
			}
			for _, method := range []string{http.MethodGet, http.MethodHead} {
				w := httptest.NewRecorder()
				h.ServeHTTP(w, httptest.NewRequest(method, "/"+name, nil))
				if w.Code != http.StatusOK {
					t.Fatalf("%s %s: status %d", method, name, w.Code)
				}
				if got := w.Header().Get("Cache-Control"); got != tc.want {
					t.Errorf("%s %s configured %q: Cache-Control %q, want %q", method, name, tc.configured, got, tc.want)
				}
			}
		}
	}
}

// A revalidation answered with 304 carries the same Cache-Control, so the
// cache that asked renews the freshness it holds (RFC 9111 section 4.3.4).
func TestNotModifiedKeepsCacheControl(t *testing.T) {
	h, err := RobotsHandler(Robots{Groups: []Group{{UserAgents: []string{"*"}, Allow: []string{"/"}}}})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/robots.txt", nil))
	etag := w.Header().Get("ETag")

	r := httptest.NewRequest(http.MethodGet, "/robots.txt", nil)
	r.Header.Set("If-None-Match", etag)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusNotModified {
		t.Fatalf("revalidation: status %d, want 304", w.Code)
	}
	if got := w.Header().Get("Cache-Control"); got != DefaultCacheControl {
		t.Errorf("304 Cache-Control %q, want %q", got, DefaultCacheControl)
	}
}

// A configured value that could split the header fails at construction, not
// on the first request.
func TestCacheControlRefusesLineBreaks(t *testing.T) {
	for _, bad := range []string{"max-age=60\r\nSet-Cookie: x=1", "max-age=60\n", "no-cache\x00"} {
		for name, build := range documentHandlers(bad) {
			if _, err := build(); err == nil || !strings.Contains(err.Error(), "cache control") {
				t.Errorf("%s with %q: err %v, want a cache control error", name, bad, err)
			}
		}
	}
}
