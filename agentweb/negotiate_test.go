// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package agentweb

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

const browserAccept = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"

func siteFiles() fstest.MapFS {
	return fstest.MapFS{
		"en/index.html":            {Data: []byte("<h1>Preface</h1>")},
		"en/index.md":              {Data: []byte("# Preface\n")},
		"en/why.html":              {Data: []byte("<h1>Why</h1>")},
		"en/why.md":                {Data: []byte("# Why\n")},
		"en/why.md.gz":             {Data: []byte("gzipped markdown")},
		"en/terms.html":            {Data: []byte("<h1>Terms</h1>")},
		"zh/文.html":                {Data: []byte("<h1>文</h1>")},
		"zh/文.md":                  {Data: []byte("# 文\n")},
		"unlisted.html":            {Data: []byte("<p>unlisted</p>")},
		"en/broken-twin-page.html": {Data: []byte("<p>page</p>")},
	}
}

// staticSite serves files the way a site with precompressed siblings does:
// clean URLs resolve to .html, an .md file gets no Content-Type of its own
// (so ServeContent sniffs text/plain), every response sets its own Vary
// with Set, and a gzip sibling is streamed when the client accepts it.
func staticSite(files fs.FS) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/")
		switch {
		case name == "" || strings.HasSuffix(name, "/"):
			name += "index.html"
		case !strings.Contains(name, "."):
			name += ".html"
		}
		data, err := fs.ReadFile(files, name)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		h := w.Header()
		if strings.HasSuffix(name, ".html") {
			h.Set("Content-Type", "text/html; charset=utf-8")
		}
		h.Set("Vary", "Accept-Encoding")
		h.Set("Cache-Control", "no-cache")
		tag := `"` + name + `"`
		if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			if gz, err := fs.ReadFile(files, name+".gz"); err == nil {
				h.Set("Content-Encoding", "gzip")
				data, tag = gz, `"`+name+`-gz"`
			}
		}
		h.Set("ETag", tag)
		http.ServeContent(w, r, "", time.Time{}, bytes.NewReader(data))
	})
}

func siteIndex() *Index {
	return &Index{Origin: "https://example.com", Title: "Site", Pages: []Page{
		{Path: "/en/", Lang: "en", Title: "Preface", Markdown: "/en/index.md"},
		{Path: "/en/why", Lang: "en", Title: "Why", Markdown: "/en/why.md"},
		{Path: "/en/terms", Lang: "en", Title: "Terms"},
		{Path: "/zh/%E6%96%87", Lang: "zh", Title: "文", Markdown: "/zh/%E6%96%87.md"},
		{Path: "/en/broken-twin-page", Lang: "en", Title: "Broken", Markdown: "/en/missing.md"},
	}}
}

func negotiated(t *testing.T, opts NegotiateOptions) http.Handler {
	t.Helper()
	h, err := Negotiate(staticSite(siteFiles()), siteIndex(), opts)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func get(h http.Handler, method, target string, header map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, nil)
	for k, v := range header {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func varyNames(h http.Header) []string {
	var names []string
	for _, v := range h.Values("Vary") {
		for n := range strings.SplitSeq(v, ",") {
			names = append(names, strings.TrimSpace(n))
		}
	}
	return names
}

func TestNegotiateBrowserGetsHTMLWithAlternateLink(t *testing.T) {
	rec := get(negotiated(t, NegotiateOptions{}), http.MethodGet, "/en/why", map[string]string{"Accept": browserAccept})
	if rec.Code != http.StatusOK || rec.Body.String() != "<h1>Why</h1>" {
		t.Fatalf("GET = %d %q", rec.Code, rec.Body.String())
	}
	h := rec.Header()
	if ct := h.Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Errorf("Content-Type = %q", ct)
	}
	if v := varyNames(h); !slices.Contains(v, "Accept") || !slices.Contains(v, "Accept-Encoding") {
		t.Errorf("Vary = %v, want Accept beside the site's Accept-Encoding", v)
	}
	if got := h.Values("Link"); !slices.Equal(got, []string{`</en/why.md>; rel="alternate"; type="text/markdown"`}) {
		t.Errorf("Link = %q", got)
	}
	if h.Get("Content-Location") != "" {
		t.Errorf("the HTML response names Content-Location %q", h.Get("Content-Location"))
	}
}

func TestNegotiateAgentGetsMarkdownThroughTheSite(t *testing.T) {
	h := negotiated(t, NegotiateOptions{})
	for _, accept := range []string{"text/markdown", "text/markdown, text/html;q=0.9", "text/markdown;q=1, text/html;q=0.5, */*;q=0.1"} {
		rec := get(h, http.MethodGet, "/en/why?ref=x", map[string]string{"Accept": accept})
		if rec.Code != http.StatusOK || rec.Body.String() != "# Why\n" {
			t.Fatalf("Accept %q: GET = %d %q", accept, rec.Code, rec.Body.String())
		}
		hd := rec.Header()
		if ct := hd.Get("Content-Type"); ct != "text/markdown; charset=utf-8" {
			t.Errorf("Accept %q: Content-Type = %q", accept, ct)
		}
		if v := varyNames(hd); !slices.Contains(v, "Accept") || !slices.Contains(v, "Accept-Encoding") {
			t.Errorf("Accept %q: Vary = %v", accept, v)
		}
		if hd.Get("Content-Location") != "/en/why.md" {
			t.Errorf("Accept %q: Content-Location = %q", accept, hd.Get("Content-Location"))
		}
		if hd.Get("ETag") != `"en/why.md"` || hd.Get("Cache-Control") != "no-cache" {
			t.Errorf("Accept %q: the site's validators were not kept: ETag %q, Cache-Control %q", accept, hd.Get("ETag"), hd.Get("Cache-Control"))
		}
		if hd.Values("Link") != nil {
			t.Errorf("Accept %q: Markdown response carries Link %q", accept, hd.Values("Link"))
		}
	}
}

func TestNegotiateKeepsPrecompressedSiblingAndRevalidation(t *testing.T) {
	h := negotiated(t, NegotiateOptions{})
	md := map[string]string{"Accept": "text/markdown", "Accept-Encoding": "gzip, br"}
	rec := get(h, http.MethodGet, "/en/why", md)
	if rec.Header().Get("Content-Encoding") != "gzip" || rec.Body.String() != "gzipped markdown" {
		t.Fatalf("gzip sibling not served: %q %q", rec.Header().Get("Content-Encoding"), rec.Body.String())
	}
	if rec.Header().Get("Content-Type") != "text/markdown; charset=utf-8" {
		t.Errorf("Content-Type = %q", rec.Header().Get("Content-Type"))
	}

	md["If-None-Match"] = rec.Header().Get("ETag")
	rec = get(h, http.MethodGet, "/en/why", md)
	if rec.Code != http.StatusNotModified || !slices.Contains(varyNames(rec.Header()), "Accept") {
		t.Errorf("revalidation = %d, Vary %v; want 304 varying on Accept", rec.Code, varyNames(rec.Header()))
	}

	rec = get(h, http.MethodGet, "/en/why", map[string]string{"Accept": browserAccept, "If-None-Match": `"en/why.html"`})
	if rec.Code != http.StatusNotModified || rec.Header().Get("Link") == "" || !slices.Contains(varyNames(rec.Header()), "Accept") {
		t.Errorf("HTML revalidation = %d, Link %q, Vary %v", rec.Code, rec.Header().Get("Link"), varyNames(rec.Header()))
	}
}

func TestNegotiateHeadAndOtherMethods(t *testing.T) {
	h := negotiated(t, NegotiateOptions{})
	rec := get(h, http.MethodHead, "/en/", map[string]string{"Accept": "text/markdown"})
	if rec.Code != http.StatusOK || rec.Body.Len() != 0 || rec.Header().Get("Content-Type") != "text/markdown; charset=utf-8" {
		t.Errorf("HEAD = %d, %d bytes, Content-Type %q", rec.Code, rec.Body.Len(), rec.Header().Get("Content-Type"))
	}
	rec = get(h, http.MethodPost, "/en/why", map[string]string{"Accept": "text/markdown"})
	if rec.Body.String() != "<h1>Why</h1>" || slices.Contains(varyNames(rec.Header()), "Accept") || rec.Header().Get("Link") != "" {
		t.Errorf("POST was negotiated: %q, Vary %v, Link %q", rec.Body.String(), varyNames(rec.Header()), rec.Header().Get("Link"))
	}
}

func TestNegotiateDirectTwinRequest(t *testing.T) {
	rec := get(negotiated(t, NegotiateOptions{}), http.MethodGet, "/en/why.md", nil)
	if rec.Code != http.StatusOK || rec.Body.String() != "# Why\n" {
		t.Fatalf("GET = %d %q", rec.Code, rec.Body.String())
	}
	h := rec.Header()
	if h.Get("Content-Type") != "text/markdown; charset=utf-8" {
		t.Errorf("Content-Type = %q", h.Get("Content-Type"))
	}
	if got := h.Values("Link"); !slices.Equal(got, []string{`<https://example.com/en/why>; rel="canonical"`}) {
		t.Errorf("Link = %q", got)
	}
	if slices.Contains(varyNames(h), "Accept") {
		t.Error("a twin's own URL is not negotiated and must not vary on Accept")
	}
}

func TestNegotiateLeavesOtherRequestsAlone(t *testing.T) {
	h := negotiated(t, NegotiateOptions{})
	for _, target := range []string{"/en/terms", "/unlisted"} {
		rec := get(h, http.MethodGet, target, map[string]string{"Accept": "text/markdown"})
		if rec.Code != http.StatusOK || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/html") {
			t.Errorf("%s: %d %q", target, rec.Code, rec.Header().Get("Content-Type"))
		}
		if slices.Contains(varyNames(rec.Header()), "Accept") || rec.Header().Get("Link") != "" {
			t.Errorf("%s: touched: Vary %v, Link %q", target, varyNames(rec.Header()), rec.Header().Get("Link"))
		}
	}
}

func TestNegotiateEncodedPaths(t *testing.T) {
	h := negotiated(t, NegotiateOptions{})
	rec := get(h, http.MethodGet, "/zh/%E6%96%87", map[string]string{"Accept": "text/markdown"})
	if rec.Code != http.StatusOK || rec.Body.String() != "# 文\n" {
		t.Fatalf("GET = %d %q", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Content-Location") != "/zh/%E6%96%87.md" {
		t.Errorf("Content-Location = %q", rec.Header().Get("Content-Location"))
	}
	rec = get(h, http.MethodGet, "/zh/%E6%96%87", map[string]string{"Accept": browserAccept})
	if got := rec.Header().Get("Link"); got != `</zh/%E6%96%87.md>; rel="alternate"; type="text/markdown"` {
		t.Errorf("Link = %q", got)
	}
}

func TestNegotiateMissingTwinIsTheSitesAnswer(t *testing.T) {
	rec := get(negotiated(t, NegotiateOptions{}), http.MethodGet, "/en/broken-twin-page", map[string]string{"Accept": "text/markdown"})
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want the site's 404", rec.Code)
	}
	if strings.HasPrefix(rec.Header().Get("Content-Type"), "text/markdown") || rec.Header().Get("Content-Location") != "" {
		t.Errorf("an error response was relabeled: %q %q", rec.Header().Get("Content-Type"), rec.Header().Get("Content-Location"))
	}
	if !slices.Contains(varyNames(rec.Header()), "Accept") {
		t.Error("an error response for a negotiable page must still vary on Accept")
	}
}

func TestNegotiateDescribedBy(t *testing.T) {
	h := negotiated(t, NegotiateOptions{DescribedBy: func(p Page) string {
		if p.Lang == "zh" {
			return "/zh/llms.txt"
		}
		if p.Path == "/en/broken-twin-page" {
			return ""
		}
		return "/llms.txt"
	}})
	const llms = `</llms.txt>; rel="describedby"`
	cases := []struct {
		target, accept string
		want           []string
	}{
		{"/en/why", browserAccept, []string{`</en/why.md>; rel="alternate"; type="text/markdown"`, llms}},
		{"/en/why", "text/markdown", []string{llms}},
		{"/en/why.md", "", []string{`<https://example.com/en/why>; rel="canonical"`, llms}},
		{"/en/terms", browserAccept, []string{llms}},
		{"/zh/%E6%96%87", browserAccept, []string{`</zh/%E6%96%87.md>; rel="alternate"; type="text/markdown"`, `</zh/llms.txt>; rel="describedby"`}},
		{"/en/broken-twin-page", browserAccept, []string{`</en/missing.md>; rel="alternate"; type="text/markdown"`}},
	}
	for _, c := range cases {
		rec := get(h, http.MethodGet, c.target, map[string]string{"Accept": c.accept})
		if got := rec.Header().Values("Link"); !slices.Equal(got, c.want) {
			t.Errorf("%s (%s): Link = %q, want %q", c.target, c.accept, got, c.want)
		}
	}
	rec := get(h, http.MethodGet, "/en/terms", map[string]string{"Accept": browserAccept})
	if slices.Contains(varyNames(rec.Header()), "Accept") {
		t.Error("a page without a twin must not vary on Accept")
	}
}

func TestNegotiateRejects(t *testing.T) {
	site := staticSite(siteFiles())
	if _, err := Negotiate(nil, siteIndex(), NegotiateOptions{}); err == nil {
		t.Error("a nil handler was accepted")
	}
	if _, err := Negotiate(site, &Index{Origin: "example.com"}, NegotiateOptions{}); err == nil {
		t.Error("an invalid index was accepted")
	}
	if _, err := Negotiate(site, siteIndex(), NegotiateOptions{DescribedBy: func(Page) string { return "llms.txt" }}); err == nil {
		t.Error("a relative describedby was accepted")
	}
}

// TestNegotiateHeaderTiming covers handlers that write their status in
// unusual ways: replacing Vary, sending nothing, declaring Vary: *, sending
// an informational status first, and flushing before the body.
func TestNegotiateHeaderTiming(t *testing.T) {
	idx := &Index{Origin: "https://example.com", Pages: []Page{{Path: "/p", Markdown: "/p.md"}}}
	wrap := func(fn http.HandlerFunc) http.Handler {
		h, err := Negotiate(fn, idx, NegotiateOptions{})
		if err != nil {
			t.Fatal(err)
		}
		return h
	}
	md := map[string]string{"Accept": "text/markdown"}

	rec := get(wrap(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Vary", "Origin")
		w.Header().Set("Content-Type", "application/octet-stream")
		if _, err := io.WriteString(w, "body"); err != nil {
			t.Error(err)
		}
	}), http.MethodGet, "/p", md)
	if v := varyNames(rec.Header()); !slices.Equal(v, []string{"Origin", "Accept"}) || rec.Header().Get("Content-Type") != "text/markdown; charset=utf-8" {
		t.Errorf("replaced headers: Vary %v, Content-Type %q", v, rec.Header().Get("Content-Type"))
	}

	rec = get(wrap(func(http.ResponseWriter, *http.Request) {}), http.MethodGet, "/p", nil)
	if rec.Code != http.StatusOK || !slices.Contains(varyNames(rec.Header()), "Accept") || rec.Header().Get("Link") == "" {
		t.Errorf("silent handler: %d, Vary %v, Link %q", rec.Code, varyNames(rec.Header()), rec.Header().Get("Link"))
	}

	rec = get(wrap(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Vary", "*")
		w.WriteHeader(http.StatusOK)
	}), http.MethodGet, "/p", nil)
	if v := varyNames(rec.Header()); !slices.Equal(v, []string{"*"}) {
		t.Errorf("Vary * gained a field: %v", v)
	}

	rec = get(wrap(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Vary", "accept")
		w.WriteHeader(http.StatusNoContent)
		w.WriteHeader(http.StatusOK) // superfluous; ignored by the recorder
	}), http.MethodGet, "/p", nil)
	if v := varyNames(rec.Header()); !slices.Equal(v, []string{"accept"}) || rec.Code != http.StatusNoContent {
		t.Errorf("Vary listing accept in another case gained a duplicate: %v (%d)", v, rec.Code)
	}

	calls := 0
	rec = get(wrap(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Link", "</style.css>; rel=preload")
		w.WriteHeader(http.StatusEarlyHints)
		calls = len(w.Header().Values("Link"))
		w.WriteHeader(http.StatusOK)
	}), http.MethodGet, "/p", nil)
	if calls != 1 || !slices.Equal(rec.Header().Values("Link"), []string{"</style.css>; rel=preload", `</p.md>; rel="alternate"; type="text/markdown"`}) {
		t.Errorf("early hints: links at 103 = %d, final %q", calls, rec.Header().Values("Link"))
	}

	rec = get(wrap(func(w http.ResponseWriter, _ *http.Request) {
		if err := http.NewResponseController(w).Flush(); err != nil {
			t.Error(err)
		}
		w.(http.Flusher).Flush()
		if _, err := io.WriteString(w, "streamed"); err != nil {
			t.Error(err)
		}
	}), http.MethodGet, "/p", md)
	if !rec.Flushed || rec.Header().Get("Content-Type") != "text/markdown; charset=utf-8" || rec.Body.String() != "streamed" {
		t.Errorf("flush: flushed %v, Content-Type %q, body %q", rec.Flushed, rec.Header().Get("Content-Type"), rec.Body.String())
	}

	rec = get(wrap(func(w http.ResponseWriter, _ *http.Request) {
		// The recorder supports no full duplex; reaching its answer means
		// the controller unwrapped the middleware's writer to ask it.
		if err := http.NewResponseController(w).EnableFullDuplex(); !errors.Is(err, http.ErrNotSupported) {
			t.Errorf("EnableFullDuplex through the wrapper = %v, want http.ErrNotSupported", err)
		}
	}), http.MethodGet, "/p", md)
	if rec.Code != http.StatusOK {
		t.Errorf("unwrap: %d", rec.Code)
	}

	rec = get(wrap(func(w http.ResponseWriter, _ *http.Request) {
		n, err := w.(io.ReaderFrom).ReadFrom(strings.NewReader("copied"))
		if err != nil || n != 6 {
			t.Errorf("ReadFrom = %d, %v", n, err)
		}
	}), http.MethodGet, "/p", md)
	if rec.Body.String() != "copied" || rec.Header().Get("Content-Type") != "text/markdown; charset=utf-8" {
		t.Errorf("ReadFrom: %q %q", rec.Body.String(), rec.Header().Get("Content-Type"))
	}
}

// TestNegotiateOverARealServer runs the middleware in front of
// http.FileServer on a loopback server, where the file body goes through
// the connection's own ReadFrom.
func TestNegotiateOverARealServer(t *testing.T) {
	files := fstest.MapFS{
		"doc.html": {Data: []byte("<!doctype html><title>Doc</title>")},
		"doc.md":   {Data: []byte(strings.Repeat("# Doc\n\n", 4096))},
	}
	idx := &Index{Origin: "https://example.com", Pages: []Page{{Path: "/doc.html", Markdown: "/doc.md"}}}
	h, err := Negotiate(http.FileServer(http.FS(files)), idx, NegotiateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/doc.html", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Accept", "text/markdown")
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	if cerr := resp.Body.Close(); cerr != nil {
		t.Error(cerr)
	}
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK || string(body) != string(files["doc.md"].Data) {
		t.Fatalf("GET = %d, %d bytes", resp.StatusCode, len(body))
	}
	if ct := resp.Header.Get("Content-Type"); ct != "text/markdown; charset=utf-8" {
		t.Errorf("Content-Type = %q, want the Markdown type over FileServer's sniffed one", ct)
	}
	if !slices.Contains(varyNames(resp.Header), "Accept") {
		t.Errorf("Vary = %v", varyNames(resp.Header))
	}
}
