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
	"strings"
	"testing"
	"testing/fstest"
)

// bookIndex is a small bilingual book: two parts in English and one in
// Chinese, one page without a twin and one without a section.
func bookIndex() *Index {
	return &Index{
		Origin:  "https://example.com",
		Title:   "A Book",
		Summary: "A book about systems.",
		Pages: []Page{
			{Path: "/en/", Lang: "en", Title: "Preface", Markdown: "/en/index.md"},
			{Path: "/en/foundations/why", Lang: "en", Title: "Why [it] matters", Description: "The case,\nin one line.", Section: "Part I: Foundations", Markdown: "/en/foundations/why.md", Alternates: map[string]string{"zh": "/zh/foundations/why"}},
			{Path: "/en/practice/deploy", Lang: "en", Title: "Deploying", Section: "Part II: Practice", Markdown: "/en/practice/deploy.md"},
			{Path: "/en/foundations/terms", Lang: "en", Title: "Terms", Description: "Vocabulary.", Section: "Part I: Foundations"},
			{Path: "/zh/foundations/why", Lang: "zh", Title: "为什么", Section: "第一部分", Markdown: "/zh/foundations/why.md", Alternates: map[string]string{"en": "/en/foundations/why"}},
		},
	}
}

func bookFS() fstest.MapFS {
	return fstest.MapFS{
		"en/index.md":             {Data: []byte("# Preface\n\nWelcome.\n")},
		"en/foundations/why.md":   {Data: []byte("# Why it matters\n\nBecause.")},
		"en/practice/deploy.md":   {Data: []byte("# Deploying\n\nShip it.\n")},
		"zh/foundations/why.md":   {Data: []byte("# 为什么\n")},
		"en/foundations/unused":   {Data: []byte("not listed")},
		"zh/foundations/empty.md": {Data: nil},
	}
}

func renderLLMs(t *testing.T, idx *Index, opts LLMsOptions) string {
	t.Helper()
	var b bytes.Buffer
	if err := WriteLLMsTxt(&b, idx, opts); err != nil {
		t.Fatalf("WriteLLMsTxt: %v", err)
	}
	return b.String()
}

func TestWriteLLMsTxt(t *testing.T) {
	got := renderLLMs(t, bookIndex(), LLMsOptions{
		Lang:    "en",
		Details: "Each link below points at the chapter's Markdown.\n\n- Chapters are in reading order.\n",
	})
	const want = `# A Book

> A book about systems.

Each link below points at the chapter's Markdown.

- Chapters are in reading order.

## Pages

- [Preface](https://example.com/en/index.md)

## Part I: Foundations

- [Why \[it\] matters](https://example.com/en/foundations/why.md): The case, in one line.
- [Terms](https://example.com/en/foundations/terms): Vocabulary.

## Part II: Practice

- [Deploying](https://example.com/en/practice/deploy.md)
`
	if got != want {
		t.Errorf("llms.txt mismatch\n--- got\n%s--- want\n%s", got, want)
	}
}

func TestWriteLLMsTxtLanguageAndOverrides(t *testing.T) {
	got := renderLLMs(t, bookIndex(), LLMsOptions{
		Lang:           "zh",
		Title:          "一本书",
		Summary:        "第一行\n\n第二行  ",
		DefaultSection: "其他",
	})
	const want = "# 一本书\n\n> 第一行\n>\n> 第二行\n\n## 第一部分\n\n- [为什么](https://example.com/zh/foundations/why.md)\n"
	if got != want {
		t.Errorf("zh llms.txt = %q, want %q", got, want)
	}
}

func TestWriteLLMsTxtDefaultSection(t *testing.T) {
	idx := &Index{Origin: "https://example.com", Title: "T", Pages: []Page{
		{Path: "/a", Title: "A", Section: " \n "},
		{Path: "/b", Title: "B", Section: "Guides"},
	}}
	got := renderLLMs(t, idx, LLMsOptions{DefaultSection: "Other\npages"})
	const want = "# T\n\n## Other pages\n\n- [A](https://example.com/a)\n\n## Guides\n\n- [B](https://example.com/b)\n"
	if got != want {
		t.Errorf("default section = %q, want %q", got, want)
	}
}

func TestWriteLLMsTxtMinimal(t *testing.T) {
	got := renderLLMs(t, &Index{Origin: "https://example.com", Title: "  Site\n name "}, LLMsOptions{})
	if got != "# Site name\n" {
		t.Errorf("minimal llms.txt = %q", got)
	}
	got = renderLLMs(t, &Index{Origin: "https://example.com", Title: "T", Pages: []Page{{Path: "/a(b)", Title: "A"}}}, LLMsOptions{})
	if !strings.Contains(got, "- [A](https://example.com/a%28b%29)\n") {
		t.Errorf("parentheses must not end the link destination:\n%s", got)
	}
}

func TestWriteLLMsTxtRejects(t *testing.T) {
	cases := map[string]struct {
		idx  *Index
		opts LLMsOptions
	}{
		"bad index":        {&Index{Origin: "nope", Title: "T"}, LLMsOptions{}},
		"no title":         {&Index{Origin: "https://example.com"}, LLMsOptions{}},
		"blank title":      {&Index{Origin: "https://example.com", Title: " \n"}, LLMsOptions{}},
		"untitled page":    {&Index{Origin: "https://example.com", Title: "T", Pages: []Page{{Path: "/a"}}}, LLMsOptions{}},
		"heading":          {&Index{Origin: "https://example.com", Title: "T"}, LLMsOptions{Details: "intro\n## More"}},
		"bare heading":     {&Index{Origin: "https://example.com", Title: "T"}, LLMsOptions{Details: "#"}},
		"indented heading": {&Index{Origin: "https://example.com", Title: "T"}, LLMsOptions{Details: "   # x"}},
	}
	for name, c := range cases {
		var b bytes.Buffer
		if err := WriteLLMsTxt(&b, c.idx, c.opts); err == nil || b.Len() != 0 {
			t.Errorf("%s: WriteLLMsTxt err = %v, wrote %q", name, err, b.String())
		}
		if _, err := LLMsTxtHandler(c.idx, c.opts); err == nil {
			t.Errorf("%s: LLMsTxtHandler accepted it", name)
		}
	}
}

func TestHeadingLine(t *testing.T) {
	for md, want := range map[string]bool{
		"# x":            true,
		"###### x":       true,
		"##":             true,
		"#\tx":           true,
		"## x\r":         true,
		"   # x":         true,
		"    # code":     false,
		"####### seven":  false,
		"#hashtag":       false,
		"text # not":     false,
		"":               false,
		"a\n\n- b\n> #c": false,
	} {
		if _, got := headingLine(md); got != want {
			t.Errorf("headingLine(%q) = %v, want %v", md, got, want)
		}
	}
}

func TestLLMsTxtHandler(t *testing.T) {
	h, err := LLMsTxtHandler(bookIndex(), LLMsOptions{Lang: "en"})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/llms.txt", nil))
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "text/plain; charset=utf-8" || !strings.HasPrefix(rec.Body.String(), "# A Book\n") {
		t.Errorf("GET = %d %q %q", rec.Code, rec.Header().Get("Content-Type"), rec.Body.String())
	}
}

func TestWriteLLMsFull(t *testing.T) {
	var b bytes.Buffer
	if err := WriteLLMsFull(&b, bookIndex(), FSOpener(bookFS()), LLMsOptions{Lang: "en"}); err != nil {
		t.Fatal(err)
	}
	const want = `# A Book

> A book about systems.

---

Source: https://example.com/en/

# Preface

Welcome.

---

Source: https://example.com/en/foundations/why

# Why it matters

Because.

---

Source: https://example.com/en/practice/deploy

# Deploying

Ship it.
`
	if got := b.String(); got != want {
		t.Errorf("llms-full.txt mismatch\n--- got\n%s--- want\n%s", got, want)
	}
}

func TestWriteLLMsFullEmptyTwin(t *testing.T) {
	idx := &Index{Origin: "https://example.com", Title: "T", Pages: []Page{{Path: "/a", Title: "A", Markdown: "/zh/foundations/empty.md"}}}
	var b bytes.Buffer
	if err := WriteLLMsFull(&b, idx, FSOpener(bookFS()), LLMsOptions{}); err != nil {
		t.Fatal(err)
	}
	if got := b.String(); got != "# T\n\n---\n\nSource: https://example.com/a\n\n" {
		t.Errorf("empty twin = %q", got)
	}
}

// brokenFile fails a read or a close, standing in for storage that breaks
// while a response streams.
type brokenFile struct {
	io.Reader
	closeErr error
}

func (b brokenFile) Close() error { return b.closeErr }

var errStorage = errors.New("storage failed")

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errStorage }

func TestWriteLLMsFullErrors(t *testing.T) {
	idx := bookIndex()
	cases := map[string]Opener{
		"missing twin": FSOpener(fstest.MapFS{}),
		"read fails": func(string) (io.ReadCloser, error) {
			return brokenFile{Reader: errReader{}}, nil
		},
		"close fails": func(string) (io.ReadCloser, error) {
			return brokenFile{Reader: strings.NewReader("x\n"), closeErr: errStorage}, nil
		},
	}
	for name, open := range cases {
		if err := WriteLLMsFull(io.Discard, idx, open, LLMsOptions{}); err == nil {
			t.Errorf("%s: WriteLLMsFull succeeded", name)
		}
		if _, err := LLMsFullHandler(idx, open, LLMsOptions{}); err == nil {
			t.Errorf("%s: LLMsFullHandler accepted it", name)
		}
	}
	if err := WriteLLMsFull(io.Discard, idx, nil, LLMsOptions{}); err == nil {
		t.Error("a nil opener was accepted")
	}
	if err := WriteLLMsFull(io.Discard, &Index{Origin: "https://example.com"}, FSOpener(bookFS()), LLMsOptions{}); err == nil {
		t.Error("an untitled index was accepted")
	}
	if err := WriteLLMsFull(failWriter{}, idx, FSOpener(bookFS()), LLMsOptions{}); !errors.Is(err, errWrite) {
		t.Errorf("header write error = %v", err)
	}
	// A writer that fails partway surfaces the failure, whether it comes
	// in a page's source line (40 bytes in) or in its body (76 bytes in),
	// rather than carrying on.
	for _, left := range []int{40, 76} {
		lw := &limitedWriter{left: left}
		if err := WriteLLMsFull(lw, idx, FSOpener(bookFS()), LLMsOptions{}); !errors.Is(err, errWrite) {
			t.Errorf("write error %d bytes in = %v", left, err)
		}
	}
}

// limitedWriter accepts left bytes and then fails.
type limitedWriter struct{ left int }

func (l *limitedWriter) Write(p []byte) (int, error) {
	if len(p) > l.left {
		n := l.left
		l.left = 0
		return n, errWrite
	}
	l.left -= len(p)
	return len(p), nil
}

func TestLLMsFullHandler(t *testing.T) {
	h, err := LLMsFullHandler(bookIndex(), FSOpener(bookFS()), LLMsOptions{Lang: "zh", Title: "一本书"})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/zh/llms-full.txt", nil))
	want := "# 一本书\n\n> A book about systems.\n\n---\n\nSource: https://example.com/zh/foundations/why\n\n# 为什么\n"
	if rec.Code != http.StatusOK || rec.Body.String() != want || rec.Header().Get("Content-Type") != "text/plain; charset=utf-8" {
		t.Errorf("GET = %d %q", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodHead, "/zh/llms-full.txt", nil))
	if rec.Code != http.StatusOK || rec.Body.Len() != 0 {
		t.Errorf("HEAD = %d with %d body bytes", rec.Code, rec.Body.Len())
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPut, "/zh/llms-full.txt", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("PUT = %d", rec.Code)
	}
}

// flakyFS serves its files until broken is set, the way storage can fail
// after the handler checked every twin at startup.
type flakyFS struct {
	fs.FS
	broken *bool
}

func (f flakyFS) Open(name string) (fs.File, error) {
	if *f.broken {
		return nil, fs.ErrNotExist
	}
	return f.FS.Open(name)
}

func TestLLMsFullHandlerAbortsAMidStreamFailure(t *testing.T) {
	broken := false
	h, err := LLMsFullHandler(bookIndex(), FSOpener(flakyFS{FS: bookFS(), broken: &broken}), LLMsOptions{Lang: "en"})
	if err != nil {
		t.Fatal(err)
	}
	broken = true
	// The llms.txt header is written before the first twin is opened, so
	// the failure comes after bytes reached the client and the only honest
	// answer left is to abort the transfer.
	defer func() {
		if rec, _ := recover().(error); !errors.Is(rec, http.ErrAbortHandler) {
			t.Errorf("recovered %v, want http.ErrAbortHandler", rec)
		}
	}()
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/llms-full.txt", nil))
	t.Error("the handler returned instead of aborting the stream")
}

// refusingWriter is a ResponseWriter whose body writes all fail, so nothing
// reaches the client.
type refusingWriter struct {
	*httptest.ResponseRecorder
	writes int
}

func (r *refusingWriter) Write(p []byte) (int, error) {
	r.writes++
	if r.writes == 1 {
		return 0, errWrite
	}
	return r.ResponseRecorder.Write(p)
}

func TestLLMsFullHandlerAnswers500WhenNothingWasSent(t *testing.T) {
	h, err := LLMsFullHandler(bookIndex(), FSOpener(bookFS()), LLMsOptions{})
	if err != nil {
		t.Fatal(err)
	}
	w := &refusingWriter{ResponseRecorder: httptest.NewRecorder()}
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/llms-full.txt", nil))
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

// FuzzWriteLLMsTxt holds llms.txt to its structure: whatever a title,
// section or description holds, each page stays one list item under one
// heading, and nothing a value carries opens a heading of its own.
func FuzzWriteLLMsTxt(f *testing.F) {
	for _, s := range [][3]string{
		{"Title", "Section", "Description"},
		{"a\n## injected", "s\n# h1", "d\n- [x](y)"},
		{"[x](y)", "", "\r\n\r\n"},
		{"\\]", "  ", " "},
	} {
		f.Add(s[0], s[1], s[2])
	}
	f.Fuzz(func(t *testing.T, title, section, desc string) {
		idx := &Index{Origin: "https://example.com", Title: "Site", Pages: []Page{
			{Path: "/a", Title: title, Section: section, Description: desc},
			{Path: "/b", Title: "B", Section: section},
		}}
		var b bytes.Buffer
		if err := WriteLLMsTxt(&b, idx, LLMsOptions{}); err != nil {
			if strings.TrimSpace(title) != "" {
				t.Fatalf("title %q refused: %v", title, err)
			}
			return
		}
		var headings, items int
		for line := range strings.SplitSeq(b.String(), "\n") {
			switch {
			case strings.HasPrefix(line, "# "):
				headings++
			case strings.HasPrefix(line, "## "):
				headings++
			case strings.HasPrefix(line, "- ["):
				items++
			}
		}
		if headings != 2 || items != 2 {
			t.Fatalf("title %q section %q desc %q: %d headings and %d items, want 2 and 2:\n%s", title, section, desc, headings, items, b.String())
		}
	})
}
