// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package agentweb

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSignalsString(t *testing.T) {
	cases := []struct {
		s    Signals
		want string
	}{
		{Signals{}, ""},
		{Signals{Search: Yes, AIInput: Yes, AITrain: Yes}, "ai-train=yes, search=yes, ai-input=yes"},
		{Signals{Search: Yes, AIInput: Yes, AITrain: No}, "ai-train=no, search=yes, ai-input=yes"},
		{Signals{Search: Yes, AIInput: No, AITrain: No}, "ai-train=no, search=yes, ai-input=no"},
		{Signals{Search: Yes}, "search=yes"},
		{Signals{AITrain: No}, "ai-train=no"},
		{Signals{Search: Yes, AITrain: Signal(9)}, "search=yes"},
	}
	for _, c := range cases {
		if got := c.s.String(); got != c.want {
			t.Errorf("%+v.String() = %q, want %q", c.s, got, c.want)
		}
	}
	if !(Signals{}).IsZero() || (Signals{AIInput: No}).IsZero() {
		t.Error("IsZero must be true only for the zero value")
	}
	if Unset.String() != "" || Yes.String() != "yes" || No.String() != "no" {
		t.Error("Signal.String must render yes, no, and empty for Unset")
	}
}

func renderRobots(t *testing.T, r Robots) string {
	t.Helper()
	var b bytes.Buffer
	if err := WriteRobots(&b, r); err != nil {
		t.Fatalf("WriteRobots: %v", err)
	}
	return b.String()
}

// TestWriteRobotsReproducesHandWrittenFile pins the byte shape of a
// hand-written robots.txt this package replaces: crawler blocks first, the
// open "*" group, then the sitemap, each separated by one empty line.
func TestWriteRobotsReproducesHandWrittenFile(t *testing.T) {
	const want = `User-agent: Sogou
Disallow: /

User-agent: MauiBot
Disallow: /

User-agent: ZoominfoBot
Disallow: /

User-agent: *
Allow: /

Sitemap: https://example.com/sitemap.xml
`
	got := renderRobots(t, Robots{
		Groups: []Group{
			{UserAgents: []string{"Sogou"}, Disallow: []string{"/"}},
			{UserAgents: []string{"MauiBot"}, Disallow: []string{"/"}},
			{UserAgents: []string{"ZoominfoBot"}, Disallow: []string{"/"}},
			{UserAgents: []string{"*"}, Allow: []string{"/"}},
		},
		Sitemaps: []string{"https://example.com/sitemap.xml"},
	})
	if got != want {
		t.Errorf("robots.txt mismatch\n--- got\n%s--- want\n%s", got, want)
	}
}

func TestWriteRobotsContentSignalPlacement(t *testing.T) {
	const want = `User-agent: ExampleBot
Disallow: /

User-agent: *
Content-Signal: ai-train=no, search=yes, ai-input=yes
Allow: /
Disallow: /private/

Sitemap: https://example.com/sitemap.xml
Sitemap: https://example.com/zh/sitemap.xml
`
	got := renderRobots(t, Robots{
		Groups: []Group{
			{UserAgents: []string{"ExampleBot"}, Disallow: []string{"/"}},
			{
				UserAgents: []string{"*"},
				Signals:    Signals{Search: Yes, AIInput: Yes, AITrain: No},
				Allow:      []string{"/"},
				Disallow:   []string{"/private/"},
			},
		},
		Sitemaps: []string{"https://example.com/sitemap.xml", "https://example.com/zh/sitemap.xml"},
	})
	if got != want {
		t.Errorf("robots.txt mismatch\n--- got\n%s--- want\n%s", got, want)
	}
}

func TestWriteRobotsSeveralUserAgentsShareAGroup(t *testing.T) {
	const want = "User-agent: a-bot\nUser-agent: b-bot\nContent-Signal: search=yes\nDisallow: \n"
	got := renderRobots(t, Robots{Groups: []Group{{
		UserAgents: []string{"a-bot", "b-bot"},
		Signals:    Signals{Search: Yes},
		Disallow:   []string{""},
	}}})
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestWriteRobotsPolicy(t *testing.T) {
	got := renderRobots(t, Robots{
		Policy: true,
		Groups: []Group{{UserAgents: []string{"*"}, Signals: Signals{Search: Yes, AITrain: No}, Allow: []string{"/"}}},
	})
	want := SignalsPolicy + "\nUser-agent: *\nContent-Signal: ai-train=no, search=yes\nAllow: /\n"
	if got != want {
		t.Errorf("policy file mismatch\n--- got\n%s--- want\n%s", got, want)
	}
	for line := range strings.SplitSeq(strings.TrimSuffix(SignalsPolicy, "\n"), "\n") {
		if line != "" && !strings.HasPrefix(line, "# ") {
			t.Errorf("policy line %q is neither empty nor a comment", line)
		}
	}
}

func TestWriteRobotsEdgeShapes(t *testing.T) {
	cases := []struct {
		name string
		r    Robots
		want string
	}{
		{"empty", Robots{}, ""},
		{"policy only", Robots{Policy: true}, SignalsPolicy},
		{"sitemap only", Robots{Sitemaps: []string{"https://example.com/s.xml"}}, "Sitemap: https://example.com/s.xml\n"},
		{"policy and sitemap", Robots{Policy: true, Sitemaps: []string{"http://example.com/s.xml"}}, SignalsPolicy + "\nSitemap: http://example.com/s.xml\n"},
	}
	for _, c := range cases {
		if got := renderRobots(t, c.r); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

func TestWriteRobotsRejects(t *testing.T) {
	star := []string{"*"}
	cases := []struct {
		name string
		r    Robots
	}{
		{"no user agent", Robots{Groups: []Group{{Allow: []string{"/"}}}}},
		{"empty user agent", Robots{Groups: []Group{{UserAgents: []string{""}}}}},
		{"user agent with newline", Robots{Groups: []Group{{UserAgents: []string{"a\nDisallow: /"}}}}},
		{"user agent with space", Robots{Groups: []Group{{UserAgents: []string{"a b"}}}}},
		{"user agent with comment", Robots{Groups: []Group{{UserAgents: []string{"a#b"}}}}},
		{"path without slash", Robots{Groups: []Group{{UserAgents: star, Allow: []string{"private"}}}}},
		{"path with newline", Robots{Groups: []Group{{UserAgents: star, Disallow: []string{"/a\nAllow: /"}}}}},
		{"path with tab", Robots{Groups: []Group{{UserAgents: star, Disallow: []string{"/a\tb"}}}}},
		{"path with delete", Robots{Groups: []Group{{UserAgents: star, Disallow: []string{"/a\x7f"}}}}},
		{"signal out of range", Robots{Groups: []Group{{UserAgents: star, Signals: Signals{AIInput: Signal(3)}}}}},
		{"relative sitemap", Robots{Sitemaps: []string{"/sitemap.xml"}}},
		{"ftp sitemap", Robots{Sitemaps: []string{"ftp://example.com/sitemap.xml"}}},
		{"sitemap without host", Robots{Sitemaps: []string{"https:///sitemap.xml"}}},
		{"sitemap with fragment", Robots{Sitemaps: []string{"https://example.com/s.xml#x"}}},
		{"sitemap with space", Robots{Sitemaps: []string{"https://example.com/a b.xml"}}},
		{"sitemap that does not parse", Robots{Sitemaps: []string{"https://[::1/s.xml"}}},
	}
	for _, c := range cases {
		var b bytes.Buffer
		if err := WriteRobots(&b, c.r); err == nil {
			t.Errorf("%s: WriteRobots accepted it and wrote %q", c.name, b.String())
		} else if b.Len() != 0 {
			t.Errorf("%s: WriteRobots wrote %q before refusing", c.name, b.String())
		}
		if _, err := RobotsHandler(c.r); err == nil {
			t.Errorf("%s: RobotsHandler accepted it", c.name)
		}
	}
}

// failWriter fails every write, standing in for a client that went away.
type failWriter struct{}

var errWrite = errors.New("write refused")

func (failWriter) Write([]byte) (int, error) { return 0, errWrite }

func TestWriteRobotsReportsWriteError(t *testing.T) {
	r := Robots{Groups: []Group{{UserAgents: []string{"*"}, Allow: []string{"/"}}}}
	if err := WriteRobots(failWriter{}, r); !errors.Is(err, errWrite) {
		t.Fatalf("WriteRobots error = %v, want the writer's error", err)
	}
}

func TestRobotsHandler(t *testing.T) {
	h, err := RobotsHandler(Robots{
		Groups:   []Group{{UserAgents: []string{"*"}, Signals: Signals{Search: Yes}, Allow: []string{"/"}}},
		Sitemaps: []string{"https://example.com/sitemap.xml"},
	})
	if err != nil {
		t.Fatal(err)
	}
	const body = "User-agent: *\nContent-Signal: search=yes\nAllow: /\n\nSitemap: https://example.com/sitemap.xml\n"

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/robots.txt", nil))
	if rec.Code != http.StatusOK || rec.Body.String() != body {
		t.Fatalf("GET = %d %q", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/plain; charset=utf-8" {
		t.Errorf("Content-Type = %q", ct)
	}
	etag := rec.Header().Get("ETag")
	if !strings.HasPrefix(etag, `"`) || len(etag) != 34 {
		t.Errorf("ETag = %q, want a quoted 32-hex strong validator", etag)
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodHead, "/robots.txt", nil))
	if rec.Code != http.StatusOK || rec.Body.Len() != 0 {
		t.Errorf("HEAD = %d with %d body bytes", rec.Code, rec.Body.Len())
	}

	req := httptest.NewRequest(http.MethodGet, "/robots.txt", nil)
	req.Header.Set("If-None-Match", etag)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotModified {
		t.Errorf("revalidation = %d, want 304", rec.Code)
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/robots.txt", nil))
	if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != "GET, HEAD" {
		t.Errorf("POST = %d, Allow %q", rec.Code, rec.Header().Get("Allow"))
	}
}

// FuzzWriteRobots holds robots.txt to its line structure: whatever a
// configuration value holds, an accepted file consists only of the
// directives this package writes, one per line, and never a line smuggled
// in through a value.
func FuzzWriteRobots(f *testing.F) {
	for _, s := range [][2]string{
		{"*", "/"},
		{"ExampleBot", "/private/"},
		{"a\nDisallow: /", "/"},
		{"*", "/a\r\nAllow: /"},
		{"*", "/#comment"},
		{"bot\u2028", "/\u00e9"},
	} {
		f.Add(s[0], s[1])
	}
	f.Fuzz(func(t *testing.T, ua, path string) {
		r := Robots{
			Groups:   []Group{{UserAgents: []string{ua}, Signals: Signals{Search: Yes}, Allow: []string{path}, Disallow: []string{path}}},
			Sitemaps: []string{"https://example.com" + path},
		}
		var b bytes.Buffer
		if err := WriteRobots(&b, r); err != nil {
			return
		}
		lines := strings.Split(strings.TrimSuffix(b.String(), "\n"), "\n")
		want := []string{"User-agent: ", "Content-Signal: ", "Allow: ", "Disallow: ", "", "Sitemap: "}
		if len(lines) != len(want) {
			t.Fatalf("ua %q path %q rendered %d lines, want %d:\n%s", ua, path, len(lines), len(want), b.String())
		}
		for i, prefix := range want {
			if !strings.HasPrefix(lines[i], prefix) || (prefix == "" && lines[i] != "") {
				t.Fatalf("line %d = %q, want prefix %q", i, lines[i], prefix)
			}
		}
	})
}
