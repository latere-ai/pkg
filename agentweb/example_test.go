// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package agentweb_test

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"testing/fstest"
	"time"

	"latere.ai/x/pkg/agentweb"
)

func ExampleWriteRobots() {
	err := agentweb.WriteRobots(os.Stdout, agentweb.Robots{
		Groups: []agentweb.Group{
			{UserAgents: []string{"ExampleBot"}, Disallow: []string{"/"}},
			{
				UserAgents: []string{"*"},
				Signals:    agentweb.Signals{Search: agentweb.Yes, AIInput: agentweb.Yes, AITrain: agentweb.No},
				Allow:      []string{"/"},
			},
		},
		Sitemaps: []string{"https://example.com/sitemap.xml"},
	})
	if err != nil {
		fmt.Println(err)
		return
	}
	// Output:
	// User-agent: ExampleBot
	// Disallow: /
	//
	// User-agent: *
	// Content-Signal: ai-train=no, search=yes, ai-input=yes
	// Allow: /
	//
	// Sitemap: https://example.com/sitemap.xml
}

func ExampleWriteLLMsTxt() {
	idx, err := agentweb.ParseIndex([]byte(`{
	  "origin": "https://example.com",
	  "title": "Example Guide",
	  "summary": "A guide to the example system.",
	  "pages": [
	    {"path": "/en/start", "lang": "en", "title": "Getting started", "description": "Install and run it.",
	     "section": "Basics", "markdown": "/en/start.md", "alternates": {"de": "/de/start"}},
	    {"path": "/de/start", "lang": "de", "title": "Erste Schritte", "section": "Grundlagen",
	     "markdown": "/de/start.md", "alternates": {"en": "/en/start"}}
	  ]
	}`))
	if err != nil {
		fmt.Println(err)
		return
	}
	if err := agentweb.WriteLLMsTxt(os.Stdout, idx, agentweb.LLMsOptions{Lang: "en"}); err != nil {
		fmt.Println(err)
	}
	// Output:
	// # Example Guide
	//
	// > A guide to the example system.
	//
	// ## Basics
	//
	// - [Getting started](https://example.com/en/start.md): Install and run it.
}

// A static site embeds its built tree and the index its build wrote, and
// mounts every document beside the negotiated pages.
func ExampleNegotiate() {
	site := fstest.MapFS{ // an embed.FS in a real server
		"en/start.html": {Data: []byte("<h1>Getting started</h1>")},
		"en/start.md":   {Data: []byte("# Getting started\n")},
	}
	idx := &agentweb.Index{
		Origin: "https://example.com",
		Title:  "Example Guide",
		Pages:  []agentweb.Page{{Path: "/en/start.html", Lang: "en", Title: "Getting started", Markdown: "/en/start.md"}},
	}

	pages, err := agentweb.Negotiate(http.FileServer(http.FS(site)), idx, agentweb.NegotiateOptions{
		DescribedBy: func(agentweb.Page) string { return "/llms.txt" },
	})
	if err != nil {
		fmt.Println(err)
		return
	}
	robots, err := agentweb.RobotsHandler(agentweb.Robots{
		Groups:   []agentweb.Group{{UserAgents: []string{"*"}, Signals: agentweb.Signals{Search: agentweb.Yes}, Allow: []string{"/"}}},
		Sitemaps: []string{idx.URL("/sitemap.xml")},
	})
	if err != nil {
		fmt.Println(err)
		return
	}
	sitemap, err := agentweb.SitemapHandler(idx, agentweb.SitemapOptions{})
	if err != nil {
		fmt.Println(err)
		return
	}
	llms, err := agentweb.LLMsTxtHandler(idx, agentweb.LLMsOptions{})
	if err != nil {
		fmt.Println(err)
		return
	}
	full, err := agentweb.LLMsFullHandler(idx, agentweb.FSOpener(site), agentweb.LLMsOptions{})
	if err != nil {
		fmt.Println(err)
		return
	}

	mux := http.NewServeMux()
	mux.Handle("GET /robots.txt", robots)
	mux.Handle("GET /sitemap.xml", sitemap)
	mux.Handle("GET /llms.txt", llms)
	mux.Handle("GET /llms-full.txt", full)
	mux.Handle("/", pages)

	srv := &http.Server{Addr: ":8080", Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	if err := srv.ListenAndServe(); err != nil {
		slog.Error("serve", "err", err)
	}
}
