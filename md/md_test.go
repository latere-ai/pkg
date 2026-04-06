package md

import (
	"strings"
	"testing"
)

const sampleWithFront = `---
title: Hello World
status: drafted
tags:
  - go
  - markdown
---
# Hello

Body text here.
`

const sampleNoFront = `# Just Markdown

No frontmatter at all.
`

func TestParse(t *testing.T) {
	front, body, err := Parse([]byte(sampleWithFront))
	if err != nil {
		t.Fatal(err)
	}
	if front["title"] != "Hello World" {
		t.Errorf("title = %v, want Hello World", front["title"])
	}
	if front["status"] != "drafted" {
		t.Errorf("status = %v, want drafted", front["status"])
	}
	tags, ok := front["tags"].([]any)
	if !ok || len(tags) != 2 {
		t.Errorf("tags = %v, want [go markdown]", front["tags"])
	}
	if !strings.HasPrefix(string(body), "# Hello") {
		t.Errorf("body should start with # Hello, got: %s", body[:30])
	}
}

func TestParseNoFrontmatter(t *testing.T) {
	front, body, err := Parse([]byte(sampleNoFront))
	if err != nil {
		t.Fatal(err)
	}
	if front != nil {
		t.Errorf("front should be nil, got %v", front)
	}
	if string(body) != sampleNoFront {
		t.Error("body should equal original source")
	}
}

type specFront struct {
	Title  string   `yaml:"title"`
	Status string   `yaml:"status"`
	Tags   []string `yaml:"tags"`
}

func TestParseInto(t *testing.T) {
	var f specFront
	body, err := ParseInto([]byte(sampleWithFront), &f)
	if err != nil {
		t.Fatal(err)
	}
	if f.Title != "Hello World" {
		t.Errorf("Title = %q, want Hello World", f.Title)
	}
	if f.Status != "drafted" {
		t.Errorf("Status = %q, want drafted", f.Status)
	}
	if len(f.Tags) != 2 || f.Tags[0] != "go" {
		t.Errorf("Tags = %v, want [go markdown]", f.Tags)
	}
	if !strings.HasPrefix(string(body), "# Hello") {
		t.Errorf("body should start with # Hello")
	}
}

func TestParseIntoNoFrontmatter(t *testing.T) {
	var f specFront
	body, err := ParseInto([]byte(sampleNoFront), &f)
	if err != nil {
		t.Fatal(err)
	}
	if f.Title != "" {
		t.Errorf("Title should be zero value, got %q", f.Title)
	}
	if string(body) != sampleNoFront {
		t.Error("body should equal original source")
	}
}

func TestParseInvalidYAML(t *testing.T) {
	src := []byte("---\n: :\n  bad yaml [[[}\n---\nbody\n")
	_, _, err := Parse(src)
	if err == nil {
		t.Error("expected error for invalid YAML")
	}
}

func TestParseIntoInvalidYAML(t *testing.T) {
	src := []byte("---\n: :\n  bad yaml [[[}\n---\nbody\n")
	var f specFront
	_, err := ParseInto(src, &f)
	if err == nil {
		t.Error("expected error for invalid YAML")
	}
}

func TestSplitFrontmatterUnclosed(t *testing.T) {
	src := []byte("---\ntitle: test\nno closing delimiter\n")
	front, body, err := Parse(src)
	if err != nil {
		t.Fatal(err)
	}
	if front != nil {
		t.Error("front should be nil for unclosed frontmatter")
	}
	if string(body) != string(src) {
		t.Error("body should equal original source")
	}
}

func TestSplitFrontmatterNoTrailingNewline(t *testing.T) {
	src := []byte("---\ntitle: test\n---body right after")
	front, body, err := Parse(src)
	if err != nil {
		t.Fatal(err)
	}
	if front["title"] != "test" {
		t.Errorf("title = %v, want test", front["title"])
	}
	if string(body) != "body right after" {
		t.Errorf("body = %q, want 'body right after'", body)
	}
}

func TestRenderEmpty(t *testing.T) {
	html, err := Render([]byte{})
	if err != nil {
		t.Fatal(err)
	}
	if len(html) != 0 {
		t.Errorf("expected empty output, got %q", html)
	}
}

func TestRender(t *testing.T) {
	src := []byte("## Heading\n\nA paragraph with **bold**.\n\n| A | B |\n|---|---|\n| 1 | 2 |\n")
	html, err := Render(src)
	if err != nil {
		t.Fatal(err)
	}
	out := string(html)
	if !strings.Contains(out, `id="heading"`) {
		t.Error("expected auto heading ID")
	}
	if !strings.Contains(out, "<strong>bold</strong>") {
		t.Error("expected bold rendering")
	}
	if !strings.Contains(out, "<table>") {
		t.Error("expected GFM table rendering")
	}
}
