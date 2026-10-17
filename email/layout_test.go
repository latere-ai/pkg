// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package email

import (
	"strings"
	"testing"
)

var testLayout = Layout{
	Logo:      Image{Src: "https://example.com/logo.png", Alt: "Example", Width: 120, Height: 38},
	LogoDark:  Image{Src: "https://example.com/logo-dark.png", Alt: "Example", Width: 120, Height: 38},
	Copyright: "© 2026 Example Inc.",
	Links:     []Span{Link("Privacy", "https://example.com/privacy"), Link("Terms", "https://example.com/terms")},
}

var testContent = Content{
	Title:     "Join Acme",
	Preheader: "Accept within 7 days.",
	Blocks: []Block{
		Paragraph(Strong("Ada"), Text(" invited you to "), Strong("Acme"), Text(".")),
		Code("123456"),
		Button("Accept invitation", "https://example.com/accept?t=1&u=2"),
		Facts(Fact{"Reference", "R-1"}, Fact{"Expires", "in 7 days"}),
		Note(Text("Questions? Write to "), Link("help@example.com", "mailto:help@example.com"), Text(".")),
	},
	Reason: "You received this because Ada invited you.",
}

// The text part is the message read aloud: every block in order, a link's
// address beside its label, and the footer after a signature line.
func TestRenderTextPart(t *testing.T) {
	_, text := testLayout.Render(testContent)
	want := "Join Acme\n\n" +
		"Ada invited you to Acme.\n\n" +
		"123456\n\n" +
		"Accept invitation: https://example.com/accept?t=1&u=2\n\n" +
		"Reference: R-1\nExpires: in 7 days\n\n" +
		"Questions? Write to help@example.com.\n\n" +
		"--\nYou received this because Ada invited you.\n" +
		"© 2026 Example Inc. · Privacy https://example.com/privacy · Terms https://example.com/terms\n"
	if text != want {
		t.Errorf("text part:\n%s\nwant:\n%s", text, want)
	}
}

func TestRenderHTMLCarriesEveryBlock(t *testing.T) {
	h, _ := testLayout.Render(testContent)
	for _, want := range []string{
		"<title>Join Acme</title>",
		"Accept within 7 days.",
		`<strong style="font-weight:600;">Ada</strong> invited you to`,
		`letter-spacing:8px`, ">123456</span>",
		`href="https://example.com/accept?t=1&amp;u=2"`, ">Accept invitation</a>",
		"Or open this link:",
		">Reference</td>", ">R-1</td>",
		`class="muted"`, `href="mailto:help@example.com"`,
		"You received this because Ada invited you.",
		"© 2026 Example Inc. &middot; ", `>Privacy</a>`,
		"prefers-color-scheme: dark",
	} {
		if !strings.Contains(h, want) {
			t.Errorf("HTML lacks %q", want)
		}
	}
}

// Gmail drops the style block, so the dark logo must be hidden by its own
// inline style, or a Gmail reader sees two logos.
func TestDarkLogoIsHiddenInline(t *testing.T) {
	h, _ := testLayout.Render(testContent)
	i := strings.Index(h, `class="logo-dark"`)
	if i < 0 {
		t.Fatal("no dark logo wrapper")
	}
	tag := h[i : i+strings.Index(h[i:], ">")]
	if !strings.Contains(tag, "display:none") {
		t.Errorf("the dark logo wrapper %q is not hidden inline", tag)
	}
	if !strings.Contains(h, `class="logo-light" src="https://example.com/logo.png"`) {
		t.Error("the light logo is not marked for the dark rules to hide")
	}
}

func TestOneLogoOrNone(t *testing.T) {
	l := testLayout
	l.LogoDark = Image{}
	h, _ := l.Render(testContent)
	if strings.Contains(h, `class="logo-dark"`) || strings.Count(h, "<img") != 1 {
		t.Error("a layout with no dark logo should show the one logo alone")
	}
	l.Logo = Image{}
	h, _ = l.Render(testContent)
	if strings.Contains(h, "<img") {
		t.Error("a layout with no logo should show no image")
	}
}

func TestEmptyPartsAreLeftOut(t *testing.T) {
	h, text := Layout{}.Render(Content{Title: "T", Blocks: []Block{Paragraph(Text("Body"))}})
	if strings.Contains(h, "mso-hide:all;\">&#847;") || strings.Contains(h, "&#847;") {
		t.Error("no preheader was given, but its filler is there")
	}
	if strings.Contains(h, "&middot;") {
		t.Error("no copyright or links were given, but the last line is there")
	}
	if text != "T\n\nBody\n\n--\n" {
		t.Errorf("text = %q", text)
	}
}

// Every value is escaped where it is written, so content can never become
// markup in a mail client.
func TestRenderEscapes(t *testing.T) {
	evil := `<script>alert(1)</script>"'&`
	l := Layout{Logo: Image{Src: `https://x/"onerror="x`, Alt: evil}, Copyright: evil, Links: []Span{Link(evil, `javascript:"x"`)}}
	c := Content{Title: evil, Preheader: evil, Reason: evil, Blocks: []Block{
		Paragraph(Text(evil), Strong(evil), Link(evil, `https://x/"y"`)),
		Note(Text(evil)), Code(evil), Button(evil, `https://x/"z"`), Facts(Fact{evil, evil}),
	}}
	h, _ := l.Render(c)
	if strings.Contains(h, "<script>") || strings.Contains(h, `"onerror="`) || strings.Contains(h, `/"y"`) {
		t.Errorf("unescaped content in:\n%s", h)
	}
}

func TestSpanText(t *testing.T) {
	for _, tt := range []struct {
		s    Span
		want string
	}{
		{Text("plain"), "plain"},
		{Strong("bold"), "bold"},
		{Link("https://x.y", "https://x.y"), "https://x.y"},
		{Link("a@x.y", "mailto:a@x.y"), "a@x.y"},
		{Link("the docs", "https://x.y/docs"), "the docs (https://x.y/docs)"},
	} {
		if got := spanText(tt.s); got != tt.want {
			t.Errorf("spanText(%+v) = %q, want %q", tt.s, got, tt.want)
		}
	}
}

// FuzzRenderEscapes: whatever a caller puts in a span, the HTML carries it
// escaped and never as raw markup.
func FuzzRenderEscapes(f *testing.F) {
	for _, seed := range []string{"", "plain", "<b>", `"><img src=x>`, "a&b", "ünïcode"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		h, text := Layout{}.Render(Content{Title: "T", Blocks: []Block{Paragraph(Text(s))}})
		if strings.ContainsAny(s, `<>"&'`) && strings.Contains(h, ">"+s+"</td>") {
			t.Errorf("%q reached the HTML unescaped", s)
		}
		if !strings.Contains(h, esc(s)) {
			t.Errorf("%q is missing from the HTML", s)
		}
		if !strings.Contains(text, s) {
			t.Errorf("%q is missing from the text", s)
		}
	})
}
