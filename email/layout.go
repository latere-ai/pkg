// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package email

import (
	"fmt"
	"html"
	"strings"
)

// Layout is the frame a service puts every message in: its logo above the
// message and its links below. A service builds one Layout and renders each
// message's Content into it, so every mail it sends looks alike and the
// HTML that has to work across mail clients is written once, here.
//
// The words stay with the service. Content is plain text in typed blocks;
// Render escapes every value, so no caller writes markup.
type Layout struct {
	// Logo is the image above the message, for a light background. Its Src
	// must be an https URL a mail client can fetch: Gmail shows neither SVG
	// nor data: images.
	Logo Image
	// LogoDark replaces Logo where a client shows a dark background and says
	// so through prefers-color-scheme (Apple Mail does; Gmail does not). An
	// empty Src keeps Logo everywhere.
	LogoDark Image
	// Copyright opens the last line, such as "© 2026 Example Inc.".
	Copyright string
	// Links follow Copyright on the last line, such as Privacy and Terms.
	Links []Span
}

// Image is a picture at a fixed size in CSS pixels; Src is best at twice
// that size, so it is sharp on high-density screens.
type Image struct {
	Src    string
	Alt    string
	Width  int
	Height int
}

// Content is what one message says.
type Content struct {
	// Title is the heading at the top of the message.
	Title string
	// Preheader is the line a client shows after the subject in the inbox.
	// Empty shows the start of the body instead.
	Preheader string
	// Blocks are the body, in order.
	Blocks []Block
	// Reason says why the reader got this mail, as the footer's first line:
	// "You received this because ...".
	Reason string
}

// Span is a run of text inside a block: plain, strong, or a link.
type Span struct {
	text   string
	url    string
	strong bool
}

// Text is plain text.
func Text(s string) Span { return Span{text: s} }

// Strong is text set in bold, such as a name the sentence is about.
func Strong(s string) Span { return Span{text: s, strong: true} }

// Link is text that links to url. A mailto: url shows its label alone in the
// text part, since the label is the address.
func Link(label, url string) Span { return Span{text: label, url: url} }

// Block is one part of a message's body. The blocks are the constructors
// below; a new kind of block is a change to this package.
type Block interface {
	html(*strings.Builder)
	text(*strings.Builder)
}

// Paragraph is body text.
func Paragraph(spans ...Span) Block { return para{spans: spans} }

// Note is smaller, quieter text, for what the reader may skip: an expiry, a
// what-if.
func Note(spans ...Span) Block { return para{spans: spans, note: true} }

// Code is a one-time code, set large so it reads at a glance.
func Code(code string) Block { return codeBlock(code) }

// Button is the message's action. The url follows it as plain text, for a
// client that hides the button.
func Button(label, url string) Block { return button{label: label, url: url} }

// Fact is one row of a Facts table.
type Fact struct {
	Label string
	Value string
}

// Facts is a small table of labels and values, such as a reference number.
func Facts(rows ...Fact) Block { return facts(rows) }

// The palette is neutral, ink on paper, so it suits any logo. Dark values
// apply where a client honors prefers-color-scheme.
type palette struct {
	bg, title, body, muted, line, codeBg, code, btnBg, btn, link, panel string
}

var (
	light = palette{bg: "#ffffff", title: "#0d0d0d", body: "#333333", muted: "#666666", line: "#ebebeb",
		codeBg: "#f4f4f4", code: "#0d0d0d", btnBg: "#0d0d0d", btn: "#ffffff", link: "#0d0d0d", panel: "#f9f9f9"}
	dark = palette{bg: "#161616", title: "#ececec", body: "#d4d4d4", muted: "#a3a3a3", line: "#2f2f2f",
		codeBg: "#262626", code: "#fafafa", btnBg: "#ececec", btn: "#0d0d0d", link: "#ececec", panel: "#1e1e1e"}
)

// font is the system stack: a web font would mean every open fetches it from
// a third party.
const font = "-apple-system, BlinkMacSystemFont, 'Segoe UI', Inter, Helvetica, Arial, sans-serif"

// Render is the message's HTML and plain-text bodies, for Message.HTML and
// Message.Text.
func (l Layout) Render(c Content) (htmlBody, textBody string) {
	return l.renderHTML(c), l.renderText(c)
}

func (l Layout) renderHTML(c Content) string {
	var b strings.Builder
	b.WriteString(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="x-apple-disable-message-reformatting">
<meta name="color-scheme" content="light dark">
<meta name="supported-color-schemes" content="light dark">
<title>`)
	b.WriteString(esc(c.Title))
	b.WriteString("</title>\n<style>")
	b.WriteString(styles)
	fmt.Fprintf(&b, "</style>\n</head>\n<body class=\"bg\" style=\"margin:0;padding:0;background:%s;\">\n", light.bg)
	if c.Preheader != "" {
		// The filler keeps a client from pulling body text into the preview
		// after the preheader.
		fmt.Fprintf(&b, `<div style="display:none;max-height:0;overflow:hidden;opacity:0;mso-hide:all;">%s%s</div>`+"\n",
			esc(c.Preheader), strings.Repeat("&#847;&zwnj;&nbsp;", 40))
	}
	fmt.Fprintf(&b, `<table role="presentation" class="bg" width="100%%" cellpadding="0" cellspacing="0" border="0" style="background:%s;">
<tr><td class="outer" align="center" style="padding:40px 24px;">
<table role="presentation" width="100%%" cellpadding="0" cellspacing="0" border="0" style="max-width:520px;">
`, light.bg)
	l.logoHTML(&b)
	fmt.Fprintf(&b, `<tr><td class="title" style="padding:0 0 16px 0;font-family:%s;font-size:24px;line-height:32px;font-weight:600;letter-spacing:-0.01em;color:%s;">%s</td></tr>`+"\n",
		font, light.title, esc(c.Title))
	for _, bl := range c.Blocks {
		bl.html(&b)
	}
	l.footerHTML(&b, c.Reason)
	b.WriteString("</table>\n</td></tr>\n</table>\n</body>\n</html>\n")
	return b.String()
}

func (l Layout) logoHTML(b *strings.Builder) {
	if l.Logo.Src == "" {
		return
	}
	b.WriteString(`<tr><td style="padding:0 0 36px 0;">`)
	img := func(i Image, class string) {
		fmt.Fprintf(b, `<img%s src="%s" width="%d" height="%d" alt="%s" style="display:block;border:0;outline:none;width:%dpx;height:%dpx;">`,
			class, esc(i.Src), i.Width, i.Height, esc(i.Alt), i.Width, i.Height)
	}
	if l.LogoDark.Src == "" {
		img(l.Logo, "")
	} else {
		img(l.Logo, ` class="logo-light"`)
		// The dark logo is hidden inline, not only by the style block: Gmail
		// drops the style block's rules, and two logos would show.
		b.WriteString(`<div class="logo-dark" style="display:none;max-height:0;overflow:hidden;mso-hide:all;">`)
		img(l.LogoDark, "")
		b.WriteString(`</div>`)
	}
	b.WriteString("</td></tr>\n")
}

func (l Layout) footerHTML(b *strings.Builder, reason string) {
	fmt.Fprintf(b, `<tr><td class="line" style="padding:24px 0 0 0;border-top:1px solid %s;">
<table role="presentation" width="100%%" cellpadding="0" cellspacing="0" border="0">
`, light.line)
	small := fmt.Sprintf(`font-family:%s;font-size:13px;line-height:20px;color:%s;`, font, light.muted)
	if reason != "" {
		fmt.Fprintf(b, `<tr><td class="muted" style="padding:0 0 8px 0;%s">%s</td></tr>`+"\n", small, esc(reason))
	}
	var parts []string
	if l.Copyright != "" {
		parts = append(parts, esc(l.Copyright))
	}
	for _, s := range l.Links {
		parts = append(parts, spanHTML(s))
	}
	if len(parts) > 0 {
		fmt.Fprintf(b, `<tr><td class="muted" style="%s">%s</td></tr>`+"\n", small, strings.Join(parts, " &middot; "))
	}
	b.WriteString("</table>\n</td></tr>\n")
}

func (l Layout) renderText(c Content) string {
	var b strings.Builder
	b.WriteString(c.Title)
	b.WriteString("\n\n")
	for _, bl := range c.Blocks {
		bl.text(&b)
		b.WriteString("\n\n")
	}
	b.WriteString("--\n")
	if c.Reason != "" {
		b.WriteString(c.Reason)
		b.WriteString("\n")
	}
	var parts []string
	if l.Copyright != "" {
		parts = append(parts, l.Copyright)
	}
	for _, s := range l.Links {
		parts = append(parts, s.text+" "+s.url)
	}
	if len(parts) > 0 {
		b.WriteString(strings.Join(parts, " · "))
		b.WriteString("\n")
	}
	return b.String()
}

type para struct {
	spans []Span
	note  bool
}

func (p para) html(b *strings.Builder) {
	class, size, lh, color := "body", 15, 24, light.body
	if p.note {
		class, size, lh, color = "muted", 13, 20, light.muted
	}
	fmt.Fprintf(b, `<tr><td class="%s" style="padding:0 0 16px 0;font-family:%s;font-size:%dpx;line-height:%dpx;color:%s;">`,
		class, font, size, lh, color)
	for _, s := range p.spans {
		b.WriteString(spanHTML(s))
	}
	b.WriteString("</td></tr>\n")
}

func (p para) text(b *strings.Builder) {
	for _, s := range p.spans {
		b.WriteString(spanText(s))
	}
}

type codeBlock string

func (c codeBlock) html(b *strings.Builder) {
	// The letter spacing also follows the last digit, so the right padding is
	// that much smaller to keep the box centered on the digits.
	fmt.Fprintf(b, `<tr><td style="padding:8px 0 24px 0;"><table role="presentation" cellpadding="0" cellspacing="0" border="0"><tr>`+
		`<td class="code-cell" style="background:%s;border-radius:12px;padding:18px 24px 18px 32px;">`+
		`<span class="code" style="font-family:%s;font-size:34px;line-height:40px;font-weight:600;letter-spacing:8px;color:%s;font-variant-numeric:tabular-nums;">%s</span>`+
		"</td></tr></table></td></tr>\n", light.codeBg, font, light.code, esc(string(c)))
}

func (c codeBlock) text(b *strings.Builder) { b.WriteString(string(c)) }

type button struct{ label, url string }

func (bt button) html(b *strings.Builder) {
	fmt.Fprintf(b, `<tr><td style="padding:8px 0 24px 0;"><table role="presentation" cellpadding="0" cellspacing="0" border="0"><tr>`+
		`<td class="btn-cell" bgcolor="%s" style="background:%s;border-radius:8px;">`+
		`<a class="btn" href="%s" target="_blank" style="display:inline-block;padding:12px 22px;font-family:%s;font-size:15px;line-height:20px;font-weight:600;color:%s;text-decoration:none;border-radius:8px;">%s</a>`+
		"</td></tr></table></td></tr>\n", light.btnBg, light.btnBg, esc(bt.url), font, light.btn, esc(bt.label))
	fmt.Fprintf(b, `<tr><td class="muted" style="padding:0 0 16px 0;font-family:%s;font-size:13px;line-height:20px;color:%s;word-break:break-all;">Or open this link: %s</td></tr>`+"\n",
		font, light.muted, spanHTML(Link(bt.url, bt.url)))
}

func (bt button) text(b *strings.Builder) { b.WriteString(bt.label + ": " + bt.url) }

type facts []Fact

func (f facts) html(b *strings.Builder) {
	fmt.Fprintf(b, `<tr><td style="padding:4px 0 24px 0;"><table role="presentation" class="panel" width="100%%" cellpadding="0" cellspacing="0" border="0" style="background:%s;border:1px solid %s;border-radius:10px;border-collapse:separate;">`,
		light.panel, light.line)
	for i, r := range f {
		top := ""
		if i > 0 {
			top = "border-top:1px solid " + light.line + ";"
		}
		fmt.Fprintf(b, `<tr><td class="muted line" style="%spadding:10px 24px 10px 16px;font-family:%s;font-size:13px;line-height:20px;color:%s;width:1%%;white-space:nowrap;vertical-align:top;">%s</td>`+
			`<td class="body line" style="%spadding:10px 16px 10px 0;font-family:%s;font-size:14px;line-height:20px;color:%s;vertical-align:top;">%s</td></tr>`,
			top, font, light.muted, esc(r.Label), top, font, light.body, esc(r.Value))
	}
	b.WriteString("</table></td></tr>\n")
}

func (f facts) text(b *strings.Builder) {
	for i, r := range f {
		if i > 0 {
			b.WriteString("\n")
		}
		b.WriteString(r.Label + ": " + r.Value)
	}
}

func spanHTML(s Span) string {
	switch {
	case s.url != "":
		return fmt.Sprintf(`<a class="link" href="%s" style="color:%s;text-decoration:underline;">%s</a>`, esc(s.url), light.link, esc(s.text))
	case s.strong:
		return `<strong style="font-weight:600;">` + esc(s.text) + `</strong>`
	default:
		return esc(s.text)
	}
}

func spanText(s Span) string {
	if s.url == "" || s.url == s.text || s.url == "mailto:"+s.text {
		return s.text
	}
	return s.text + " (" + s.url + ")"
}

func esc(s string) string { return html.EscapeString(s) }

// styles are the rules only a style block can carry: the phone layout and the
// dark palette. Every other style is inline, since some clients drop the
// block.
var styles = fmt.Sprintf(`
:root { color-scheme: light dark; supported-color-schemes: light dark; }
body { margin: 0; padding: 0; -webkit-text-size-adjust: 100%%; }
@media (max-width: 480px) {
  .outer { padding: 28px 20px !important; }
  .title { font-size: 22px !important; line-height: 30px !important; }
  .code { font-size: 30px !important; letter-spacing: 6px !important; }
}
@media (prefers-color-scheme: dark) {
  .bg { background: %[1]s !important; }
  .title { color: %[2]s !important; }
  .body { color: %[3]s !important; }
  .muted, .muted .link { color: %[4]s !important; }
  .line { border-color: %[5]s !important; }
  .code-cell { background: %[6]s !important; }
  .code { color: %[7]s !important; }
  .panel { background: %[8]s !important; border-color: %[5]s !important; }
  .btn-cell { background: %[9]s !important; }
  .btn { color: %[10]s !important; }
  .link { color: %[11]s !important; }
  .logo-light { display: none !important; }
  .logo-dark { display: block !important; max-height: none !important; overflow: visible !important; }
}
`, dark.bg, dark.title, dark.body, dark.muted, dark.line, dark.codeBg, dark.code, dark.panel, dark.btnBg, dark.btn, dark.link)
