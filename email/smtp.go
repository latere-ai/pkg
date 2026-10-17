// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package email

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"mime/multipart"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"strings"
)

// smtpSender delivers over SMTP, either STARTTLS (587, the default) or
// implicit TLS (465). Plaintext delivery is not offered.
type smtpSender struct {
	host     string
	addr     string
	auth     smtp.Auth
	from     string
	implicit bool // port 465 uses implicit TLS
	// rootCAs overrides the trust store used for TLS verification. It is nil in
	// production (system roots) and set only by tests to trust a self-signed
	// in-process SMTP server.
	rootCAs *x509.CertPool
}

func newSMTPSender(cfg *SMTPConfig) (*smtpSender, error) {
	port := cfg.Port
	if port == "" {
		port = "587"
	}
	s := &smtpSender{
		host:     cfg.Host,
		addr:     net.JoinHostPort(cfg.Host, port),
		from:     cfg.From,
		implicit: port == "465",
	}
	if cfg.Username != "" {
		s.auth = smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.Host)
	}
	return s, nil
}

// rejectCRLF returns an error if value contains CR or LF. Every string that
// becomes a header passes through here: a line break in a header is how one
// message is turned into two.
func rejectCRLF(field, value string) error {
	if strings.ContainsAny(value, "\r\n") {
		return fmt.Errorf("invalid %s: contains line break", field)
	}
	return nil
}

// Send composes the message and delivers it. ctx bounds the connect phase on
// both transports: without it an unreachable or silently hanging SMTP host
// blocks the caller until the OS TCP timeout, with no way to abandon it.
// net/smtp itself takes no context, so the greeting read and the envelope
// exchange after the connection is up remain uncancellable.
func (s *smtpSender) Send(ctx context.Context, m Message) error {
	addr, err := mail.ParseAddress(m.To)
	if err != nil {
		return fmt.Errorf("invalid recipient address: %w", err)
	}
	if err := rejectCRLF("from", s.from); err != nil {
		return err
	}
	if err := rejectCRLF("subject", m.Subject); err != nil {
		return err
	}
	if err := checkReplyTo(m.ReplyTo); err != nil {
		return err
	}

	// Header fields use the sanitized address and CRLF-checked values so no
	// untrusted input can inject additional headers. addr.Address is the
	// parsed mailbox with any line breaks already stripped by mail.ParseAddress.
	head := "MIME-Version: 1.0\r\n" +
		"From: " + s.from + "\r\n" +
		"To: " + addr.Address + "\r\n"
	if m.ReplyTo != "" {
		head += "Reply-To: " + m.ReplyTo + "\r\n"
	}
	head += "Subject: " + m.Subject + "\r\n"
	body, err := mimeBody(m.HTML, m.Text)
	if err != nil {
		return err
	}
	msg := []byte(head + body)

	if s.implicit {
		return s.sendImplicitTLS(ctx, m.To, msg)
	}
	return s.sendSTARTTLS(ctx, m.To, msg)
}

// newBoundary is the multipart boundary; a test fixes it to compare output.
var newBoundary = func() string { return multipart.NewWriter(io.Discard).Boundary() }

// mimeBody is the Content-Type header and the body after it: the HTML alone,
// or a multipart/alternative with the text first, since a client shows the
// last part it can render. Both parts are quoted-printable, so a long line or
// a non-ASCII character survives any relay.
func mimeBody(html, text string) (string, error) {
	if text == "" {
		return "Content-Type: text/html; charset=\"UTF-8\"\r\n\r\n" + html, nil
	}
	var b strings.Builder
	w := multipart.NewWriter(&b)
	if err := w.SetBoundary(newBoundary()); err != nil {
		return "", fmt.Errorf("smtp boundary: %w", err)
	}
	for _, part := range []struct{ kind, body string }{{"text/plain", text}, {"text/html", html}} {
		h := textproto.MIMEHeader{}
		h.Set("Content-Type", part.kind+"; charset=\"UTF-8\"")
		h.Set("Content-Transfer-Encoding", "quoted-printable")
		pw, err := w.CreatePart(h)
		if err != nil {
			return "", fmt.Errorf("smtp part: %w", err)
		}
		qw := quotedprintable.NewWriter(pw)
		if _, err := qw.Write([]byte(part.body)); err != nil {
			return "", fmt.Errorf("smtp part: %w", err)
		}
		if err := qw.Close(); err != nil {
			return "", fmt.Errorf("smtp part: %w", err)
		}
	}
	if err := w.Close(); err != nil {
		return "", fmt.Errorf("smtp parts: %w", err)
	}
	return "Content-Type: multipart/alternative; boundary=\"" + w.Boundary() + "\"\r\n\r\n" + b.String(), nil
}

// sendSTARTTLS connects on port 587 and upgrades to TLS via STARTTLS.
// smtp.Dial is not used because it dials without a context. Dialing separately
// and handing the connection to smtp.NewClient is the same exchange with the
// connect phase bounded by ctx.
func (s *smtpSender) sendSTARTTLS(ctx context.Context, to string, msg []byte) error {
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", s.addr)
	if err != nil {
		return fmt.Errorf("smtp dial: %w", err)
	}
	c, err := smtp.NewClient(conn, s.host)
	if err != nil {
		conn.Close() //nolint:errcheck
		return fmt.Errorf("smtp new client: %w", err)
	}
	defer c.Close() //nolint:errcheck

	if err := c.StartTLS(&tls.Config{ServerName: s.host, RootCAs: s.rootCAs}); err != nil {
		return fmt.Errorf("smtp starttls: %w", err)
	}
	return s.deliver(c, to, msg)
}

// sendImplicitTLS connects on port 465 with TLS from the start.
func (s *smtpSender) sendImplicitTLS(ctx context.Context, to string, msg []byte) error {
	d := &tls.Dialer{Config: &tls.Config{ServerName: s.host, RootCAs: s.rootCAs}}
	conn, err := d.DialContext(ctx, "tcp", s.addr)
	if err != nil {
		return fmt.Errorf("smtp tls dial: %w", err)
	}
	c, err := smtp.NewClient(conn, s.host)
	if err != nil {
		conn.Close() //nolint:errcheck
		return fmt.Errorf("smtp new client: %w", err)
	}
	defer c.Close() //nolint:errcheck
	return s.deliver(c, to, msg)
}

// deliver is the envelope exchange both transports share once a secured
// connection exists. It was duplicated per transport before; one copy means an
// auth step cannot be fixed on one path and missed on the other.
func (s *smtpSender) deliver(c *smtp.Client, to string, msg []byte) error {
	if s.auth != nil {
		if err := c.Auth(s.auth); err != nil {
			return fmt.Errorf("smtp auth: %w", err)
		}
	}
	if err := c.Mail(s.from); err != nil {
		return fmt.Errorf("smtp mail: %w", err)
	}
	if err := c.Rcpt(to); err != nil {
		return fmt.Errorf("smtp rcpt: %w", err)
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("smtp data: %w", err)
	}
	if _, err := w.Write(msg); err != nil {
		return fmt.Errorf("smtp write: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("smtp close data: %w", err)
	}
	return c.Quit()
}
