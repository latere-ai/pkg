// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// Package email sends transactional mail. It owns the transport and the HTML
// frame a message sits in; a service composes what each message says and
// hands it here.
//
// The split is deliberate. Delivery is a platform concern with one correct
// answer (pick a working transport, refuse header injection, instrument the
// outbound call), and so is HTML that renders across mail clients. What a
// message says is a product decision that belongs to the service making it.
// Sharing the transport and the Layout keeps the careful parts in one place;
// keeping the words out means adding a new kind of mail is a change in one
// service rather than a release of this module.
package email

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/mail"
	"time"

	"latere.ai/x/pkg/otel"
)

// Sender delivers one message. ctx is the caller's request context, so an
// outbound delivery and its logs stay correlated with the request that caused
// them.
//
// The body is HTML, with an optional plain-text alternative. A transport that
// cannot express that is not implemented here rather than silently degrading.
type Sender interface {
	Send(ctx context.Context, m Message) error
}

// Message is one mail to one recipient. Layout.Render fills HTML and Text
// from a message's Content.
type Message struct {
	// To is the recipient's address.
	To string
	// Subject is one line; a line break is refused.
	Subject string
	// HTML is the body.
	HTML string
	// Text is the plain-text body, sent beside HTML as its alternative for
	// clients that do not show HTML. Empty sends HTML alone.
	Text string
	// ReplyTo is where a reply goes instead of the From address, such as a
	// monitored mailbox behind a no-reply sender. Empty sets none.
	ReplyTo string
}

// checkReplyTo refuses a Reply-To that would forge a header or is not one
// address. An empty one is no Reply-To.
func checkReplyTo(replyTo string) error {
	if replyTo == "" {
		return nil
	}
	if err := rejectCRLF("reply-to", replyTo); err != nil {
		return err
	}
	if _, err := mail.ParseAddress(replyTo); err != nil {
		return fmt.Errorf("invalid reply-to address: %w", err)
	}
	return nil
}

// SMTPConfig configures the SMTP transport. Port defaults to 587 (STARTTLS);
// 465 selects implicit TLS.
type SMTPConfig struct {
	Host     string
	Port     string
	Username string
	Password string
	From     string
}

// Option adjusts the transport New returns.
type Option func(*options)

type options struct {
	from string
}

// WithFrom sets the From header of every message the Mailgun transport sends:
// a bare address, or one with a display name ("Example <noreply@example.com>").
// Unset or empty, it is noreply@ the sending domain. The address may sit on a
// parent of the sending domain: under DMARC's relaxed alignment, a message
// Mailgun signs for mg.example.com passes for example.com. The SMTP transport
// takes its From from SMTPConfig instead.
//
// It is a deployment setting, not a per-message one: a service composes what
// it says, and the operator decides who it says it from.
func WithFrom(from string) Option {
	return func(o *options) { o.from = from }
}

// New returns the first transport the configuration supports:
//
//  1. Mailgun, when apiKey is set and is not "test".
//  2. SMTP, when smtp.Host is set.
//  3. A log-only sender otherwise.
//
// The fallback is what lets a service run locally and in CI with no
// credentials and no network: mail is written to the log, and nothing fails.
// "test" is spelled out as a non-key so a test environment can set the
// variable without reaching a real provider.
func New(apiKey, domain, region string, smtp *SMTPConfig, opts ...Option) (Sender, error) {
	var o options
	for _, opt := range opts {
		opt(&o)
	}
	if apiKey != "" && apiKey != "test" {
		if domain == "" {
			return nil, fmt.Errorf("email: a domain is required when an API key is set")
		}
		from, sender, err := mailgunFrom(o.from, domain)
		if err != nil {
			return nil, err
		}
		baseURL := "https://api.mailgun.net"
		if region == "eu" {
			baseURL = "https://api.eu.mailgun.net"
		}
		return &mailgunSender{
			apiKey:  apiKey,
			domain:  domain,
			from:    from,
			sender:  sender,
			baseURL: baseURL,
			client:  &http.Client{Timeout: 10 * time.Second, Transport: otel.Transport(nil)},
		}, nil
	}
	if smtp != nil && smtp.Host != "" {
		return newSMTPSender(smtp)
	}
	return &LogSender{}, nil
}

// LogSender writes a message to the log instead of delivering it — the
// transport an unconfigured deployment gets. It is exported so a service can
// name it when it wants that behavior deliberately rather than by omission.
type LogSender struct{}

// Send logs the recipient and subject. The body is not logged: it is the part
// most likely to carry something that should not sit in a log aggregator.
func (*LogSender) Send(ctx context.Context, m Message) error {
	slog.InfoContext(ctx, "email.sent", "to", m.To, "subject", m.Subject)
	return nil
}
