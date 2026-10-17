// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package email

import (
	"context"
	"fmt"
	"net/http"
	"net/mail"
	"net/url"
	"strings"
)

// mailgunSender delivers through the Mailgun HTTP API.
type mailgunSender struct {
	apiKey string
	domain string
	// from is the From header as configured; sender is its bare address,
	// which also goes in the Sender header.
	from    string
	sender  string
	baseURL string
	client  *http.Client
}

// mailgunFrom resolves the From header and its bare address, refusing one
// that does not parse or carries a line break, so a bad setting stops the
// start rather than the first message.
func mailgunFrom(from, domain string) (string, string, error) {
	if from == "" {
		from = "noreply@" + domain
	}
	if err := rejectCRLF("from", from); err != nil {
		return "", "", fmt.Errorf("email: %w", err)
	}
	addr, err := mail.ParseAddress(from)
	if err != nil {
		return "", "", fmt.Errorf("email: invalid from address %q: %w", from, err)
	}
	return from, addr.Address, nil
}

// Send posts one message. The subject is refused if it carries a line break:
// it becomes a header, and a header that can be split is a header that can be
// forged. The recipient and body do not need the check — the recipient is a
// form field Mailgun parses itself, and the body is not a header.
func (m *mailgunSender) Send(ctx context.Context, msg Message) error {
	if err := rejectCRLF("subject", msg.Subject); err != nil {
		return err
	}
	if err := checkReplyTo(msg.ReplyTo); err != nil {
		return err
	}
	apiURL := fmt.Sprintf("%s/v3/%s/messages", m.baseURL, m.domain)

	form := url.Values{}
	form.Set("from", m.from)
	// When From is on another domain than the sending one, Mailgun writes its
	// own Sender on the sending domain, and Outlook shows the message as sent
	// on behalf of From. Naming the From address keeps one sender in view.
	form.Set("h:Sender", m.sender)
	form.Set("to", msg.To)
	form.Set("subject", msg.Subject)
	form.Set("html", msg.HTML)
	if msg.Text != "" {
		form.Set("text", msg.Text)
	}
	if msg.ReplyTo != "" {
		form.Set("h:Reply-To", msg.ReplyTo)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("create mailgun request: %w", err)
	}
	req.SetBasicAuth("api", m.apiKey)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := m.client.Do(req)
	if err != nil {
		return fmt.Errorf("mailgun request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("mailgun returned %d", resp.StatusCode)
	}
	return nil
}
