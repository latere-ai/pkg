package email

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// mailgunSender delivers through the Mailgun HTTP API.
type mailgunSender struct {
	apiKey  string
	domain  string
	baseURL string
	client  *http.Client
}

// Send posts one message. The subject is refused if it carries a line break:
// it becomes a header, and a header that can be split is a header that can be
// forged. The recipient and body do not need the check — the recipient is a
// form field Mailgun parses itself, and the body is not a header.
func (m *mailgunSender) Send(ctx context.Context, to, subject, htmlBody string) error {
	if err := rejectCRLF("subject", subject); err != nil {
		return err
	}
	apiURL := fmt.Sprintf("%s/v3/%s/messages", m.baseURL, m.domain)

	form := url.Values{}
	form.Set("from", fmt.Sprintf("noreply@%s", m.domain))
	form.Set("to", to)
	form.Set("subject", subject)
	form.Set("html", htmlBody)

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
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode >= 400 {
		return fmt.Errorf("mailgun returned %d", resp.StatusCode)
	}
	return nil
}
