// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package email

import (
	"context"
	"testing"
)

// The selection order is the contract: an unconfigured service must still run.
func TestNewSelectsATransport(t *testing.T) {
	tests := []struct {
		name   string
		apiKey string
		domain string
		region string
		smtp   *SMTPConfig
		want   string // %T of the returned Sender
	}{
		{"nothing configured logs", "", "", "", nil, "*email.LogSender"},
		{"the literal test key logs", "test", "", "", nil, "*email.LogSender"},
		{"smtp when a host is set", "", "", "", &SMTPConfig{Host: "smtp.example.com", Port: "587"}, "*email.smtpSender"},
		{"an empty smtp host still logs", "", "", "", &SMTPConfig{}, "*email.LogSender"},
		{"a real key takes mailgun", "real-key", "mg.example.com", "", nil, "*email.mailgunSender"},
		{"mailgun outranks smtp", "real-key", "mg.example.com", "eu", &SMTPConfig{Host: "smtp.example.com"}, "*email.mailgunSender"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := New(tt.apiKey, tt.domain, tt.region, tt.smtp)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			if got := typeOf(s); got != tt.want {
				t.Errorf("New returned %s, want %s", got, tt.want)
			}
		})
	}
}

func typeOf(s Sender) string {
	switch s.(type) {
	case *LogSender:
		return "*email.LogSender"
	case *smtpSender:
		return "*email.smtpSender"
	case *mailgunSender:
		return "*email.mailgunSender"
	default:
		return "unknown"
	}
}

// A key with no domain is a misconfiguration that must fail at startup rather
// than at the first message.
func TestNewRefusesAKeyWithNoDomain(t *testing.T) {
	if _, err := New("real-key", "", "", nil); err == nil {
		t.Fatal("expected an error for an API key with no domain")
	}
}

func TestNewResolvesTheMailgunFrom(t *testing.T) {
	tests := []struct {
		name       string
		opts       []Option
		wantFrom   string
		wantSender string
	}{
		{"no option sends from the sending domain", nil, "noreply@mg.example.com", "noreply@mg.example.com"},
		{"an empty option is no option", []Option{WithFrom("")}, "noreply@mg.example.com", "noreply@mg.example.com"},
		{"a bare address on the parent domain", []Option{WithFrom("noreply@example.com")}, "noreply@example.com", "noreply@example.com"},
		{"a display name keeps the header as given", []Option{WithFrom("Example <noreply@example.com>")}, "Example <noreply@example.com>", "noreply@example.com"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := New("real-key", "mg.example.com", "eu", nil, tt.opts...)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			m := s.(*mailgunSender)
			if m.from != tt.wantFrom || m.sender != tt.wantSender {
				t.Errorf("from, sender = %q, %q; want %q, %q", m.from, m.sender, tt.wantFrom, tt.wantSender)
			}
		})
	}
}

// A from address that cannot be sent is a misconfiguration that must fail at
// startup, and a line break in it is a header injection.
func TestNewRefusesABadFrom(t *testing.T) {
	for _, from := range []string{"not an address", "Example <noreply@example.com", "noreply@example.com\r\nBcc: attacker@evil.com"} {
		if _, err := New("real-key", "mg.example.com", "eu", nil, WithFrom(from)); err == nil {
			t.Errorf("New with from %q: expected an error", from)
		}
	}
}

func TestNewRegionPicksTheBaseURL(t *testing.T) {
	for region, want := range map[string]string{
		"":   "https://api.mailgun.net",
		"us": "https://api.mailgun.net",
		"eu": "https://api.eu.mailgun.net",
	} {
		s, err := New("real-key", "mg.example.com", region, nil)
		if err != nil {
			t.Fatalf("New(%q): %v", region, err)
		}
		if got := s.(*mailgunSender).baseURL; got != want {
			t.Errorf("region %q → baseURL %q, want %q", region, got, want)
		}
	}
}

// The Mailgun client must carry the otel transport so outbound spans are
// recorded and the trace context propagates.
func TestMailgunClientUsesInstrumentedTransport(t *testing.T) {
	s, err := New("key-real", "mg.example.com", "", nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	m, ok := s.(*mailgunSender)
	if !ok {
		t.Fatalf("New returned %T, want *mailgunSender", s)
	}
	if m.client.Transport == nil {
		t.Fatal("mailgunSender.client.Transport is nil, want otel.Transport")
	}
	if m.client.Timeout == 0 {
		t.Error("mailgunSender.client has no timeout; a hung provider would hang the caller")
	}
}

// The log transport never fails: it is what an unconfigured deployment runs on,
// and a message it cannot deliver must not become an error the caller handles.
func TestLogSenderNeverFails(t *testing.T) {
	var s Sender = &LogSender{}
	if err := s.Send(context.Background(), "user@example.com", "Subject", "<p>body</p>"); err != nil {
		t.Errorf("LogSender.Send = %v, want nil", err)
	}
	if err := s.Send(context.Background(), "", "", ""); err != nil {
		t.Errorf("LogSender.Send on empty input = %v, want nil", err)
	}
}
