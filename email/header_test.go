package email

import (
	"strings"
	"testing"
)

func TestRejectCRLF(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		wantErr bool
	}{
		{"clean string", "Hello World", false},
		{"contains CR", "line1\rline2", true},
		{"contains LF", "line1\nline2", true},
		{"contains CRLF", "line1\r\nBcc: attacker@evil.com", true},
		{"empty string", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := rejectCRLF("test", tt.value)
			if (err != nil) != tt.wantErr {
				t.Errorf("rejectCRLF(%q): got err=%v, wantErr=%v", tt.value, err, tt.wantErr)
			}
		})
	}
}

// FuzzRejectCRLF asserts the one property the whole header defence rests on:
// a value that survives the check cannot carry a line break, whatever it is.
func FuzzRejectCRLF(f *testing.F) {
	for _, seed := range []string{"", "Subject", "a\r\nb", "a\nb", "a\rb", "ünïcode", "\x00"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		if err := rejectCRLF("field", value); err == nil && strings.ContainsAny(value, "\r\n") {
			t.Errorf("rejectCRLF accepted %q, which contains a line break", value)
		}
	})
}

func TestSMTPSendRejectsInvalidRecipient(t *testing.T) {
	s := &smtpSender{
		host: "localhost",
		addr: "localhost:587",
		from: "noreply@example.com",
	}

	tests := []struct {
		name string
		to   string
	}{
		{"CRLF injection", "victim@example.com\r\nBcc: attacker@evil.com"},
		{"missing domain", "nodomain"},
		{"empty", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// send fails at validation, before trying to connect.
			err := s.send(tt.to, "Subject", "<p>body</p>")
			if err == nil {
				t.Error("expected error for invalid recipient, got nil")
			}
		})
	}
}

func TestSMTPSendRejectsCRLFInSubject(t *testing.T) {
	s := &smtpSender{host: "localhost", addr: "localhost:587", from: "noreply@example.com"}

	err := s.send("valid@example.com", "Subject\r\nBcc: attacker@evil.com", "<p>body</p>")
	if err == nil {
		t.Error("expected error for CRLF in subject, got nil")
	}
}

// The From address is configuration rather than user input, but it is still a
// header, and a misconfigured one must fail rather than send.
func TestSMTPSendRejectsCRLFInFrom(t *testing.T) {
	s := &smtpSender{
		host: "localhost",
		addr: "localhost:587",
		from: "noreply@example.com\r\nBcc: attacker@evil.com",
	}

	err := s.send("valid@example.com", "Subject", "<p>body</p>")
	if err == nil || !strings.Contains(err.Error(), "line break") {
		t.Errorf("expected CRLF-in-from rejection, got %v", err)
	}
}
