package email

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMailgunSend_Success(t *testing.T) {
	var capturedSubject, capturedTo, capturedHTML, capturedFrom, capturedAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse: %v", err)
			return
		}
		capturedSubject = r.FormValue("subject")
		capturedTo = r.FormValue("to")
		capturedHTML = r.FormValue("html")
		capturedFrom = r.FormValue("from")
		capturedAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	m := &mailgunSender{apiKey: "k", domain: "mg.example.com", baseURL: srv.URL, client: srv.Client()}
	if err := m.Send(context.Background(), "user@example.com", "Your login code", "<p>654321</p>"); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if capturedTo != "user@example.com" {
		t.Errorf("to = %q", capturedTo)
	}
	if capturedSubject != "Your login code" {
		t.Errorf("subject = %q", capturedSubject)
	}
	if capturedHTML != "<p>654321</p>" {
		t.Errorf("html = %q; the transport must not alter the body", capturedHTML)
	}
	// The from address is derived from the sending domain, never taken from the
	// caller: a service composes what it says, not who it says it from.
	if capturedFrom != "noreply@mg.example.com" {
		t.Errorf("from = %q", capturedFrom)
	}
	if capturedAuth == "" || !strings.HasPrefix(capturedAuth, "Basic ") {
		t.Errorf("authorization = %q, want basic auth", capturedAuth)
	}
}

func TestMailgunSend_RejectsCRLFInSubject(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("a message with a forged header must never reach the provider")
	}))
	defer srv.Close()

	m := &mailgunSender{apiKey: "k", domain: "mg.example.com", baseURL: srv.URL, client: srv.Client()}
	err := m.Send(context.Background(), "user@example.com", "Hi\r\nBcc: attacker@evil.com", "<p>b</p>")
	if err == nil || !strings.Contains(err.Error(), "line break") {
		t.Errorf("error = %v, want a line-break rejection", err)
	}
}

func TestMailgunSend_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	m := &mailgunSender{apiKey: "k", domain: "mg.example.com", baseURL: srv.URL, client: srv.Client()}
	err := m.Send(context.Background(), "user@example.com", "s", "<p>b</p>")
	if err == nil || !strings.Contains(err.Error(), "502") {
		t.Fatalf("error = %v, want the provider status reported", err)
	}
}

func TestMailgunSend_TransportError(t *testing.T) {
	m := &mailgunSender{
		apiKey:  "k",
		domain:  "mg.example.com",
		baseURL: "http://127.0.0.1:1", // unreachable
		client:  &http.Client{},
	}
	if err := m.Send(context.Background(), "user@example.com", "s", "<p>b</p>"); err == nil {
		t.Fatal("expected transport error")
	}
}

func TestMailgunSend_BadURL(t *testing.T) {
	// A baseURL with a control character makes http.NewRequest fail while
	// building the request, exercising the "create mailgun request" branch.
	m := &mailgunSender{
		apiKey:  "k",
		domain:  "mg.example.com",
		baseURL: "http://\x7f-bad-host",
		client:  &http.Client{},
	}
	err := m.Send(context.Background(), "user@example.com", "s", "<p>b</p>")
	if err == nil || !strings.Contains(err.Error(), "create mailgun request") {
		t.Errorf("error = %v, want create-request failure", err)
	}
}
