// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package email

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMailgunSend_Success(t *testing.T) {
	var capturedSubject, capturedTo, capturedHTML, capturedFrom, capturedSender, capturedAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse: %v", err)
			return
		}
		capturedSubject = r.FormValue("subject")
		capturedTo = r.FormValue("to")
		capturedHTML = r.FormValue("html")
		capturedFrom = r.FormValue("from")
		capturedSender = r.FormValue("h:Sender")
		capturedAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	m := &mailgunSender{apiKey: "k", domain: "mg.example.com", from: "Example <noreply@example.com>", sender: "noreply@example.com", baseURL: srv.URL, client: srv.Client()}
	if err := m.Send(context.Background(), Message{To: "user@example.com", Subject: "Your login code", HTML: "<p>654321</p>"}); err != nil {
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
	// The from address is the transport's, never taken from the caller: a
	// service composes what it says, not who it says it from.
	if capturedFrom != "Example <noreply@example.com>" {
		t.Errorf("from = %q", capturedFrom)
	}
	if capturedSender != "noreply@example.com" {
		t.Errorf("h:Sender = %q, want the bare from address", capturedSender)
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
	err := m.Send(context.Background(), Message{To: "user@example.com", Subject: "Hi\r\nBcc: attacker@evil.com", HTML: "<p>b</p>"})
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
	err := m.Send(context.Background(), Message{To: "user@example.com", Subject: "s", HTML: "<p>b</p>"})
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
	if err := m.Send(context.Background(), Message{To: "user@example.com", Subject: "s", HTML: "<p>b</p>"}); err == nil {
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
	err := m.Send(context.Background(), Message{To: "user@example.com", Subject: "s", HTML: "<p>b</p>"})
	if err == nil || !strings.Contains(err.Error(), "create mailgun request") {
		t.Errorf("error = %v, want create-request failure", err)
	}
}

// The text part and Reply-To travel as Mailgun's own fields, and an empty
// one sends no field at all.
func TestMailgunSend_TextAndReplyTo(t *testing.T) {
	var got map[string][]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse: %v", err)
		}
		got = r.PostForm
	}))
	defer srv.Close()
	m := &mailgunSender{apiKey: "k", domain: "mg.example.com", from: "noreply@example.com", sender: "noreply@example.com", baseURL: srv.URL, client: srv.Client()}

	msg := Message{To: "user@example.com", Subject: "s", HTML: "<p>b</p>", Text: "b", ReplyTo: "Billing <billing@example.com>"}
	if err := m.Send(context.Background(), msg); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if got["text"][0] != "b" || got["h:Reply-To"][0] != "Billing <billing@example.com>" {
		t.Errorf("text, reply-to = %q, %q", got["text"], got["h:Reply-To"])
	}

	if err := m.Send(context.Background(), Message{To: "user@example.com", Subject: "s", HTML: "<p>b</p>"}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if _, ok := got["text"]; ok {
		t.Error("an empty text part was sent")
	}
	if _, ok := got["h:Reply-To"]; ok {
		t.Error("an empty Reply-To was sent")
	}
}

func TestMailgunSend_RefusesABadReplyTo(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("a message with a bad Reply-To must never reach the provider")
	}))
	defer srv.Close()
	m := &mailgunSender{apiKey: "k", domain: "mg.example.com", baseURL: srv.URL, client: srv.Client()}
	for _, rt := range []string{"not an address", "a@example.com\r\nBcc: attacker@evil.com"} {
		if err := m.Send(context.Background(), Message{To: "user@example.com", Subject: "s", HTML: "<p>b</p>", ReplyTo: rt}); err == nil {
			t.Errorf("Reply-To %q was taken", rt)
		}
	}
}
