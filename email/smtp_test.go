package email

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

func TestSMTP_Send_BadRecipient(t *testing.T) {
	s, _ := newSMTPSender(&SMTPConfig{Host: "smtp.example.com", Port: "587", From: "noreply@example.com"})
	if err := s.Send(context.Background(), "not-an-email", "Your login code", "<p>123456</p>"); err == nil {
		t.Fatal("expected error for invalid recipient")
	}
}

// A subject is a header, so a line break in one is refused before anything is
// dialled — whatever the calling service put in it.
func TestSMTP_Send_RejectsCRLFInSubject(t *testing.T) {
	s, _ := newSMTPSender(&SMTPConfig{Host: "smtp.example.com", Port: "587", From: "noreply@example.com"})
	err := s.Send(context.Background(), "user@example.com", "Evil\r\nBcc: attacker@evil.com", "<p>b</p>")
	if err == nil || !strings.Contains(err.Error(), "line break") {
		t.Errorf("expected CRLF rejection, got %v", err)
	}
}

func TestSMTP_PortDefault(t *testing.T) {
	s, err := newSMTPSender(&SMTPConfig{Host: "smtp.example.com", From: "noreply@example.com"})
	if err != nil {
		t.Fatalf("newSMTPSender: %v", err)
	}
	if !strings.HasSuffix(s.addr, ":587") {
		t.Errorf("default port not applied: %q", s.addr)
	}
	if s.implicit {
		t.Error("implicit TLS should be false at port 587")
	}
	// Production leaves rootCAs nil so TLS uses the system trust store.
	if s.rootCAs != nil {
		t.Error("newSMTPSender must not set rootCAs (production uses system roots)")
	}
}

func TestSMTP_ImplicitTLSPort(t *testing.T) {
	s, _ := newSMTPSender(&SMTPConfig{Host: "smtp.example.com", Port: "465", From: "noreply@example.com"})
	if !s.implicit {
		t.Error("implicit should be true for port 465")
	}
}

func TestSMTP_AuthSet(t *testing.T) {
	s, _ := newSMTPSender(&SMTPConfig{
		Host: "smtp.example.com", Port: "587",
		Username: "u", Password: "p",
		From: "noreply@example.com",
	})
	if s.auth == nil {
		t.Error("auth should be set when username provided")
	}
}

func TestSMTP_SendDialFailure(t *testing.T) {
	s, _ := newSMTPSender(&SMTPConfig{
		Host: "127.0.0.1", Port: "1", // closed port
		From: "noreply@example.com",
	})
	err := s.Send(context.Background(), "user@example.com", "Subject", "<p>b</p>")
	if err == nil {
		t.Fatal("expected dial failure")
	}
}

func TestSMTP_ImplicitDialFailure(t *testing.T) {
	s, _ := newSMTPSender(&SMTPConfig{
		Host: "127.0.0.1", Port: "465",
		From: "noreply@example.com",
	})
	err := s.Send(context.Background(), "user@example.com", "Subject", "<p>b</p>")
	if err == nil {
		t.Fatal("expected dial failure")
	}
}

// --- Local in-process SMTP server with a trusted self-signed cert ---

// generateSelfSignedTLS returns a server TLS config plus a cert pool a client
// can use as RootCAs to trust it. The cert carries an IP SAN for 127.0.0.1 and
// is marked as a CA so it verifies when added directly to a RootCAs pool.
func generateSelfSignedTLS(t *testing.T) (*tls.Config, *x509.CertPool) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{der},
			PrivateKey:  priv,
			Leaf:        cert,
		}},
	}, pool
}

// mockOpts configures fault injection in the in-process SMTP server so the
// error branches of the sender can be exercised deterministically.
type mockOpts struct {
	supportSTARTTLS bool
	tlsCfg          *tls.Config // used to upgrade the socket on STARTTLS
	failCmd         string      // command prefix ("STARTTLS","MAIL","RCPT","DATA") to reject with 5xx
	failAuth        bool        // reject AUTH with 535
	failDot         bool        // reject the end-of-DATA "." with 5xx
}

// runSMTPMock runs a minimal SMTP server on ln and returns a channel that
// receives the captured DATA payload once a message completes.
func runSMTPMock(t *testing.T, ln net.Listener, opts mockOpts) <-chan string {
	t.Helper()
	dataCh := make(chan string, 1)
	go func() {
		defer close(dataCh)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close() //nolint:errcheck

		c := conn
		readLine := func() (string, error) {
			buf := make([]byte, 4096)
			n, err := c.Read(buf)
			if err != nil {
				return "", err
			}
			return string(buf[:n]), nil
		}
		write := func(s string) error {
			_, err := c.Write([]byte(s))
			return err
		}
		if err := write("220 mock ESMTP\r\n"); err != nil {
			return
		}

		var data strings.Builder
		inData := false
		for {
			line, err := readLine()
			if err != nil {
				return
			}
			cmds := strings.SplitSeq(line, "\r\n")
			for cmd := range cmds {
				if cmd == "" {
					continue
				}
				if inData {
					if cmd == "." {
						inData = false
						if opts.failDot {
							_ = write("554 rejected\r\n")
							continue
						}
						_ = write("250 OK\r\n")
						dataCh <- data.String()
						continue
					}
					data.WriteString(cmd)
					data.WriteString("\r\n")
					continue
				}
				upper := strings.ToUpper(cmd)
				switch {
				case strings.HasPrefix(upper, "EHLO"), strings.HasPrefix(upper, "HELO"):
					if opts.supportSTARTTLS {
						_ = write("250-mock\r\n250-STARTTLS\r\n250-AUTH PLAIN\r\n250 OK\r\n")
					} else {
						_ = write("250-mock\r\n250-AUTH PLAIN\r\n250 OK\r\n")
					}
				case strings.HasPrefix(upper, "STARTTLS"):
					if opts.failCmd == "STARTTLS" {
						_ = write("554 no tls\r\n")
						continue
					}
					_ = write("220 ready\r\n")
					tlsConn := tls.Server(c, opts.tlsCfg)
					if err := tlsConn.Handshake(); err != nil {
						return
					}
					c = tlsConn
				case strings.HasPrefix(upper, "AUTH"):
					if opts.failAuth {
						_ = write("535 auth failed\r\n")
						continue
					}
					_ = write("235 authenticated\r\n")
				case strings.HasPrefix(upper, "MAIL"):
					if opts.failCmd == "MAIL" {
						_ = write("550 no mail\r\n")
						continue
					}
					_ = write("250 OK\r\n")
				case strings.HasPrefix(upper, "RCPT"):
					if opts.failCmd == "RCPT" {
						_ = write("550 no rcpt\r\n")
						continue
					}
					_ = write("250 OK\r\n")
				case strings.HasPrefix(upper, "DATA"):
					if opts.failCmd == "DATA" {
						_ = write("554 no data\r\n")
						continue
					}
					_ = write("354 send\r\n")
					inData = true
				case strings.HasPrefix(upper, "QUIT"):
					_ = write("221 bye\r\n")
					return
				default:
					_ = write("250 OK\r\n")
				}
			}
		}
	}()
	return dataCh
}

// newTestSTARTTLSSender starts a plaintext listener that upgrades on STARTTLS
// and returns a sender configured to trust it.
func newTestSTARTTLSSender(t *testing.T, opts mockOpts, withAuth bool) (*smtpSender, <-chan string) {
	t.Helper()
	tlsCfg, pool := generateSelfSignedTLS(t)
	opts.tlsCfg = tlsCfg
	opts.supportSTARTTLS = true

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	dataCh := runSMTPMock(t, ln, opts)

	host, port, _ := net.SplitHostPort(ln.Addr().String())
	cfg := &SMTPConfig{Host: host, Port: port, From: "noreply@example.com"}
	if withAuth {
		cfg.Username = "u"
		cfg.Password = "p"
	}
	s, _ := newSMTPSender(cfg)
	s.rootCAs = pool
	return s, dataCh
}

// newTestImplicitTLSSender starts a TLS listener (implicit TLS, port-465 style)
// and returns a sender configured to trust it.
func newTestImplicitTLSSender(t *testing.T, opts mockOpts, withAuth bool) (*smtpSender, <-chan string) {
	t.Helper()
	tlsCfg, pool := generateSelfSignedTLS(t)
	opts.tlsCfg = tlsCfg
	opts.supportSTARTTLS = false

	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	dataCh := runSMTPMock(t, ln, opts)

	host, port, _ := net.SplitHostPort(ln.Addr().String())
	cfg := &SMTPConfig{Host: host, Port: port, From: "noreply@example.com"}
	if withAuth {
		cfg.Username = "u"
		cfg.Password = "p"
	}
	s, _ := newSMTPSender(cfg)
	s.implicit = true
	s.rootCAs = pool
	return s, dataCh
}

func TestSMTP_STARTTLS_HappyPath(t *testing.T) {
	s, dataCh := newTestSTARTTLSSender(t, mockOpts{}, false)

	msg := []byte("Subject: hello\r\n\r\nbody text")
	if err := s.sendSTARTTLS(t.Context(), "user@example.com", msg); err != nil {
		t.Fatalf("sendSTARTTLS: %v", err)
	}
	select {
	case d := <-dataCh:
		if !strings.Contains(d, "Subject: hello") || !strings.Contains(d, "body text") {
			t.Errorf("captured DATA = %q", d)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for DATA")
	}
}

func TestSMTP_STARTTLS_WithAuth(t *testing.T) {
	s, dataCh := newTestSTARTTLSSender(t, mockOpts{}, true)
	if s.auth == nil {
		t.Fatal("expected auth to be configured")
	}
	if err := s.sendSTARTTLS(t.Context(), "user@example.com", []byte("Subject: a\r\n\r\nb")); err != nil {
		t.Fatalf("sendSTARTTLS with auth: %v", err)
	}
	select {
	case <-dataCh:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out")
	}
}

func TestSMTP_STARTTLS_SendEndToEnd(t *testing.T) {
	// Exercise the full public path Send -> send -> sendSTARTTLS, and assert the
	// service's subject and body arrive intact — the transport composes headers
	// around them and must not touch either.
	s, dataCh := newTestSTARTTLSSender(t, mockOpts{}, false)
	if err := s.Send(context.Background(), "user@example.com", "Your login code", "<p>424242</p>"); err != nil {
		t.Fatalf("Send: %v", err)
	}
	select {
	case d := <-dataCh:
		if !strings.Contains(d, "Subject: Your login code") || !strings.Contains(d, "<p>424242</p>") {
			t.Errorf("subject or body missing from DATA: %q", d)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out")
	}
}

func TestSMTP_STARTTLS_ErrorBranches(t *testing.T) {
	tests := []struct {
		name    string
		opts    mockOpts
		wantSub string
	}{
		{"starttls refused", mockOpts{failCmd: "STARTTLS"}, "starttls"},
		{"auth failed", mockOpts{failAuth: true}, "auth"},
		{"mail rejected", mockOpts{failCmd: "MAIL"}, "mail"},
		{"rcpt rejected", mockOpts{failCmd: "RCPT"}, "rcpt"},
		{"data rejected", mockOpts{failCmd: "DATA"}, "data"},
		{"close data rejected", mockOpts{failDot: true}, "close data"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withAuth := tt.opts.failAuth
			s, _ := newTestSTARTTLSSender(t, tt.opts, withAuth)
			err := s.sendSTARTTLS(t.Context(), "user@example.com", []byte("Subject: x\r\n\r\nb"))
			if err == nil {
				t.Fatalf("expected error for %s", tt.name)
			}
			if !strings.Contains(err.Error(), tt.wantSub) {
				t.Errorf("error = %q, want substring %q", err, tt.wantSub)
			}
		})
	}
}

func TestSMTP_ImplicitTLS_HappyPath(t *testing.T) {
	s, dataCh := newTestImplicitTLSSender(t, mockOpts{}, false)
	msg := []byte("Subject: implicit\r\n\r\nbody here")
	if err := s.sendImplicitTLS(t.Context(), "user@example.com", msg); err != nil {
		t.Fatalf("sendImplicitTLS: %v", err)
	}
	select {
	case d := <-dataCh:
		if !strings.Contains(d, "Subject: implicit") || !strings.Contains(d, "body here") {
			t.Errorf("captured DATA = %q", d)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for DATA")
	}
}

func TestSMTP_ImplicitTLS_WithAuth(t *testing.T) {
	s, dataCh := newTestImplicitTLSSender(t, mockOpts{}, true)
	if err := s.sendImplicitTLS(t.Context(), "user@example.com", []byte("Subject: a\r\n\r\nb")); err != nil {
		t.Fatalf("sendImplicitTLS with auth: %v", err)
	}
	select {
	case <-dataCh:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out")
	}
}

func TestSMTP_ImplicitTLS_SendEndToEnd(t *testing.T) {
	s, dataCh := newTestImplicitTLSSender(t, mockOpts{}, false)
	if err := s.Send(context.Background(), "user@example.com", "You've been invited to Acme", "<a href=\"https://example.com/accept\">Accept</a>"); err != nil {
		t.Fatalf("Send: %v", err)
	}
	select {
	case d := <-dataCh:
		if !strings.Contains(d, "Acme") || !strings.Contains(d, "https://example.com/accept") {
			t.Errorf("subject or body missing from DATA: %q", d)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out")
	}
}

func TestSMTP_ImplicitTLS_ErrorBranches(t *testing.T) {
	tests := []struct {
		name    string
		opts    mockOpts
		wantSub string
	}{
		{"auth failed", mockOpts{failAuth: true}, "auth"},
		{"mail rejected", mockOpts{failCmd: "MAIL"}, "mail"},
		{"rcpt rejected", mockOpts{failCmd: "RCPT"}, "rcpt"},
		{"data rejected", mockOpts{failCmd: "DATA"}, "data"},
		{"close data rejected", mockOpts{failDot: true}, "close data"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withAuth := tt.opts.failAuth
			s, _ := newTestImplicitTLSSender(t, tt.opts, withAuth)
			err := s.sendImplicitTLS(t.Context(), "user@example.com", []byte("Subject: x\r\n\r\nb"))
			if err == nil {
				t.Fatalf("expected error for %s", tt.name)
			}
			if !strings.Contains(err.Error(), tt.wantSub) {
				t.Errorf("error = %q, want substring %q", err, tt.wantSub)
			}
		})
	}
}

// TestSMTP_ImplicitTLS_NewClientFailure covers the smtp.NewClient error branch:
// a server that completes the TLS handshake but never speaks SMTP causes the
// client greeting read to fail.
func TestSMTP_ImplicitTLS_NewClientFailure(t *testing.T) {
	tlsCfg, pool := generateSelfSignedTLS(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		// Force the TLS handshake, then close without an SMTP greeting.
		if tc, ok := conn.(*tls.Conn); ok {
			_ = tc.Handshake()
		}
		_ = conn.Close()
	}()

	host, port, _ := net.SplitHostPort(ln.Addr().String())
	s, _ := newSMTPSender(&SMTPConfig{Host: host, Port: port, From: "noreply@example.com"})
	s.implicit = true
	s.rootCAs = pool
	if err := s.sendImplicitTLS(t.Context(), "user@example.com", []byte("Subject: x\r\n\r\nb")); err == nil {
		t.Fatal("expected new client failure")
	}
}

// TestSMTP_Send_CancelledContextAbortsDial proves the caller's context reaches
// the dial on both transports. The listeners here would accept, so a send that
// still fails can only have failed because the context said so; before the
// dials took a context, an unreachable or silently hanging host blocked the
// caller until the OS TCP timeout with no way to abandon it.
func TestSMTP_Send_CancelledContextAbortsDial(t *testing.T) {
	starttlsSender, _ := newTestSTARTTLSSender(t, mockOpts{}, false)
	implicitSender, _ := newTestImplicitTLSSender(t, mockOpts{}, false)

	tests := []struct {
		name   string
		sender *smtpSender
	}{
		{"starttls", starttlsSender},
		{"implicit tls", implicitSender},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			err := tt.sender.Send(ctx, "user@example.com", "Subject", "<p>b</p>")
			if err == nil {
				t.Fatal("send with a cancelled context must fail")
			}
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("err = %v, want it to wrap context.Canceled", err)
			}
		})
	}
}
