package authkit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// ── ExchangeForAgent ─────────────────────────────────────────────────────────

func TestExchangeForAgentSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/token" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"access_token":"agent-tok-123","token_type":"Bearer"}`))
	}))
	defer srv.Close()

	// Swap client.
	orig := exchangeHTTPClient
	exchangeHTTPClient = srv.Client()
	t.Cleanup(func() { exchangeHTTPClient = orig })

	tok, err := ExchangeForAgent(context.Background(), srv.URL, "user-jwt", "agent-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok != "agent-tok-123" {
		t.Fatalf("token = %q, want agent-tok-123", tok)
	}
}

func TestExchangeForAgentNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"invalid_grant"}`))
	}))
	defer srv.Close()

	orig := exchangeHTTPClient
	exchangeHTTPClient = srv.Client()
	t.Cleanup(func() { exchangeHTTPClient = orig })

	_, err := ExchangeForAgent(context.Background(), srv.URL, "jwt", "agent")
	if err == nil {
		t.Fatal("expected error for 400")
	}
}

func TestExchangeForAgentEmptyAccessToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"token_type":"Bearer"}`))
	}))
	defer srv.Close()

	orig := exchangeHTTPClient
	exchangeHTTPClient = srv.Client()
	t.Cleanup(func() { exchangeHTTPClient = orig })

	_, err := ExchangeForAgent(context.Background(), srv.URL, "jwt", "agent")
	if err == nil {
		t.Fatal("expected error for empty access_token")
	}
}

func TestExchangeForAgentMalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{not json`))
	}))
	defer srv.Close()

	orig := exchangeHTTPClient
	exchangeHTTPClient = srv.Client()
	t.Cleanup(func() { exchangeHTTPClient = orig })

	_, err := ExchangeForAgent(context.Background(), srv.URL, "jwt", "agent")
	if err == nil {
		t.Fatal("expected error for malformed JSON")
	}
}

func TestExchangeForAgentNetworkError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	url := srv.URL
	client := srv.Client()
	srv.Close()

	orig := exchangeHTTPClient
	exchangeHTTPClient = client
	t.Cleanup(func() { exchangeHTTPClient = orig })

	_, err := ExchangeForAgent(context.Background(), url, "jwt", "agent")
	if err == nil {
		t.Fatal("expected network error")
	}
}

func TestExchangeForAgentBadURL(t *testing.T) {
	orig := exchangeHTTPClient
	exchangeHTTPClient = &http.Client{}
	t.Cleanup(func() { exchangeHTTPClient = orig })

	_, err := ExchangeForAgent(context.Background(), "://bad", "jwt", "agent")
	if err == nil {
		t.Fatal("expected error for bad URL")
	}
}

// ── RegisterAgentPrincipal ───────────────────────────────────────────────────

func TestRegisterAgentPrincipalSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/agents" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"principal_id":"agent-principal-uuid"}`))
	}))
	defer srv.Close()

	orig := exchangeHTTPClient
	exchangeHTTPClient = srv.Client()
	t.Cleanup(func() { exchangeHTTPClient = orig })

	pid, err := RegisterAgentPrincipal(context.Background(), srv.URL, "user-jwt", RegisterAgentRequest{
		OrgID:         "org-1",
		AgentType:     "assistant",
		Description:   "test agent",
		MaxScopes:     []string{"read:x"},
		DefaultScopes: []string{"read:x"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pid != "agent-principal-uuid" {
		t.Fatalf("principal_id = %q", pid)
	}
}

func TestRegisterAgentPrincipal200(t *testing.T) {
	// 200 OK (not just 201) should also succeed.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"principal_id":"pid-200"}`))
	}))
	defer srv.Close()

	orig := exchangeHTTPClient
	exchangeHTTPClient = srv.Client()
	t.Cleanup(func() { exchangeHTTPClient = orig })

	pid, err := RegisterAgentPrincipal(context.Background(), srv.URL, "jwt", RegisterAgentRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if pid != "pid-200" {
		t.Fatalf("pid = %q", pid)
	}
}

// TestExchangeTrimsTrailingSlash verifies a base URL with a trailing slash
// hits "/token" (not "//token"), so consumers need no wrapper to normalise it.
func TestExchangeTrimsTrailingSlash(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"access_token":"t"}`))
	}))
	defer srv.Close()

	orig := exchangeHTTPClient
	exchangeHTTPClient = srv.Client()
	t.Cleanup(func() { exchangeHTTPClient = orig })

	if _, err := ExchangeForAgent(context.Background(), srv.URL+"/", "jwt", "agent"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotPath != "/token" {
		t.Fatalf("path = %q, want /token (trailing slash not trimmed)", gotPath)
	}
}

// TestRegisterTrimsTrailingSlash is the same check for RegisterAgentPrincipal.
func TestRegisterTrimsTrailingSlash(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"principal_id":"p"}`))
	}))
	defer srv.Close()

	orig := exchangeHTTPClient
	exchangeHTTPClient = srv.Client()
	t.Cleanup(func() { exchangeHTTPClient = orig })

	if _, err := RegisterAgentPrincipal(context.Background(), srv.URL+"/", "jwt", RegisterAgentRequest{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotPath != "/agents" {
		t.Fatalf("path = %q, want /agents (trailing slash not trimmed)", gotPath)
	}
}

func TestRegisterAgentPrincipalNon201(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"error":"forbidden"}`))
	}))
	defer srv.Close()

	orig := exchangeHTTPClient
	exchangeHTTPClient = srv.Client()
	t.Cleanup(func() { exchangeHTTPClient = orig })

	_, err := RegisterAgentPrincipal(context.Background(), srv.URL, "jwt", RegisterAgentRequest{})
	if err == nil {
		t.Fatal("expected error for 403")
	}
}

func TestRegisterAgentPrincipalEmptyPrincipalID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"other_field":"x"}`))
	}))
	defer srv.Close()

	orig := exchangeHTTPClient
	exchangeHTTPClient = srv.Client()
	t.Cleanup(func() { exchangeHTTPClient = orig })

	_, err := RegisterAgentPrincipal(context.Background(), srv.URL, "jwt", RegisterAgentRequest{})
	if err == nil {
		t.Fatal("expected error for empty principal_id")
	}
}

func TestRegisterAgentPrincipalMalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{not json`))
	}))
	defer srv.Close()

	orig := exchangeHTTPClient
	exchangeHTTPClient = srv.Client()
	t.Cleanup(func() { exchangeHTTPClient = orig })

	_, err := RegisterAgentPrincipal(context.Background(), srv.URL, "jwt", RegisterAgentRequest{})
	if err == nil {
		t.Fatal("expected error for malformed JSON")
	}
}

func TestRegisterAgentPrincipalNetworkError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	url := srv.URL
	client := srv.Client()
	srv.Close()

	orig := exchangeHTTPClient
	exchangeHTTPClient = client
	t.Cleanup(func() { exchangeHTTPClient = orig })

	_, err := RegisterAgentPrincipal(context.Background(), url, "jwt", RegisterAgentRequest{})
	if err == nil {
		t.Fatal("expected network error")
	}
}

func TestRegisterAgentPrincipalBadURL(t *testing.T) {
	orig := exchangeHTTPClient
	exchangeHTTPClient = &http.Client{}
	t.Cleanup(func() { exchangeHTTPClient = orig })

	_, err := RegisterAgentPrincipal(context.Background(), "://bad", "jwt", RegisterAgentRequest{})
	if err == nil {
		t.Fatal("expected error for bad URL")
	}
}
