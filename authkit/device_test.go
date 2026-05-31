package authkit

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"
	"latere.ai/x/pkg/oidc"
)

// newDeviceTestClient stands up a fake auth server speaking the device
// authorization + token endpoints and returns an *oidc.Client wired to it.
// The server's behavior is steered by the response struct so tests can
// model approval, denial, error responses, etc. without orchestrating real
// HTTP plumbing.
type deviceServer struct {
	deviceAuthBody   string
	deviceAuthStatus int
	tokenBody        string
	tokenStatus      int
	hits             struct{ device, token int }
}

func newDeviceTestClient(t *testing.T, ds *deviceServer) (*oidc.Client, *httptest.Server) {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/device/code", func(w http.ResponseWriter, r *http.Request) {
		ds.hits.device++
		w.Header().Set("Content-Type", "application/json")
		if ds.deviceAuthStatus != 0 {
			w.WriteHeader(ds.deviceAuthStatus)
		}
		fmt.Fprint(w, ds.deviceAuthBody)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		ds.hits.token++
		w.Header().Set("Content-Type", "application/json")
		if ds.tokenStatus != 0 {
			w.WriteHeader(ds.tokenStatus)
		}
		fmt.Fprint(w, ds.tokenBody)
	})
	srv := httptest.NewServer(mux)

	c := oidc.New(oidc.Config{
		AuthURL:         srv.URL,
		ClientID:        "test",
		ClientSecret:    "secret",
		RedirectURL:     srv.URL + "/cb",
		CookieKey:       "00112233445566778899aabbccddeeff",
		InsecureCookies: true,
	})
	if c == nil {
		t.Fatal("oidc.New nil")
	}
	return c, srv
}

func TestDeviceCodeClient_Login_NilOIDC(t *testing.T) {
	d := NewDeviceCodeClient(nil, nil)
	if err := d.Login(context.Background()); err == nil {
		t.Fatal("expected error when OIDC nil")
	}

	var nild *DeviceCodeClient
	if err := nild.Login(context.Background()); err == nil {
		t.Fatal("expected error on nil receiver")
	}
}

func TestDeviceCodeClient_Login_DeviceAuthError(t *testing.T) {
	ds := &deviceServer{
		deviceAuthBody:   `{"error":"server_error"}`,
		deviceAuthStatus: http.StatusInternalServerError,
	}
	c, srv := newDeviceTestClient(t, ds)
	defer srv.Close()

	d := NewDeviceCodeClient(c, nil)
	d.Output = &bytes.Buffer{}
	d.OpenBrowser = func(string) error { return nil }
	if err := d.Login(context.Background()); err == nil {
		t.Fatal("expected device authorization error")
	}
}

func TestDeviceCodeClient_Login_HappyPath(t *testing.T) {
	ds := &deviceServer{
		deviceAuthBody: `{"device_code":"dc","user_code":"UC-1234","verification_uri":"https://verify.example/","verification_uri_complete":"https://verify.example/?u=UC-1234","expires_in":300,"interval":1}`,
		tokenBody:      `{"access_token":"at-x","token_type":"Bearer","refresh_token":"rt-x","expires_in":3600}`,
	}
	c, srv := newDeviceTestClient(t, ds)
	defer srv.Close()

	out := &bytes.Buffer{}
	var openedURL string
	store := &memoryStore{}

	d := NewDeviceCodeClient(c, store)
	d.Output = out
	d.OpenBrowser = func(u string) error { openedURL = u; return nil }

	if err := d.Login(context.Background()); err != nil {
		t.Fatalf("Login: %v", err)
	}
	if openedURL != "https://verify.example/?u=UC-1234" {
		t.Fatalf("OpenBrowser url = %q", openedURL)
	}
	if !strings.Contains(out.String(), "UC-1234") {
		t.Fatalf("prompt missing user code: %q", out.String())
	}
	if store.saved == nil || store.saved.AccessToken != "at-x" {
		t.Fatalf("token not persisted: %+v", store.saved)
	}
}

func TestDeviceCodeClient_Login_FallbackVerificationURI(t *testing.T) {
	// No verification_uri_complete → falls back to verification_uri.
	ds := &deviceServer{
		deviceAuthBody: `{"device_code":"dc","user_code":"UC","verification_uri":"https://verify.example/","expires_in":300,"interval":1}`,
		tokenBody:      `{"access_token":"at-x","token_type":"Bearer","expires_in":3600}`,
	}
	c, srv := newDeviceTestClient(t, ds)
	defer srv.Close()

	out := &bytes.Buffer{}
	var openedURL string
	d := NewDeviceCodeClient(c, nil)
	d.Output = out
	d.OpenBrowser = func(u string) error { openedURL = u; return nil }
	if err := d.Login(context.Background()); err != nil {
		t.Fatal(err)
	}
	if openedURL != "https://verify.example/" {
		t.Fatalf("OpenBrowser url = %q", openedURL)
	}
}

func TestDeviceCodeClient_Login_BrowserErrorIgnored(t *testing.T) {
	ds := &deviceServer{
		deviceAuthBody: `{"device_code":"dc","user_code":"UC","verification_uri":"https://verify.example/","expires_in":300,"interval":1}`,
		tokenBody:      `{"access_token":"at-x","token_type":"Bearer","expires_in":3600}`,
	}
	c, srv := newDeviceTestClient(t, ds)
	defer srv.Close()
	d := NewDeviceCodeClient(c, &memoryStore{})
	d.Output = &bytes.Buffer{}
	d.OpenBrowser = func(string) error { return errors.New("no browser") }
	if err := d.Login(context.Background()); err != nil {
		t.Fatalf("browser error must not abort login: %v", err)
	}
}

func TestDeviceCodeClient_Login_TokenError(t *testing.T) {
	ds := &deviceServer{
		deviceAuthBody: `{"device_code":"dc","user_code":"UC","verification_uri":"https://verify.example/","expires_in":300,"interval":1}`,
		tokenBody:      `{"error":"access_denied"}`,
		tokenStatus:    http.StatusForbidden,
	}
	c, srv := newDeviceTestClient(t, ds)
	defer srv.Close()
	d := NewDeviceCodeClient(c, nil)
	d.Output = &bytes.Buffer{}
	d.OpenBrowser = func(string) error { return nil }
	if err := d.Login(context.Background()); err == nil {
		t.Fatal("expected token error")
	}
}

func TestDeviceCodeClient_Login_StoreError(t *testing.T) {
	ds := &deviceServer{
		deviceAuthBody: `{"device_code":"dc","user_code":"UC","verification_uri":"https://verify.example/","expires_in":300,"interval":1}`,
		tokenBody:      `{"access_token":"at-x","token_type":"Bearer","expires_in":3600}`,
	}
	c, srv := newDeviceTestClient(t, ds)
	defer srv.Close()
	d := NewDeviceCodeClient(c, &memoryStore{saveErr: errors.New("disk full")})
	d.Output = &bytes.Buffer{}
	d.OpenBrowser = func(string) error { return nil }
	if err := d.Login(context.Background()); err == nil {
		t.Fatal("expected persist error")
	}
}

func TestDeviceCodeClient_Login_NilStoreOK(t *testing.T) {
	ds := &deviceServer{
		deviceAuthBody: `{"device_code":"dc","user_code":"UC","verification_uri":"https://verify.example/","expires_in":300,"interval":1}`,
		tokenBody:      `{"access_token":"at-x","token_type":"Bearer","expires_in":3600}`,
	}
	c, srv := newDeviceTestClient(t, ds)
	defer srv.Close()
	d := NewDeviceCodeClient(c, nil)
	d.Output = &bytes.Buffer{}
	d.OpenBrowser = func(string) error { return nil }
	if err := d.Login(context.Background()); err != nil {
		t.Fatalf("nil store should succeed: %v", err)
	}
}

func TestDeviceCodeClient_Login_DefaultOutputAndBrowser(t *testing.T) {
	// Verifies the Output==nil and OpenBrowser==nil defaults run without
	// crashing. The browser is stubbed at the exec.Command level so no
	// real process is spawned.
	old := execCommand
	t.Cleanup(func() { execCommand = old })
	execCommand = func(name string, args ...string) *exec.Cmd {
		// "true" exits 0 on every unix; on windows "cmd /c rem" would do
		// but device_test does not pretend to support windows here.
		return exec.Command("true")
	}

	ds := &deviceServer{
		deviceAuthBody: `{"device_code":"dc","user_code":"UC","verification_uri":"https://verify.example/","expires_in":300,"interval":1}`,
		tokenBody:      `{"access_token":"at-x","token_type":"Bearer","expires_in":3600}`,
	}
	c, srv := newDeviceTestClient(t, ds)
	defer srv.Close()
	d := NewDeviceCodeClient(c, nil)
	// Output left nil to exercise stderr default; OpenBrowser left nil to
	// exercise the runtime.GOOS dispatch.
	if err := d.Login(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestOpenBrowser_EmptyURL(t *testing.T) {
	if err := openBrowser(""); err == nil {
		t.Fatal("expected error for empty URL")
	}
}

// ── memoryStore: in-process TokenStore for device-flow tests ────────────────

type memoryStore struct {
	saved   *oauth2.Token
	saveErr error
}

func (m *memoryStore) Save(t *oauth2.Token) error {
	if m.saveErr != nil {
		return m.saveErr
	}
	m.saved = t
	return nil
}

func (m *memoryStore) Load() (*oauth2.Token, error)        { return m.saved, nil }
func (m *memoryStore) Clear() error                        { m.saved = nil; return nil }
func (m *memoryStore) Touched() bool                       { return m.saved != nil }
func (m *memoryStore) WithExpiry(d time.Duration) *memoryStore {
	if m.saved != nil {
		m.saved.Expiry = time.Now().Add(d)
	}
	return m
}
