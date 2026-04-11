// Package oidc provides an OAuth 2.0 / OIDC Relying Party client for
// integrating latere-ai services with the auth service. It handles
// Authorization Code + PKCE flows, encrypted cookie-based sessions,
// token refresh, and userinfo fetching.
//
// Usage:
//
//	cfg := oidc.LoadConfig()
//	client := oidc.New(cfg)
//	if client == nil {
//	    // auth not configured, run without login
//	}
package oidc

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"time"

	"golang.org/x/oauth2"
)

const (
	SessionCookieName = "__Host-latere-session"
	FlowCookieName    = "__Host-latere-flow"
	SessionMaxAge     = 86400 // 24 hours
	FlowMaxAge        = 600   // 10 minutes
)

// User holds authenticated user info from the /userinfo endpoint.
type User struct {
	Sub     string `json:"sub"`
	Email   string `json:"email"`
	Name    string `json:"name"`
	Picture string `json:"picture"`
}

// Session holds tokens and user info stored in the encrypted session cookie.
type Session struct {
	AccessToken  string    `json:"at"`
	RefreshToken string    `json:"rt"`
	Expiry       time.Time `json:"exp"`
	User         User      `json:"u"`
}

// FlowState holds PKCE and state params during the OAuth authorization flow.
type FlowState struct {
	CodeVerifier string `json:"cv"`
	State        string `json:"st"`
	ReturnTo     string `json:"rt"`
}

// Config holds auth integration configuration.
type Config struct {
	AuthURL      string // base URL of the auth service, e.g. https://auth.latere.ai
	ClientID     string
	ClientSecret string
	RedirectURL  string // callback URL, e.g. https://app.latere.ai/callback
	CookieKey    string // encryption key for cookies (hex or raw string)
}

// Client is the OIDC Relying Party for a latere-ai service.
type Client struct {
	cfg       Config
	oauthCfg  oauth2.Config
	cookieKey [32]byte
}

// LoadConfig reads auth configuration from environment variables.
func LoadConfig() Config {
	return Config{
		AuthURL:      getenv("AUTH_URL", "https://auth.latere.ai"),
		ClientID:     os.Getenv("AUTH_CLIENT_ID"),
		ClientSecret: os.Getenv("AUTH_CLIENT_SECRET"),
		RedirectURL:  os.Getenv("AUTH_REDIRECT_URL"),
		CookieKey:    os.Getenv("AUTH_COOKIE_KEY"),
	}
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// Enabled returns true if the required configuration is present.
func (c Config) Enabled() bool {
	return c.ClientID != "" && c.ClientSecret != "" && c.RedirectURL != ""
}

// New creates a new OIDC Client. Returns nil if the config is not enabled.
func New(cfg Config) *Client {
	if !cfg.Enabled() {
		slog.Info("oidc: disabled (AUTH_CLIENT_ID, AUTH_CLIENT_SECRET, or AUTH_REDIRECT_URL not set)")
		return nil
	}

	c := &Client{
		cfg: cfg,
		oauthCfg: oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Endpoint: oauth2.Endpoint{
				AuthURL:   cfg.AuthURL + "/authorize",
				TokenURL:  cfg.AuthURL + "/token",
				AuthStyle: oauth2.AuthStyleInHeader,
			},
			Scopes: []string{"openid", "email", "profile"},
		},
	}

	if cfg.CookieKey != "" {
		if key, err := hex.DecodeString(cfg.CookieKey); err == nil && len(key) >= 16 {
			c.cookieKey = sha256.Sum256(key)
		} else {
			c.cookieKey = sha256.Sum256([]byte(cfg.CookieKey))
		}
	} else {
		slog.Warn("oidc: AUTH_COOKIE_KEY not set, falling back to client secret — set AUTH_COOKIE_KEY for production")
		c.cookieKey = sha256.Sum256([]byte(cfg.ClientSecret))
	}

	slog.Info("oidc: enabled", "auth_url", cfg.AuthURL, "client_id", cfg.ClientID)
	return c
}

// AuthURL returns the auth service base URL.
func (c *Client) AuthURL() string {
	return c.cfg.AuthURL
}

// --- PKCE and state ---

// randReader is the entropy source. Package-level variable for testability.
var randReader io.Reader = rand.Reader

// GenerateVerifier creates a PKCE code verifier.
// Uses the oauth2 package's built-in generator for correct formatting.
func GenerateVerifier() string {
	return oauth2.GenerateVerifier()
}

// GenerateState creates a random state parameter for CSRF protection.
func GenerateState() (string, error) {
	buf := make([]byte, 16)
	if _, err := io.ReadFull(randReader, buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// --- OAuth2 operations ---

// AuthCodeURL returns the URL to redirect the user to for authorization.
// The verifier is used to derive the S256 challenge automatically.
func (c *Client) AuthCodeURL(state, verifier string) string {
	return c.oauthCfg.AuthCodeURL(state,
		oauth2.S256ChallengeOption(verifier),
	)
}

// Exchange trades an authorization code for tokens using the PKCE verifier.
func (c *Client) Exchange(r *http.Request, code, verifier string) (*oauth2.Token, error) {
	return c.oauthCfg.Exchange(r.Context(), code,
		oauth2.VerifierOption(verifier),
	)
}

// FetchUserInfo calls the auth service /userinfo endpoint.
func (c *Client) FetchUserInfo(r *http.Request, accessToken string) (*User, error) {
	req, err := http.NewRequestWithContext(r.Context(), "GET", c.cfg.AuthURL+"/userinfo", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := httpDo(req)
	if err != nil {
		return nil, fmt.Errorf("userinfo request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("userinfo returned %d", resp.StatusCode)
	}

	var u User
	if err := json.NewDecoder(resp.Body).Decode(&u); err != nil {
		return nil, fmt.Errorf("decode userinfo: %w", err)
	}
	return &u, nil
}

// RefreshToken uses a refresh token to obtain a new access token.
func (c *Client) RefreshToken(r *http.Request, refreshToken string) (*oauth2.Token, error) {
	ts := c.oauthCfg.TokenSource(r.Context(), &oauth2.Token{
		RefreshToken: refreshToken,
	})
	return ts.Token()
}

// httpDo is a package-level variable for testability.
var httpDo = func(req *http.Request) (*http.Response, error) {
	return http.DefaultClient.Do(req)
}

// --- Cookie helpers ---

// SetFlowState encrypts and writes the flow cookie.
func (c *Client) SetFlowState(w http.ResponseWriter, state *FlowState) error {
	return c.setCookie(w, FlowCookieName, state, FlowMaxAge)
}

// GetFlowState reads and decrypts the flow cookie.
func (c *Client) GetFlowState(r *http.Request) (*FlowState, error) {
	var state FlowState
	if err := c.getCookie(r, FlowCookieName, &state); err != nil {
		return nil, err
	}
	return &state, nil
}

// ClearFlowState expires the flow cookie.
func ClearFlowState(w http.ResponseWriter) {
	clearCookie(w, FlowCookieName)
}

// SetSession encrypts and writes the session cookie.
func (c *Client) SetSession(w http.ResponseWriter, sess *Session) error {
	return c.setCookie(w, SessionCookieName, sess, SessionMaxAge)
}

// GetSession reads and decrypts the session cookie.
func (c *Client) GetSession(r *http.Request) (*Session, error) {
	var sess Session
	if err := c.getCookie(r, SessionCookieName, &sess); err != nil {
		return nil, err
	}
	return &sess, nil
}

// ClearSession expires the session cookie.
func ClearSession(w http.ResponseWriter) {
	clearCookie(w, SessionCookieName)
}

func (c *Client) setCookie(w http.ResponseWriter, name string, v any, maxAge int) error {
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("marshal cookie %s: %w", name, err)
	}

	ciphertext, err := aesGCMEncrypt(c.cookieKey[:], data)
	if err != nil {
		return fmt.Errorf("encrypt cookie %s: %w", name, err)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    base64.RawURLEncoding.EncodeToString(ciphertext),
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	return nil
}

func (c *Client) getCookie(r *http.Request, name string, v any) error {
	cookie, err := r.Cookie(name)
	if err != nil {
		if errors.Is(err, http.ErrNoCookie) {
			return fmt.Errorf("cookie %s not found", name)
		}
		return fmt.Errorf("read cookie %s: %w", name, err)
	}

	ciphertext, err := base64.RawURLEncoding.DecodeString(cookie.Value)
	if err != nil {
		return fmt.Errorf("decode cookie %s: %w", name, err)
	}

	plaintext, err := aesGCMDecrypt(c.cookieKey[:], ciphertext)
	if err != nil {
		return fmt.Errorf("decrypt cookie %s: %w", name, err)
	}

	return json.Unmarshal(plaintext, v)
}

func clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

// --- AES-GCM (same pattern as auth service) ---

// Package-level function variables for testability (see otel package).
var aesGCMEncrypt = defaultAESGCMEncrypt

func defaultAESGCMEncrypt(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(randReader, nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func aesGCMDecrypt(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ct := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, ct, nil)
}
