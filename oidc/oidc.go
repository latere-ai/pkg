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
	"context"
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
	"net/url"
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
//
// Picture and AvatarURL are aliases — auth's /userinfo emits the OIDC
// standard "picture" claim, but downstream callers historically referred
// to the URL as avatar_url. Populated together by FetchUserInfo so a
// caller can pick whichever name fits its template.
type User struct {
	Sub       string `json:"sub"`
	Email     string `json:"email"`
	Name      string `json:"name"`
	Picture   string `json:"picture"`
	OrgID     string `json:"org_id,omitempty"`     // active org for this session, "" for personal view
	AvatarURL string `json:"avatar_url,omitempty"` // alias of Picture
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

	// Audience requested on /authorize. Defaults to AuthURL when empty,
	// which is what the auth service requires for its JWT-protected
	// endpoints (/me/orgs, /userinfo, /tokeninfo). Set explicitly only
	// when the issued access token is meant for a different relying
	// party (e.g. tokens with aud="<other-service>").
	Audience string

	// Scopes requested on /authorize. When empty, defaults to
	// ["openid", "email", "profile"] — the minimum needed for the
	// /userinfo claims this package surfaces. Set explicitly to
	// request additional scopes (offline_access for refresh tokens,
	// or product-specific scopes the relying party gates on).
	Scopes []string
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
//
// ClientID + ClientSecret + RedirectURL are the trio needed for the
// browser-based authorization-code + PKCE flow. Public clients that
// only want the RFC 8628 device-code flow can leave ClientSecret and
// RedirectURL empty — DeviceAuth and DeviceAccessToken work without
// either; the cookie helpers and HandleLogin will fail loudly at use
// time if called against such a client.
func (c Config) Enabled() bool {
	if c.ClientID == "" {
		return false
	}
	if c.ClientSecret == "" && c.RedirectURL == "" {
		// Device-code-only client.
		return true
	}
	return c.ClientSecret != "" && c.RedirectURL != ""
}

// New creates a new OIDC Client. Returns nil if the config is not enabled.
func New(cfg Config) *Client {
	if !cfg.Enabled() {
		slog.Info("oidc: disabled (AUTH_CLIENT_ID, AUTH_CLIENT_SECRET, or AUTH_REDIRECT_URL not set)")
		return nil
	}

	if cfg.Audience == "" {
		cfg.Audience = cfg.AuthURL
	}
	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "email", "profile"}
	}

	c := &Client{
		cfg: cfg,
		oauthCfg: oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Endpoint: oauth2.Endpoint{
				AuthURL:       cfg.AuthURL + "/authorize",
				TokenURL:      cfg.AuthURL + "/token",
				DeviceAuthURL: cfg.AuthURL + "/device/code",
				AuthStyle:     oauth2.AuthStyleInHeader,
			},
			Scopes: scopes,
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
	return c.AuthCodeURLWithOpts(state, verifier, nil)
}

// AuthCodeURLWithOpts returns the authorize URL with additional
// extension parameters appended as-is. Use for non-standard hints the
// auth service understands — e.g. org_id to scope the resulting token
// to a specific organization, or login_hint to preselect an identity
// provider. Standard OAuth parameters (response_type, scope, state,
// code_challenge, redirect_uri) are already handled; do not pass them
// here.
//
// Each value becomes a single oauth2.SetAuthURLParam so unknown keys
// round-trip through to the auth server unchanged.
func (c *Client) AuthCodeURLWithOpts(state, verifier string, extra url.Values) string {
	opts := []oauth2.AuthCodeOption{
		oauth2.S256ChallengeOption(verifier),
	}
	// Stamp the audience on every authorize URL. Without it, fosite
	// emits aud:[] in the access token (the JWT strategy always
	// materialises the claim from the granted audience set, even when
	// empty), and the auth service's JWT validator then rejects every
	// JWT-protected endpoint as an audience mismatch.
	if c.cfg.Audience != "" {
		opts = append(opts, oauth2.SetAuthURLParam("audience", c.cfg.Audience))
	}
	for k, vs := range extra {
		// Forward every key that's present in extra, including
		// empty-string values. Callers rely on this to pass signals
		// like org_id="" which the auth service interprets as
		// "clear the active org" — silently dropping it would
		// turn the switch-to-personal UX into a no-op.
		if len(vs) == 0 {
			opts = append(opts, oauth2.SetAuthURLParam(k, ""))
			continue
		}
		for _, v := range vs {
			opts = append(opts, oauth2.SetAuthURLParam(k, v))
		}
	}
	return c.oauthCfg.AuthCodeURL(state, opts...)
}

// Exchange trades an authorization code for tokens using the PKCE verifier.
func (c *Client) Exchange(r *http.Request, code, verifier string) (*oauth2.Token, error) {
	return c.ExchangeContext(r.Context(), code, verifier)
}

// ExchangeContext is the context-only form of Exchange. Prefer this in
// non-HTTP-handler contexts (background workers, internal auth bridges)
// where threading a *http.Request just to pass its Context is awkward.
func (c *Client) ExchangeContext(ctx context.Context, code, verifier string) (*oauth2.Token, error) {
	return c.oauthCfg.Exchange(ctx, code,
		oauth2.VerifierOption(verifier),
	)
}

// FetchUserInfo calls the auth service /userinfo endpoint.
//
// Auth emits the OIDC-standard "picture" claim; mirror it onto
// User.AvatarURL so callers that key off avatar_url don't have to
// reach for the Picture field.
func (c *Client) FetchUserInfo(r *http.Request, accessToken string) (*User, error) {
	return c.FetchUserInfoContext(r.Context(), accessToken)
}

// FetchUserInfoContext is the context-only form of FetchUserInfo.
// Same response handling; pick this when threading r is awkward.
func (c *Client) FetchUserInfoContext(ctx context.Context, accessToken string) (*User, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", c.cfg.AuthURL+"/userinfo", nil)
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
	if u.AvatarURL == "" {
		u.AvatarURL = u.Picture
	}
	return &u, nil
}

// DeviceAuth initiates an RFC 8628 device authorization flow against
// the configured AuthURL. The caller renders the returned UserCode +
// VerificationURI to the user, then calls DeviceAccessToken to poll
// for approval. extra carries auth-server extension parameters
// (auth.latere.ai honours `org_id` to scope the resulting token).
//
// Use this for headless / CLI flows. Browser-based clients should
// use HandleLogin instead.
func (c *Client) DeviceAuth(ctx context.Context, extra url.Values) (*oauth2.DeviceAuthResponse, error) {
	var opts []oauth2.AuthCodeOption
	for k, vs := range extra {
		if len(vs) == 0 {
			opts = append(opts, oauth2.SetAuthURLParam(k, ""))
			continue
		}
		for _, v := range vs {
			opts = append(opts, oauth2.SetAuthURLParam(k, v))
		}
	}
	return c.oauthCfg.DeviceAuth(ctx, opts...)
}

// DeviceAccessToken polls the token endpoint with the device-code
// grant until the user approves, denies, or the code expires. RFC
// 8628 slow_down / authorization_pending semantics are honoured by
// the underlying oauth2 client.
func (c *Client) DeviceAccessToken(ctx context.Context, da *oauth2.DeviceAuthResponse) (*oauth2.Token, error) {
	return c.oauthCfg.DeviceAccessToken(ctx, da)
}

// RefreshToken uses a refresh token to obtain a new access token.
func (c *Client) RefreshToken(r *http.Request, refreshToken string) (*oauth2.Token, error) {
	return c.RefreshTokenContext(r.Context(), refreshToken)
}

// RefreshTokenContext is the context-only form of RefreshToken.
// Same flow; pick this when threading r is awkward.
func (c *Client) RefreshTokenContext(ctx context.Context, refreshToken string) (*oauth2.Token, error) {
	ts := c.oauthCfg.TokenSource(ctx, &oauth2.Token{
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
