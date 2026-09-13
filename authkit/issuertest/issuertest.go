// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// Package issuertest is the family's stub issuer for tests: a discovery
// document, a JWKS, and a control API that mints any token, so a test
// produces the token for each row of a service's verification table by
// setting one field wrong. It also serves POST /actor-tokens, the one hop
// of latere-ai/specs infrastructure/identity/id-03-one-hop.md, so a
// consumer's end-to-end tier can mint for a product the way the issuer
// does. It serves plain HTTP on a loopback address.
//
// The stub began as Origo's test/stubs/issuer and moved here with id-04 so
// that the conformance suite (authkit/conformance) and every repository's
// tests share one issuer.
package issuertest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"maps"
	"math/big"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// Claims is what a test asks the stub to sign. Every field is optional:
// an empty Sub becomes DefaultSubject, an empty Aud the server's default
// audience, a zero Exp one DefaultLifetime from now, and Kid and Alg the
// current key's. Omit names claims to leave out after the defaults are
// applied, so a test can mint a token with no sub or no aud at all.
// Extra carries claims this struct does not name, verbatim.
type Claims struct {
	Sub           string         `json:"sub,omitempty"`
	Aud           StringList     `json:"aud,omitempty"`
	Exp           int64          `json:"exp,omitempty"`
	Nbf           int64          `json:"nbf,omitempty"`
	Iat           int64          `json:"iat,omitempty"`
	Kid           string         `json:"kid,omitempty"`
	Alg           string         `json:"alg,omitempty"`
	OrgID         string         `json:"org_id,omitempty"`
	Roles         []string       `json:"roles,omitempty"`
	PrincipalType string         `json:"principal_type,omitempty"`
	Email         string         `json:"email,omitempty"`
	ClientID      string         `json:"client_id,omitempty"`
	Extra         map[string]any `json:"extra,omitempty"`
	Omit          []string       `json:"omit,omitempty"`
}

// StringList decodes a JSON string or array of strings, the two shapes
// RFC 7519 allows for aud.
type StringList []string

// UnmarshalJSON accepts "a" and ["a", "b"].
func (s *StringList) UnmarshalJSON(b []byte) error {
	var one string
	if err := json.Unmarshal(b, &one); err == nil {
		*s = StringList{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return err
	}
	*s = many
	return nil
}

// Defaults a minted token falls back to.
const (
	DefaultSubject  = "dev"
	DefaultLifetime = time.Hour
	// ActorTokenLifetime caps what POST /actor-tokens grants, as the issuer
	// does: at most 300 seconds.
	ActorTokenLifetime = 300 * time.Second
)

// Option configures a Server.
type Option func(*Server)

// WithIssuer sets the iss the stub signs with and reports in discovery. The
// default is the httptest server's own URL, which is right for a test in
// one process; a stub serving other containers names the URL they reach.
func WithIssuer(url string) Option {
	return func(s *Server) { s.issuer = strings.TrimRight(url, "/") }
}

// WithKey signs with the given P-256 key, ES256, instead of a generated one.
func WithKey(key *ecdsa.PrivateKey) Option {
	return func(s *Server) { s.keys = []signingKey{newECKey(key)} }
}

// WithES256 generates P-256 keys and signs with ES256 instead of the
// family's RS256, for a verifier that accepts both.
func WithES256() Option {
	return func(s *Server) { s.es256 = true }
}

// WithRS256 signs with RSA keys, the default; it undoes an earlier WithES256
// so a wrapper that defaults to ES256 can be asked for RS256.
func WithRS256() Option {
	return func(s *Server) { s.es256 = false }
}

// WithClock replaces time.Now for iat and exp defaults.
func WithClock(now func() time.Time) Option {
	return func(s *Server) { s.now = now }
}

// WithDefaultAudience sets the aud a minted token carries when Claims
// names none. Without it a token with no Aud has no aud claim.
func WithDefaultAudience(aud string) Option {
	return func(s *Server) { s.defaultAud = aud }
}

// Server is the stub issuer.
type Server struct {
	mu         sync.Mutex
	issuer     string
	defaultAud string
	keys       []signingKey
	es256      bool
	now        func() time.Time
	hung       chan struct{}
	closed     chan struct{}
	requests   []string
	srv        *httptest.Server
	mux        *http.ServeMux
}

type signingKey struct {
	kid string
	alg string
	ec  *ecdsa.PrivateKey
	rsa *rsa.PrivateKey
}

// New starts a stub on a loopback listener and closes it when the test
// ends.
func New(t testing.TB, opts ...Option) *Server {
	t.Helper()
	s := NewHandler(opts...)
	s.srv = httptest.NewServer(s.Handler())
	if s.issuer == "" {
		s.issuer = s.srv.URL
	}
	t.Cleanup(s.Close)
	return s
}

// NewHandler builds a stub without a listener, for a binary that mounts
// Handler on its own address. WithIssuer is required then.
func NewHandler(opts ...Option) *Server {
	s := &Server{now: time.Now, closed: make(chan struct{}), mux: http.NewServeMux()}
	for _, o := range opts {
		o(s)
	}
	if len(s.keys) == 0 {
		s.keys = []signingKey{s.generate()}
	}
	s.mux.HandleFunc("GET /.well-known/openid-configuration", s.discovery)
	s.mux.HandleFunc("GET /jwks", s.jwks)
	s.mux.HandleFunc("POST /mint", s.mint)
	s.mux.HandleFunc("POST /actor-tokens", s.actorTokens)
	s.mux.HandleFunc("POST /rotate", func(w http.ResponseWriter, _ *http.Request) { s.Rotate(); w.WriteHeader(http.StatusNoContent) })
	s.mux.HandleFunc("POST /hang", func(w http.ResponseWriter, _ *http.Request) { s.Hang(); w.WriteHeader(http.StatusNoContent) })
	s.mux.HandleFunc("POST /resume", func(w http.ResponseWriter, _ *http.Request) { s.Resume(); w.WriteHeader(http.StatusNoContent) })
	return s
}

// Handler is the stub's routes, recording every request it serves.
func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.requests = append(s.requests, r.Method+" "+r.URL.Path)
		s.mu.Unlock()
		s.mux.ServeHTTP(w, r)
	})
}

// Requests lists every request the stub has served since the last
// ResetRequests, as "METHOD /path". A conformance check reads it to prove
// a service called nothing but the key set during a request.
func (s *Server) Requests() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.requests)
}

// ResetRequests forgets the recorded requests.
func (s *Server) ResetRequests() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests = nil
}

// Close stops the listener and releases any hung request.
func (s *Server) Close() {
	s.mu.Lock()
	select {
	case <-s.closed:
	default:
		close(s.closed)
	}
	s.mu.Unlock()
	if s.srv != nil {
		s.srv.Close()
	}
}

// URL is the issuer: the iss claim and the discovery base.
func (s *Server) URL() string { return s.issuer }

// JWKSURL is where the public keys are served.
func (s *Server) JWKSURL() string { return s.issuer + "/jwks" }

// KID is the current signing key's id.
func (s *Server) KID() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.keys[len(s.keys)-1].kid
}

// Rotate adds a key and drops the oldest, so a token signed before the
// rotation no longer verifies against the served set.
func (s *Server) Rotate() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys = append(s.keys, s.generate())
	s.keys = s.keys[1:]
}

// Hang makes discovery and the JWKS block until Resume or Close, for a
// verifier's unavailable-issuer case.
func (s *Server) Hang() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.hung == nil {
		s.hung = make(chan struct{})
	}
}

// Resume releases Hang.
func (s *Server) Resume() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.hung != nil {
		close(s.hung)
		s.hung = nil
	}
}

// Mint signs a token with the current key, applying the defaults Claims
// documents and then removing the names in Omit.
func (s *Server) Mint(c Claims) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	key := s.keys[len(s.keys)-1]
	if c.Sub == "" {
		c.Sub = DefaultSubject
	}
	if len(c.Aud) == 0 && s.defaultAud != "" {
		c.Aud = StringList{s.defaultAud}
	}
	if c.Iat == 0 {
		c.Iat = now.Unix()
	}
	if c.Exp == 0 {
		c.Exp = now.Add(DefaultLifetime).Unix()
	}
	if c.Kid == "" {
		c.Kid = key.kid
	}
	if c.Alg == "" {
		c.Alg = key.alg
	}
	claims := map[string]any{"iss": s.issuer, "sub": c.Sub, "exp": c.Exp, "iat": c.Iat}
	if len(c.Aud) > 0 {
		claims["aud"] = []string(c.Aud)
	}
	if c.Nbf != 0 {
		claims["nbf"] = c.Nbf
	}
	for k, v := range map[string]any{
		"org_id": c.OrgID, "principal_type": c.PrincipalType, "email": c.Email, "client_id": c.ClientID,
	} {
		if v != "" {
			claims[k] = v
		}
	}
	if len(c.Roles) > 0 {
		claims["roles"] = c.Roles
	}
	maps.Copy(claims, c.Extra)
	for _, k := range c.Omit {
		delete(claims, k)
	}
	header, err := json.Marshal(map[string]string{"alg": c.Alg, "kid": c.Kid, "typ": "JWT"})
	if err != nil {
		panic(err)
	}
	body, err := json.Marshal(claims)
	if err != nil {
		panic(err)
	}
	signing := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(body)
	return signing + "." + base64.RawURLEncoding.EncodeToString(key.sign([]byte(signing)))
}

func (s *Server) wait(w http.ResponseWriter) bool {
	s.mu.Lock()
	hung := s.hung
	s.mu.Unlock()
	if hung == nil {
		return true
	}
	select {
	case <-hung:
		return true
	case <-s.closed:
		w.WriteHeader(http.StatusServiceUnavailable)
		return false
	}
}

func (s *Server) discovery(w http.ResponseWriter, _ *http.Request) {
	if !s.wait(w) {
		return
	}
	writeJSON(w, map[string]any{
		"issuer": s.issuer, "jwks_uri": s.JWKSURL(),
		"response_types_supported": []string{"id_token"}, "subject_types_supported": []string{"public"},
		"id_token_signing_alg_values_supported": []string{"ES256", "RS256"},
	})
}

func (s *Server) jwks(w http.ResponseWriter, _ *http.Request) {
	if !s.wait(w) {
		return
	}
	s.mu.Lock()
	keys := make([]map[string]string, 0, len(s.keys))
	for _, k := range s.keys {
		keys = append(keys, k.jwk())
	}
	s.mu.Unlock()
	writeJSON(w, map[string]any{"keys": keys})
}

func (s *Server) mint(w http.ResponseWriter, r *http.Request) {
	var c Claims
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&c); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]string{"token": s.Mint(c)})
}

// actorTokens is the issuer's POST /actor-tokens: a bearer this stub
// minted and {"audience", "ttl_seconds"} answer a token for that one
// audience carrying the bearer's identity and membership, as the issuer's
// does. The stub does not hold a client registry, so it mints for any
// audience; the registry gate is the issuer's own test.
func (s *Server) actorTokens(w http.ResponseWriter, r *http.Request) {
	bearer, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || bearer == "" {
		http.Error(w, `{"error":"unauthorized","message":"a bearer is required"}`, http.StatusUnauthorized)
		return
	}
	parent, ok := payloadOf(bearer)
	if !ok || parent.Sub == "" {
		http.Error(w, `{"error":"unauthorized","message":"the bearer is not a token"}`, http.StatusUnauthorized)
		return
	}
	var body struct {
		Audience string `json:"audience"`
		TTL      int64  `json:"ttl_seconds"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&body); err != nil {
		http.Error(w, `{"error":"bad_request","message":"invalid json"}`, http.StatusBadRequest)
		return
	}
	if body.Audience == "" {
		http.Error(w, `{"error":"bad_request","message":"audience is required"}`, http.StatusBadRequest)
		return
	}
	ttl := time.Duration(body.TTL) * time.Second
	if ttl <= 0 || ttl > ActorTokenLifetime {
		ttl = ActorTokenLifetime
	}
	s.mu.Lock()
	now := s.now()
	s.mu.Unlock()
	token := s.Mint(Claims{
		Sub: parent.Sub, Aud: StringList{body.Audience}, Iat: now.Unix(), Exp: now.Add(ttl).Unix(),
		OrgID: parent.OrgID, Roles: parent.Roles, PrincipalType: parent.PrincipalType, Email: parent.Email,
	})
	writeJSON(w, map[string]any{"actor_token": token, "token_type": "Bearer", "expires_in": int64(ttl / time.Second)})
}

type payload struct {
	Sub           string   `json:"sub"`
	OrgID         string   `json:"org_id"`
	Roles         []string `json:"roles"`
	PrincipalType string   `json:"principal_type"`
	Email         string   `json:"email"`
}

func payloadOf(token string) (payload, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return payload{}, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return payload{}, false
	}
	var p payload
	if json.Unmarshal(raw, &p) != nil {
		return payload{}, false
	}
	return p, true
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// generate makes the next signing key: RS256, the algorithm the family's
// issuer signs with and its verifier accepts, unless WithES256 was set.
func (s *Server) generate() signingKey {
	if s.es256 {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			panic(err)
		}
		return newECKey(key)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return signingKey{kid: kid(&key.PublicKey), alg: "RS256", rsa: key}
}

func newECKey(key *ecdsa.PrivateKey) signingKey {
	return signingKey{kid: kid(&key.PublicKey), alg: "ES256", ec: key}
}

// kid is the first 16 hex characters of the SHA-256 of the public key's
// DER encoding, the convention Origo's spec 007 set.
func kid(pub any) string {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		panic(err)
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])[:16]
}

func (k signingKey) sign(msg []byte) []byte {
	digest := sha256.Sum256(msg)
	if k.rsa != nil {
		sig, err := rsa.SignPKCS1v15(rand.Reader, k.rsa, crypto.SHA256, digest[:])
		if err != nil {
			panic(err)
		}
		return sig
	}
	r, sv, err := ecdsa.Sign(rand.Reader, k.ec, digest[:])
	if err != nil {
		panic(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	sv.FillBytes(sig[32:])
	return sig
}

func (k signingKey) jwk() map[string]string {
	if k.rsa != nil {
		return map[string]string{
			"kty": "RSA", "kid": k.kid, "alg": "RS256", "use": "sig",
			"n": base64.RawURLEncoding.EncodeToString(k.rsa.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.rsa.E)).Bytes()),
		}
	}
	x := make([]byte, 32)
	y := make([]byte, 32)
	k.ec.X.FillBytes(x)
	k.ec.Y.FillBytes(y)
	return map[string]string{
		"kty": "EC", "kid": k.kid, "alg": "ES256", "use": "sig", "crv": "P-256",
		"x": base64.RawURLEncoding.EncodeToString(x), "y": base64.RawURLEncoding.EncodeToString(y),
	}
}
