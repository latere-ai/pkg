// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package egress

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"latere.ai/x/pkg/bearer"
)

// Kinds of credential a pushed map may carry, the IngestEntry.Kind values.
const (
	// IngestKindStatic is a secret held in IngestEntry.Secret. An empty Kind
	// means the same, so a body written before Kind existed decodes as it
	// always did.
	IngestKindStatic = "static"
	// IngestKindOAuthClientCredentials is a token minted on demand by
	// [OAuthClientCredentials] from IngestEntry.OAuth.
	IngestKindOAuthClientCredentials = "oauth_client_credentials"
)

// IngestEntry is one credential in a pushed map. Secret is base64 so arbitrary
// bytes survive JSON transport. Kind selects the credential kind; the fields
// that follow it are the additive ones a static entry may leave out.
type IngestEntry struct {
	Placeholder  string   `json:"placeholder"`
	Secret       string   `json:"secret"` // base64 (std); the static kind's secret
	AllowedHosts []string `json:"allowed_hosts"`

	// Kind is [IngestKindStatic] (or empty) or
	// [IngestKindOAuthClientCredentials]. Any other value rejects the body.
	Kind string `json:"kind,omitempty"`
	// SubstituteBody sets [Entry.SubstituteBody].
	SubstituteBody bool `json:"substitute_body,omitempty"`
	// OAuth is the token endpoint for the oauth_client_credentials kind and
	// must be present for it; token_url, client_id, and client_secret are
	// required.
	OAuth *IngestOAuth `json:"oauth,omitempty"`
}

// IngestOAuth is the client_credentials grant an oauth entry mints from: the
// fields of [OAuthClientCredentials] that cross the wire.
type IngestOAuth struct {
	TokenURL     string `json:"token_url"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Scope        string `json:"scope,omitempty"`
	Audience     string `json:"audience,omitempty"`
}

// IngestBody is the payload the control plane PUTs to push a principal's map.
type IngestBody struct {
	Entries []IngestEntry `json:"entries"`
}

// IngestHandler is the cluster-internal API the control plane calls to push or
// purge a principal's substitution map. Mount it at PUT/DELETE
// /internal/maps/{principal}.
//
// Token, when set, is a shared secret every request must present as
// "Authorization: Bearer <token>". This is in-process authorization: a
// same-host loopback dial (a CONNECT tunnel that reaches this listener without
// leaving the network namespace) bypasses deployment mTLS and any network
// policy, so the map API cannot rely on the mesh alone to keep one principal
// from rewriting another's map. An empty Token authorizes nothing: every
// request is rejected with 401, so a deployment that has not provisioned the
// secret fails closed instead of accepting any caller.
type IngestHandler struct {
	Registry *Registry
	Token    string
}

// Mount registers the ingest routes on mux.
func (h *IngestHandler) Mount(mux *http.ServeMux) {
	mux.HandleFunc("PUT /internal/maps/{id}", h.put)
	mux.HandleFunc("DELETE /internal/maps/{id}", h.delete)
}

// authorized reports whether r carries the shared ingest secret. Always false
// when no Token is configured: an unset secret must not open the map API.
func (h *IngestHandler) authorized(r *http.Request) bool {
	if h.Token == "" {
		return false
	}
	got, ok := bearer.FromRequest(r)
	return ok && bearer.Equal(got, h.Token)
}

func (h *IngestHandler) put(w http.ResponseWriter, r *http.Request) {
	if !h.authorized(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	id := r.PathValue("id")
	if strings.TrimSpace(id) == "" {
		http.Error(w, "missing principal id", http.StatusBadRequest)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}
	entries, err := DecodeIngestBody(body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	h.Registry.Set(id, entries)
	w.WriteHeader(http.StatusNoContent)
}

// DecodeIngestBody parses a pushed map into the entries a [Registry] stores.
// It is the wire-to-engine step [IngestHandler] runs, exported so a front door
// that receives maps over another transport can share it. A static secret
// that is not standard base64, an unknown kind, or an oauth entry missing
// token_url, client_id, or client_secret rejects the whole body with an
// error that names the entry and the field. An oauth entry gets its own
// [OAuthClientCredentials], so the token cache lives and dies with the map.
func DecodeIngestBody(body []byte) ([]Entry, error) {
	var in IngestBody
	if err := json.Unmarshal(body, &in); err != nil {
		return nil, &ingestError{"invalid json: " + err.Error()}
	}
	entries := make([]Entry, 0, len(in.Entries))
	for i, e := range in.Entries {
		out := Entry{
			Placeholder:    []byte(e.Placeholder),
			AllowedHosts:   e.AllowedHosts,
			SubstituteBody: e.SubstituteBody,
		}
		switch e.Kind {
		case "", IngestKindStatic:
			secret, err := base64.StdEncoding.DecodeString(e.Secret)
			if err != nil {
				return nil, &ingestError{"invalid base64 secret"}
			}
			out.Secret = secret
		case IngestKindOAuthClientCredentials:
			cc, err := e.OAuth.resolver()
			if err != nil {
				return nil, &ingestError{fmt.Sprintf("entry %d (%s): %v", i, e.Placeholder, err)}
			}
			out.Resolve = cc.Resolve
		default:
			return nil, &ingestError{fmt.Sprintf("entry %d (%s): unknown kind %q", i, e.Placeholder, e.Kind)}
		}
		entries = append(entries, out)
	}
	return entries, nil
}

// resolver builds the entry's OAuthClientCredentials, or says which
// required field is missing.
func (o *IngestOAuth) resolver() (*OAuthClientCredentials, error) {
	if o == nil {
		return nil, errors.New("missing oauth")
	}
	for _, f := range []struct{ name, value string }{
		{"oauth.token_url", o.TokenURL},
		{"oauth.client_id", o.ClientID},
		{"oauth.client_secret", o.ClientSecret},
	} {
		if f.value == "" {
			return nil, errors.New("missing " + f.name)
		}
	}
	return &OAuthClientCredentials{
		TokenURL:     o.TokenURL,
		ClientID:     o.ClientID,
		ClientSecret: o.ClientSecret,
		Scope:        o.Scope,
		Audience:     o.Audience,
	}, nil
}

// ingestError is a client-caused decode failure; its text is safe to return
// in a 400 body.
type ingestError struct{ msg string }

func (e *ingestError) Error() string { return e.msg }

func (h *IngestHandler) delete(w http.ResponseWriter, r *http.Request) {
	if !h.authorized(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	id := r.PathValue("id")
	h.Registry.Delete(id)
	w.WriteHeader(http.StatusNoContent)
}
