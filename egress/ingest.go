// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package egress

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"latere.ai/x/pkg/bearer"
)

// IngestEntry is one credential in a pushed map. Secret is base64 so arbitrary
// bytes survive JSON transport.
type IngestEntry struct {
	Placeholder  string   `json:"placeholder"`
	Secret       string   `json:"secret"` // base64 (std)
	AllowedHosts []string `json:"allowed_hosts"`
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
// from rewriting another's map. An empty Token disables the check (a
// deployment that has not yet provisioned the secret), so provisioning it is
// what activates the boundary.
type IngestHandler struct {
	Registry *Registry
	Token    string
}

// Mount registers the ingest routes on mux.
func (h *IngestHandler) Mount(mux *http.ServeMux) {
	mux.HandleFunc("PUT /internal/maps/{id}", h.put)
	mux.HandleFunc("DELETE /internal/maps/{id}", h.delete)
}

// authorized reports whether r carries the shared ingest secret. Always true when
// no Token is configured.
func (h *IngestHandler) authorized(r *http.Request) bool {
	if h.Token == "" {
		return true
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
// that receives maps over another transport can share it. A secret that is
// not standard base64 rejects the whole body.
func DecodeIngestBody(body []byte) ([]Entry, error) {
	var in IngestBody
	if err := json.Unmarshal(body, &in); err != nil {
		return nil, &ingestError{"invalid json: " + err.Error()}
	}
	entries := make([]Entry, 0, len(in.Entries))
	for _, e := range in.Entries {
		secret, err := base64.StdEncoding.DecodeString(e.Secret)
		if err != nil {
			return nil, &ingestError{"invalid base64 secret"}
		}
		entries = append(entries, Entry{
			Placeholder:  []byte(e.Placeholder),
			Secret:       secret,
			AllowedHosts: e.AllowedHosts,
		})
	}
	return entries, nil
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
