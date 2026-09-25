// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// Package drive implements the Drive workspace HTTP contract. It resolves a
// bearer per request and leaves refresh, filesystem operations, and mount
// orchestration to its callers.
package drive

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	pkgotel "latere.ai/x/pkg/otel"
)

// TokenSource yields a delegated bearer for a drive call. It is invoked once per
// request so a rotated token is always current; implementations own the refresh
// policy.
type TokenSource interface {
	Token(ctx context.Context) (string, error)
}

// TokenSourceFunc adapts a function to a TokenSource.
type TokenSourceFunc func(ctx context.Context) (string, error)

// Token implements TokenSource.
func (f TokenSourceFunc) Token(ctx context.Context) (string, error) { return f(ctx) }

// Client calls drive's workspace mount API. A nil Client is NOT valid — mounts
// require a configured drive; callers gate on NewClient returning non-nil.
type Client struct {
	baseURL string
	tokens  TokenSource
	http    *http.Client
}

// NewClient returns a Client for drive's API base, the deployment's origin.
// Returns nil when baseURL is empty so a deployment without drive configured can
// detect "mounts unsupported" and reject mount requests rather than panic.
func NewClient(baseURL string, tokens TokenSource) *Client {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if baseURL == "" || tokens == nil {
		return nil
	}
	return &Client{
		baseURL: baseURL,
		tokens:  tokens,
		http:    &http.Client{Timeout: 30 * time.Second, Transport: pkgotel.Transport(nil)},
	}
}

// WithHTTPClient overrides the HTTP client (tests inject an httptest server's
// client; production may inject a mesh/mTLS transport).
func (c *Client) WithHTTPClient(h *http.Client) *Client {
	if c != nil && h != nil {
		c.http = h
	}
	return c
}

// ManifestEntry is one file in a workspace snapshot: a workspace-relative path,
// its sha256 hex checksum, and byte size. It is the sync unit both directions.
type ManifestEntry struct {
	Path     string `json:"path"`
	Checksum string `json:"checksum"`
	Size     int64  `json:"size"`
}

// Attachment is the result of attaching a workspace: the lock/lease id, its
// mode, and expiry.
type Attachment struct {
	ID          string    `json:"id"`
	WorkspaceID string    `json:"workspace_id"`
	Mode        Mode      `json:"mode"`
	ExpiresAt   time.Time `json:"expires_at"`
}

// MaterializeFile is a manifest entry plus a presigned GET URL (short-lived; the
// caller downloads the bytes directly from object storage, not through drive).
type MaterializeFile struct {
	ManifestEntry
	URL string `json:"url"`
}

// Materialization is the snapshot to write into the PVC: the workspace root and
// the per-file presigned URLs, pinned to the last completed sync.
type Materialization struct {
	Root     string            `json:"root"`
	PinnedAt string            `json:"pinned_at"`
	Files    []MaterializeFile `json:"files"`
}

// SyncResult reports what a writeback reconciled.
type SyncResult struct {
	SyncedFiles  int    `json:"synced_files"`
	DeletedFiles int    `json:"deleted_files"`
	LastSync     string `json:"last_sync"`
}

// Sentinel errors map drive's documented status codes so mount logic reacts
// precisely (spec 114): fail the create fast on writer-held, treat not-found as
// policy (agent-hidden or unauthorized — existence-hiding), re-attach on gone.
var (
	// ErrWriterHeld is the 409 on a second rw attach; see WriterHeldError for
	// the holder.
	ErrWriterHeld = errors.New("drive: workspace writer already held")
	// ErrNotFound is drive's existence-hiding 404: the workspace is unknown,
	// the caller is unauthorized, or (for a machine principal) the workspace is
	// agent-hidden. Not retryable — it is a policy outcome, not a transient miss.
	ErrNotFound = errors.New("drive: workspace not found or not accessible")
	// ErrAttachmentGone is the 410 on a released/reaped attachment: the sandbox
	// must re-attach, never continue blind.
	ErrAttachmentGone = errors.New("drive: attachment gone; re-attach")
)

// WriterHeldError carries the holder from a 409 so cella can surface exactly
// which sandbox owns the rw lock.
type WriterHeldError struct {
	HolderSandboxID string
}

func (e *WriterHeldError) Error() string {
	return fmt.Sprintf("drive: workspace writer held by sandbox %q", e.HolderSandboxID)
}

// Is lets errors.Is(err, ErrWriterHeld) match a *WriterHeldError.
func (e *WriterHeldError) Is(target error) bool { return target == ErrWriterHeld }

// ManifestIncompleteError is the 409 on sync when some declared files were never
// uploaded; Missing lists them so the caller finishes the PUTs and re-syncs.
type ManifestIncompleteError struct {
	Missing []string
}

func (e *ManifestIncompleteError) Error() string {
	return fmt.Sprintf("drive: sync manifest incomplete, %d file(s) not uploaded", len(e.Missing))
}

// APIError is any other non-2xx drive response.
type APIError struct {
	Method string
	Path   string
	Status int
	Body   string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("drive: %s %s: status %d: %s", e.Method, e.Path, e.Status, e.Body)
}

// Attach acquires an attachment on the workspace. mode is RO
// (unbounded snapshot) or RW (exclusive writer via drive's CAS lock).
// ttl bounds the lease before drive's reaper reclaims it; zero uses drive's default.
func (c *Client) Attach(ctx context.Context, workspaceID, sandboxID string, mode Mode, ttl time.Duration) (*Attachment, error) {
	body := map[string]any{"sandbox_id": sandboxID, "mode": mode}
	if ttl > 0 {
		body["ttl_seconds"] = int(ttl.Seconds())
	}
	raw, err := c.do(ctx, http.MethodPost, c.wsPath(workspaceID, "/attach"), body)
	if err != nil {
		return nil, err
	}
	defer func() { _ = raw.Body.Close() }()
	resp := newResponse(raw)
	if resp.status == http.StatusConflict {
		var held struct {
			Error  string `json:"error"`
			Holder string `json:"holder_sandbox_id"`
		}
		_ = json.Unmarshal(resp.bytes(), &held)
		return nil, &WriterHeldError{HolderSandboxID: held.Holder}
	}
	if err := resp.expect(http.StatusCreated); err != nil {
		return nil, err
	}
	var att Attachment
	if err := resp.decode(&att); err != nil {
		return nil, fmt.Errorf("drive: decode attach: %w", err)
	}
	return &att, nil
}

// Materialize returns the pinned snapshot (manifest + presigned URLs) for an
// attachment. The caller downloads each URL and writes it into the PVC.
func (c *Client) Materialize(ctx context.Context, workspaceID, attachmentID string) (*Materialization, error) {
	path := c.wsPath(workspaceID, "/materialize") + "?attachment=" + url.QueryEscape(attachmentID)
	raw, err := c.do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = raw.Body.Close() }()
	resp := newResponse(raw)
	if err := resp.expect(http.StatusOK); err != nil {
		return nil, err
	}
	var m Materialization
	if err := resp.decode(&m); err != nil {
		return nil, fmt.Errorf("drive: decode materialize: %w", err)
	}
	return &m, nil
}

// Sync writes back a full post-state manifest for a rw attachment. Changed bytes
// must already have been PUT to drive; sync reconciles rows and deletes files
// absent from the manifest. Idempotent per manifest.
func (c *Client) Sync(ctx context.Context, workspaceID, attachmentID string, files []ManifestEntry) (*SyncResult, error) {
	if files == nil {
		files = []ManifestEntry{}
	}
	body := map[string]any{"attachment_id": attachmentID, "files": files}
	raw, err := c.do(ctx, http.MethodPost, c.wsPath(workspaceID, "/sync"), body)
	if err != nil {
		return nil, err
	}
	defer func() { _ = raw.Body.Close() }()
	resp := newResponse(raw)
	if resp.status == http.StatusConflict {
		var inc struct {
			Error   string   `json:"error"`
			Missing []string `json:"missing"`
		}
		_ = json.Unmarshal(resp.bytes(), &inc)
		if inc.Error == "manifest_incomplete" {
			return nil, &ManifestIncompleteError{Missing: inc.Missing}
		}
		return nil, resp.apiError()
	}
	if err := resp.expect(http.StatusOK); err != nil {
		return nil, err
	}
	var res SyncResult
	if err := resp.decode(&res); err != nil {
		return nil, fmt.Errorf("drive: decode sync: %w", err)
	}
	return &res, nil
}

// Renew extends an attachment's lease before its TTL so a long mount keeps its
// lock. Returns the new expiry.
func (c *Client) Renew(ctx context.Context, workspaceID, attachmentID string, ttl time.Duration) (time.Time, error) {
	body := map[string]any{}
	if ttl > 0 {
		body["ttl_seconds"] = int(ttl.Seconds())
	}
	raw, err := c.do(ctx, http.MethodPost, c.wsPath(workspaceID, "/attach/"+url.PathEscape(attachmentID)+"/renew"), body)
	if err != nil {
		return time.Time{}, err
	}
	defer func() { _ = raw.Body.Close() }()
	resp := newResponse(raw)
	if err := resp.expect(http.StatusOK); err != nil {
		return time.Time{}, err
	}
	var out struct {
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := resp.decode(&out); err != nil {
		return time.Time{}, fmt.Errorf("drive: decode renew: %w", err)
	}
	return out.ExpiresAt, nil
}

// PutFile uploads one file's bytes to drive's file API, at
// /v1/files/{owner}/{root}{relPath} — the address a rw mount writes changed
// content to before declaring it in a sync. owner is "u-{id}" or "o-{id}"; root
// is the workspace root prefix ("workspaces/<slug>/", trailing slash); relPath
// is workspace-relative. size is the content length (drive requires it).
func (c *Client) PutFile(ctx context.Context, owner, root, relPath string, body io.Reader, size int64) error {
	u, err := url.Parse(c.baseURL)
	if err != nil {
		return fmt.Errorf("drive: parse base url: %w", err)
	}
	// Assign the decoded path and let url.URL escape the request URI. relPath is
	// a user-chosen filename that may contain '#', '?', or '%'; string
	// concatenation would truncate at '#'/'?' or emit an invalid escape at '%'.
	// The '/' separators between owner/root/relPath segments are preserved.
	u.Path = strings.TrimRight(u.Path, "/") + "/v1/files/" + owner + "/" + strings.TrimRight(root, "/") + "/" + relPath
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, u.String(), body)
	if err != nil {
		return err
	}
	tok, err := c.tokens.Token(ctx)
	if err != nil {
		return fmt.Errorf("drive: token: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.ContentLength = size
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode/100 != 2 {
		return &APIError{Method: http.MethodPut, Path: req.URL.Path, Status: resp.StatusCode}
	}
	return nil
}

// Release drops an attachment (rw releases clear the writer lock). Idempotent:
// drive returns 204 whether or not the attachment was already gone.
func (c *Client) Release(ctx context.Context, workspaceID, attachmentID string) error {
	raw, err := c.do(ctx, http.MethodDelete, c.wsPath(workspaceID, "/attach/"+url.PathEscape(attachmentID)), nil)
	if err != nil {
		return err
	}
	defer func() { _ = raw.Body.Close() }()
	resp := newResponse(raw)
	return resp.expect(http.StatusNoContent)
}

// Workspace is a row from drive's workspace list (GET /v1/workspaces): the
// user's durable Drive workspaces the dashboard mount picker browses. Locked is
// true when another sandbox holds the writer lock (a rw mount would fail fast).
type Workspace struct {
	ID          string  `json:"id"`
	Owner       string  `json:"owner"`
	Kind        string  `json:"kind"` // "workspace" | "repo"
	Slug        string  `json:"slug"`
	Locked      bool    `json:"locked"`
	LastSync    *string `json:"last_sync,omitempty"`
	CreatedBy   string  `json:"created_by"`
	AgentAccess string  `json:"agent_access"`
	RootPrefix  string  `json:"root_prefix"`
}

func (c *Client) wsPath(workspaceID, suffix string) string {
	return c.baseURL + "/v1/workspaces/" + url.PathEscape(workspaceID) + suffix
}

// response wraps a drive HTTP response with lazy body read + status mapping.
type response struct {
	status int
	raw    *http.Response
	body   []byte
	read   bool
}

// maxErrorBody caps the bytes read for error/409 diagnostic capture; those
// payloads are small JSON. maxDecodeBody caps a full 2xx decode: a Materialize
// or Attach manifest carries one presigned URL plus path/checksum per file, so a
// large workspace's body runs to many MiB and must not be truncated mid-JSON.
const (
	maxErrorBody  = 1 << 20
	maxDecodeBody = 256 << 20
)

// bytes reads the response body capped for error/diagnostic use.
func (r *response) bytes() []byte { return r.readCapped(maxErrorBody) }

// decode reads a full 2xx body for JSON decoding, capped generously so a
// large workspace snapshot is not truncated.
func (r *response) decode(out any) error {
	return r.decodeLimit(out, maxDecodeBody)
}

func (r *response) decodeLimit(out any, limit int64) error {
	b, err := io.ReadAll(io.LimitReader(r.raw.Body, limit+1))
	if err != nil {
		return fmt.Errorf("drive: read response: %w", err)
	}
	if int64(len(b)) > limit {
		return fmt.Errorf("drive: response exceeds %d bytes", limit)
	}
	return json.Unmarshal(b, out)
}

func (r *response) readCapped(limit int64) []byte {
	if !r.read {
		r.body, _ = io.ReadAll(io.LimitReader(r.raw.Body, limit))
		r.read = true
	}
	return r.body
}

// newResponse wraps a live HTTP response. It does not take ownership of the
// body: the caller that obtained resp closes it.
func newResponse(resp *http.Response) *response {
	return &response{status: resp.StatusCode, raw: resp}
}

// expect returns nil when the status matches, else the mapped sentinel/APIError.
func (r *response) expect(want int) error {
	if r.status == want {
		return nil
	}
	switch r.status {
	case http.StatusNotFound:
		return ErrNotFound
	case http.StatusGone:
		return ErrAttachmentGone
	default:
		return r.apiError()
	}
}

func (r *response) apiError() error {
	return &APIError{Status: r.status, Body: string(r.bytes()),
		Method: r.raw.Request.Method, Path: r.raw.Request.URL.Path}
}

// do issues an authorized request. body is JSON-encoded when non-nil. The
// live response is handed to the caller, which owns its body and must close
// it; wrap it with newResponse for status mapping and capped body reads.
func (c *Client) do(ctx context.Context, method, fullURL string, body any) (*http.Response, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, fullURL, rd)
	if err != nil {
		return nil, err
	}
	tok, err := c.tokens.Token(ctx)
	if err != nil {
		return nil, fmt.Errorf("drive: token: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return c.http.Do(req)
}
