// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package drive

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
)

// ListOptions selects a workspace page. Empty Kind includes all kinds; Scope
// defaults to the caller's own spaces, while "all" includes grant-reachable
// workspaces. Cursor is opaque. Zero Limit uses the server default.
type ListOptions struct {
	Kind   string
	Scope  string
	Cursor string
	Limit  int
}

// WorkspacePage is Drive's list envelope. An empty NextCursor ends pagination.
type WorkspacePage struct {
	Entries    []Workspace `json:"entries"`
	NextCursor string      `json:"next_cursor,omitempty"`
}

// CreateWorkspace creates an owner/kind/slug entry. A duplicate slug returns
// an APIError with status 409; selecting an existing workspace belongs to the
// caller because the list endpoint does not filter by owner.
func (c *Client) CreateWorkspace(ctx context.Context, owner, kind, slug string) (*Workspace, error) {
	raw, err := c.do(ctx, http.MethodPost, c.baseURL+"/v1/workspaces", map[string]string{"owner": owner, "kind": kind, "slug": slug})
	if err != nil {
		return nil, err
	}
	defer raw.Body.Close() //nolint:errcheck
	resp := newResponse(raw)
	if err := resp.expect(http.StatusCreated); err != nil {
		return nil, err
	}
	var workspace Workspace
	if err := resp.decode(&workspace); err != nil {
		return nil, fmt.Errorf("drive: decode create workspace: %w", err)
	}
	return &workspace, nil
}

// GetWorkspace returns one authorized workspace, including its canonical owner.
func (c *Client) GetWorkspace(ctx context.Context, id string) (*Workspace, error) {
	raw, err := c.do(ctx, http.MethodGet, c.wsPath(id, ""), nil)
	if err != nil {
		return nil, err
	}
	defer raw.Body.Close() //nolint:errcheck
	resp := newResponse(raw)
	if err := resp.expect(http.StatusOK); err != nil {
		return nil, err
	}
	var workspace Workspace
	if err := resp.decode(&workspace); err != nil {
		return nil, fmt.Errorf("drive: decode workspace: %w", err)
	}
	return &workspace, nil
}

// ListWorkspacesPage reads one page and preserves the server's opaque cursor.
func (c *Client) ListWorkspacesPage(ctx context.Context, opts ListOptions) (*WorkspacePage, error) {
	query := url.Values{}
	for key, value := range map[string]string{"kind": opts.Kind, "scope": opts.Scope, "cursor": opts.Cursor} {
		if value != "" {
			query.Set(key, value)
		}
	}
	if opts.Limit != 0 {
		query.Set("limit", strconv.Itoa(opts.Limit))
	}
	u := c.baseURL + "/v1/workspaces"
	if len(query) != 0 {
		u += "?" + query.Encode()
	}
	raw, err := c.do(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	defer raw.Body.Close() //nolint:errcheck
	resp := newResponse(raw)
	if err := resp.expect(http.StatusOK); err != nil {
		return nil, err
	}
	var page WorkspacePage
	if err := resp.decode(&page); err != nil {
		return nil, fmt.Errorf("drive: decode workspaces: %w", err)
	}
	return &page, nil
}

// ListWorkspaces follows all pages starting at opts.Cursor, preserving filters.
// A failed page or cyclic cursor returns an error and no partial result.
func (c *Client) ListWorkspaces(ctx context.Context, opts ListOptions) ([]Workspace, error) {
	var entries []Workspace
	seen := map[string]bool{opts.Cursor: true}
	for {
		page, err := c.ListWorkspacesPage(ctx, opts)
		if err != nil {
			return nil, err
		}
		entries = append(entries, page.Entries...)
		if page.NextCursor == "" {
			return entries, nil
		}
		if seen[page.NextCursor] {
			return nil, fmt.Errorf("drive: repeated workspace cursor %q", page.NextCursor)
		}
		seen[page.NextCursor] = true
		opts.Cursor = page.NextCursor
	}
}
