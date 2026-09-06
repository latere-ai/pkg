// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package egress

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	pkgotel "latere.ai/x/pkg/otel"
)

// Client is the control plane's client for the gateway's ingest API. It
// pushes and purges per-principal substitution maps. A nil Client is a no-op
// (the platform runs without a gateway configured), so callers need no nil
// check.
type Client struct {
	baseURL string
	http    *http.Client
	// replicasHost, when set, is the headless-service DNS name whose A records
	// are the individual gateway replica IPs. PushMapAllReplicas fans a push
	// out to each so every replica holds the map even behind a load-balanced
	// service. replicasPort is the ingest port on each replica. resolve is
	// injectable for tests; nil uses the default resolver.
	replicasHost string
	replicasPort string
	resolve      func(ctx context.Context, host string) ([]string, error)
	// ingestToken, when set, is sent as an Authorization bearer on every ingest
	// request so the gateway's in-process check (IngestHandler.Token) accepts it.
	// It closes the same-host loopback path that bypasses deployment mTLS.
	ingestToken string
}

// WithIngestToken sets the shared secret sent on every ingest request. Empty
// leaves requests unauthenticated (a deployment that has not provisioned it).
func (c *Client) WithIngestToken(token string) *Client {
	if c != nil {
		c.ingestToken = strings.TrimSpace(token)
	}
	return c
}

// WithReplicas configures per-replica push fan-out against a headless service.
// host is the headless-service DNS name, port the ingest port.
func (c *Client) WithReplicas(host, port string) *Client {
	if c != nil && host != "" {
		c.replicasHost = strings.TrimSpace(host)
		c.replicasPort = strings.TrimSpace(port)
		if c.resolve == nil {
			c.resolve = func(ctx context.Context, h string) ([]string, error) {
				return net.DefaultResolver.LookupHost(ctx, h)
			}
		}
	}
	return c
}

// PushMapAllReplicas pushes the map to EVERY gateway replica (resolved from the
// headless service) so a load-balanced request to any replica finds it. Falls
// back to the single load-balanced baseURL when no replicas host is configured
// or resolution fails. Returns an error only when every push fails. Implements
// [MapPusher].
func (c *Client) PushMapAllReplicas(ctx context.Context, principal string, entries []IngestEntry) error {
	if c == nil {
		return nil
	}
	if c.replicasHost == "" || c.resolve == nil {
		return c.PushMap(ctx, principal, entries)
	}
	ips, err := c.resolve(ctx, c.replicasHost)
	if err != nil || len(ips) == 0 {
		return c.PushMap(ctx, principal, entries) // fall back to the service
	}
	body, err := json.Marshal(IngestBody{Entries: entries})
	if err != nil {
		return err
	}
	// Reuse the load-balanced baseURL's scheme (http internally, https with the
	// mTLS transport) so per-replica pushes speak the same protocol as PushMap.
	scheme := "https"
	if i := strings.Index(c.baseURL, "://"); i > 0 {
		scheme = c.baseURL[:i]
	}
	var lastErr error
	ok := 0
	for _, ip := range ips {
		url := scheme + "://" + net.JoinHostPort(ip, c.replicasPort) + "/internal/maps/" + principal
		req, rerr := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewReader(body))
		if rerr != nil {
			lastErr = rerr
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		if derr := c.do(req); derr != nil {
			lastErr = derr
			continue
		}
		ok++
	}
	if ok == 0 && lastErr != nil {
		return lastErr
	}
	return nil
}

// PurgeMapAllReplicas drops the principal's map from EVERY gateway replica
// (resolved from the headless service) so a delete does not leave the map live
// on the N-1 replicas a single load-balanced DELETE never reaches. Falls back
// to the single load-balanced baseURL when no replicas host is configured or
// resolution fails. Best-effort: returns an error only when every purge fails.
func (c *Client) PurgeMapAllReplicas(ctx context.Context, principal string) error {
	if c == nil {
		return nil
	}
	if c.replicasHost == "" || c.resolve == nil {
		return c.PurgeMap(ctx, principal)
	}
	ips, err := c.resolve(ctx, c.replicasHost)
	if err != nil || len(ips) == 0 {
		return c.PurgeMap(ctx, principal) // fall back to the service
	}
	scheme := "https"
	if i := strings.Index(c.baseURL, "://"); i > 0 {
		scheme = c.baseURL[:i]
	}
	var lastErr error
	ok := 0
	for _, ip := range ips {
		url := scheme + "://" + net.JoinHostPort(ip, c.replicasPort) + "/internal/maps/" + principal
		req, rerr := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
		if rerr != nil {
			lastErr = rerr
			continue
		}
		if derr := c.do(req); derr != nil {
			lastErr = derr
			continue
		}
		ok++
	}
	if ok == 0 && lastErr != nil {
		return lastErr
	}
	return nil
}

// NewClient returns a Client for the gateway ingest base URL (e.g.
// https://egress.internal:9443). Returns nil when baseURL is empty so an
// unconfigured deployment degrades to no-op pushes.
func NewClient(baseURL string) *Client {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if baseURL == "" {
		return nil
	}
	return &Client{baseURL: baseURL, http: &http.Client{Timeout: 5 * time.Second, Transport: pkgotel.Transport(nil)}}
}

// WithHTTPClient overrides the HTTP client (e.g. for the internal mTLS
// transport, or a test server's client).
func (c *Client) WithHTTPClient(h *http.Client) *Client {
	if c != nil && h != nil {
		c.http = h
	}
	return c
}

// IngestEntryFor builds an ingest entry from a resolved credential, base64-
// encoding the secret for JSON transport.
func IngestEntryFor(placeholder string, secret []byte, allowedHosts []string) IngestEntry {
	return IngestEntry{
		Placeholder:  placeholder,
		Secret:       base64.StdEncoding.EncodeToString(secret),
		AllowedHosts: allowedHosts,
	}
}

// IngestOAuthEntryFor builds an ingest entry whose secret is minted on the
// gateway by the client_credentials grant: the client secret crosses the wire
// once, and the gateway holds the token cache.
func IngestOAuthEntryFor(placeholder string, oauth IngestOAuth, allowedHosts []string) IngestEntry {
	return IngestEntry{
		Placeholder:  placeholder,
		AllowedHosts: allowedHosts,
		Kind:         IngestKindOAuthClientCredentials,
		OAuth:        &oauth,
	}
}

// PushMap replaces the principal's substitution map on the gateway. A nil
// Client is a no-op.
func (c *Client) PushMap(ctx context.Context, principal string, entries []IngestEntry) error {
	if c == nil {
		return nil
	}
	body, err := json.Marshal(IngestBody{Entries: entries})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, c.mapURL(principal), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	return c.do(req)
}

// PurgeMap drops the principal's map from the gateway. A nil Client is a
// no-op.
func (c *Client) PurgeMap(ctx context.Context, principal string) error {
	if c == nil {
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.mapURL(principal), nil)
	if err != nil {
		return err
	}
	return c.do(req)
}

func (c *Client) mapURL(principal string) string {
	return c.baseURL + "/internal/maps/" + principal
}

func (c *Client) do(req *http.Request) error {
	if c.ingestToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.ingestToken)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("egress ingest %s %s: status %d", req.Method, req.URL.Path, resp.StatusCode)
	}
	return nil
}
