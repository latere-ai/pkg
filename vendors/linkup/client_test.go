// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package linkup

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

// testKey is the API key every test client carries.
const testKey = "lk-test-0123456789abcdef"

// recorder is a test server that records each request it is sent and
// answers with the status, headers and body set on it.
type recorder struct {
	mu      sync.Mutex
	method  string
	path    string
	header  http.Header
	body    []byte
	calls   int
	status  int
	headers map[string]string
	answer  string
}

func (rec *recorder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	raw, err := io.ReadAll(r.Body)
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	rec.method, rec.path, rec.header, rec.body = r.Method, r.URL.Path, r.Header.Clone(), raw
	rec.calls++
	for k, v := range rec.headers {
		w.Header().Set(k, v)
	}
	status := rec.status
	if status == 0 {
		status = http.StatusOK
	}
	w.WriteHeader(status)
	_, _ = io.WriteString(w, rec.answer)
}

// sent decodes the body of the last request as a JSON object.
func (rec *recorder) sent(t *testing.T) map[string]any {
	t.Helper()
	rec.mu.Lock()
	defer rec.mu.Unlock()
	var got map[string]any
	if err := json.Unmarshal(rec.body, &got); err != nil {
		t.Fatalf("the body %s: %v", rec.body, err)
	}
	return got
}

// serve starts a recorder and a client pointed at it.
func serve(t *testing.T, opts ...Option) (*Client, *recorder) {
	t.Helper()
	rec := &recorder{}
	srv := httptest.NewServer(rec)
	t.Cleanup(srv.Close)
	c, err := New(testKey, append([]Option{WithBaseURL(srv.URL + "/"), WithHTTPClient(srv.Client())}, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	return c, rec
}

// search is a valid request of the given output type.
func search(output OutputType) Request {
	return Request{Query: "go release", Depth: DepthStandard, OutputType: output}
}

func TestNew(t *testing.T) {
	if _, err := New(" \t"); err == nil || err.Error() != "linkup: no API key" {
		t.Fatalf("a blank key: %v", err)
	}
	c, err := New(" k ", nil, WithBaseURL("  "), WithHTTPClient(nil))
	if err != nil {
		t.Fatal(err)
	}
	if c.apiKey != "k" || c.baseURL != DefaultBaseURL || c.timeout != DefaultTimeout || c.http == nil || c.http.Transport == nil {
		t.Fatalf("defaults: %+v", c)
	}
	custom := &http.Client{}
	c, err = New("k", WithBaseURL("https://search.example.com/root///"), WithHTTPClient(custom), WithTimeout(-1))
	if err != nil {
		t.Fatal(err)
	}
	if c.baseURL != "https://search.example.com/root" || c.http != custom || c.timeout != -1 {
		t.Fatalf("options: %+v", c)
	}
	for _, bad := range []string{"search.example.com", "http://[::1", "/v1"} {
		if _, err := New("k", WithBaseURL(bad)); err == nil {
			t.Errorf("base URL %q was accepted", bad)
		}
	}
}

func TestSearchEncodesTheRequest(t *testing.T) {
	c, rec := serve(t)
	rec.answer = `{"answer":"a","sources":[]}`
	req := Request{
		Query:                  "What is new in Go?",
		Depth:                  DepthDeep,
		OutputType:             OutputSourcedAnswer,
		MaxResults:             7,
		IncludeDomains:         []string{"go.dev", "github.com"},
		ExcludeDomains:         []string{"example.com"},
		FromDate:               time.Date(2025, 1, 2, 23, 30, 0, 0, time.UTC),
		ToDate:                 time.Date(2025, 12, 31, 0, 0, 0, 0, time.FixedZone("east", 9*3600)),
		IncludeImages:          true,
		IncludeInlineCitations: true,
		IncludeSources:         true,
	}
	if _, err := c.Search(t.Context(), req); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"q":                      "What is new in Go?",
		"depth":                  "deep",
		"outputType":             "sourcedAnswer",
		"maxResults":             float64(7),
		"includeDomains":         []any{"go.dev", "github.com"},
		"excludeDomains":         []any{"example.com"},
		"fromDate":               "2025-01-02",
		"toDate":                 "2025-12-31",
		"includeImages":          true,
		"includeInlineCitations": true,
		"includeSources":         true,
	}
	if got := rec.sent(t); !reflect.DeepEqual(got, want) {
		t.Fatalf("sent %v\nwant %v", got, want)
	}
	if rec.method != http.MethodPost || rec.path != "/v1/search" {
		t.Fatalf("%s %s", rec.method, rec.path)
	}
	if got := rec.header.Get("Authorization"); got != "Bearer "+testKey {
		t.Fatalf("Authorization %q", got)
	}
	if rec.header.Get("Content-Type") != "application/json" || rec.header.Get("Accept") != "application/json" {
		t.Fatalf("headers %v", rec.header)
	}

	// A request with only the required fields sends only those.
	rec.answer = `{"results":[]}`
	if _, err := c.Search(t.Context(), search(OutputSearchResults)); err != nil {
		t.Fatal(err)
	}
	if got, want := rec.sent(t), map[string]any{"q": "go release", "depth": "standard", "outputType": "searchResults"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("a minimal request sent %v", got)
	}

	// A structured request sends its schema as a JSON string.
	rec.answer = `{"revenue":"245.1"}`
	structured := search(OutputStructured)
	structured.StructuredOutputSchema = json.RawMessage(`{"type":"object","properties":{"revenue":{"type":"string"}}}`)
	if _, err := c.Search(t.Context(), structured); err != nil {
		t.Fatal(err)
	}
	if got := rec.sent(t)["structuredOutputSchema"]; got != `{"type":"object","properties":{"revenue":{"type":"string"}}}` {
		t.Fatalf("the schema was sent as %#v", got)
	}

	// A depth this package does not name is sent as it is.
	rec.answer = `{"results":[]}`
	future := search(OutputSearchResults)
	future.Depth = "exhaustive"
	if _, err := c.Search(t.Context(), future); err != nil {
		t.Fatal(err)
	}
	if got := rec.sent(t)["depth"]; got != "exhaustive" {
		t.Fatalf("the depth was sent as %v", got)
	}
}

func TestSearchRefusesAnIncompleteRequest(t *testing.T) {
	c, rec := serve(t)
	schemaless := search(OutputStructured)
	badSchema := search(OutputStructured)
	badSchema.StructuredOutputSchema = json.RawMessage(`{"type":`)
	negative := search(OutputSearchResults)
	negative.MaxResults = -1
	for name, tc := range map[string]struct {
		req    Request
		detail string
	}{
		"no query":      {Request{Query: "  ", Depth: DepthFast, OutputType: OutputSearchResults}, "q is empty"},
		"no depth":      {Request{Query: "q", OutputType: OutputSearchResults}, "depth is empty"},
		"no output":     {Request{Query: "q", Depth: DepthFast}, "outputType is empty"},
		"negative max":  {negative, "maxResults is negative"},
		"no schema":     {schemaless, "structuredOutputSchema is required for outputType structured"},
		"schema broken": {badSchema, "structuredOutputSchema is not JSON"},
	} {
		_, err := c.Search(t.Context(), tc.req)
		if !errors.Is(err, ErrBadRequest) || err.Error() != "linkup: bad request: "+tc.detail {
			t.Errorf("%s: %v", name, err)
		}
		if _, ok := errors.AsType[*Error](err); ok {
			t.Errorf("%s: a refusal before sending is an *Error", name)
		}
	}
	if rec.calls != 0 {
		t.Fatalf("%d refused requests reached the API", rec.calls)
	}
}

func TestSearchEncodingFailure(t *testing.T) {
	c, rec := serve(t)
	t.Cleanup(func() { marshal = json.Marshal })
	marshal = func(any) ([]byte, error) { return nil, errors.New("injected") }
	if _, err := c.Search(t.Context(), search(OutputSearchResults)); err == nil || !strings.Contains(err.Error(), "injected") {
		t.Fatalf("an encoding failure: %v", err)
	}
	if rec.calls != 0 {
		t.Fatal("a request that did not encode was sent")
	}
}

func TestSearchResults(t *testing.T) {
	c, rec := serve(t)
	rec.answer = `{"results":[
		{"type":"text","name":"Go 1.25 is released","url":"https://go.dev/blog/go1.25","content":"Go 1.25 is now available.","favicon":"https://go.dev/favicon.ico"},
		{"type":"image","name":"gopher","url":"https://go.dev/gopher.png"},
		{"type":"text","name":"Release History","url":"https://go.dev/doc/devel/release","content":"go1.25.0","favicon":""}]}`
	resp, err := c.Search(t.Context(), search(OutputSearchResults))
	if err != nil {
		t.Fatal(err)
	}
	want := Response{Results: []Result{
		{Type: ResultText, Name: "Go 1.25 is released", URL: "https://go.dev/blog/go1.25", Content: "Go 1.25 is now available.", Favicon: "https://go.dev/favicon.ico"},
		{Type: ResultImage, Name: "gopher", URL: "https://go.dev/gopher.png"},
		{Type: ResultText, Name: "Release History", URL: "https://go.dev/doc/devel/release", Content: "go1.25.0"},
	}}
	if !reflect.DeepEqual(resp, want) {
		t.Fatalf("got %+v", resp)
	}

	rec.answer = `{"results":[]}`
	resp, err = c.Search(t.Context(), search(OutputSearchResults))
	if err != nil || resp.Results == nil || len(resp.Results) != 0 {
		t.Fatalf("no results: %+v %v", resp, err)
	}
}

func TestSearchSourcedAnswer(t *testing.T) {
	c, rec := serve(t)
	rec.answer = `{"answer":"Revenue was $245.1 billion.","sources":[
		{"name":"Annual Report","url":"https://example.com/ar24","snippet":"Revenue increased.","favicon":"https://example.com/favicon.ico"}]}`
	resp, err := c.Search(t.Context(), search(OutputSourcedAnswer))
	if err != nil {
		t.Fatal(err)
	}
	want := Response{Answer: "Revenue was $245.1 billion.", Sources: []Source{
		{Name: "Annual Report", URL: "https://example.com/ar24", Snippet: "Revenue increased.", Favicon: "https://example.com/favicon.ico"},
	}}
	if !reflect.DeepEqual(resp, want) {
		t.Fatalf("got %+v", resp)
	}
}

func TestSearchStructured(t *testing.T) {
	c, rec := serve(t)
	req := search(OutputStructured)
	req.StructuredOutputSchema = json.RawMessage(`{"type":"object"}`)

	rec.answer = " {\"revenue\": \"245.1\"}\n"
	resp, err := c.Search(t.Context(), req)
	if err != nil {
		t.Fatal(err)
	}
	if string(resp.Data) != `{"revenue": "245.1"}` || resp.Results != nil {
		t.Fatalf("got %+v", resp)
	}

	req.IncludeSources = true
	rec.answer = `{"data":{"revenue":"245.1"},"sources":[{"type":"text","name":"Annual Report","url":"https://example.com/ar24","content":"Revenue increased."}]}`
	resp, err = c.Search(t.Context(), req)
	if err != nil {
		t.Fatal(err)
	}
	want := Response{Data: json.RawMessage(`{"revenue":"245.1"}`), Results: []Result{
		{Type: ResultText, Name: "Annual Report", URL: "https://example.com/ar24", Content: "Revenue increased."},
	}}
	if !reflect.DeepEqual(resp, want) {
		t.Fatalf("with sources got %+v", resp)
	}
}

func TestSearchAnOutputTypeItDoesNotName(t *testing.T) {
	c, rec := serve(t)
	req := search("timeline")
	rec.answer = ` [1, 2] `
	resp, err := c.Search(t.Context(), req)
	if err != nil {
		t.Fatal(err)
	}
	if string(resp.Data) != `[1, 2]` {
		t.Fatalf("got %+v", resp)
	}
}

func TestSearchAnswerOutsideItsShape(t *testing.T) {
	c, rec := serve(t)
	structured := search(OutputStructured)
	structured.StructuredOutputSchema = json.RawMessage(`{"type":"object"}`)
	withSources := structured
	withSources.IncludeSources = true
	for name, tc := range map[string]struct {
		req    Request
		answer string
		detail string
	}{
		"results broken":       {search(OutputSearchResults), `{"results":`, "the searchResults answer does not decode"},
		"no results member":    {search(OutputSearchResults), `{"answer":"x"}`, "the searchResults answer has no results"},
		"results null":         {search(OutputSearchResults), `{"results":null}`, "the searchResults answer has no results"},
		"answer broken":        {search(OutputSourcedAnswer), `[]`, "the sourcedAnswer answer does not decode"},
		"no answer member":     {search(OutputSourcedAnswer), `{"sources":[]}`, "the sourcedAnswer answer has no answer"},
		"no sources member":    {search(OutputSourcedAnswer), `{"answer":"x"}`, "the sourcedAnswer answer has no sources"},
		"structured not JSON":  {structured, `<html>`, "the structured answer is not a JSON object"},
		"structured an array":  {structured, `[{"a":1}]`, "the structured answer is not a JSON object"},
		"with sources broken":  {withSources, `{"data":`, "the structured answer does not decode"},
		"with sources no data": {withSources, `{"data":null,"sources":[]}`, "the structured answer has no data"},
		"with sources none":    {withSources, `{"data":{}}`, "the structured answer has no sources"},
		"unnamed not JSON":     {search("timeline"), `nope`, "the timeline answer is not JSON"},
	} {
		rec.answer = tc.answer
		_, err := c.Search(t.Context(), tc.req)
		if !errors.Is(err, ErrUpstream) || !strings.Contains(err.Error(), tc.detail) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestSearchAnswerPastTheBound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"results":[{"type":"text","name":"`)
		_, _ = io.Copy(w, io.LimitReader(repeat('a'), maxResponseBody))
	}))
	t.Cleanup(srv.Close)
	c, err := New(testKey, WithBaseURL(srv.URL), WithHTTPClient(srv.Client()))
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Search(t.Context(), search(OutputSearchResults))
	if !errors.Is(err, ErrUpstream) || !strings.Contains(err.Error(), "passed") {
		t.Fatalf("an answer past the bound: %v", err)
	}
}

// repeat is an endless reader of one byte.
type repeat byte

func (r repeat) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(r)
	}
	return len(p), nil
}

func TestSearchTransportFailure(t *testing.T) {
	gone := httptest.NewServer(http.NotFoundHandler())
	gone.Close()
	c, err := New(testKey, WithBaseURL(gone.URL))
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Search(t.Context(), search(OutputSearchResults))
	if err == nil || !strings.HasPrefix(err.Error(), "linkup: search: ") || strings.Contains(err.Error(), testKey) {
		t.Fatalf("a closed endpoint: %v", err)
	}
	if _, ok := errors.AsType[*Error](err); ok {
		t.Fatal("a transport failure is an *Error")
	}
}

func TestSearchHonorsTheContext(t *testing.T) {
	release := make(chan struct{})
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(slow.Close)
	t.Cleanup(func() { close(release) })

	c, err := New(testKey, WithBaseURL(slow.URL), WithHTTPClient(slow.Client()))
	if err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := c.Search(canceled, search(OutputSearchResults)); !errors.Is(err, context.Canceled) {
		t.Fatalf("a canceled context: %v", err)
	}

	short, stop := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer stop()
	if _, err := c.Search(short, search(OutputSearchResults)); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("the caller's deadline: %v", err)
	}

	bounded, err := New(testKey, WithBaseURL(slow.URL), WithHTTPClient(slow.Client()), WithTimeout(50*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bounded.Search(t.Context(), search(OutputSearchResults)); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("the client's timeout: %v", err)
	}
}

// cancelAfter is a transport that ends the request's context once the
// response headers have arrived, so the body is read under an ended context.
type cancelAfter struct {
	inner  http.RoundTripper
	cancel context.CancelFunc
}

func (c cancelAfter) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := c.inner.RoundTrip(r)
	c.cancel()
	return resp, err
}

func TestSearchCanceledWhileReading(t *testing.T) {
	for name, status := range map[string]int{"an answer": http.StatusOK, "a failure": http.StatusBadGateway} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(status)
				_, _ = io.WriteString(w, `{"results":[`)
				w.(http.Flusher).Flush()
				<-r.Context().Done()
			}))
			t.Cleanup(srv.Close)
			transport := cancelAfter{inner: srv.Client().Transport, cancel: cancel}
			c, err := New(testKey, WithBaseURL(srv.URL), WithHTTPClient(&http.Client{Transport: transport}), WithTimeout(0))
			if err != nil {
				t.Fatal(err)
			}
			_, err = c.Search(ctx, search(OutputSearchResults))
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("canceled while reading: %v", err)
			}
			if status != http.StatusOK && !errors.Is(err, ErrUpstream) {
				t.Fatalf("a failure canceled while reading lost its status: %v", err)
			}
		})
	}
}

// failingBody is a response body whose reads fail.
type failingBody struct{}

func (failingBody) Read([]byte) (int, error) { return 0, errors.New("connection reset") }
func (failingBody) Close() error             { return nil }

// roundTrip answers every request with one status and a body whose reads
// fail.
type roundTrip int

func (status roundTrip) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: int(status), Header: http.Header{}, Body: failingBody{}}, nil
}

func TestSearchBodyReadFailure(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusTooManyRequests} {
		c, err := New(testKey, WithHTTPClient(&http.Client{Transport: roundTrip(status)}))
		if err != nil {
			t.Fatal(err)
		}
		_, err = c.Search(t.Context(), search(OutputSearchResults))
		if err == nil || !strings.Contains(err.Error(), "connection reset") {
			t.Fatalf("%d: %v", status, err)
		}
		apiErr, ok := errors.AsType[*Error](err)
		if status == http.StatusOK && ok {
			t.Fatalf("a failed read of an answer is an *Error: %v", err)
		}
		if status != http.StatusOK && (!ok || apiErr.StatusCode != status || !errors.Is(err, ErrRateLimited)) {
			t.Fatalf("a failed read of a failure lost its status: %v", err)
		}
	}
}

func TestSearchBuildFailure(t *testing.T) {
	c, err := New(testKey)
	if err != nil {
		t.Fatal(err)
	}
	c.baseURL = "http://exa mple.com"
	if _, err := c.Search(t.Context(), search(OutputSearchResults)); err == nil || !strings.HasPrefix(err.Error(), "linkup: building the search request") {
		t.Fatalf("an unbuildable request: %v", err)
	}
}
