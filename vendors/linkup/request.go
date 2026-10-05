// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package linkup

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Depth is how much search work the API does for one query. Its price and
// its latency rise with it.
type Depth string

// The depths the API documents. A value outside them is sent as it is, so a
// depth the API adds later is usable before this package names it.
const (
	// DepthFlash answers ranked sources and snippets from Linkup's index
	// with no query interpretation, in under 200 ms.
	DepthFlash Depth = "flash"
	// DepthFast is one-shot retrieval from the index with the query passed
	// as it is, in about a second.
	DepthFast Depth = "fast"
	// DepthStandard is one pass of agentic search: the query is
	// interpreted, sub-searches may run in parallel, and one URL named in
	// the query may be read. It takes one to three seconds.
	DepthStandard Depth = "standard"
	// DepthDeep chains several passes of search and page reading, and costs
	// ten times a standard search. It takes 5 to 30 seconds.
	DepthDeep Depth = "deep"
)

// OutputType is the shape of a search's answer.
type OutputType string

// The output types the API documents. A value outside them is sent as it is,
// and its answer is kept whole in Response.Data.
const (
	// OutputSearchResults answers ranked results in Response.Results.
	OutputSearchResults OutputType = "searchResults"
	// OutputSourcedAnswer answers a written answer in Response.Answer and
	// the sources it cites in Response.Sources.
	OutputSourcedAnswer OutputType = "sourcedAnswer"
	// OutputStructured answers an object that follows
	// Request.StructuredOutputSchema, in Response.Data.
	OutputStructured OutputType = "structured"
)

// Request is one search. Query, Depth and OutputType are required; every
// other field left at its zero value is not sent, and the API's default
// applies.
type Request struct {
	// Query is the question in natural language, sent as q. At the
	// standard and deep depths, instructions in it are followed.
	Query string
	// Depth is how much search work the API does.
	Depth Depth
	// OutputType is the shape of the answer.
	OutputType OutputType
	// MaxResults caps how many results or sources are answered. Zero
	// leaves the count to the API; a negative count is refused.
	MaxResults int
	// IncludeDomains restricts the search to these domains or URLs.
	IncludeDomains []string
	// ExcludeDomains removes these domains or URLs from the search. Where a
	// URL matches both lists, IncludeDomains wins.
	ExcludeDomains []string
	// FromDate and ToDate bound the dates the results are drawn from. Each
	// is sent as its calendar date, YYYY-MM-DD, in the value's own
	// location; the zero time leaves that side open.
	FromDate time.Time
	ToDate   time.Time
	// IncludeImages asks for image results beside the text ones.
	IncludeImages bool
	// IncludeInlineCitations asks a sourced answer to cite its sources
	// inline. It applies to OutputSourcedAnswer only.
	IncludeInlineCitations bool
	// StructuredOutputSchema is the JSON Schema a structured answer
	// follows, with an object at its root. It is required for
	// OutputStructured and sent as a JSON string, as the API takes it.
	StructuredOutputSchema json.RawMessage
	// IncludeSources asks a structured answer to carry the results it was
	// built from, which changes the answer's shape; Search reads either.
	// It applies to OutputStructured only.
	IncludeSources bool
}

// wireRequest is the body of POST /v1/search.
type wireRequest struct {
	Query                  string     `json:"q"`
	Depth                  Depth      `json:"depth"`
	OutputType             OutputType `json:"outputType"`
	MaxResults             int        `json:"maxResults,omitempty"`
	IncludeDomains         []string   `json:"includeDomains,omitempty"`
	ExcludeDomains         []string   `json:"excludeDomains,omitempty"`
	FromDate               string     `json:"fromDate,omitempty"`
	ToDate                 string     `json:"toDate,omitempty"`
	IncludeImages          bool       `json:"includeImages,omitempty"`
	IncludeInlineCitations bool       `json:"includeInlineCitations,omitempty"`
	StructuredOutputSchema string     `json:"structuredOutputSchema,omitempty"`
	IncludeSources         bool       `json:"includeSources,omitempty"`
}

// marshal encodes the request body. Tests replace it to reach the branch
// where encoding fails.
var marshal = json.Marshal

// encode checks the request and renders the body sent to the API.
func (r Request) encode() ([]byte, error) {
	if err := r.validate(); err != nil {
		return nil, err
	}
	body, err := marshal(wireRequest{
		Query:                  r.Query,
		Depth:                  r.Depth,
		OutputType:             r.OutputType,
		MaxResults:             r.MaxResults,
		IncludeDomains:         r.IncludeDomains,
		ExcludeDomains:         r.ExcludeDomains,
		FromDate:               date(r.FromDate),
		ToDate:                 date(r.ToDate),
		IncludeImages:          r.IncludeImages,
		IncludeInlineCitations: r.IncludeInlineCitations,
		StructuredOutputSchema: string(r.StructuredOutputSchema),
		IncludeSources:         r.IncludeSources,
	})
	if err != nil {
		return nil, fmt.Errorf("linkup: encoding the search request: %w", err)
	}
	return body, nil
}

// validate refuses a request the API would refuse for a missing or
// malformed field, naming the field as the API does.
func (r Request) validate() error {
	switch {
	case strings.TrimSpace(r.Query) == "":
		return fmt.Errorf("%w: q is empty", ErrBadRequest)
	case r.Depth == "":
		return fmt.Errorf("%w: depth is empty", ErrBadRequest)
	case r.OutputType == "":
		return fmt.Errorf("%w: outputType is empty", ErrBadRequest)
	case r.MaxResults < 0:
		return fmt.Errorf("%w: maxResults is negative", ErrBadRequest)
	case r.OutputType == OutputStructured && len(r.StructuredOutputSchema) == 0:
		return fmt.Errorf("%w: structuredOutputSchema is required for outputType structured", ErrBadRequest)
	case len(r.StructuredOutputSchema) > 0 && !json.Valid(r.StructuredOutputSchema):
		return fmt.Errorf("%w: structuredOutputSchema is not JSON", ErrBadRequest)
	}
	return nil
}

// date renders a date bound as the API takes it, and the zero time as
// absent.
func date(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format(time.DateOnly)
}
