// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package linkup

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// ResultType tells a page result from an image result.
type ResultType string

// The result types the API documents.
const (
	// ResultText is a page, with the text extracted from it in Content.
	ResultText ResultType = "text"
	// ResultImage is an image, answered only when the request set
	// IncludeImages. It has no Content.
	ResultImage ResultType = "image"
)

// Result is one ranked result: a page or an image.
type Result struct {
	// Type tells a page from an image.
	Type ResultType `json:"type"`
	// Name is the title or name of the resource.
	Name string `json:"name"`
	// URL is the address of the resource.
	URL string `json:"url"`
	// Content is the text extracted from a page. It is empty for an image.
	Content string `json:"content,omitempty"`
	// Favicon is the address of the site's icon, or empty when it has none.
	Favicon string `json:"favicon,omitempty"`
}

// Source is one source a sourced answer was written from.
type Source struct {
	// Name is the title or name of the resource.
	Name string `json:"name"`
	// URL is the address of the resource.
	URL string `json:"url"`
	// Snippet is the text of the resource the answer drew on.
	Snippet string `json:"snippet"`
	// Favicon is the address of the site's icon, or empty when it has none.
	Favicon string `json:"favicon,omitempty"`
}

// Response is a search's answer. Which fields are filled follows the
// request's OutputType:
//
//   - OutputSearchResults fills Results, in the API's ranking.
//   - OutputSourcedAnswer fills Answer and Sources.
//   - OutputStructured fills Data with the object that follows the schema;
//     with IncludeSources, Results holds the results it was built from.
//   - An output type this package does not name fills Data with the body as
//     it arrived.
type Response struct {
	Results []Result
	Answer  string
	Sources []Source
	Data    json.RawMessage
}

// decodeResponse reads a 200 body into the fields its output type fills. A
// body that does not decode, or lacks a member the API documents as
// required for the output type, matches ErrUpstream.
func decodeResponse(raw []byte, req Request) (Response, error) {
	switch req.OutputType {
	case OutputSearchResults:
		var doc struct {
			Results *[]Result `json:"results"`
		}
		if err := json.Unmarshal(raw, &doc); err != nil {
			return Response{}, malformed(req.OutputType, err)
		}
		if doc.Results == nil {
			return Response{}, missing(req.OutputType, "results")
		}
		return Response{Results: *doc.Results}, nil
	case OutputSourcedAnswer:
		var doc struct {
			Answer  *string   `json:"answer"`
			Sources *[]Source `json:"sources"`
		}
		if err := json.Unmarshal(raw, &doc); err != nil {
			return Response{}, malformed(req.OutputType, err)
		}
		if doc.Answer == nil {
			return Response{}, missing(req.OutputType, "answer")
		}
		if doc.Sources == nil {
			return Response{}, missing(req.OutputType, "sources")
		}
		return Response{Answer: *doc.Answer, Sources: *doc.Sources}, nil
	case OutputStructured:
		if req.IncludeSources {
			var doc struct {
				Data    json.RawMessage `json:"data"`
				Sources *[]Result       `json:"sources"`
			}
			if err := json.Unmarshal(raw, &doc); err != nil {
				return Response{}, malformed(req.OutputType, err)
			}
			if !isObject(doc.Data) {
				return Response{}, missing(req.OutputType, "data")
			}
			if doc.Sources == nil {
				return Response{}, missing(req.OutputType, "sources")
			}
			return Response{Data: doc.Data, Results: *doc.Sources}, nil
		}
		if !json.Valid(raw) || !isObject(raw) {
			return Response{}, fmt.Errorf("%w: the %s answer is not a JSON object", ErrUpstream, req.OutputType)
		}
		return Response{Data: bytes.TrimSpace(raw)}, nil
	default:
		if !json.Valid(raw) {
			return Response{}, fmt.Errorf("%w: the %s answer is not JSON", ErrUpstream, req.OutputType)
		}
		return Response{Data: bytes.TrimSpace(raw)}, nil
	}
}

// isObject reports whether a JSON value is an object. It reads the first
// byte only, so it is called on values already known to be JSON.
func isObject(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) > 0 && trimmed[0] == '{'
}

// malformed is a 200 body that does not decode.
func malformed(output OutputType, err error) error {
	return fmt.Errorf("%w: the %s answer does not decode: %w", ErrUpstream, output, err)
}

// missing is a 200 body without a member its output type requires.
func missing(output OutputType, member string) error {
	return fmt.Errorf("%w: the %s answer has no %s", ErrUpstream, output, member)
}
