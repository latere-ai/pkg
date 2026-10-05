// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// Package linkup is a client for Linkup's web search API
// (https://docs.linkup.so). It is unofficial and is not published by Linkup.
// Import it as latere.ai/x/pkg/vendors/linkup.
//
// One call is one POST /v1/search. A [Request] names the query, the
// [Depth] of the search and the [OutputType] of the answer, and may narrow
// the search to domains and to a date range. The [Response] holds what the
// output type returns: ranked results, a sourced answer with the sources it
// cites, or a structured object that follows the request's JSON Schema.
//
// # Usage
//
//	client, err := linkup.New(apiKey)
//	if err != nil {
//		return err
//	}
//	resp, err := client.Search(ctx, linkup.Request{
//		Query:      "What changed in the latest Go release?",
//		Depth:      linkup.DepthStandard,
//		OutputType: linkup.OutputSearchResults,
//		MaxResults: 5,
//	})
//	if err != nil {
//		return err
//	}
//	for _, r := range resp.Results {
//		fmt.Println(r.Name, r.URL)
//	}
//
// # Errors
//
// A request missing what the API requires is refused before it is sent,
// with an error that matches [ErrBadRequest]. A status other than 200 is an
// [*Error] carrying the status, the API's error code, its message and field
// details, and the wait the Retry-After header asked for. Each [*Error]
// matches exactly one of [ErrBadRequest], [ErrNoResult], [ErrAuth],
// [ErrInsufficientCredit], [ErrRateLimited] and [ErrUpstream] under
// [errors.Is]; a 200 whose body is not the documented shape matches
// [ErrUpstream] too. A transport failure, and a context that ended, are
// returned wrapped, so [errors.Is] reaches [context.Canceled] or
// [context.DeadlineExceeded].
//
// The client retries nothing: every search is billed, and whether a rate
// limit or a failure is worth another call is the caller's decision. The
// API key is never part of an error: where the API echoes it in an error
// body, it is replaced before the text is kept.
package linkup
