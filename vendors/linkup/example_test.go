// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package linkup_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"

	"latere.ai/x/pkg/vendors/linkup"
)

// serve starts a server that answers every search with one canned status and
// body, and returns a client pointed at it. A real program passes no base
// URL and reaches https://api.linkup.so.
func serve(status int, header map[string]string, body string) (*linkup.Client, func()) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		for k, v := range header {
			w.Header().Set(k, v)
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	client, err := linkup.New("demo-key", linkup.WithBaseURL(srv.URL))
	if err != nil {
		panic(err)
	}
	return client, srv.Close
}

// Search the web and read the ranked results.
func Example() {
	client, stop := serve(http.StatusOK, nil, `{"results":[
		{"type":"text","name":"Go 1.25 is released","url":"https://go.dev/blog/go1.25","content":"Go 1.25 is now available.","favicon":""}
	]}`)
	defer stop()

	resp, err := client.Search(context.Background(), linkup.Request{
		Query:      "What changed in the latest Go release?",
		Depth:      linkup.DepthStandard,
		OutputType: linkup.OutputSearchResults,
		MaxResults: 5,
	})
	if err != nil {
		fmt.Println("search:", err)
		return
	}
	for _, r := range resp.Results {
		fmt.Println(r.Name, r.URL)
	}
	// Output:
	// Go 1.25 is released https://go.dev/blog/go1.25
}

// Ask for a written answer with the sources it cites, on chosen domains.
func ExampleClient_Search_sourcedAnswer() {
	client, stop := serve(http.StatusOK, nil, `{
		"answer": "Go 1.25 was released in August 2025.",
		"sources": [{"name":"Go 1.25 is released","url":"https://go.dev/blog/go1.25","snippet":"Go 1.25 is now available."}]
	}`)
	defer stop()

	resp, err := client.Search(context.Background(), linkup.Request{
		Query:          "When was Go 1.25 released?",
		Depth:          linkup.DepthStandard,
		OutputType:     linkup.OutputSourcedAnswer,
		IncludeDomains: []string{"go.dev"},
	})
	if err != nil {
		fmt.Println("search:", err)
		return
	}
	fmt.Println(resp.Answer)
	fmt.Println(len(resp.Sources), "source:", resp.Sources[0].URL)
	// Output:
	// Go 1.25 was released in August 2025.
	// 1 source: https://go.dev/blog/go1.25
}

// Tell a rate limit, which passes, from exhausted credit, which does not.
func ExampleError() {
	client, stop := serve(http.StatusTooManyRequests, map[string]string{"Retry-After": "2"},
		`{"statusCode":429,"error":{"code":"TOO_MANY_REQUESTS","message":"Too many requests","details":[]}}`)
	defer stop()

	_, err := client.Search(context.Background(), linkup.Request{
		Query:      "go release",
		Depth:      linkup.DepthFast,
		OutputType: linkup.OutputSearchResults,
	})
	switch apiErr, ok := errors.AsType[*linkup.Error](err); {
	case errors.Is(err, linkup.ErrRateLimited) && ok:
		fmt.Println("rate limited; wait", apiErr.RetryAfter)
	case errors.Is(err, linkup.ErrInsufficientCredit):
		fmt.Println("out of credit")
	case err != nil:
		fmt.Println("search:", err)
	}
	// Output:
	// rate limited; wait 2s
}
