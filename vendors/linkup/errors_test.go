// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package linkup

import (
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"
)

// kinds is every failure kind an *Error can match.
var kinds = []error{ErrBadRequest, ErrNoResult, ErrAuth, ErrInsufficientCredit, ErrRateLimited, ErrUpstream}

func TestSearchErrors(t *testing.T) {
	at := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	t.Cleanup(func() { now = time.Now })
	now = func() time.Time { return at }

	for name, tc := range map[string]struct {
		status int
		header map[string]string
		body   string
		kind   error
		want   Error
		text   string
	}{
		"a refused field": {
			status: 400,
			body:   `{"statusCode":400,"error":{"code":"VALIDATION_ERROR","message":"Validation failed","details":[{"field":"outputType","message":"outputType must be one of the following values: sourcedAnswer, searchResults, structured"}]}}`,
			kind:   ErrBadRequest,
			want: Error{StatusCode: 400, Code: CodeValidation, Message: "Validation failed", Details: []Detail{
				{Field: "outputType", Message: "outputType must be one of the following values: sourcedAnswer, searchResults, structured"},
			}},
			text: "linkup: http 400 VALIDATION_ERROR: Validation failed (outputType: outputType must be one of the following values: sourcedAnswer, searchResults, structured)",
		},
		"no result": {
			status: 400,
			body:   `{"statusCode":400,"error":{"code":"SEARCH_QUERY_NO_RESULT","message":"The query did not yield any result","details":[]}}`,
			kind:   ErrNoResult,
			want:   Error{StatusCode: 400, Code: CodeNoResult, Message: "The query did not yield any result"},
			text:   "linkup: http 400 SEARCH_QUERY_NO_RESULT: The query did not yield any result",
		},
		"a missing key": {
			status: 401,
			body:   `{"statusCode":401,"error":{"code":"UNAUTHORIZED","message":"Unauthorized action"}}`,
			kind:   ErrAuth,
			want:   Error{StatusCode: 401, Code: "UNAUTHORIZED", Message: "Unauthorized action"},
			text:   "linkup: http 401 UNAUTHORIZED: Unauthorized action",
		},
		"payment required": {
			status: 402,
			body:   `{"statusCode":402,"error":{"code":"PAYMENT_REQUIRED","message":"Payment required"}}`,
			kind:   ErrAuth,
			want:   Error{StatusCode: 402, Code: "PAYMENT_REQUIRED", Message: "Payment required"},
			text:   "linkup: http 402 PAYMENT_REQUIRED: Payment required",
		},
		"a key without access": {
			status: 403,
			body:   `{"statusCode":403,"error":{"code":"IP_NOT_WHITELISTED","message":"Forbidden"}}`,
			kind:   ErrAuth,
			want:   Error{StatusCode: 403, Code: "IP_NOT_WHITELISTED", Message: "Forbidden"},
			text:   "linkup: http 403 IP_NOT_WHITELISTED: Forbidden",
		},
		"out of credit": {
			status: 429,
			body:   `{"statusCode":429,"error":{"code":"INSUFFICIENT_FUNDS_CREDITS","message":"You do not have enough credits"}}`,
			kind:   ErrInsufficientCredit,
			want:   Error{StatusCode: 429, Code: CodeInsufficientCredit, Message: "You do not have enough credits"},
			text:   "linkup: http 429 INSUFFICIENT_FUNDS_CREDITS: You do not have enough credits",
		},
		"at the budget limit": {
			status: 429,
			body:   `{"statusCode":429,"error":{"code":"EXCEED_BUDGET_LIMIT","message":"Budget limit reached"}}`,
			kind:   ErrInsufficientCredit,
			want:   Error{StatusCode: 429, Code: CodeBudgetLimit, Message: "Budget limit reached"},
			text:   "linkup: http 429 EXCEED_BUDGET_LIMIT: Budget limit reached",
		},
		"too many requests": {
			status: 429,
			header: map[string]string{"Retry-After": "3"},
			body:   `{"statusCode":429,"error":{"code":"TOO_MANY_REQUESTS","message":"Too many requests"}}`,
			kind:   ErrRateLimited,
			want:   Error{StatusCode: 429, Code: CodeTooManyRequests, Message: "Too many requests", RetryAfter: 3 * time.Second},
			text:   "linkup: http 429 TOO_MANY_REQUESTS: Too many requests, retry after 3s",
		},
		"a gateway's rate limit": {
			status: 429,
			header: map[string]string{"Retry-After": at.Add(90 * time.Second).Format(http.TimeFormat)},
			body:   ``,
			kind:   ErrRateLimited,
			want:   Error{StatusCode: 429, Message: "Too Many Requests", RetryAfter: 90 * time.Second},
			text:   "linkup: http 429: Too Many Requests, retry after 1m30s",
		},
		"a server failure": {
			status: 500,
			body:   `upstream connect error`,
			kind:   ErrUpstream,
			want:   Error{StatusCode: 500, Message: "upstream connect error"},
			text:   "linkup: http 500: upstream connect error",
		},
		"a deadline": {
			status: 504,
			body:   `{"statusCode":504,"error":{"code":"REQUEST_DEADLINE_EXCEEDED","message":"Request deadline exceeded"}}`,
			kind:   ErrUpstream,
			want:   Error{StatusCode: 504, Code: "REQUEST_DEADLINE_EXCEEDED", Message: "Request deadline exceeded"},
			text:   "linkup: http 504 REQUEST_DEADLINE_EXCEEDED: Request deadline exceeded",
		},
		"an undocumented status": {
			status: 404,
			body:   `{"message":"Cannot POST /v2/search"}`,
			kind:   ErrUpstream,
			want:   Error{StatusCode: 404, Message: "Cannot POST /v2/search"},
			text:   "linkup: http 404: Cannot POST /v2/search",
		},
		"an error string": {
			status: 429,
			body:   `{"error":"insufficient credits"}`,
			kind:   ErrRateLimited,
			want:   Error{StatusCode: 429, Message: "insufficient credits"},
			text:   "linkup: http 429: insufficient credits",
		},
		"an error of another shape": {
			status: 502,
			body:   `{"error": [ "a", 1 ]}`,
			kind:   ErrUpstream,
			want:   Error{StatusCode: 502, Message: `["a",1]`},
			text:   `linkup: http 502: ["a",1]`,
		},
		"an error object of another shape": {
			status: 502,
			body:   `{"error": {"code": 7}}`,
			kind:   ErrUpstream,
			want:   Error{StatusCode: 502, Message: `{"code":7}`},
			text:   `linkup: http 502: {"code":7}`,
		},
		"an error null": {
			status: 503,
			body:   `{"error":null}`,
			kind:   ErrUpstream,
			want:   Error{StatusCode: 503, Message: "Service Unavailable"},
			text:   "linkup: http 503: Service Unavailable",
		},
		"details without a field or a message": {
			status: 400,
			body:   `{"error":{"code":"VALIDATION_ERROR","details":[{"field":"q"},{"message":"too long"},{}]}}`,
			kind:   ErrBadRequest,
			want:   Error{StatusCode: 400, Code: CodeValidation, Message: "Bad Request", Details: []Detail{{Field: "q"}, {Message: "too long"}, {}}},
			text:   "linkup: http 400 VALIDATION_ERROR: Bad Request (q; too long)",
		},
		"a status without text": {
			status: 599,
			body:   ``,
			kind:   ErrUpstream,
			want:   Error{StatusCode: 599},
			text:   "linkup: http 599",
		},
	} {
		t.Run(name, func(t *testing.T) {
			c, rec := serve(t)
			rec.status, rec.headers, rec.answer = tc.status, tc.header, tc.body
			_, err := c.Search(t.Context(), search(OutputSearchResults))
			got, ok := errors.AsType[*Error](err)
			if !ok {
				t.Fatalf("not an *Error: %v", err)
			}
			if !reflect.DeepEqual(*got, tc.want) {
				t.Fatalf("got  %#v\nwant %#v", *got, tc.want)
			}
			if err.Error() != tc.text {
				t.Fatalf("Error() = %q\nwant      %q", err.Error(), tc.text)
			}
			for _, kind := range kinds {
				if errors.Is(err, kind) != errors.Is(tc.kind, kind) {
					t.Errorf("errors.Is(err, %v) = %v", kind, errors.Is(err, kind))
				}
			}
		})
	}
}

func TestTheKeyIsNeverInAnError(t *testing.T) {
	for name, body := range map[string]string{
		"in the message":   `{"error":{"code":"UNAUTHORIZED","message":"bad key ` + testKey + `"}}`,
		"in the code":      `{"error":{"code":"` + testKey + `","message":"x"}}`,
		"in a detail":      `{"error":{"code":"VALIDATION_ERROR","message":"x","details":[{"field":"` + testKey + `","message":"key ` + testKey + ` is invalid"}]}}`,
		"in an error text": `{"error":"no such key ` + testKey + `"}`,
		"in a message":     `{"message":"Bearer ` + testKey + `"}`,
		"in a plain body":  `<html>Authorization: Bearer ` + testKey + `</html>`,
		"in another shape": `{"error":["` + testKey + `"]}`,
	} {
		t.Run(name, func(t *testing.T) {
			c, rec := serve(t)
			rec.status, rec.answer = http.StatusUnauthorized, body
			_, err := c.Search(t.Context(), search(OutputSearchResults))
			if err == nil || strings.Contains(err.Error(), testKey) || !strings.Contains(err.Error(), redacted) {
				t.Fatalf("the error %v", err)
			}
			got, ok := errors.AsType[*Error](err)
			if !ok {
				t.Fatalf("not an *Error: %v", err)
			}
			fields := []string{got.Code, got.Message}
			for _, d := range got.Details {
				fields = append(fields, d.Field, d.Message)
			}
			for _, f := range fields {
				if strings.Contains(f, testKey) {
					t.Fatalf("a field holds the key: %#v", got)
				}
			}
		})
	}
}

func TestALongMessageIsCut(t *testing.T) {
	long := strings.Repeat("a", maxMessage-1) + "é" + strings.Repeat("b", 100)
	e := newError(http.StatusBadGateway, http.Header{}, []byte(long), testKey)
	if !strings.HasSuffix(e.Message, "a...") || len(e.Message) != maxMessage-1+len("...") {
		t.Fatalf("a long message is %d bytes ending %q", len(e.Message), e.Message[len(e.Message)-8:])
	}
	short := strings.Repeat("c", maxMessage)
	if e := newError(http.StatusBadGateway, http.Header{}, []byte(short), testKey); e.Message != short {
		t.Fatalf("a message at the bound was cut to %d bytes", len(e.Message))
	}
}

func TestRetryAfter(t *testing.T) {
	at := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	for value, want := range map[string]struct {
		wait time.Duration
		ok   bool
	}{
		"":                              {0, false},
		"  ":                            {0, false},
		"0":                             {0, true},
		" 120 ":                         {2 * time.Minute, true},
		"-1":                            {0, false},
		"1.5":                           {0, false},
		"soon":                          {0, false},
		"99999999999999999":             {maxRetryAfter, true},
		"Mon, 05 Oct 2026 12:00:30 GMT": {30 * time.Second, true},
		"Mon, 05 Oct 2026 11:00:00 GMT": {0, true},
	} {
		wait, ok := retryAfter(value, at)
		if wait != want.wait || ok != want.ok {
			t.Errorf("retryAfter(%q) = %v, %v; want %v, %v", value, wait, ok, want.wait, want.ok)
		}
	}
}

func TestErrorWithoutParts(t *testing.T) {
	e := &Error{StatusCode: 400, Details: []Detail{{}}}
	if got := e.Error(); got != "linkup: http 400" {
		t.Fatalf("Error() = %q", got)
	}
	if !errors.Is(e, ErrBadRequest) || errors.Is(e, ErrUpstream) {
		t.Fatal("the kind of a bare 400")
	}
}

func FuzzNewError(f *testing.F) {
	f.Add(400, []byte(`{"statusCode":400,"error":{"code":"VALIDATION_ERROR","message":"Validation failed","details":[{"field":"q","message":"q is required"}]}}`))
	f.Add(401, []byte(`{"error":{"message":"bad key `+testKey+`"}}`))
	f.Add(429, []byte(`{"error":"`+testKey+`"}`))
	f.Add(502, []byte(`<html>`+testKey+`</html>`))
	f.Add(500, []byte(`{"error":[1,{"a":"`+testKey+`"}]}`))
	f.Add(503, []byte{})
	f.Fuzz(func(t *testing.T, status int, body []byte) {
		e := newError(status, http.Header{}, body, testKey)
		if strings.Contains(e.Error(), testKey) {
			t.Fatalf("the key is in %q", e.Error())
		}
		matched := 0
		for _, kind := range kinds {
			if errors.Is(e, kind) {
				matched++
			}
		}
		if matched != 1 {
			t.Fatalf("status %d code %q matched %d kinds", status, e.Code, matched)
		}
	})
}

func FuzzRetryAfter(f *testing.F) {
	for _, seed := range []string{"", "0", "120", "-5", "1e3", "99999999999999999999", "Mon, 05 Oct 2026 12:00:30 GMT", "Monday, 05-Oct-26 12:00:30 GMT"} {
		f.Add(seed)
	}
	at := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	f.Fuzz(func(t *testing.T, value string) {
		wait, ok := retryAfter(value, at)
		if wait < 0 || (!ok && wait != 0) {
			t.Fatalf("retryAfter(%q) = %v, %v", value, wait, ok)
		}
	})
}

func FuzzDecodeResponse(f *testing.F) {
	for _, seed := range []string{`{"results":[]}`, `{"answer":"a","sources":[]}`, `{"data":{},"sources":[]}`, `{}`, `[]`, `null`, ``} {
		f.Add(seed, "searchResults", false)
		f.Add(seed, "sourcedAnswer", false)
		f.Add(seed, "structured", true)
		f.Add(seed, "structured", false)
	}
	f.Fuzz(func(t *testing.T, raw, output string, sources bool) {
		resp, err := decodeResponse([]byte(raw), Request{OutputType: OutputType(output), IncludeSources: sources})
		if err != nil && !errors.Is(err, ErrUpstream) {
			t.Fatalf("a failure outside ErrUpstream: %v", err)
		}
		if err == nil && OutputType(output) == OutputSearchResults && resp.Results == nil {
			t.Fatal("a searchResults answer decoded with no results")
		}
	})
}
