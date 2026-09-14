// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package bridge

import (
	"bytes"
	"encoding/json"
	"maps"

	"latere.ai/x/pkg/httpjson"
)

// Failure is one refusal rendered in a wire's own error shape. Code and
// Message are the caller's vocabulary; this package owns no codes and
// no sentences but its own.
type Failure struct {
	Code      string         // the machine-readable member of every shape
	Message   string         // the one user sentence
	Detail    string         // details.detail on the lux shape; nowhere else
	RequestID string         // the Anthropic shape's request_id, the lux shape's details.request_id
	Status    int            // the Google shape's error.code
	Domain    string         // the Google ErrorInfo domain; "" omits the member
	Details   map[string]any // merged into the lux shape's details; ignored by the other three
}

// errorInfoType is the @type of the one detail the Google shape carries.
const errorInfoType = "type.googleapis.com/google.rpc.ErrorInfo"

// openaiError is the OpenAI error shape, as a body and as a stream frame.
type openaiError struct {
	Error struct {
		Message string  `json:"message"`
		Type    string  `json:"type"`
		Code    string  `json:"code"`
		Param   *string `json:"param"`
	} `json:"error"`
}

// anthropicError is the Anthropic error shape, as a body and as the
// data of an event: error frame.
type anthropicError struct {
	Type  string `json:"type"`
	Error struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error"`
	RequestID string `json:"request_id"`
}

// googleErrorInfo is Google's ErrorInfo detail, which carries the
// caller's code as its reason.
type googleErrorInfo struct {
	Type   string `json:"@type"`
	Reason string `json:"reason"`
	Domain string `json:"domain,omitempty"`
}

// googleError is Google's error shape.
type googleError struct {
	Error struct {
		Code    int               `json:"code"`
		Message string            `json:"message"`
		Status  string            `json:"status"`
		Details []googleErrorInfo `json:"details"`
	} `json:"error"`
}

// Envelope renders f in the wire's error shape with one trailing
// newline, exactly as the four APIs write them: OpenAI's
// {"error":{message,type,code,param}} with type and code both the Code
// and param null; Anthropic's {"type":"error","error":{type,message},
// "request_id"}; Google's {"error":{code,message,status,details}} with
// Status as code, GoogleStatus(Status) as status, and one ErrorInfo
// detail whose reason is the Code; and, for WireLux,
// httpjson.ErrorEnvelope with request_id and detail under details
// beside Details, each only when set. A wire that is none of the four
// renders nil.
func Envelope(w Wire, f Failure) []byte {
	var body any
	switch w {
	case WireOpenAI:
		var e openaiError
		e.Error.Message, e.Error.Type, e.Error.Code = f.Message, f.Code, f.Code
		body = e
	case WireAnthropic:
		var e anthropicError
		e.Type, e.Error.Type, e.Error.Message, e.RequestID = "error", f.Code, f.Message, f.RequestID
		body = e
	case WireGoogle:
		var e googleError
		e.Error.Code, e.Error.Message, e.Error.Status = f.Status, f.Message, GoogleStatus(f.Status)
		e.Error.Details = []googleErrorInfo{{Type: errorInfoType, Reason: f.Code, Domain: f.Domain}}
		body = e
	case WireLux:
		details := maps.Clone(f.Details)
		if f.RequestID != "" || f.Detail != "" {
			if details == nil {
				details = map[string]any{}
			}
			if f.RequestID != "" {
				details["request_id"] = f.RequestID
			}
			if f.Detail != "" {
				details["detail"] = f.Detail
			}
		}
		body = httpjson.ErrorEnvelope{Error: httpjson.Error{Code: f.Code, Message: f.Message, Details: details}}
	default:
		return nil
	}
	out, err := json.Marshal(body)
	if err != nil {
		// Only the lux shape can fail, on a Details value that does not
		// marshal; the envelope is then written without them.
		var bare struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		bare.Error.Code, bare.Error.Message = f.Code, f.Message
		out = marshal(bare)
	}
	return append(out, '\n')
}

// ParseEnvelope reads a Failure back out of one of the four bodies and
// reports whether body was one: an object whose error member has the
// wire's shape. It is the decoding half a client needs and the round
// trip a fuzz target checks. Code is error.code, or error.type when the
// code is null, on the OpenAI shape; error.type on Anthropic's; the
// ErrorInfo reason on Google's; error.code on the lux shape, whose
// details.request_id and details.detail become RequestID and Detail and
// whose other details become Details.
func ParseEnvelope(w Wire, body []byte) (Failure, bool) {
	switch w {
	case WireOpenAI:
		var e struct {
			Error *struct {
				Message *string         `json:"message"`
				Type    string          `json:"type"`
				Code    json.RawMessage `json:"code"`
			} `json:"error"`
		}
		if json.Unmarshal(body, &e) != nil || e.Error == nil || e.Error.Message == nil {
			return Failure{}, false
		}
		code := e.Error.Type
		if len(e.Error.Code) > 0 && string(e.Error.Code) != "null" {
			if json.Unmarshal(e.Error.Code, &code) != nil {
				return Failure{}, false
			}
		}
		return Failure{Code: code, Message: *e.Error.Message}, true
	case WireAnthropic:
		var e struct {
			Type  string `json:"type"`
			Error *struct {
				Type    string `json:"type"`
				Message string `json:"message"`
			} `json:"error"`
			RequestID string `json:"request_id"`
		}
		if json.Unmarshal(body, &e) != nil || e.Type != "error" || e.Error == nil {
			return Failure{}, false
		}
		return Failure{Code: e.Error.Type, Message: e.Error.Message, RequestID: e.RequestID}, true
	case WireGoogle:
		var e struct {
			Error *struct {
				Code    int               `json:"code"`
				Message string            `json:"message"`
				Status  string            `json:"status"`
				Details []googleErrorInfo `json:"details"`
			} `json:"error"`
		}
		if json.Unmarshal(body, &e) != nil || e.Error == nil || (e.Error.Code == 0 && e.Error.Status == "") {
			return Failure{}, false
		}
		f := Failure{Message: e.Error.Message, Status: e.Error.Code}
		for _, d := range e.Error.Details {
			if d.Type == errorInfoType {
				f.Code, f.Domain = d.Reason, d.Domain
				break
			}
		}
		return f, true
	case WireLux:
		var e struct {
			Error *struct {
				Code    *string        `json:"code"`
				Message string         `json:"message"`
				Details map[string]any `json:"details"`
			} `json:"error"`
		}
		if json.Unmarshal(body, &e) != nil || e.Error == nil || e.Error.Code == nil {
			return Failure{}, false
		}
		f := Failure{Code: *e.Error.Code, Message: e.Error.Message}
		if len(e.Error.Details) > 0 {
			f.Details = maps.Clone(e.Error.Details)
			if id, ok := f.Details["request_id"].(string); ok {
				f.RequestID = id
				delete(f.Details, "request_id")
			}
			if d, ok := f.Details["detail"].(string); ok {
				f.Detail = d
				delete(f.Details, "detail")
			}
			if len(f.Details) == 0 {
				f.Details = nil
			}
		}
		return f, true
	}
	return Failure{}, false
}

// ErrorFrame is the one SSE frame that ends a stream which failed past
// its first byte: "data: " and the OpenAI envelope with no [DONE] for
// WireOpenAI, "event: error" and the envelope for WireAnthropic and
// WireLux, and nil for WireGoogle, which has no such frame.
func ErrorFrame(w Wire, f Failure) []byte {
	var prefix string
	switch w {
	case WireOpenAI:
		prefix = "data: "
	case WireAnthropic, WireLux:
		prefix = "event: error\ndata: "
	default:
		return nil
	}
	body := bytes.TrimSuffix(Envelope(w, f), []byte("\n"))
	return append(append([]byte(prefix), body...), "\n\n"...)
}

// GoogleStatus is the google.rpc.Code name for an HTTP status, the
// member of the Google shape a client may switch on: 400 and 413 are
// INVALID_ARGUMENT, 401 UNAUTHENTICATED, 403 PERMISSION_DENIED, 404
// NOT_FOUND, 429 RESOURCE_EXHAUSTED, 502 and 503 UNAVAILABLE, 504
// DEADLINE_EXCEEDED, and every other status INTERNAL.
func GoogleStatus(status int) string {
	switch status {
	case 400, 413:
		return "INVALID_ARGUMENT"
	case 401:
		return "UNAUTHENTICATED"
	case 403:
		return "PERMISSION_DENIED"
	case 404:
		return "NOT_FOUND"
	case 429:
		return "RESOURCE_EXHAUSTED"
	case 502, 503:
		return "UNAVAILABLE"
	case 504:
		return "DEADLINE_EXCEEDED"
	default:
		return "INTERNAL"
	}
}
