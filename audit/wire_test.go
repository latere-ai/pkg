// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"reflect"
	"testing"
	"time"
)

func TestEventKeepsAnEmptySubjectAndANonNilPayload(t *testing.T) {
	ev := Event{EventID: "e1", TS: time.Date(2026, 5, 10, 0, 0, 0, 0, time.UTC), Category: CategoryLifecycle,
		Actor: Actor{Type: "user"}, Subject: &Subject{}, Payload: jsontext.Value(`{}`)}
	got, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"event_id":"e1","ts":"2026-05-10T00:00:00Z","category":"` + string(CategoryLifecycle) + `","actor":{"type":"user"},"subject":{},"payload":{}}`
	if string(got) != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
}

func TestEventOmitsANilSubjectAndPayload(t *testing.T) {
	ev := Event{EventID: "e1", TS: time.Date(2026, 5, 10, 0, 0, 0, 0, time.UTC), Category: CategoryLifecycle, Actor: Actor{Type: "user"}}
	got, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"event_id":"e1","ts":"2026-05-10T00:00:00Z","category":"` + string(CategoryLifecycle) + `","actor":{"type":"user"}}`
	if string(got) != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
}

func TestRedactJSONKeepsNumbersExactAndSortsKeys(t *testing.T) {
	got := string(RedactJSON([]byte(`{"z":9007199254740993,"a":[1.50,"x"],"api_key":"s3cret"}`)))
	want := `{"a":[1.50,"x"],"api_key":"***","z":9007199254740993}`
	if got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
}

func TestRedactJSONAcceptsDuplicateNamesAndRejectsTrailingData(t *testing.T) {
	if got := string(RedactJSON([]byte(`{"a":1,"a":2}`))); got != `{"a":2}` {
		t.Errorf("duplicate names: got %s", got)
	}
	if got := string(RedactJSON([]byte(`{"a":1}garbage`))); got != `{"a":1}garbage` {
		t.Errorf("trailing data: got %s", got)
	}
}

// The mirror in MarshalJSONTo must carry every field of Event.
func TestEventMarshalCoversEveryField(t *testing.T) {
	var ev Event
	ev.EventID, ev.Replica, ev.RequestID, ev.OrgID, ev.Policy = "1", "2", "3", "4", "5"
	ev.Subject = &Subject{Kind: "k"}
	ev.Payload = jsontext.Value(`1`)
	got, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(got, &m); err != nil {
		t.Fatal(err)
	}
	if want := reflect.TypeFor[Event]().NumField(); len(m) != want {
		t.Errorf("wrote %d members for %d fields: %s", len(m), want, got)
	}
}

// A blob that is not one whole JSON value, wherever it breaks, is scrubbed
// as a string rather than dropped or half-read.
func TestRedactJSONFallsBackOnABrokenBlob(t *testing.T) {
	for _, in := range []string{
		``,
		`{`,
		`{"a"`,
		`{"a":`,
		`{"a":[1,`,
		`{"a":{"b":tru}}`,
		`[{"a":1},`,
		`["x",{"a":1}`,
		`{"a":1}garbage`,
	} {
		if got := string(RedactJSON([]byte(in))); got != Redact(in) {
			t.Errorf("RedactJSON(%q) = %q, want the string scrub %q", in, got, Redact(in))
		}
	}
}

// Every kind of value survives the walk, numbers with their exact digits.
func TestRedactJSONKeepsEveryKind(t *testing.T) {
	const in = `{"n":12345678901234567890,"f":false,"t":true,"z":null,"s":"x","l":[[],{}]}`
	const want = `{"f":false,"l":[[],{}],"n":12345678901234567890,"s":"x","t":true,"z":null}`
	if got := string(RedactJSON([]byte(in))); got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}
