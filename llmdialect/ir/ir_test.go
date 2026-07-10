package ir

import (
	"reflect"
	"testing"
)

func TestLossAddDedup(t *testing.T) {
	var l Loss
	if got := l.Fields(); got != nil {
		t.Fatalf("empty loss should have nil fields, got %v", got)
	}
	l.Add("top_k")
	l.Add("cache_control")
	l.Add("top_k")
	want := []string{"top_k", "cache_control"}
	if !reflect.DeepEqual(l.Fields(), want) {
		t.Fatalf("got %v want %v", l.Fields(), want)
	}
}
