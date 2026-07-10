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
	l.Add(LossTopK)
	l.Add(LossCacheControl)
	l.Add(LossTopK)
	want := []LossField{LossTopK, LossCacheControl}
	if !reflect.DeepEqual(l.Fields(), want) {
		t.Fatalf("got %v want %v", l.Fields(), want)
	}
	if !reflect.DeepEqual(l.Strings(), []string{"top_k", "cache_control"}) {
		t.Fatalf("strings = %v", l.Strings())
	}
}
