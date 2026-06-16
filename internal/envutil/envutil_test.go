package envutil

import "testing"

func TestIsTruthy(t *testing.T) {
	truthy := []string{
		"1", "true", "yes", "on",
		"TRUE", "Yes", "ON", "True",
		"  1  ", " true ", "\tyes\n", " on ",
	}
	for _, v := range truthy {
		if !IsTruthy(v) {
			t.Errorf("IsTruthy(%q) = false, want true", v)
		}
	}
	falsy := []string{
		"", "0", "false", "no", "off",
		"2", "enabled", "y", "t", "  ", "truthy",
	}
	for _, v := range falsy {
		if IsTruthy(v) {
			t.Errorf("IsTruthy(%q) = true, want false", v)
		}
	}
}
