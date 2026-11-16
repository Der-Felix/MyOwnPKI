package racemode

import (
	"testing"
	"time"
)

func TestScale(t *testing.T) {
	t.Parallel()
	if got, want := Scale(2*time.Second), 2*time.Second*slowdown; got != want {
		t.Fatalf("Scale(2s) = %v, want %v", got, want)
	}
	if slowdown != 1 && slowdown != 10 {
		t.Fatalf("slowdown %d is neither the normal 1 nor the race 10", slowdown)
	}
}
