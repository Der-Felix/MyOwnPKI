package clock

import (
	"sync"
	"testing"
	"time"
)

func TestSystemIsUTC(t *testing.T) {
	t.Parallel()
	now := System{}.Now()
	if now.Location() != time.UTC {
		t.Errorf("System.Now() location = %v, want UTC", now.Location())
	}
	if d := time.Since(now); d < 0 || d > time.Minute {
		t.Errorf("System.Now() is %v away from the wall clock", d)
	}
}

func TestFake(t *testing.T) {
	t.Parallel()
	berlin := time.FixedZone("CEST", 2*60*60)
	start := time.Date(2026, 10, 13, 10, 0, 0, 0, berlin) // 08:00 UTC
	f := NewFake(start)

	if got := f.Now(); !got.Equal(start) || got.Location() != time.UTC {
		t.Fatalf("Now() = %v, want %v in UTC", got, start)
	}
	if got := f.Now(); !got.Equal(f.Now()) {
		t.Error("fake time moved by itself")
	}
	if got := f.Advance(90 * 24 * time.Hour); !got.Equal(start.Add(90 * 24 * time.Hour)) {
		t.Errorf("Advance = %v", got)
	}
	earlier := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	f.Set(earlier)
	if got := f.Now(); !got.Equal(earlier) {
		t.Errorf("after Set: %v, want %v", got, earlier)
	}
}

func TestFakeConcurrentUse(t *testing.T) {
	t.Parallel()
	f := NewFake(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 100 {
				f.Advance(time.Second)
				_ = f.Now()
			}
		})
	}
	wg.Wait()
	if got, want := f.Now(), time.Date(2026, 1, 1, 0, 13, 20, 0, time.UTC); !got.Equal(want) {
		t.Errorf("after 800 concurrent seconds: %v, want %v", got, want)
	}
}

// Both clocks satisfy the interface.
var (
	_ Clock = System{}
	_ Clock = (*Fake)(nil)
)
