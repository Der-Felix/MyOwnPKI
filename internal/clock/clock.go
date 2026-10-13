// Package clock provides the injectable clock (go-conventions.md "Time").
//
// Everything that checks validity, schedules renewals or writes audit entries
// takes a Clock instead of calling time.Now, so tests control time exactly –
// certificate tests must never depend on the wall clock. Times are UTC.
package clock

import (
	"sync"
	"time"
)

// Clock returns the current time in UTC.
type Clock interface {
	Now() time.Time
}

// System is the real clock.
type System struct{}

// Now returns the current wall-clock time in UTC.
// It is the only place outside tests that may read the wall clock.
func (System) Now() time.Time { return time.Now().UTC() } //nolint:forbidigo // the injected clock itself

// Fake is a manually controlled clock for tests. It is safe for concurrent
// use; time only moves when Set or Advance is called.
type Fake struct {
	mu  sync.Mutex
	now time.Time
}

// NewFake returns a fake clock standing at t (converted to UTC).
func NewFake(t time.Time) *Fake {
	return &Fake{now: t.UTC()}
}

// Now returns the fake time.
func (f *Fake) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}

// Set moves the clock to t (converted to UTC); it may go backwards, which
// lets tests simulate a wrong system clock.
func (f *Fake) Set(t time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.now = t.UTC()
}

// Advance moves the clock forward by d and returns the new time.
func (f *Fake) Advance(d time.Duration) time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.now = f.now.Add(d)
	return f.now
}
