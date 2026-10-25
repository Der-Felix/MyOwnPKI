// Package clock provides the injectable clock (go-conventions.md "Time").
//
// Everything that checks validity, schedules renewals or writes audit entries
// takes a Clock instead of calling time.Now, so tests control time exactly –
// certificate tests must never depend on the wall clock. Times are UTC.
package clock

import (
	"context"
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
	mu    sync.Mutex
	now   time.Time
	waits map[*fakeWait]struct{}
}

type fakeWait struct {
	at   time.Time
	done chan struct{}
}

// Sleep is the production wait; scheduling code injects Fake.Sleep in tests.
func Sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Sleep waits until Set or Advance reaches the deadline, or ctx ends.
func (f *Fake) Sleep(ctx context.Context, d time.Duration) error {
	f.mu.Lock()
	if d <= 0 {
		f.mu.Unlock()
		return ctx.Err()
	}
	w := &fakeWait{f.now.Add(d), make(chan struct{})}
	if f.waits == nil {
		f.waits = map[*fakeWait]struct{}{}
	}
	f.waits[w] = struct{}{}
	f.mu.Unlock()
	defer func() { f.mu.Lock(); delete(f.waits, w); f.mu.Unlock() }()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-w.done:
		return nil
	}
}

func (f *Fake) wake() {
	for w := range f.waits {
		if !f.now.Before(w.at) {
			close(w.done)
			delete(f.waits, w)
		}
	}
}

// Waiting is the number of registered waits, for deterministic test barriers.
func (f *Fake) Waiting() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.waits) }

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
	f.wake()
}

// Advance moves the clock forward by d and returns the new time.
func (f *Fake) Advance(d time.Duration) time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.now = f.now.Add(d)
	f.wake()
	return f.now
}
