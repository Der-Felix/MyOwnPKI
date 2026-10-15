package server

import (
	"context"
	"log/slog"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/clock"
)

// job runs every interval. A failing job is logged with its name and runs
// again at its next time – it never stops the server.
type job struct {
	name  string
	every time.Duration
	next  time.Time
	run   func(context.Context) error
}

// scheduler runs due jobs. The clock only knows Now, so the loop wakes up
// regularly and asks what is due; tests call runDue with a fake clock.
type scheduler struct {
	clk  clock.Clock
	log  *slog.Logger
	jobs []*job
}

// add registers a job; first is the delay before its first run (0 = at the
// first check).
func (s *scheduler) add(name string, every, first time.Duration, run func(context.Context) error) {
	s.jobs = append(s.jobs, &job{name: name, every: every, next: s.clk.Now().Add(first), run: run})
}

// runDue runs every job whose time has come.
func (s *scheduler) runDue(ctx context.Context) {
	now := s.clk.Now()
	for _, j := range s.jobs {
		if now.Before(j.next) {
			continue
		}
		if err := j.run(ctx); err != nil && ctx.Err() == nil {
			s.log.Warn("job failed", slog.String("job", j.name), slog.Any("error", err))
		}
		j.next = now.Add(j.every)
	}
}

// runNow runs one job at once (the deliverer after a wake-up).
func (s *scheduler) runNow(ctx context.Context, name string) {
	for _, j := range s.jobs {
		if j.name == name {
			if err := j.run(ctx); err != nil && ctx.Err() == nil {
				s.log.Warn("job failed", slog.String("job", j.name), slog.Any("error", err))
			}
			return
		}
	}
}

// loop checks every tick and on wake (outbox written) until ctx ends.
func (s *scheduler) loop(ctx context.Context, tick time.Duration, wake <-chan struct{}) {
	t := time.NewTicker(tick)
	defer t.Stop()
	s.runDue(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.runDue(ctx)
		case <-wake:
			s.runNow(ctx, jobDeliver)
		}
	}
}
