package agents

import (
	"context"
	"crypto/rand"
	"errors"
	"math/big"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/clock"
	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
)

const MaxWatches = 1024

var (
	ErrWatchClosed   = errors.New("the agent service is shutting down")
	ErrWatchReplaced = errors.New("a newer watch replaced this agent's watch")
)

type watchSlot struct {
	done   chan struct{}
	reason error
}

type DesiredDeployment struct {
	Name, RequestedAt string
	RenewalVersion    int64
}
type DesiredState struct {
	Version      int64
	Changed      bool
	AllowedNames []string
	Deployments  []DesiredDeployment
}

func (s *Service) subscribe(id string) (*watchSlot, error) {
	s.watchMu.Lock()
	defer s.watchMu.Unlock()
	if s.watchesClosed {
		return nil, ErrWatchClosed
	}
	if s.watches == nil {
		s.watches = map[string]*watchSlot{}
	}
	if old := s.watches[id]; old != nil {
		old.reason = ErrWatchReplaced
		close(old.done)
	} else if len(s.watches) >= MaxWatches {
		return nil, ErrRateLimited
	}
	slot := &watchSlot{done: make(chan struct{})}
	s.watches[id] = slot
	return slot, nil
}

func (s *Service) notify(id string) {
	s.watchMu.Lock()
	defer s.watchMu.Unlock()
	if slot := s.watches[id]; slot != nil {
		delete(s.watches, id)
		close(slot.done)
	}
}

// CloseWatches is called before HTTP shutdown, so long polls release the
// request budget immediately. A service closed this way is never reused.
func (s *Service) CloseWatches() {
	s.watchMu.Lock()
	defer s.watchMu.Unlock()
	s.watchesClosed = true
	for id, slot := range s.watches {
		slot.reason = ErrWatchClosed
		close(slot.done)
		delete(s.watches, id)
	}
}

func (s *Service) desired(ctx context.Context, id string) (*DesiredState, error) {
	q := pkidb.New(s.PKI)
	a, err := q.GetAgent(ctx, id)
	if err != nil {
		return nil, err
	}
	if a.Status != StatusActive {
		return nil, ErrUnknownAgent
	}
	rows, err := q.ListAgentNames(ctx, id)
	if err != nil {
		return nil, err
	}
	out := &DesiredState{Version: a.DesiredVersion, AllowedNames: []string{}, Deployments: []DesiredDeployment{}}
	for _, row := range rows {
		out.AllowedNames = append(out.AllowedNames, row.Pattern)
	}
	deployments, err := q.ListAgentDeployments(ctx, id)
	if err != nil {
		return nil, err
	}
	for _, d := range deployments {
		if d.RenewRequestedAt.Valid {
			out.Deployments = append(out.Deployments, DesiredDeployment{d.Name, d.RenewRequestedAt.String, d.RenewRequestedVersion.Int64})
		}
	}
	return out, nil
}

// WatchDesiredState subscribes before reading the database: a commit
// between the read and the wait can never be lost.
func (s *Service) WatchDesiredState(ctx context.Context, c *Caller, known int64) (*DesiredState, error) {
	if !s.limiter().allow("watch:"+c.Agent.ID, watchPerWindow, 10*time.Minute, s.now()) {
		return nil, ErrRateLimited
	}
	if known < 0 {
		return nil, ErrInvalid
	}
	slot, err := s.subscribe(c.Agent.ID)
	if err != nil {
		return nil, err
	}
	defer func() {
		s.watchMu.Lock()
		if s.watches[c.Agent.ID] == slot {
			delete(s.watches, c.Agent.ID)
		}
		s.watchMu.Unlock()
	}()
	state, err := s.desired(ctx, c.Agent.ID)
	if err != nil {
		return nil, err
	}
	if state.Version != known {
		state.Changed = true
		return state, nil
	}
	wait := s.Sleep
	if wait == nil {
		wait = clock.Sleep
	}
	r, err := rand.Int(s.rnd(), big.NewInt(int64(5*time.Second)+1))
	if err != nil {
		return nil, err
	}
	waitCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	timeout := make(chan error, 1)
	go func() { timeout <- wait(waitCtx, 45*time.Second+time.Duration(r.Int64())) }()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-slot.done:
		if slot.reason != nil {
			return nil, slot.reason
		}
	case waitErr := <-timeout:
		if waitErr != nil {
			return nil, waitErr
		}
	}
	state, err = s.desired(ctx, c.Agent.ID)
	if err == nil {
		state.Changed = state.Version != known
	}
	return state, err
}
