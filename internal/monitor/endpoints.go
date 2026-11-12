package monitor

import (
	"context"

	"github.com/Der-Felix/MyOwnPKI/internal/clock"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/tlsscan"
)

// Endpoints is the TLS scan as the REST API and the UI use it (docs/PHASE3.md
// §10): the endpoint service, which checks the roles and audits, plus the
// assessment the alerts follow, so that the page, the API and the alerts show
// the same state.
type Endpoints struct {
	Service *tlsscan.Service
	Eval    *Evaluator
	Clock   clock.Clock
}

// List returns every endpoint with its assessed state, by host. The endpoint
// service decides whether who may read (tenant-wide pki.read); the assessment
// itself is computed with the evaluator's system principal and only for what
// the service returned.
func (e *Endpoints) List(ctx context.Context, who keys.Who) ([]EndpointState, error) {
	eps, err := e.Service.List(ctx, who)
	if err != nil {
		return nil, err
	}
	states, err := e.Eval.EndpointStates(ctx, e.Clock.Now())
	if err != nil {
		return nil, err
	}
	byID := make(map[string]EndpointState, len(states))
	for _, s := range states {
		byID[s.Endpoint.ID] = s
	}
	out := make([]EndpointState, 0, len(eps))
	for _, ep := range eps {
		// An endpoint removed between the two reads is simply gone.
		if s, ok := byID[ep.ID]; ok {
			out = append(out, s)
		}
	}
	return out, nil
}

// Created is the state of an endpoint that was just added: nothing is known
// about it before its first scan.
func Created(ep tlsscan.Endpoint) EndpointState {
	return EndpointState{Endpoint: ep, Assessment: tlsscan.Assessment{State: tlsscan.StatePending}}
}

// Create adds an endpoint (permission endpoint.manage, audited by the service).
func (e *Endpoints) Create(ctx context.Context, who keys.Who, req tlsscan.Request) (*tlsscan.Endpoint, error) {
	return e.Service.Create(ctx, who, req)
}

// Delete removes an endpoint (permission endpoint.manage, audited).
func (e *Endpoints) Delete(ctx context.Context, who keys.Who, id string) error {
	return e.Service.Delete(ctx, who, id)
}

// ScanNow makes an endpoint due at once (permission endpoint.scan, audited,
// once per endpoint and 60 seconds: a *tlsscan.WaitError otherwise).
func (e *Endpoints) ScanNow(ctx context.Context, who keys.Who, id string) error {
	return e.Service.ScanNow(ctx, who, id)
}

// Settings are the monitor.scan_* keys the scan runs with (the allowed ports,
// the limit of endpoints, scanning off) – the page shows them next to the add
// form.
func (e *Endpoints) Settings() tlsscan.Settings { return e.Service.Settings }
