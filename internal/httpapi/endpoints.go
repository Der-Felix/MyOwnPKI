package httpapi

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/monitor"
	"github.com/Der-Felix/MyOwnPKI/internal/tlsscan"
)

// TLS scan (v0.3.4, docs/PHASE3.md §10): the endpoints an admin entered and
// what each one serves. The tlsscan service checks the roles, applies the
// rules and writes the audit entries – refusals included – so the handlers
// here only translate between HTTP and it and never audit a second time.

// maxEndpointBody is the body limit of createEndpoint: three short strings.
const maxEndpointBody = 4 << 10

type endpointJSON struct {
	ID             string      `json:"id"`
	Host           string      `json:"host"`
	Port           int         `json:"port"`
	SNI            *string     `json:"sni"`
	Name           string      `json:"name"`
	Source         string      `json:"source"`
	CreatedAt      time.Time   `json:"created_at"`
	CreatedBy      *string     `json:"created_by,omitempty"`
	State          string      `json:"state"`
	ExpirySeverity *string     `json:"expiry_severity"`
	NextScanAt     time.Time   `json:"next_scan_at"`
	LastScanAt     *time.Time  `json:"last_scan_at"`
	LastOKAt       *time.Time  `json:"last_ok_at"`
	FailStreak     int         `json:"fail_streak"`
	LastErrorKind  *string     `json:"last_error_kind"`
	Served         *servedJSON `json:"served"`
}

type servedJSON struct {
	Fingerprint   string     `json:"fingerprint"`
	CertificateID *string    `json:"certificate_id"`
	Serial        string     `json:"serial"`
	Subject       string     `json:"subject"`
	Issuer        string     `json:"issuer"`
	NotBefore     time.Time  `json:"not_before"`
	NotAfter      time.Time  `json:"not_after"`
	ChainLen      int        `json:"chain_len"`
	ChainState    string     `json:"chain_state"`
	TLSVersion    string     `json:"tls_version"`
	SeenCount     int        `json:"seen_count"`
	SeenSince     *time.Time `json:"seen_since"`
}

// toEndpointJSON is the API form of an endpoint with its assessed state.
// creator says whether who added it is shown: only to roles that manage
// endpoints, not to viewers and operators (the user names of the tenant).
func toEndpointJSON(s monitor.EndpointState, creator bool) endpointJSON {
	ep := s.Endpoint
	out := endpointJSON{
		ID: ep.ID, Host: ep.Host, Port: ep.Port, Name: ep.Name(), Source: ep.Source, CreatedAt: ep.CreatedAt,
		State: s.Assessment.State, NextScanAt: ep.NextScanAt, LastScanAt: timeOrNil(ep.LastScanAt), LastOKAt: timeOrNil(ep.LastOKAt),
		FailStreak: ep.FailStreak,
	}
	if ep.SNI != "" {
		out.SNI = &ep.SNI
	}
	if creator {
		out.CreatedBy = &ep.CreatedBy
	}
	if al := s.Assessment.Expiry; al != nil {
		out.ExpirySeverity = &al.Severity
	}
	if tlsscan.KnownKind(ep.LastErrorKind) {
		out.LastErrorKind = &ep.LastErrorKind
	}
	if ep.Fingerprint != "" {
		sv := &servedJSON{
			Fingerprint: ep.Fingerprint, Serial: ep.Serial, Subject: ep.Subject, Issuer: ep.Issuer, NotBefore: ep.NotBefore,
			NotAfter: ep.NotAfter, ChainLen: ep.ChainLen, ChainState: ep.ChainState, TLSVersion: ep.TLSVersion,
			SeenCount: ep.SameCount, SeenSince: timeOrNil(ep.FingerprintSince),
		}
		if s.ServedID != "" {
			sv.CertificateID = &s.ServedID
		}
		out.Served = sv
	}
	return out
}

// endpointsOn returns the endpoint service or the "off" answer.
func (a *API) endpointsOn(c *call) (*monitor.Endpoints, error) {
	if a.d.Endpoints == nil {
		return nil, c.problem(http.StatusNotFound, "not-found", "monitoring is off", nil)
	}
	return a.d.Endpoints, nil
}

// mayManageEndpoints reports whether the caller holds endpoint.manage for the
// whole tenant – the roles that see who added an endpoint.
func (a *API) mayManageEndpoints(c *call) bool {
	if c.session == nil {
		return false
	}
	return c.session.Principal.Check(authz.ManageEndpoints, authz.Resource{Tenant: a.d.Tenant}, a.now()) == nil
}

func (a *API) listEndpoints(c *call) error {
	s, err := a.endpointsOn(c)
	if err != nil {
		return err
	}
	states, err := s.List(c.ctx(), c.who())
	if err != nil {
		return err
	}
	creator := a.mayManageEndpoints(c)
	out := make([]endpointJSON, 0, len(states))
	for _, st := range states {
		out = append(out, toEndpointJSON(st, creator))
	}
	return c.reply(http.StatusOK, out)
}

func (a *API) createEndpoint(c *call) error {
	s, err := a.endpointsOn(c)
	if err != nil {
		return err
	}
	var req struct {
		Host string `json:"host"`
		Port int    `json:"port"`
		SNI  string `json:"sni"`
	}
	if derr := c.decode(&req); derr != nil {
		return derr
	}
	ep, err := s.Create(c.ctx(), c.who(), tlsscan.Request{Host: req.Host, Port: req.Port, SNI: req.SNI})
	if err != nil {
		return err
	}
	return c.reply(http.StatusCreated, toEndpointJSON(monitor.Created(*ep), true))
}

func (a *API) deleteEndpoint(c *call) error {
	s, err := a.endpointsOn(c)
	if err != nil {
		return err
	}
	// The raw path value: the service checks the role first and treats an ID that is not well-formed as unknown (403 before 404).
	id := c.r.PathValue("endpointId")
	if err := s.Delete(c.ctx(), c.who(), id); err != nil {
		return err
	}
	c.status = http.StatusNoContent
	c.w.WriteHeader(http.StatusNoContent)
	return nil
}

func (a *API) scanEndpoint(c *call) error {
	s, err := a.endpointsOn(c)
	if err != nil {
		return err
	}
	// The raw path value: the service checks the role first and treats an ID that is not well-formed as unknown (403 before 404).
	id := c.r.PathValue("endpointId")
	if err := s.ScanNow(c.ctx(), c.who(), id); err != nil {
		return err
	}
	c.status = http.StatusAccepted
	c.w.WriteHeader(http.StatusAccepted)
	return nil
}

// endpointError maps the errors of the tlsscan service. Only InvalidError
// carries input-dependent text: the field and the rule, written by the
// service, never an address that was resolved.
func endpointError(c *call, err error) bool {
	var invalid *tlsscan.InvalidError
	var wait *tlsscan.WaitError
	switch {
	case errors.As(err, &invalid):
		_ = c.problem(http.StatusUnprocessableEntity, "policy-violation", "the endpoint is refused",
			[]fieldError{{Field: "/" + invalid.Field, Message: invalid.Rule}})
	case errors.As(err, &wait):
		c.retryAfter(wait.RetryAfter)
		_ = c.problem(http.StatusTooManyRequests, "rate-limited", wait.Error(), nil)
	case errors.Is(err, tlsscan.ErrConflict):
		_ = c.problem(http.StatusConflict, "conflict", strings.TrimPrefix(err.Error(), tlsscan.ErrConflict.Error()+": "), nil)
	default:
		return false
	}
	return true
}
