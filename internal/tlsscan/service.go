package tlsscan

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/audit"
	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/clock"
	"github.com/Der-Felix/MyOwnPKI/internal/ids"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/netguard"
	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
)

// Audit actions of the endpoints. A refusal is audited too (denied or
// failure), so an attempt to point the server at 127.0.0.1 is on record.
const (
	ActionCreate = "endpoint.create"
	ActionDelete = "endpoint.delete"
	ActionScan   = "endpoint.scan" // scan now
)

// Service keeps the endpoints of one tenant. It checks permissions itself:
// the REST API and the UI call it, so neither can bypass them
// (security.md "Authorization").
type Service struct {
	PKI      *sql.DB // pki.db writer
	Tenant   string
	Engine   *ca.Engine // domains for the host rule, the audit log for refusals
	Clock    clock.Clock
	Settings Settings
	// Wake is called after a commit with an outbox row (audit delivery).
	Wake func()
	// Kick is called after a "scan now": the dispatcher looks for due
	// endpoints at once instead of at its next tick. nil = wait for the tick.
	Kick func()
	Rand io.Reader // nil = crypto/rand
}

func (s *Service) now() time.Time { return s.Clock.Now().UTC().Truncate(time.Second) }

func (s *Service) rnd() io.Reader {
	if s.Rand != nil {
		return s.Rand
	}
	return rand.Reader
}

// authorize checks perm on the whole tenant: a role limited to one CA does
// not count, the endpoints name the hosts of the whole tenant.
func (s *Service) authorize(who keys.Who, perm authz.Permission) error {
	return who.Principal.Check(perm, authz.Resource{Tenant: s.Tenant}, s.Clock.Now())
}

// List returns every endpoint, by host. It needs the tenant-wide read role.
func (s *Service) List(ctx context.Context, who keys.Who) ([]Endpoint, error) {
	if err := s.authorize(who, authz.ReadPKI); err != nil {
		return nil, err
	}
	return s.list(ctx)
}

func (s *Service) list(ctx context.Context) ([]Endpoint, error) {
	rows, err := pkidb.New(s.PKI).ListEndpoints(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]Endpoint, 0, len(rows))
	for _, r := range rows {
		out = append(out, toEndpoint(r))
	}
	return out, nil
}

// Get returns one endpoint.
func (s *Service) Get(ctx context.Context, who keys.Who, id string) (*Endpoint, error) {
	if err := s.authorize(who, authz.ReadPKI); err != nil {
		return nil, err
	}
	r, err := pkidb.New(s.PKI).GetEndpoint(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	} else if err != nil {
		return nil, err
	}
	e := toEndpoint(r)
	return &e, nil
}

// Create adds an endpoint (permission endpoint.manage). The host must be
// covered by a domain, the port must be on monitor.scan_ports, and the
// address policy of that domain applies (docs/PHASE3.md §10.2). It is
// scanned at the next dispatch.
func (s *Service) Create(ctx context.Context, who keys.Who, req Request) (*Endpoint, error) {
	e, err := s.create(ctx, who, req)
	details := map[string]any{"host": clean(req.Host, 100), "port": req.Port}
	if req.SNI != "" {
		details["sni"] = clean(req.SNI, 100)
	}
	return e, s.refused(ctx, who, ActionCreate, audit.Target{Type: "endpoint"}, details, err)
}

func (s *Service) create(ctx context.Context, who keys.Who, req Request) (*Endpoint, error) {
	if err := s.authorize(who, authz.ManageEndpoints); err != nil {
		return nil, err
	}
	c, err := s.Settings.check(req)
	if err != nil {
		return nil, err
	}
	typ := "dns"
	if c.IP.IsValid() {
		typ = "ip"
	}
	d, err := s.Engine.DomainFor(ctx, typ, c.Host)
	if err != nil {
		return nil, err
	}
	if d == nil {
		return nil, &InvalidError{"host", "no domain covers this host – the host must lie in a domain of this PKI (Domains)"}
	}
	if c.IP.IsValid() {
		if aerr := netguard.Allowed(c.IP, d.AddressPolicy); aerr != nil {
			return nil, &InvalidError{"host", fmt.Sprintf("the address policy of the domain %q (%s) does not allow this address", d.Name, d.AddressPolicy)}
		}
	}
	now := s.now()
	id, err := ids.New("ep", now, s.rnd())
	if err != nil {
		return nil, err
	}
	err = s.inTx(ctx, func(q *pkidb.Queries, tx *sql.Tx) error {
		n, cerr := q.CountEndpoints(ctx)
		if cerr != nil {
			return cerr
		}
		if int(n) >= s.Settings.MaxEndpoints {
			return fmt.Errorf("%w: the limit of %d endpoints is reached (monitor.scan_max_endpoints) – remove one first", ErrConflict, s.Settings.MaxEndpoints)
		}
		if _, ferr := q.FindEndpoint(ctx, pkidb.FindEndpointParams{Host: c.Host, Port: int64(c.Port), Sni: sql.NullString{String: c.SNI, Valid: true}}); ferr == nil {
			return fmt.Errorf("%w: this endpoint is entered already", ErrConflict)
		} else if !errors.Is(ferr, sql.ErrNoRows) {
			return ferr
		}
		if ierr := q.InsertEndpoint(ctx, pkidb.InsertEndpointParams{
			ID: id, Host: c.Host, Port: int64(c.Port), Sni: nullString(c.SNI), Source: SourceManual,
			CreatedAt: dbTime(now), CreatedBy: who.Actor.Name, NextScanAt: dbTime(now),
		}); ierr != nil {
			return ierr
		}
		details := map[string]any{"host": c.Host, "port": c.Port, "source": SourceManual}
		if c.SNI != "" {
			details["sni"] = c.SNI
		}
		return enqueue(ctx, tx, now, who, ActionCreate, audit.Target{Type: "endpoint", ID: id}, details)
	})
	if err != nil {
		return nil, err
	}
	r, err := pkidb.New(s.PKI).GetEndpoint(ctx, id)
	if err != nil {
		return nil, err
	}
	e := toEndpoint(r)
	return &e, nil
}

// Delete removes an endpoint (permission endpoint.manage). Its alerts resolve
// with the next evaluation.
func (s *Service) Delete(ctx context.Context, who keys.Who, id string) error {
	return s.refused(ctx, who, ActionDelete, audit.Target{Type: "endpoint", ID: id}, nil, s.delete(ctx, who, id))
}

func (s *Service) delete(ctx context.Context, who keys.Who, id string) error {
	if err := s.authorize(who, authz.ManageEndpoints); err != nil {
		return err
	}
	now := s.now()
	return s.inTx(ctx, func(q *pkidb.Queries, tx *sql.Tx) error {
		r, err := q.GetEndpoint(ctx, id)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		if _, err := q.DeleteEndpoint(ctx, id); err != nil {
			return err
		}
		details := map[string]any{"host": r.Host, "port": r.Port}
		if r.Sni.Valid {
			details["sni"] = r.Sni.String
		}
		return enqueue(ctx, tx, now, who, ActionDelete, audit.Target{Type: "endpoint", ID: id}, details)
	})
}

// ScanNow makes an endpoint due at once (permission endpoint.scan): no new
// target, so the operator role is enough. At most once per endpoint and 60
// seconds – a *WaitError says how long to wait; the time is kept in the row,
// so a restart does not forget it. It does not wait for the scan.
func (s *Service) ScanNow(ctx context.Context, who keys.Who, id string) error {
	err := s.scanNow(ctx, who, id)
	if err == nil && s.Kick != nil {
		s.Kick()
	}
	var wait *WaitError
	if errors.As(err, &wait) {
		return err // a too-eager click is no event for the audit log
	}
	return s.refused(ctx, who, ActionScan, audit.Target{Type: "endpoint", ID: id}, nil, err)
}

func (s *Service) scanNow(ctx context.Context, who keys.Who, id string) error {
	if err := s.authorize(who, authz.ScanEndpoint); err != nil {
		return err
	}
	if s.Settings.Off() {
		return ErrOff
	}
	now := s.now()
	return s.inTx(ctx, func(q *pkidb.Queries, tx *sql.Tx) error {
		n, err := q.RequestEndpointScan(ctx, pkidb.RequestEndpointScanParams{
			ScanRequestedAt: nullString(dbTime(now)), NextScanAt: dbTime(now), ID: id,
			ScanRequestedAt_2: nullString(dbTime(now.Add(-ScanNowEvery))),
		})
		if err != nil {
			return err
		}
		if n == 0 {
			r, gerr := q.GetEndpoint(ctx, id)
			if errors.Is(gerr, sql.ErrNoRows) {
				return ErrNotFound
			} else if gerr != nil {
				return gerr
			}
			return &WaitError{RetryAfter: parseTime(r.ScanRequestedAt.String).Add(ScanNowEvery).Sub(now)}
		}
		r, err := q.GetEndpoint(ctx, id)
		if err != nil {
			return err
		}
		return enqueue(ctx, tx, now, who, ActionScan, audit.Target{Type: "endpoint", ID: id}, map[string]any{"host": r.Host, "port": r.Port})
	})
}

// inTx runs fn in one pki.db transaction and wakes the audit delivery.
func (s *Service) inTx(ctx context.Context, fn func(q *pkidb.Queries, tx *sql.Tx) error) error {
	tx, err := s.PKI.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := fn(pkidb.New(tx), tx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	if s.Wake != nil {
		s.Wake()
	}
	return nil
}

func enqueue(ctx context.Context, tx *sql.Tx, now time.Time, who keys.Who, action string, target audit.Target, details map[string]any) error {
	return audit.Enqueue(ctx, tx, now, audit.Entry{
		Time: now, Actor: who.Actor, Action: action, Target: target, Result: audit.ResultSuccess,
		SourceIP: who.SourceIP, Details: details,
	})
}

// refused audits a refused action (denied by the role or the rules, or
// failed) and returns err. An unknown endpoint is not audited: it is no
// attempt at anything.
func (s *Service) refused(ctx context.Context, who keys.Who, action string, target audit.Target, details map[string]any, err error) error {
	if err == nil || errors.Is(err, ErrNotFound) {
		return err
	}
	result := audit.ResultFailure
	if errors.Is(err, authz.ErrDenied) || errors.Is(err, authz.ErrStepUpRequired) || errors.Is(err, ErrInvalid) {
		result = audit.ResultDenied
	}
	d := map[string]any{"error": clean(err.Error(), 300)}
	for k, v := range details {
		d[k] = v
	}
	if _, _, aerr := audit.Append(ctx, s.Engine.Audit, s.Engine.Scope, audit.Entry{
		Time: s.now(), Actor: who.Actor, Action: action, Target: target, Result: result, SourceIP: who.SourceIP, Details: d,
	}, ""); aerr != nil {
		return errors.Join(err, fmt.Errorf("audit: %w", aerr))
	}
	return err
}

func toEndpoint(r pkidb.Endpoint) Endpoint {
	return Endpoint{
		ID: r.ID, Host: r.Host, Port: int(r.Port), SNI: r.Sni.String, Source: r.Source,
		CreatedAt: parseTime(r.CreatedAt), CreatedBy: r.CreatedBy, NextScanAt: parseTime(r.NextScanAt),
		RequestedAt: parseNull(r.ScanRequestedAt), LastScanAt: parseNull(r.LastScanAt), LastOKAt: parseNull(r.LastOkAt),
		FailStreak: int(r.FailStreak), LastErrorKind: r.LastErrorKind.String, LastError: r.LastError.String,
		Fingerprint: r.Fingerprint.String, Serial: r.Serial.String, Subject: r.Subject.String, Issuer: r.Issuer.String,
		NotBefore: parseNull(r.NotBefore), NotAfter: parseNull(r.NotAfter),
		ChainLen: int(r.ChainLen.Int64), ChainState: r.ChainState.String, TLSVersion: r.TlsVersion.String,
		SameCount: int(r.SameCount), FingerprintSince: parseNull(r.FingerprintSince),
	}
}

const timeFormat = "2006-01-02T15:04:05Z"

func dbTime(t time.Time) string { return t.UTC().Format(timeFormat) }

func parseTime(s string) time.Time {
	t, err := time.Parse(timeFormat, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

func parseNull(n sql.NullString) time.Time {
	if !n.Valid {
		return time.Time{}
	}
	return parseTime(n.String)
}

func nullString(s string) sql.NullString { return sql.NullString{String: s, Valid: s != ""} }
