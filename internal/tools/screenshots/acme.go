package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/acme"
	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/clock"
	"github.com/Der-Felix/MyOwnPKI/internal/ids"
	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
)

// sampleACME switches the ACME server on and fills its pages (PHASE2 step
// 13): a domain, an approved and a waiting account, a waiting name, an EAB
// key and three orders – all in the neutral demo name space.
func (in *instance) sampleACME(ctx context.Context, e *ca.Engine, clk clock.Clock) (*acme.Server, error) {
	if xerr := in.ring.Unseal(ctx, []byte(in.passphrase), console); xerr != nil {
		return nil, xerr
	}
	defer func() { _ = in.ring.Seal(ctx, console) }()
	s, err := acme.New(acme.Options{Engine: e, BaseURL: "https://pki.homelab.example/acme", Clock: clk})
	if err != nil {
		return nil, err
	}
	issuing, wild := "issuing", false
	if _, derr := e.CreateDomain(ctx, ca.DomainRequest{Name: "homelab.example", DomainSettings: ca.DomainSettings{CA: &issuing, Wildcards: &wild,
		IPRanges: []string{"192.0.2.0/24"}}, Who: console}); derr != nil {
		return nil, derr
	}
	if _, kerr := s.CreateEABKey(ctx, "backup.homelab.example", acme.DefaultEABDays, console); kerr != nil {
		return nil, kerr
	}
	q := pkidb.New(e.PKI)
	now := clk.Now().UTC()
	stamp := func(ago time.Duration) string { return now.Add(-ago).Format("2006-01-02T15:04:05Z") }
	id := func(prefix string, ago time.Duration) string {
		v, _ := ids.New(prefix, now.Add(-ago), rand.Reader)
		return v
	}
	approved, waiting := id("acc", 50*time.Hour), id("acc", 20*time.Minute)
	for _, a := range []pkidb.InsertACMEAccountParams{
		{ID: approved, KeyThumbprint: "hXv2kR9nC0pQe7sWm3LdYt8uFa1bZo6JgKiN4cVrE5w", Jwk: `{}`, Status: "valid", Contact: `["mailto:admin@homelab.example"]`,
			ApprovedAt: sql.NullString{String: stamp(49 * time.Hour), Valid: true}, ApprovedBy: sql.NullString{String: "demo", Valid: true},
			CreatedAt: stamp(50 * time.Hour), CreatedIp: "192.0.2.20", UpdatedAt: stamp(49 * time.Hour)},
		{ID: waiting, KeyThumbprint: "Q3mT8wYc1Vb5nRk0LsJ7eHd2GpX9aZu4oFi6CqWlE8s", Jwk: `{}`, Status: "valid", Contact: `["mailto:nas@homelab.example"]`,
			CreatedAt: stamp(20 * time.Minute), CreatedIp: "192.0.2.10", UpdatedAt: stamp(20 * time.Minute)},
	} {
		if ierr := q.InsertACMEAccount(ctx, a); ierr != nil {
			return nil, ierr
		}
	}
	if xerr := q.RequestACMEName(ctx, pkidb.RequestACMENameParams{Name: "dns:printer.homelab.example", RequestedBy: approved, RequestedAt: stamp(5 * time.Minute)}); xerr != nil {
		return nil, xerr
	}
	if xerr := s.DecideName(ctx, "dns:web.homelab.example", true, console); xerr != nil {
		return nil, xerr
	}
	for _, o := range []pkidb.InsertACMEOrderParams{
		{ID: id("ord", 48*time.Hour), AccountID: approved, Status: "pending", Identifiers: `[{"type":"dns","value":"web.homelab.example"}]`,
			ExpiresAt: stamp(24 * time.Hour), CreatedAt: stamp(48 * time.Hour), UpdatedAt: stamp(48 * time.Hour)},
		{ID: id("ord", 3*time.Hour), AccountID: approved, Status: "pending", Identifiers: `[{"type":"dns","value":"wiki.homelab.example"}]`,
			ExpiresAt: stamp(-21 * time.Hour), CreatedAt: stamp(3 * time.Hour), UpdatedAt: stamp(3 * time.Hour)},
		{ID: id("ord", 2*time.Hour), AccountID: approved, Status: "pending", Identifiers: `[{"type":"dns","value":"nas.homelab.example"},{"type":"dns","value":"files.homelab.example"},{"type":"ip","value":"192.0.2.10"}]`,
			ExpiresAt: stamp(-22 * time.Hour), CreatedAt: stamp(2 * time.Hour), UpdatedAt: stamp(2 * time.Hour)},
	} {
		if xerr := q.InsertACMEOrder(ctx, o); xerr != nil {
			return nil, xerr
		}
	}
	// Their outcome, as the server records it.
	orders, err := q.ListACMEOrders(ctx, 10)
	if err != nil {
		return nil, err
	}
	for _, o := range orders {
		switch o.Identifiers {
		case `[{"type":"dns","value":"web.homelab.example"}]`:
			err = q.SetACMEOrderStatus(ctx, pkidb.SetACMEOrderStatusParams{Status: "invalid", UpdatedAt: o.CreatedAt, ID: o.ID,
				Error: sql.NullString{String: `{"type":"urn:ietf:params:acme:error:rejectedIdentifier","detail":"the order expired before its challenges were solved","status":403}`, Valid: true}})
		case `[{"type":"dns","value":"wiki.homelab.example"}]`:
			err = q.SetACMEOrderStatus(ctx, pkidb.SetACMEOrderStatusParams{Status: "invalid", UpdatedAt: o.CreatedAt, ID: o.ID,
				Error: sql.NullString{String: `{"type":"urn:ietf:params:acme:error:incorrectResponse","detail":"http://wiki.homelab.example/.well-known/acme-challenge/… answered with status 404","status":403}`, Valid: true}})
		default:
			_, err = e.PKI.ExecContext(ctx, `UPDATE acme_orders SET status = 'valid', certificate_id = ? WHERE id = ?`, in.detailID, o.ID)
		}
		if err != nil {
			return nil, err
		}
	}
	in.deps.ACME, in.deps.ACMEDirectory = s, s.BaseURL()+"/directory"
	return s, nil
}
