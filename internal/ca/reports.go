package ca

import (
	"context"
	"fmt"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/audit"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
)

// Read paths of the reports (docs/PHASE3.md section 14, step 45). Like
// CertificateCounts they leave out agent identity certificates and every CA
// the caller may not read; a tenant-wide role also sees the certificates
// without a CA (external ones).

// Issuance source classes (docs/PHASE3.md D6). The data tells them apart only
// by joins: an ACME order that points at the certificate, and whether the
// order's account belongs to an agent.
const (
	SourceUI    = "ui"    // no order: UI and API issuance share one engine call
	SourceACME  = "acme"  // an order of an account without an agent
	SourceAgent = "agent" // an order of an account that belongs to an agent
)

// Issuance is one issued certificate of the issuances report.
type Issuance struct {
	At     time.Time // when it was created (UTC)
	Source string    // SourceUI, SourceACME or SourceAgent
}

// readableCAs returns a function that tells whether the CA with this ID (""
// = no CA) may be read by who.
func (e *Engine) readableCAs(ctx context.Context, q *pkidb.Queries, who keys.Who, now time.Time) (func(caID string) bool, error) {
	names, err := caNames(ctx, q)
	if err != nil {
		return nil, err
	}
	return func(caID string) bool { return e.canRead(who, names[caID], now) }, nil
}

// ExpiryTimes returns the end of every certificate who may read that is not
// revoked and ends in (after, until]. Imported and external certificates are
// included, agent identity certificates are not. The caller buckets them.
func (e *Engine) ExpiryTimes(ctx context.Context, who keys.Who, after, until time.Time) ([]time.Time, error) {
	q := pkidb.New(e.PKI)
	may, err := e.readableCAs(ctx, q, who, e.now())
	if err != nil {
		return nil, err
	}
	rows, err := q.ExpiryTimes(ctx, pkidb.ExpiryTimesParams{After: after.UTC().Format(dbTime), Until: until.UTC().Format(dbTime)})
	if err != nil {
		return nil, err
	}
	out := make([]time.Time, 0, len(rows))
	for _, r := range rows {
		if !may(r.CaID.String) {
			continue
		}
		t, err := time.Parse(time.RFC3339, r.NotAfter)
		if err != nil {
			return nil, fmt.Errorf("certificate not_after %q: %w", r.NotAfter, err)
		}
		out = append(out, t.UTC())
	}
	return out, nil
}

// IssuanceSources returns the certificates issued in [since, until) that who
// may read, with their source class (SourceUI, SourceACME, SourceAgent).
// Only source "issued" counts: imported and external certificates are no
// issuances, agent identity certificates are left out.
func (e *Engine) IssuanceSources(ctx context.Context, who keys.Who, since, until time.Time) ([]Issuance, error) {
	q := pkidb.New(e.PKI)
	may, err := e.readableCAs(ctx, q, who, e.now())
	if err != nil {
		return nil, err
	}
	// created_at is stored with milliseconds, unlike not_after.
	rows, err := q.IssuanceSources(ctx, pkidb.IssuanceSourcesParams{
		Since: since.UTC().Format(audit.TimeFormat), Until: until.UTC().Format(audit.TimeFormat),
	})
	if err != nil {
		return nil, err
	}
	out := make([]Issuance, 0, len(rows))
	for _, r := range rows {
		if !may(r.CaID.String) {
			continue
		}
		t, err := time.Parse(time.RFC3339, r.CreatedAt)
		if err != nil {
			return nil, fmt.Errorf("certificate created_at %q: %w", r.CreatedAt, err)
		}
		out = append(out, Issuance{At: t.UTC(), Source: r.SourceClass})
	}
	return out, nil
}
