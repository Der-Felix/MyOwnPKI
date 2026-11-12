package tlsscan

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
)

// The scanner's side of the endpoints table. One transaction, one database:
// a scan writes only its own row here, and the evaluation reads it and
// writes alerts to system.db in another transaction (ADR-06).

// claimDue claims up to limit endpoints that are due at now and are not in
// skip: each one's next scan moves to next(id) first, so neither a crash nor
// a slow scan makes it due again at once. An endpoint whose next scan lies
// beyond horizon is due as well: the clock was ahead when it was claimed.
func (s *Service) claimDue(ctx context.Context, now, horizon time.Time, limit int, skip func(id string) bool, next func() time.Time) ([]Endpoint, error) {
	if limit <= 0 {
		return nil, nil
	}
	tx, err := s.PKI.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	q := pkidb.New(tx)
	// Endpoints in flight can be due again (scan now), so ask for more.
	rows, err := q.ListDueEndpoints(ctx, pkidb.ListDueEndpointsParams{NextScanAt: dbTime(now), NextScanAt_2: dbTime(horizon), Limit: int64(limit) * 4})
	if err != nil {
		return nil, err
	}
	var claimed []Endpoint
	for _, r := range rows {
		if len(claimed) == limit {
			break
		}
		if skip(r.ID) {
			continue
		}
		n, err := q.ClaimEndpoint(ctx, pkidb.ClaimEndpointParams{NextScanAt: dbTime(next()), ID: r.ID, NextScanAt_2: r.NextScanAt})
		if err != nil {
			return nil, err
		}
		if n == 1 {
			claimed = append(claimed, toEndpoint(r))
		}
	}
	return claimed, tx.Commit()
}

// served is what a successful scan found out about the served leaf.
type served struct {
	Fingerprint, Serial, Subject, Issuer string
	NotBefore, NotAfter                  time.Time
	ChainLen                             int
	ChainState, TLSVersion               string
}

// recordSuccess stores a good scan. It counts the successful scans in a row
// that saw this fingerprint.
func (s *Service) recordSuccess(ctx context.Context, id string, now, next time.Time, v served) error {
	tx, err := s.PKI.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	q := pkidb.New(tx)
	prev, err := q.GetEndpoint(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil // deleted while the scan ran: nothing to record
	} else if err != nil {
		return err
	}
	same, since := int64(1), now
	if prev.Fingerprint.Valid && prev.Fingerprint.String == v.Fingerprint {
		same, since = prev.SameCount+1, parseTime(prev.FingerprintSince.String)
	}
	if err := q.RecordScanSuccess(ctx, pkidb.RecordScanSuccessParams{
		LastScanAt: nullString(dbTime(now)), LastOkAt: nullString(dbTime(now)),
		Fingerprint: nullString(v.Fingerprint), Serial: nullString(v.Serial), Subject: nullString(v.Subject), Issuer: nullString(v.Issuer),
		NotBefore: nullString(dbTime(v.NotBefore)), NotAfter: nullString(dbTime(v.NotAfter)),
		ChainLen: sql.NullInt64{Int64: int64(v.ChainLen), Valid: true}, ChainState: nullString(v.ChainState), TlsVersion: nullString(v.TLSVersion),
		SameCount: same, FingerprintSince: nullString(dbTime(since)), NextScanAt: dbTime(next), ID: id,
	}); err != nil {
		return err
	}
	return tx.Commit()
}

// recordFailure stores a failed scan: the kind from the fixed vocabulary and
// its fixed message. The last good scan's data stays.
func (s *Service) recordFailure(ctx context.Context, id string, now, next time.Time, kind, message string) error {
	return s.inTxQuiet(ctx, func(q *pkidb.Queries) error {
		return q.RecordScanFailure(ctx, pkidb.RecordScanFailureParams{
			LastScanAt: nullString(dbTime(now)), LastErrorKind: nullString(kind), LastError: nullString(clean(message, 200)),
			NextScanAt: dbTime(next), ID: id,
		})
	})
}

// inTxQuiet is a transaction without the audit wake-up: scans write no audit
// entries.
func (s *Service) inTxQuiet(ctx context.Context, fn func(q *pkidb.Queries) error) error {
	tx, err := s.PKI.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := fn(pkidb.New(tx)); err != nil {
		return err
	}
	return tx.Commit()
}
