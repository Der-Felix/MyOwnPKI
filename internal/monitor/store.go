package monitor

import (
	"context"
	"database/sql"
	"io"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/ids"
	"github.com/Der-Felix/MyOwnPKI/internal/store/systemdb"
)

// Alert is one row of the alerts table.
type Alert struct {
	ID, Key, Kind, Subject, Severity, Detail, Href string
	FirstSeen, LastSeen                            time.Time
	Resolved                                       time.Time // zero while open
	NotifiedSeverity                               string    // "" = not reported yet
	Notified                                       time.Time
}

// Open reports whether the alert still holds.
func (a Alert) Open() bool { return a.Resolved.IsZero() }

// Changes is what one Sync changed – for the log; notifications read the
// notified_* columns, so a lost Changes value loses no message.
type Changes struct {
	Opened, Raised, Lowered, Resolved []Alert
}

// Empty reports whether nothing changed.
func (c Changes) Empty() bool {
	return len(c.Opened)+len(c.Raised)+len(c.Lowered)+len(c.Resolved) == 0
}

// Store keeps the alerts of one tenant in system.db.
type Store struct {
	DB     *sql.DB // system.db, the write connection
	Tenant string
	Rand   io.Reader // nil = crypto/rand (IDs)
}

// Sync makes the open alerts match findings in one transaction: new keys
// open an alert, known keys are updated (and may rise or fall), open alerts
// without a finding are resolved.
func (s *Store) Sync(ctx context.Context, now time.Time, findings []Finding) (Changes, error) {
	var ch Changes
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return ch, err
	}
	defer func() { _ = tx.Rollback() }()
	q := systemdb.New(tx)
	rows, err := q.ListOpenAlerts(ctx, s.Tenant)
	if err != nil {
		return ch, err
	}
	open := make(map[string]systemdb.Alert, len(rows))
	for _, r := range rows {
		open[r.AlertKey] = r
	}
	ts := dbTime(now)
	seen := make(map[string]bool, len(findings))
	for _, f := range findings {
		if seen[f.Key] {
			continue
		}
		seen[f.Key] = true
		r, ok := open[f.Key]
		if !ok {
			id, err := ids.New("alr", now, s.Rand)
			if err != nil {
				return ch, err
			}
			if err := q.InsertAlert(ctx, systemdb.InsertAlertParams{
				ID: id, Tenant: s.Tenant, AlertKey: f.Key, Kind: f.Kind, Subject: f.Subject, Severity: f.Severity,
				Detail: f.Detail, Href: f.Href, FirstSeenAt: ts, LastSeenAt: ts,
			}); err != nil {
				return ch, err
			}
			ch.Opened = append(ch.Opened, Alert{ID: id, Key: f.Key, Kind: f.Kind, Subject: f.Subject, Severity: f.Severity,
				Detail: f.Detail, Href: f.Href, FirstSeen: now, LastSeen: now})
			continue
		}
		if err := q.UpdateOpenAlert(ctx, systemdb.UpdateOpenAlertParams{
			Subject: f.Subject, Severity: f.Severity, Detail: f.Detail, Href: f.Href, LastSeenAt: ts, ID: r.ID,
		}); err != nil {
			return ch, err
		}
		a := toAlert(r)
		a.Subject, a.Severity, a.Detail, a.Href, a.LastSeen = f.Subject, f.Severity, f.Detail, f.Href, now
		switch {
		case r.Severity == Warning && f.Severity == Critical:
			ch.Raised = append(ch.Raised, a)
		case r.Severity == Critical && f.Severity == Warning:
			ch.Lowered = append(ch.Lowered, a)
		}
	}
	for _, r := range rows {
		if seen[r.AlertKey] {
			continue
		}
		if err := q.ResolveAlert(ctx, systemdb.ResolveAlertParams{ResolvedAt: sql.NullString{String: ts, Valid: true}, ID: r.ID}); err != nil {
			return ch, err
		}
		a := toAlert(r)
		a.Resolved = now
		ch.Resolved = append(ch.Resolved, a)
	}
	return ch, tx.Commit()
}

// Open lists the open alerts, critical first.
func (s *Store) Open(ctx context.Context) ([]Alert, error) {
	rows, err := systemdb.New(s.DB).ListOpenAlerts(ctx, s.Tenant)
	if err != nil {
		return nil, err
	}
	return toAlerts(rows), nil
}

// Since lists the open alerts and those resolved at or after since.
func (s *Store) Since(ctx context.Context, since time.Time) ([]Alert, error) {
	rows, err := systemdb.New(s.DB).ListAlertsSince(ctx, systemdb.ListAlertsSinceParams{
		Tenant: s.Tenant, ResolvedAt: sql.NullString{String: dbTime(since), Valid: true},
	})
	if err != nil {
		return nil, err
	}
	return toAlerts(rows), nil
}

// Prune deletes alerts resolved before cutoff.
func (s *Store) Prune(ctx context.Context, cutoff time.Time) (int64, error) {
	return systemdb.New(s.DB).DeleteResolvedAlertsBefore(ctx, sql.NullString{String: dbTime(cutoff), Valid: true})
}

func toAlerts(rows []systemdb.Alert) []Alert {
	out := make([]Alert, 0, len(rows))
	for _, r := range rows {
		out = append(out, toAlert(r))
	}
	return out
}

func toAlert(r systemdb.Alert) Alert {
	return Alert{
		ID: r.ID, Key: r.AlertKey, Kind: r.Kind, Subject: r.Subject, Severity: r.Severity, Detail: r.Detail, Href: r.Href,
		FirstSeen: parseTime(r.FirstSeenAt), LastSeen: parseTime(r.LastSeenAt), Resolved: parseNull(r.ResolvedAt),
		NotifiedSeverity: r.NotifiedSeverity.String, Notified: parseNull(r.NotifiedAt),
	}
}

func dbTime(t time.Time) string { return t.UTC().Format(time.RFC3339) }

func parseTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

func parseNull(s sql.NullString) time.Time {
	if !s.Valid {
		return time.Time{}
	}
	return parseTime(s.String)
}
