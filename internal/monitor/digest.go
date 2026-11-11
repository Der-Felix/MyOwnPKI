package monitor

import (
	"context"
	"database/sql"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/notify"
	"github.com/Der-Felix/MyOwnPKI/internal/store/systemdb"
)

// DigestOptions shape the digest of one evaluation.
type DigestOptions struct {
	Server      string              // host name in the subject
	RepeatEvery time.Duration       // reminder for an alert still open
	Link        func(string) string // UI path → absolute link; nil = none
	Channels    []string            // queue one message per channel
}

// Digest collects what to report since the last digest – new alerts, alerts
// that became critical, reminders, resolved alerts whose opening was
// reported – marks them and queues one message per channel, all in one
// transaction. It returns the digest (no events = nothing queued). Without
// channels nothing is marked: once a channel is configured, the first
// message lists every open alert.
func (s *Store) Digest(ctx context.Context, now time.Time, opt DigestOptions) (notify.Digest, error) {
	d := notify.Digest{Server: opt.Server, Created: now.UTC()}
	if len(opt.Channels) == 0 {
		return d, nil
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return d, err
	}
	defer func() { _ = tx.Rollback() }()
	q := systemdb.New(tx)
	open, err := q.ListOpenAlerts(ctx, s.Tenant)
	if err != nil {
		return d, err
	}
	ts := sql.NullString{String: dbTime(now), Valid: true}
	link := func(href string) string {
		if opt.Link == nil || href == "" {
			return ""
		}
		return opt.Link(href)
	}
	for _, r := range open {
		a := toAlert(r)
		state := ""
		switch {
		case a.NotifiedSeverity == "":
			state = notify.Opened
		case a.NotifiedSeverity == Warning && a.Severity == Critical:
			state = notify.Raised
		case now.Sub(a.Notified) >= opt.RepeatEvery:
			state = notify.Reminder
		case a.NotifiedSeverity != a.Severity:
			// Critical → warning: no message, but remember it, so a
			// second rise is reported again.
			if err = q.MarkAlertNotified(ctx, systemdb.MarkAlertNotifiedParams{
				NotifiedSeverity: sql.NullString{String: a.Severity, Valid: true}, NotifiedAt: r.NotifiedAt, ID: a.ID,
			}); err != nil {
				return d, err
			}
			continue
		default:
			continue
		}
		d.Events = append(d.Events, notify.Event{Kind: a.Kind, Subject: a.Subject, Severity: a.Severity, State: state,
			Since: a.FirstSeen, Detail: a.Detail, Link: link(a.Href)})
		if err = q.MarkAlertNotified(ctx, systemdb.MarkAlertNotifiedParams{
			NotifiedSeverity: sql.NullString{String: a.Severity, Valid: true}, NotifiedAt: ts, ID: a.ID,
		}); err != nil {
			return d, err
		}
	}
	resolved, err := q.ListResolvedUnnotified(ctx, s.Tenant)
	if err != nil {
		return d, err
	}
	for _, r := range resolved {
		a := toAlert(r)
		d.Events = append(d.Events, notify.Event{Kind: a.Kind, Subject: a.Subject, Severity: a.Severity, State: notify.Resolved,
			Since: a.FirstSeen, Detail: a.Detail, Link: link(a.Href)})
		if err = q.MarkAlertResolveNotified(ctx, a.ID); err != nil {
			return d, err
		}
	}
	if len(d.Events) > 0 {
		if err = notify.Enqueue(ctx, tx, now, d, opt.Channels); err != nil {
			return d, err
		}
	}
	return d, tx.Commit()
}
