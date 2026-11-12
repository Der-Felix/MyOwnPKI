package notify

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/store/systemdb"
)

// Channel delivers a digest.
type Channel interface {
	Name() string
	Send(ctx context.Context, d Digest) error
}

// Retries are the waits after the 1st, 2nd, … failed attempt; after the
// last one the message is dropped (and logged as an error).
var Retries = []time.Duration{time.Minute, 5 * time.Minute, 30 * time.Minute, 2 * time.Hour}

// Queue delivers the queued digests of system.db.
type Queue struct {
	DB       *sql.DB // system.db, the write connection
	Log      *slog.Logger
	Channels []Channel
}

// Enqueue adds d for every channel inside tx (the transaction that marks
// the alerts as notified, so a crash loses or doubles nothing).
func Enqueue(ctx context.Context, tx *sql.Tx, now time.Time, d Digest, channels []string) error {
	payload, err := d.JSON()
	if err != nil {
		return err
	}
	q := systemdb.New(tx)
	ts := dbTime(now)
	for _, ch := range channels {
		if _, err := q.InsertNotification(ctx, systemdb.InsertNotificationParams{
			Channel: ch, CreatedAt: ts, PayloadJson: string(payload), NextAttemptAt: ts,
		}); err != nil {
			return err
		}
	}
	return nil
}

// Names are the names of the configured channels.
func (q *Queue) Names() []string {
	out := make([]string, 0, len(q.Channels))
	for _, c := range q.Channels {
		out = append(out, c.Name())
	}
	return out
}

// Deliver sends every due message once. A failure schedules the next
// attempt; the error is logged, never returned – one broken channel must not
// stop the other one.
func (q *Queue) Deliver(ctx context.Context, now time.Time) error {
	db := systemdb.New(q.DB)
	due, err := db.ListDueNotifications(ctx, dbTime(now))
	if err != nil {
		return err
	}
	for _, n := range due {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		sendErr := q.send(ctx, n)
		switch {
		case sendErr == nil:
			err = db.MarkNotificationSent(ctx, systemdb.MarkNotificationSentParams{SentAt: null(dbTime(now)), ID: n.ID})
			if n.Attempts > 0 {
				q.Log.Info("notification sent", slog.String("channel", n.Channel), slog.Int64("attempt", n.Attempts+1))
			}
		case int(n.Attempts) < len(Retries):
			next := now.Add(Retries[n.Attempts])
			err = db.MarkNotificationRetry(ctx, systemdb.MarkNotificationRetryParams{NextAttemptAt: dbTime(next), LastError: null(sendErr.Error()), ID: n.ID})
			q.Log.Warn("notification failed – will retry", slog.String("channel", n.Channel), slog.Int64("attempt", n.Attempts+1),
				slog.Time("next_attempt", next), slog.String("error", sendErr.Error()))
		default:
			err = db.MarkNotificationDropped(ctx, systemdb.MarkNotificationDroppedParams{DroppedAt: null(dbTime(now)), LastError: null(sendErr.Error()), ID: n.ID})
			q.Log.Error("notification dropped after the last retry – the alerts are still on the dashboard", slog.String("channel", n.Channel),
				slog.Int64("attempts", n.Attempts+1), slog.String("error", sendErr.Error()))
		}
		if err != nil {
			return err
		}
	}
	return nil
}

var errNoChannel = errors.New("the channel is no longer configured")

func (q *Queue) send(ctx context.Context, n systemdb.Notification) error {
	d, err := ParseDigest([]byte(n.PayloadJson))
	if err != nil {
		return err
	}
	for _, c := range q.Channels {
		if c.Name() == n.Channel {
			return c.Send(ctx, d)
		}
	}
	return errNoChannel
}

// Prune deletes messages sent or dropped before cutoff.
func (q *Queue) Prune(ctx context.Context, cutoff time.Time) (int64, error) {
	ts := null(dbTime(cutoff))
	return systemdb.New(q.DB).DeleteFinishedNotificationsBefore(ctx, systemdb.DeleteFinishedNotificationsBeforeParams{SentAt: ts, DroppedAt: ts})
}

func dbTime(t time.Time) string { return t.UTC().Format(time.RFC3339) }

func null(s string) sql.NullString { return sql.NullString{String: s, Valid: true} }
