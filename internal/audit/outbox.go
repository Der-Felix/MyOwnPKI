package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/clock"
)

// The outbox table is identical in every producing database (schema/system
// and schema/pki, migration 0002), so its few statements live here as plain
// SQL instead of one generated copy per database package.

// OutboxRetention: delivered outbox rows are deleted after this time; they
// are only needed to redeliver after a crash or restore. Undelivered rows
// are never deleted.
const OutboxRetention = 30 * 24 * time.Hour

const topicAudit = "audit"

// payload is the outbox form of an Entry.
type payload struct {
	Time       string          `json:"time"`
	ActorType  ActorType       `json:"actor_type"`
	ActorID    string          `json:"actor_id"`
	ActorName  string          `json:"actor_name"`
	Action     string          `json:"action"`
	TargetType string          `json:"target_type"`
	TargetID   string          `json:"target_id"`
	Result     Result          `json:"result"`
	SourceIP   string          `json:"source_ip"`
	Details    json.RawMessage `json:"details"`
}

// Enqueue writes e to the outbox of the producing database inside tx – the
// same transaction as the business change it describes, so both are stored
// or neither is. now is the outbox row's creation time.
func Enqueue(ctx context.Context, tx *sql.Tx, now time.Time, e Entry) error {
	details, err := e.validate()
	if err != nil {
		return err
	}
	p, err := json.Marshal(payload{
		Time: e.Time.UTC().Format(TimeFormat), ActorType: e.Actor.Type, ActorID: e.Actor.ID, ActorName: e.Actor.Name,
		Action: e.Action, TargetType: e.Target.Type, TargetID: e.Target.ID, Result: e.Result,
		SourceIP: e.SourceIP, Details: json.RawMessage(details),
	})
	if err != nil {
		return fmt.Errorf("audit enqueue: %w", err)
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO outbox (created_at, topic, payload_json) VALUES (?, ?, ?)`,
		now.UTC().Format(TimeFormat), topicAudit, string(p))
	if err != nil {
		return fmt.Errorf("audit enqueue: %w", err)
	}
	return nil
}

func (p payload) entry() (Entry, error) {
	t, err := time.Parse(TimeFormat, p.Time)
	if err != nil {
		return Entry{}, err
	}
	var details map[string]any
	if len(p.Details) > 0 {
		if err := json.Unmarshal(p.Details, &details); err != nil {
			return Entry{}, err
		}
	}
	return Entry{
		Time: t, Actor: Actor{Type: p.ActorType, ID: p.ActorID, Name: p.ActorName}, Action: p.Action,
		Target: Target{Type: p.TargetType, ID: p.TargetID}, Result: p.Result, SourceIP: p.SourceIP, Details: details,
	}, nil
}

// Route connects the outbox of one producing database with one audit log.
type Route struct {
	Source string  // outbox_id prefix, e.g. "system" or "pki"; unique per audit log
	From   *sql.DB // writer of the producing database
	To     *sql.DB // writer of the audit log
	Scope  string  // scope of the audit log
}

// Deliverer moves outbox rows into the audit logs.
type Deliverer struct {
	Routes []Route
	Clock  clock.Clock
	Log    *slog.Logger

	// Checkpoints, if set, makes a checkpoint after every 1000 entries and
	// once a day (step 6a).
	Checkpoints *Checkpointer

	// afterAppend runs between appending to the audit log and marking the
	// outbox row; tests use it to simulate a crash at exactly that point.
	afterAppend func() error
}

const deliverBatch = 100

// DeliverPending delivers every undelivered outbox row of every route and
// returns how many entries were added. Each row is appended in its own
// audit transaction and then marked delivered in the producing database.
// A crash in between is harmless: the row is delivered again and the audit
// log recognizes its outbox_id. Errors of one route don't stop the others.
func (d *Deliverer) DeliverPending(ctx context.Context) (int, error) {
	added := 0
	var errs []error
	for _, r := range d.Routes {
		n, err := d.deliverRoute(ctx, r)
		added += n
		if err != nil {
			errs = append(errs, fmt.Errorf("outbox %s → audit %s: %w", r.Source, r.Scope, err))
		}
	}
	return added, errors.Join(errs...)
}

func (d *Deliverer) deliverRoute(ctx context.Context, r Route) (int, error) {
	added := 0
	for {
		rows, err := pending(ctx, r.From)
		if err != nil {
			return added, err
		}
		for _, row := range rows {
			e, err := row.p.entry()
			if err != nil {
				return added, fmt.Errorf("outbox row %d: unreadable payload: %w", row.id, err)
			}
			_, appended, err := Append(ctx, r.To, r.Scope, e, r.Source+":"+strconv.FormatInt(row.id, 10))
			if err != nil {
				return added, fmt.Errorf("outbox row %d: %w", row.id, err)
			}
			if appended {
				added++
			}
			if d.afterAppend != nil {
				if err := d.afterAppend(); err != nil {
					return added, err
				}
			}
			if _, err := r.From.ExecContext(ctx, `UPDATE outbox SET delivered_at = ? WHERE id = ? AND delivered_at IS NULL`,
				d.Clock.Now().UTC().Format(TimeFormat), row.id); err != nil {
				return added, fmt.Errorf("outbox row %d: mark delivered: %w", row.id, err)
			}
		}
		if len(rows) < deliverBatch {
			return added, nil
		}
	}
}

type outboxRow struct {
	id int64
	p  payload
}

func pending(ctx context.Context, db *sql.DB) ([]outboxRow, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT id, payload_json FROM outbox WHERE delivered_at IS NULL AND topic = ? ORDER BY id LIMIT ?`,
		topicAudit, deliverBatch)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []outboxRow
	for rows.Next() {
		var (
			r    outboxRow
			text string
		)
		if err := rows.Scan(&r.id, &text); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(text), &r.p); err != nil {
			return nil, fmt.Errorf("outbox row %d: unreadable payload: %w", r.id, err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Cleanup deletes outbox rows that were delivered more than OutboxRetention
// ago. Undelivered rows are never deleted, however old they are.
func (d *Deliverer) Cleanup(ctx context.Context) (int64, error) {
	cutoff := d.Clock.Now().Add(-OutboxRetention).UTC().Format(TimeFormat)
	var total int64
	for _, r := range d.Routes {
		res, err := r.From.ExecContext(ctx, `DELETE FROM outbox WHERE delivered_at IS NOT NULL AND delivered_at < ?`, cutoff)
		if err != nil {
			return total, fmt.Errorf("outbox %s cleanup: %w", r.Source, err)
		}
		n, _ := res.RowsAffected()
		total += n
	}
	return total, nil
}

// LogHeads writes the head of every audit log to the process log. The
// process log usually ends up somewhere else (journald, a log collector), so
// it is an anchor for `myownpki audit verify --expect-head`.
func (d *Deliverer) LogHeads(ctx context.Context) {
	seen := map[*sql.DB]bool{}
	for _, r := range d.Routes {
		if seen[r.To] {
			continue
		}
		seen[r.To] = true
		rep, err := Verify(ctx, r.To, r.Scope)
		switch {
		case err != nil:
			d.Log.ErrorContext(ctx, "audit chain head", slog.String("scope", r.Scope), slog.Any("error", err))
		case rep.Break != nil:
			d.Log.ErrorContext(ctx, "audit chain BROKEN", slog.String("scope", r.Scope),
				slog.Int64("seq", rep.Break.Seq), slog.String("reason", rep.Break.Reason))
		default:
			d.Log.InfoContext(ctx, "audit chain head", slog.String("scope", r.Scope),
				slog.Int64("entries", rep.Entries), slog.String("head", rep.Head.String()))
		}
	}
}

// Run delivers at start, whenever wake fires (send after committing outbox
// rows), and every pollInterval; once a day it logs the chain heads and
// cleans up the outbox. It returns when ctx ends.
func (d *Deliverer) Run(ctx context.Context, wake <-chan struct{}, pollInterval time.Duration) {
	deliver := func() {
		if _, err := d.DeliverPending(ctx); err != nil && ctx.Err() == nil {
			d.Log.ErrorContext(ctx, "audit delivery", slog.Any("error", err))
		}
		if d.Checkpoints != nil {
			if err := d.Checkpoints.MaybeEvery(ctx); err != nil && ctx.Err() == nil {
				d.Log.ErrorContext(ctx, "audit checkpoint", slog.Any("error", err))
			}
		}
	}
	daily := func() {
		if d.Checkpoints != nil {
			if err := d.Checkpoints.MakeAll(ctx, "daily"); err != nil {
				d.Log.ErrorContext(ctx, "audit checkpoint", slog.Any("error", err))
			}
		}
		d.LogHeads(ctx)
		if n, err := d.Cleanup(ctx); err != nil {
			d.Log.ErrorContext(ctx, "outbox cleanup", slog.Any("error", err))
		} else if n > 0 {
			d.Log.InfoContext(ctx, "outbox cleanup", slog.Int64("deleted", n))
		}
	}
	deliver()
	daily()
	poll := time.NewTicker(pollInterval)
	defer poll.Stop()
	day := time.NewTicker(24 * time.Hour)
	defer day.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-wake:
			deliver()
		case <-poll.C:
			deliver()
		case <-day.C:
			daily()
		}
	}
}

// Backlog is the undelivered part of one outbox.
type Backlog struct {
	Source  string
	Pending int64
	Oldest  time.Time // zero when nothing is pending
}

// Backlog reports what waits in each route's outbox – the server warns with
// count and age while deliveries fail (owner 2026-10-16: outbox entries may
// pile up, they are never lost; direct entries are fail-closed instead).
func (d *Deliverer) Backlog(ctx context.Context) ([]Backlog, error) {
	out := make([]Backlog, 0, len(d.Routes))
	for _, r := range d.Routes {
		var (
			n      int64
			oldest sql.NullString
		)
		if err := r.From.QueryRowContext(ctx, `SELECT count(*), min(created_at) FROM outbox WHERE delivered_at IS NULL AND topic = ?`,
			topicAudit).Scan(&n, &oldest); err != nil {
			return out, fmt.Errorf("outbox %s: %w", r.Source, err)
		}
		b := Backlog{Source: r.Source, Pending: n}
		if oldest.Valid {
			if t, err := time.Parse(TimeFormat, oldest.String); err == nil {
				b.Oldest = t
			}
		}
		out = append(out, b)
	}
	return out, nil
}
