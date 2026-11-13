package settingsver

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Entry describes one change to record. Every call happens inside the
// writer's transaction on the database that owns the object, so the version,
// the change and its audit entry commit or roll back together.
type Entry struct {
	Kind     string
	ObjectID string
	// Change is ChangeCreate, ChangeUpdate, ChangeDelete or ChangeRestore
	// (ChangeBaseline is written by Append itself).
	Change string
	// Before is the state before the change, needed (and only used) when the
	// object has no history yet: it becomes the baseline, version 1, so the
	// very first change can be undone. Nil for a create, and for a restore
	// of an object that does not exist (a deleted domain).
	Before Snapshot
	// After is the state after the change; for a delete, the deleted state.
	After Snapshot
	Actor Actor
	// Reason is optional free text (at most MaxReason characters, no control
	// characters). It stays in this table and never goes to the audit log.
	Reason string
	// ExpectedVersion, when set, must equal the newest version number of the
	// object (0 = none yet), or Append returns a *ConflictError. This is the
	// optimistic-concurrency check; run it with CheckExpected before the
	// business change so a conflict writes nothing at all.
	ExpectedVersion *int64
	// RestoredFrom is the version a restore copies; required for (and only
	// valid with) ChangeRestore.
	RestoredFrom int64
	// Now is the time of the change (UTC, injectable clock).
	Now time.Time
}

// Result of Append.
type Result struct {
	// Baseline is the baseline version Append wrote first, or nil.
	Baseline *Version
	// Version is the version of the change itself.
	Version Version
}

// Current returns the newest version number of an object, 0 if it has no
// history. It is the ETag of the object.
func Current(ctx context.Context, b Backend, kind, objectID string) (int64, error) {
	v, err := b.Latest(ctx, kind, objectID)
	switch {
	case errors.Is(err, ErrNotFound):
		return 0, nil
	case err != nil:
		return 0, err
	}
	return v.Number, nil
}

// CheckExpected returns a *ConflictError (errors.Is ErrConflict) when
// expected is set and is not the newest version number of the object. Call
// it first thing in the writer's transaction: SQLite has one writer, so
// nobody can change the object between this check and the Append that
// follows in the same transaction.
func CheckExpected(ctx context.Context, b Backend, kind, objectID string, expected *int64) error {
	if expected == nil {
		return nil
	}
	latest, err := b.Latest(ctx, kind, objectID)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	if latest.Number != *expected {
		return &ConflictError{Expected: *expected, Latest: latest}
	}
	return nil
}

// Append records a change as the next version of an object, inside the
// caller's transaction. It writes, in this order: the expected-version
// check, a baseline version 1 if the object has no history and the change
// is an update or delete, then the version itself. If the second insert
// fails the caller must roll back (the first is part of the same
// transaction).
func Append(ctx context.Context, b Backend, e Entry) (Result, error) {
	if err := e.validate(); err != nil {
		return Result{}, err
	}
	latest, err := b.Latest(ctx, e.Kind, e.ObjectID)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return Result{}, err
	}
	exists := err == nil
	if e.ExpectedVersion != nil && latest.Number != *e.ExpectedVersion {
		return Result{}, &ConflictError{Expected: *e.ExpectedVersion, Latest: latest}
	}
	switch e.Change {
	case ChangeCreate:
		if exists {
			return Result{}, fmt.Errorf("%w: %s %s already has a history, so it is not a create", ErrInvalid, e.Kind, e.ObjectID)
		}
	case ChangeUpdate, ChangeDelete:
		if !exists && e.Before == nil {
			return Result{}, fmt.Errorf("%w: the state before the change is needed to write the baseline", ErrInvalid)
		}
	case ChangeRestore:
		if !exists {
			return Result{}, fmt.Errorf("%w: nothing to restore, %s %s has no history", ErrInvalid, e.Kind, e.ObjectID)
		}
		if _, err = b.Get(ctx, e.Kind, e.ObjectID, e.RestoredFrom); err != nil {
			return Result{}, fmt.Errorf("restored_from %d: %w", e.RestoredFrom, err)
		}
	}

	var res Result
	next := latest.Number + 1
	if !exists && e.Change != ChangeCreate && e.Before != nil {
		base, berr := insert(ctx, b, e, ChangeBaseline, e.Before, BaselineActor, "", 0, 1)
		if berr != nil {
			return Result{}, berr
		}
		res.Baseline = &base
		next = 2
	}
	res.Version, err = insert(ctx, b, e, e.Change, e.After, e.Actor, e.Reason, e.RestoredFrom, next)
	return res, err
}

func insert(ctx context.Context, b Backend, e Entry, change string, snap Snapshot, actor Actor, reason string, restoredFrom, number int64) (Version, error) {
	data, sum, err := Canonical(snap)
	if err != nil {
		return Version{}, err
	}
	return b.Insert(ctx, Version{
		Kind: e.Kind, ObjectID: e.ObjectID, Number: number, Change: change, Schema: snap.SchemaVersion(),
		Snapshot: data, SHA256: sum, Actor: actor, Reason: reason, RestoredFrom: restoredFrom,
		CreatedAt: e.Now.UTC().Truncate(time.Second),
	})
}

func (e Entry) validate() error {
	bad := func(format string, a ...any) error {
		return fmt.Errorf("%w: "+format, append([]any{ErrInvalid}, a...)...)
	}
	if !slices.Contains([]string{KindDomain, KindTenant}, e.Kind) {
		return bad("unknown kind %q", e.Kind)
	}
	if n := utf8.RuneCountInString(e.ObjectID); n < 1 || n > 128 || hasControl(e.ObjectID) {
		return bad("object ID: 1 to 128 characters, no control characters")
	}
	if !slices.Contains([]string{ChangeCreate, ChangeUpdate, ChangeDelete, ChangeRestore}, e.Change) {
		return bad("change %q", e.Change)
	}
	if e.After == nil || e.After.Kind() != e.Kind {
		return bad("the state after the change must be a %s snapshot", e.Kind)
	}
	if e.Before != nil && e.Before.Kind() != e.Kind {
		return bad("the state before the change must be a %s snapshot", e.Kind)
	}
	if e.Change == ChangeCreate && e.Before != nil {
		return bad("a create has no state before it")
	}
	if (e.Change == ChangeRestore) != (e.RestoredFrom > 0) {
		return bad("restored_from is required for a restore and only valid with one")
	}
	if !slices.Contains([]string{ActorUser, ActorToken, ActorSystem, ActorACMEAccount, ActorAgent}, e.Actor.Type) {
		return bad("actor type %q", e.Actor.Type)
	}
	if err := CheckReason(e.Reason); err != nil {
		return err
	}
	if e.Now.IsZero() {
		return bad("no time")
	}
	return nil
}

// CheckReason refuses a reason that is longer than MaxReason characters or
// holds a control character (a newline would break a log line and a table
// cell) or an invisible formatting character (Unicode category Cf: bidi
// overrides, zero-width characters, a byte order mark – they let a reason
// pose as something else). The reason is shown to other admins.
func CheckReason(reason string) error {
	if utf8.RuneCountInString(reason) > MaxReason || hasControl(reason) || strings.ContainsFunc(reason, isFormat) || !utf8.ValidString(reason) {
		return fmt.Errorf("%w: reason: at most %d characters, no control or invisible formatting characters", ErrInvalid, MaxReason)
	}
	return nil
}

func hasControl(s string) bool {
	return strings.ContainsFunc(s, unicode.IsControl)
}

// Page is one page of a history, newest first.
type Page struct {
	Versions []Version
	// Next is the cursor for the following (older) page, 0 at the end.
	Next int64
}

// List returns the history of an object, newest first. before is the cursor
// from the previous page (0 = from the newest); limit defaults to
// DefaultListLimit and is capped at MaxListLimit.
func List(ctx context.Context, b Backend, kind, objectID string, before int64, limit int) (Page, error) {
	if before < 0 {
		return Page{}, fmt.Errorf("%w: cursor %d", ErrInvalid, before)
	}
	if limit <= 0 {
		limit = DefaultListLimit
	}
	limit = min(limit, MaxListLimit)
	vs, err := b.List(ctx, kind, objectID, before, limit+1)
	if err != nil {
		return Page{}, err
	}
	p := Page{Versions: vs}
	if len(vs) > limit {
		p.Versions = vs[:limit]
		p.Next = vs[limit-1].Number
	}
	return p, nil
}

// Get returns one version of an object (ErrNotFound if there is none).
func Get(ctx context.Context, b Backend, kind, objectID string, number int64) (Version, error) {
	if number < 1 {
		return Version{}, fmt.Errorf("%w: version %d", ErrInvalid, number)
	}
	return b.Get(ctx, kind, objectID, number)
}

// isFormat reports a Unicode format character (category Cf).
func isFormat(r rune) bool { return unicode.Is(unicode.Cf, r) }
