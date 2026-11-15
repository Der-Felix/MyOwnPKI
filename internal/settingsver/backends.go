package settingsver

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
	"github.com/Der-Felix/MyOwnPKI/internal/store/systemdb"
)

// PKIBackend is the table of pki.db (kind domain). Pass queries bound to the
// writer's transaction (pkidb.New(db).WithTx(tx)) for Append, or to a read
// connection for List, Get and DiffVersions.
func PKIBackend(q *pkidb.Queries) Backend { return pkiBackend{q} }

// SystemBackend is the table of system.db (kind tenant); see PKIBackend.
func SystemBackend(q *systemdb.Queries) Backend { return systemBackend{q} }

type pkiBackend struct{ q *pkidb.Queries }

func (b pkiBackend) Insert(ctx context.Context, v Version) (Version, error) {
	r, err := b.q.InsertSettingsVersion(ctx, pkidb.InsertSettingsVersionParams{
		Kind: v.Kind, ObjectID: v.ObjectID, Version: v.Number, Change: v.Change, Schema: int64(v.Schema),
		SnapshotJson: string(v.Snapshot), SnapshotSha256: v.SHA256,
		ActorType: v.Actor.Type, ActorID: v.Actor.ID, ActorName: v.Actor.Name,
		Reason: v.Reason, RestoredFrom: nullInt(v.RestoredFrom), CreatedAt: v.CreatedAt.UTC().Format(dbTime),
	})
	if err != nil {
		return Version{}, insertErr(err)
	}
	return pkiVersion(r)
}

func (b pkiBackend) Latest(ctx context.Context, kind, objectID string) (Version, error) {
	r, err := b.q.LatestSettingsVersion(ctx, pkidb.LatestSettingsVersionParams{Kind: kind, ObjectID: objectID})
	if err != nil {
		return Version{}, readErr(err)
	}
	return pkiVersion(r)
}

func (b pkiBackend) Get(ctx context.Context, kind, objectID string, number int64) (Version, error) {
	r, err := b.q.GetSettingsVersion(ctx, pkidb.GetSettingsVersionParams{Kind: kind, ObjectID: objectID, Version: number})
	if err != nil {
		return Version{}, readErr(err)
	}
	return pkiVersion(r)
}

func (b pkiBackend) List(ctx context.Context, kind, objectID string, before int64, limit int) ([]Version, error) {
	rows, err := b.q.ListSettingsVersions(ctx, pkidb.ListSettingsVersionsParams{Kind: kind, ObjectID: objectID, Before: before, RowLimit: int64(limit)})
	if err != nil {
		return nil, readErr(err)
	}
	return convert(rows, pkiVersion)
}

func (b pkiBackend) LatestOfKind(ctx context.Context, kind string) ([]Version, error) {
	rows, err := b.q.ListLatestSettingsVersions(ctx, kind)
	if err != nil {
		return nil, readErr(err)
	}
	return convert(rows, pkiVersion)
}

func pkiVersion(r pkidb.SettingsVersion) (Version, error) {
	return toVersion(r.ID, r.Kind, r.ObjectID, r.Version, r.Change, r.Schema, r.SnapshotJson, r.SnapshotSha256,
		r.ActorType, r.ActorID, r.ActorName, r.Reason, r.RestoredFrom, r.CreatedAt)
}

type systemBackend struct{ q *systemdb.Queries }

func (b systemBackend) Insert(ctx context.Context, v Version) (Version, error) {
	r, err := b.q.InsertSettingsVersion(ctx, systemdb.InsertSettingsVersionParams{
		Kind: v.Kind, ObjectID: v.ObjectID, Version: v.Number, Change: v.Change, Schema: int64(v.Schema),
		SnapshotJson: string(v.Snapshot), SnapshotSha256: v.SHA256,
		ActorType: v.Actor.Type, ActorID: v.Actor.ID, ActorName: v.Actor.Name,
		Reason: v.Reason, RestoredFrom: nullInt(v.RestoredFrom), CreatedAt: v.CreatedAt.UTC().Format(dbTime),
	})
	if err != nil {
		return Version{}, insertErr(err)
	}
	return systemVersion(r)
}

func (b systemBackend) Latest(ctx context.Context, kind, objectID string) (Version, error) {
	r, err := b.q.LatestSettingsVersion(ctx, systemdb.LatestSettingsVersionParams{Kind: kind, ObjectID: objectID})
	if err != nil {
		return Version{}, readErr(err)
	}
	return systemVersion(r)
}

func (b systemBackend) Get(ctx context.Context, kind, objectID string, number int64) (Version, error) {
	r, err := b.q.GetSettingsVersion(ctx, systemdb.GetSettingsVersionParams{Kind: kind, ObjectID: objectID, Version: number})
	if err != nil {
		return Version{}, readErr(err)
	}
	return systemVersion(r)
}

func (b systemBackend) List(ctx context.Context, kind, objectID string, before int64, limit int) ([]Version, error) {
	rows, err := b.q.ListSettingsVersions(ctx, systemdb.ListSettingsVersionsParams{Kind: kind, ObjectID: objectID, Before: before, RowLimit: int64(limit)})
	if err != nil {
		return nil, readErr(err)
	}
	return convert(rows, systemVersion)
}

func (b systemBackend) LatestOfKind(ctx context.Context, kind string) ([]Version, error) {
	rows, err := b.q.ListLatestSettingsVersions(ctx, kind)
	if err != nil {
		return nil, readErr(err)
	}
	return convert(rows, systemVersion)
}

func systemVersion(r systemdb.SettingsVersion) (Version, error) {
	return toVersion(r.ID, r.Kind, r.ObjectID, r.Version, r.Change, r.Schema, r.SnapshotJson, r.SnapshotSha256,
		r.ActorType, r.ActorID, r.ActorName, r.Reason, r.RestoredFrom, r.CreatedAt)
}

func toVersion(id int64, kind, objectID string, number int64, change string, schema int64, snapshot, sum,
	actorType, actorID, actorName, reason string, restoredFrom sql.NullInt64, createdAt string) (Version, error) {
	at, err := time.Parse(dbTime, createdAt)
	if err != nil {
		return Version{}, fmt.Errorf("%w: %s %s version %d has the time %q", ErrCorrupt, kind, objectID, number, createdAt)
	}
	return Version{
		ID: id, Kind: kind, ObjectID: objectID, Number: number, Change: change, Schema: int(schema),
		Snapshot: []byte(snapshot), SHA256: sum, Actor: Actor{Type: actorType, ID: actorID, Name: actorName},
		Reason: reason, RestoredFrom: restoredFrom.Int64, CreatedAt: at,
	}, nil
}

func convert[R any](rows []R, f func(R) (Version, error)) ([]Version, error) {
	out := make([]Version, 0, len(rows))
	for _, r := range rows {
		v, err := f(r)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

func nullInt(n int64) sql.NullInt64 { return sql.NullInt64{Int64: n, Valid: n > 0} }

func readErr(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

// insertErr maps a duplicate (kind, object, number) to ErrConflict. Two
// writers that both passed the expected-version check could only collide if
// the check were skipped, and the database still refuses the second: the
// no_replace trigger first, the UNIQUE constraint behind it.
func insertErr(err error) error {
	if msg := err.Error(); strings.Contains(msg, "settings history is append-only: that version exists") || strings.Contains(msg, "UNIQUE constraint failed: settings_versions") {
		return fmt.Errorf("%w: %w", ErrConflict, err)
	}
	return err
}
