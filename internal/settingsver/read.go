package settingsver

import (
	"context"
	"errors"
	"fmt"
)

// The two errors of a restore that are not about the state of the data
// (PHASE3 section 16, step 63).
var (
	// ErrIdentical: the version to restore is the state the object already has.
	ErrIdentical = errors.New("the version is identical to the current state")
	// ErrPreconditionRequired: a restore must name the version it is based on.
	ErrPreconditionRequired = errors.New("a restore needs the newest version number (If-Match)")
)

// What a version is compared with. A number of 0 or more is a version; 0 means
// "nothing before".
const (
	// AgainstPrevious is the version before it (the first version has nothing before it).
	AgainstPrevious int64 = -1
	// AgainstCurrent is the object as it is now (nothing if it is deleted).
	AgainstCurrent int64 = -2
)

// Same reports whether two snapshots are the same state: the same canonical
// bytes. A nil snapshot is only the same as another nil one.
func Same(a, b Snapshot) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	da, _, ea := Canonical(a)
	db, _, eb := Canonical(b)
	return ea == nil && eb == nil && string(da) == string(db)
}

// Comparison is the diff between a compared state and a version.
type Comparison struct {
	// From is the compared version number; 0 means nothing before (also the
	// current state of a deleted object).
	From int64
	// To is the version that was asked for.
	To      int64
	Against string // "previous", "current" or "version"
	Changes []FieldChange
}

// Compare reads one version and the diff from what it is compared with to
// that version. against is AgainstPrevious, AgainstCurrent or a version number
// (0 = nothing). current is the live state of the object (nil when there is
// none, a deleted domain) and currentNumber its newest version number; both
// are only used for AgainstCurrent. The snapshot of the version is returned
// decoded (ErrUnknownSchema or ErrCorrupt when it cannot be read).
func Compare(ctx context.Context, b Backend, kind, objectID string, number, against int64, current Snapshot, currentNumber int64) (Version, Snapshot, Comparison, error) {
	v, err := Get(ctx, b, kind, objectID, number)
	if err != nil {
		return Version{}, nil, Comparison{}, err
	}
	snap, err := v.Decoded()
	if err != nil {
		return v, nil, Comparison{}, err
	}
	cmp := Comparison{To: number}
	var from Snapshot
	switch {
	case against == AgainstPrevious:
		cmp.Against, cmp.From = "previous", number-1
	case against == AgainstCurrent:
		cmp.Against, from = "current", current
		if current != nil {
			cmp.From = currentNumber
		}
	case against >= 0:
		cmp.Against, cmp.From = "version", against
	default:
		return v, nil, Comparison{}, fmt.Errorf("%w: against %d", ErrInvalid, against)
	}
	if against != AgainstCurrent && cmp.From > 0 {
		pv, perr := b.Get(ctx, kind, objectID, cmp.From)
		if perr != nil {
			return v, nil, Comparison{}, perr
		}
		if from, err = pv.Decoded(); err != nil {
			return v, nil, Comparison{}, err
		}
	}
	cmp.Changes = Diff(from, snap)
	if cmp.Changes == nil {
		cmp.Changes = []FieldChange{}
	}
	return v, snap, cmp, nil
}

// PageChanges returns, for each version of a page (newest first), the keys of
// the settings it changed compared with the version before it; version 1 shows
// every setting that is set. An entry is nil when a snapshot of that version
// or of the one before cannot be read (the page itself must still be shown).
func PageChanges(ctx context.Context, b Backend, vs []Version) [][]string {
	out := make([][]string, len(vs))
	for i, v := range vs {
		var before Snapshot
		if v.Number > 1 {
			prev := Version{}
			if i+1 < len(vs) && vs[i+1].Number == v.Number-1 {
				prev = vs[i+1]
			} else {
				p, err := b.Get(ctx, v.Kind, v.ObjectID, v.Number-1)
				if err != nil {
					continue
				}
				prev = p
			}
			s, err := prev.Decoded()
			if err != nil {
				continue
			}
			before = s
		}
		after, err := v.Decoded()
		if err != nil {
			continue
		}
		out[i] = Keys(Diff(before, after))
	}
	return out
}

// Keys lists the keys of a diff.
func Keys(changes []FieldChange) []string {
	out := make([]string, 0, len(changes))
	for _, c := range changes {
		out = append(out, c.Key)
	}
	return out
}
