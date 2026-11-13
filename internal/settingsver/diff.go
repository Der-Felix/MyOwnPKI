package settingsver

import (
	"context"
	"fmt"
	"slices"
)

// Kinds of a FieldChange.
const (
	Changed = "changed" // set before and after, to different values
	Added   = "added"   // unset before, set after
	Removed = "removed" // set before, unset after
)

// FieldChange is one setting that differs between two snapshots. Before and
// After are the values as text, in the order the snapshots hold them; a
// list is compared as a set, so a pure reordering is no change.
type FieldChange struct {
	Key    string
	Label  string
	Before []string
	After  []string
	Kind   string
}

// Diff lists the settings that differ between a and b, in the field order of
// b (fields only a has come last, in a's order). It is a pure function of the
// two snapshots: nothing is stored, and there is no text diff of JSON. A nil
// snapshot has no fields, so Diff(nil, b) reports every set field of b as
// added. Values are returned as they are; they are data, and whoever shows
// them must escape them.
func Diff(a, b Snapshot) []FieldChange {
	var af, bf []Field
	if a != nil {
		af = a.Fields()
	}
	if b != nil {
		bf = b.Fields()
	}
	before := make(map[string]Field, len(af))
	for _, f := range af {
		before[f.Key] = f
	}
	var out []FieldChange
	seen := make(map[string]bool, len(bf))
	for _, f := range bf {
		seen[f.Key] = true
		if c, ok := compare(before[f.Key], f); ok {
			out = append(out, c)
		}
	}
	for _, f := range af {
		if seen[f.Key] {
			continue
		}
		if c, ok := compare(f, Field{Key: f.Key, Label: f.Label}); ok {
			out = append(out, c)
		}
	}
	return out
}

// compare returns the change from a to b (same key) if there is one. A
// missing field (zero Field) counts as unset.
func compare(a, b Field) (FieldChange, bool) {
	if sameSet(a.Values, b.Values) {
		return FieldChange{}, false
	}
	c := FieldChange{Key: b.Key, Label: b.Label, Before: slices.Clone(a.Values), After: slices.Clone(b.Values)}
	switch {
	case len(a.Values) == 0:
		c.Kind = Added
	case len(b.Values) == 0:
		c.Kind = Removed
	default:
		c.Kind = Changed
	}
	return c, true
}

// sameSet reports whether a and b hold the same values, ignoring order and
// duplicates.
func sameSet(a, b []string) bool {
	x, y := slices.Clone(a), slices.Clone(b)
	slices.Sort(x)
	slices.Sort(y)
	return slices.Equal(slices.Compact(x), slices.Compact(y))
}

// DiffVersions compares two versions of one object; from = 0 means "nothing
// before" (the first version shows every set field as added). Both numbers
// must exist.
func DiffVersions(ctx context.Context, b Backend, kind, objectID string, from, to int64) ([]FieldChange, error) {
	if from < 0 || to < 1 {
		return nil, fmt.Errorf("%w: versions %d and %d", ErrInvalid, from, to)
	}
	var a Snapshot
	if from > 0 {
		v, err := b.Get(ctx, kind, objectID, from)
		if err != nil {
			return nil, err
		}
		if a, err = v.Decoded(); err != nil {
			return nil, err
		}
	}
	v, err := b.Get(ctx, kind, objectID, to)
	if err != nil {
		return nil, err
	}
	snap, err := v.Decoded()
	if err != nil {
		return nil, err
	}
	return Diff(a, snap), nil
}
