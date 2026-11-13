package settingsver

import (
	"errors"
	"slices"
	"testing"
)

// Step 63 of PHASE3 section 16: the read side of the history, for both kinds.

func TestSame(t *testing.T) {
	t.Parallel()
	a, b := baseDomain(), baseDomain()
	if !Same(a, b) {
		t.Error("equal states differ")
	}
	b.ChallengeTypes = nil
	a.ChallengeTypes = []string{}
	if !Same(a, b) {
		t.Error("nil and empty lists are the same state (canonical form)")
	}
	b.ValidityDays = 5
	if Same(a, b) {
		t.Error("different states are the same")
	}
	if Same(a, nil) || Same(nil, a) || !Same(nil, nil) {
		t.Error("a nil snapshot is the same only as another nil snapshot")
	}
	if Same(baseDomain(), baseTenant()) {
		t.Error("a domain and a tenant state are never the same")
	}
}

func TestCompareAndPageChanges(t *testing.T) {
	t.Parallel()
	for _, tg := range targets(t) {
		t.Run(tg.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()
			if _, err := tg.appendEntry(t, Entry{Change: ChangeCreate, After: tg.snap(1)}); err != nil {
				t.Fatal(err)
			}
			for n := 2; n <= 4; n++ {
				if _, err := tg.appendEntry(t, Entry{Change: ChangeUpdate, After: tg.snap(n)}); err != nil {
					t.Fatal(err)
				}
			}
			b := tg.reader()

			// previous (version 1 has nothing before it), current, a number, 0.
			_, snap, cmp, err := Compare(ctx, b, tg.kind, "obj1", 3, AgainstPrevious, nil, 0)
			if err != nil || cmp.From != 2 || cmp.To != 3 || cmp.Against != "previous" || len(cmp.Changes) != 1 || snap == nil {
				t.Fatalf("previous: %+v %v", cmp, err)
			}
			_, _, cmp, err = Compare(ctx, b, tg.kind, "obj1", 1, AgainstPrevious, nil, 0)
			if err != nil || cmp.From != 0 || len(cmp.Changes) == 0 {
				t.Fatalf("version 1 against nothing: %+v %v", cmp, err)
			}
			for _, c := range cmp.Changes {
				if c.Kind != Added {
					t.Errorf("%s: %s, want added", c.Key, c.Kind)
				}
			}
			_, _, cmp, err = Compare(ctx, b, tg.kind, "obj1", 1, AgainstCurrent, tg.snap(4), 4)
			if err != nil || cmp.From != 4 || cmp.Against != "current" || len(cmp.Changes) != 1 {
				t.Fatalf("current: %+v %v", cmp, err)
			}
			_, _, cmp, err = Compare(ctx, b, tg.kind, "obj1", 2, AgainstCurrent, nil, 0)
			if err != nil || cmp.From != 0 || len(cmp.Changes) == 0 {
				t.Fatalf("current of a deleted object: %+v %v", cmp, err)
			}
			_, _, cmp, err = Compare(ctx, b, tg.kind, "obj1", 4, 1, nil, 0)
			if err != nil || cmp.From != 1 || cmp.Against != "version" || len(cmp.Changes) != 1 {
				t.Fatalf("against 1: %+v %v", cmp, err)
			}
			// The same state compared with itself: an empty list, not nil (it is JSON).
			if _, _, cmp, err = Compare(ctx, b, tg.kind, "obj1", 4, 4, nil, 0); err != nil || cmp.Changes == nil || len(cmp.Changes) != 0 {
				t.Errorf("identical: %+v %v", cmp, err)
			}
			for _, bad := range []struct {
				number, against int64
				want            error
			}{{0, AgainstPrevious, ErrInvalid}, {9, AgainstPrevious, ErrNotFound}, {2, 9, ErrNotFound}, {2, -7, ErrInvalid}} {
				if _, _, _, err = Compare(ctx, b, tg.kind, "obj1", bad.number, bad.against, nil, 0); !errors.Is(err, bad.want) {
					t.Errorf("Compare(%d, %d): %v, want %v", bad.number, bad.against, err, bad.want)
				}
			}

			// The keys each version of a page changed, also across a page border.
			page, err := List(ctx, b, tg.kind, "obj1", 0, 2)
			if err != nil || len(page.Versions) != 2 || page.Next != 3 {
				t.Fatalf("page: %+v %v", page, err)
			}
			changed := PageChanges(ctx, b, page.Versions)
			if len(changed) != 2 || len(changed[0]) != 1 || len(changed[1]) != 1 {
				t.Errorf("keys of versions 4 and 3: %v (the older one needs version 2 from outside the page)", changed)
			}
			rest, _ := List(ctx, b, tg.kind, "obj1", page.Next, 5)
			if c := PageChanges(ctx, b, rest.Versions); len(c) != 2 || len(c[0]) != 1 || len(c[1]) < 5 {
				t.Errorf("keys of versions 2 and 1: %v", c)
			}
			if !slices.Equal(Keys(Diff(tg.snap(1), tg.snap(2))), changed[1]) {
				t.Errorf("Keys %v differ from the page keys %v", Keys(Diff(tg.snap(1), tg.snap(2))), changed[1])
			}
		})
	}
}
