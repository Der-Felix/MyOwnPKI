package settingsver

import (
	"context"
	"database/sql"
	"errors"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode"

	"github.com/Der-Felix/MyOwnPKI/internal/store"
	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
	"github.com/Der-Felix/MyOwnPKI/internal/store/systemdb"
)

var t0 = time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)

// openDBs migrates a data directory and opens pki.db of the default tenant
// and system.db, the two homes of settings_versions.
func openDBs(t *testing.T) (pki, sys *store.DB) {
	t.Helper()
	ctx := t.Context()
	l := store.Layout{DataDir: t.TempDir()}
	if _, err := store.Migrate(ctx, l, store.DefaultTenant, func() time.Time { return t0 }); err != nil {
		t.Fatal(err)
	}
	pkiPath, err := l.TenantDB(store.DefaultTenant, store.KindPKI)
	if err != nil {
		t.Fatal(err)
	}
	if pki, err = store.Open(ctx, pkiPath); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pki.Close() })
	if sys, err = store.Open(ctx, l.SystemDB()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sys.Close() })
	return pki, sys
}

// target is one database with its kind, so each test runs against both.
type target struct {
	name    string
	kind    string
	db      *sql.DB
	read    *sql.DB
	backend func(pkidb.DBTX) Backend
	snap    func(n int) Snapshot // the n-th distinct state
}

func targets(t *testing.T) []target {
	t.Helper()
	pki, sys := openDBs(t)
	return []target{
		{name: "domain/pki.db", kind: KindDomain, db: pki.Write, read: pki.Read,
			backend: func(q pkidb.DBTX) Backend { return PKIBackend(pkidb.New(q)) },
			snap: func(n int) Snapshot {
				d := baseDomain()
				d.ValidityDays = n
				return d
			}},
		{name: "tenant/system.db", kind: KindTenant, db: sys.Write, read: sys.Read,
			backend: func(q pkidb.DBTX) Backend { return SystemBackend(systemdb.New(q)) },
			snap: func(n int) Snapshot {
				s := baseTenant()
				s.StepUpMinutes = n
				return s
			}},
	}
}

// do runs f in one writer transaction and commits it unless f fails.
func (tg target) do(t *testing.T, f func(ctx context.Context, b Backend) error) error {
	t.Helper()
	ctx := t.Context()
	tx, err := tg.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err = f(ctx, tg.backend(tx)); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

func (tg target) reader() Backend { return tg.backend(tg.read) }

func user(name string) Actor { return Actor{Type: ActorUser, ID: "usr_" + name, Name: name} }

func (tg target) appendEntry(t *testing.T, e Entry) (res Result, err error) {
	t.Helper()
	e.Kind = tg.kind
	if e.ObjectID == "" {
		e.ObjectID = "obj1"
	}
	if e.Now.IsZero() {
		e.Now = t0
	}
	if e.Actor.Type == "" {
		e.Actor = user("alice")
	}
	err = tg.do(t, func(ctx context.Context, b Backend) (err error) {
		res, err = Append(ctx, b, e)
		return err
	})
	return res, err
}

func TestAppendCreateThenUpdates(t *testing.T) {
	t.Parallel()
	for _, tg := range targets(t) {
		t.Run(tg.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()
			r, err := tg.appendEntry(t, Entry{Change: ChangeCreate, After: tg.snap(1), Reason: "first"})
			if err != nil {
				t.Fatal(err)
			}
			if r.Baseline != nil || r.Version.Number != 1 || r.Version.Change != ChangeCreate {
				t.Fatalf("create: %+v", r)
			}
			_, sum, _ := Canonical(tg.snap(1))
			if r.Version.SHA256 != sum || r.Version.Reason != "first" || r.Version.Actor != user("alice") || !r.Version.CreatedAt.Equal(t0) {
				t.Errorf("create stored %+v", r.Version)
			}
			// An update of an object with history needs no Before and writes no baseline.
			r, err = tg.appendEntry(t, Entry{Change: ChangeUpdate, After: tg.snap(2), Actor: user("bob")})
			if err != nil {
				t.Fatal(err)
			}
			if r.Baseline != nil || r.Version.Number != 2 || r.Version.Actor.Name != "bob" {
				t.Fatalf("update: %+v", r)
			}
			if n, cerr := Current(ctx, tg.reader(), tg.kind, "obj1"); cerr != nil || n != 2 {
				t.Errorf("Current = %d, %v, want 2", n, cerr)
			}
			if n, cerr := Current(ctx, tg.reader(), tg.kind, "other"); cerr != nil || n != 0 {
				t.Errorf("Current of an untouched object = %d, %v, want 0", n, cerr)
			}
			// A create over an existing history is refused.
			if _, err = tg.appendEntry(t, Entry{Change: ChangeCreate, After: tg.snap(3)}); !errors.Is(err, ErrInvalid) {
				t.Errorf("second create: %v, want ErrInvalid", err)
			}
		})
	}
}

func TestBaselineBeforeTheFirstChange(t *testing.T) {
	t.Parallel()
	for _, tg := range targets(t) {
		t.Run(tg.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()
			// No history, no Before: refused, nothing written.
			if _, err := tg.appendEntry(t, Entry{Change: ChangeUpdate, After: tg.snap(2)}); !errors.Is(err, ErrInvalid) {
				t.Fatalf("update without a baseline source: %v, want ErrInvalid", err)
			}
			if n, _ := Current(ctx, tg.reader(), tg.kind, "obj1"); n != 0 {
				t.Fatalf("a refused change left version %d", n)
			}
			r, err := tg.appendEntry(t, Entry{Change: ChangeUpdate, Before: tg.snap(1), After: tg.snap(2), Reason: "tighten", Actor: user("bob")})
			if err != nil {
				t.Fatal(err)
			}
			if r.Baseline == nil || r.Baseline.Number != 1 || r.Baseline.Change != ChangeBaseline || r.Baseline.Actor != BaselineActor || r.Baseline.Reason != "" {
				t.Fatalf("baseline: %+v", r.Baseline)
			}
			if r.Version.Number != 2 || r.Version.Change != ChangeUpdate {
				t.Fatalf("version: %+v", r.Version)
			}
			// Version 1 is the state before, version 2 the state after.
			d, err := DiffVersions(ctx, tg.reader(), tg.kind, "obj1", 1, 2)
			if err != nil || len(d) != 1 {
				t.Fatalf("DiffVersions = %+v, %v", d, err)
			}
			base, err := Get(ctx, tg.reader(), tg.kind, "obj1", 1)
			if err != nil {
				t.Fatal(err)
			}
			if s, err := base.Decoded(); err != nil || !reflectEqual(s, tg.snap(1)) {
				t.Errorf("baseline snapshot = %+v, %v", s, err)
			}
		})
	}
}

func TestDeleteStoresTheDeletedState(t *testing.T) {
	t.Parallel()
	for _, tg := range targets(t) {
		t.Run(tg.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()
			// An object that never had a version: baseline, then the delete,
			// both with the deleted state.
			r, err := tg.appendEntry(t, Entry{Change: ChangeDelete, Before: tg.snap(1), After: tg.snap(1)})
			if err != nil {
				t.Fatal(err)
			}
			if r.Baseline == nil || r.Version.Number != 2 || r.Version.Change != ChangeDelete || r.Version.SHA256 != r.Baseline.SHA256 {
				t.Fatalf("delete: %+v", r)
			}
			latest, err := tg.reader().LatestOfKind(ctx, tg.kind)
			if err != nil || len(latest) != 1 || latest[0].Change != ChangeDelete {
				t.Fatalf("LatestOfKind = %+v, %v", latest, err)
			}
			// Restore of the deleted object: a new version that points at 1.
			r, err = tg.appendEntry(t, Entry{Change: ChangeRestore, RestoredFrom: 1, After: tg.snap(1), Reason: "oops"})
			if err != nil {
				t.Fatal(err)
			}
			if r.Version.Number != 3 || r.Version.RestoredFrom != 1 || r.Version.Change != ChangeRestore {
				t.Fatalf("restore: %+v", r.Version)
			}
			for _, bad := range []Entry{
				{Change: ChangeRestore, After: tg.snap(1)},                  // no source
				{Change: ChangeUpdate, RestoredFrom: 1, After: tg.snap(1)},  // source without restore
				{Change: ChangeRestore, RestoredFrom: 9, After: tg.snap(1)}, // no such version
			} {
				if _, err = tg.appendEntry(t, bad); err == nil {
					t.Errorf("accepted %+v", bad)
				}
			}
			// Restore of an object without any history.
			if _, err = tg.appendEntry(t, Entry{ObjectID: "nohistory", Change: ChangeRestore, RestoredFrom: 1, After: tg.snap(1)}); !errors.Is(err, ErrInvalid) {
				t.Errorf("restore without history: %v, want ErrInvalid", err)
			}
		})
	}
}

func TestVersionNumbersAreContiguousAndListPages(t *testing.T) {
	t.Parallel()
	for _, tg := range targets(t) {
		t.Run(tg.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()
			if _, err := tg.appendEntry(t, Entry{Change: ChangeCreate, After: tg.snap(1)}); err != nil {
				t.Fatal(err)
			}
			for n := 2; n <= 7; n++ {
				if _, err := tg.appendEntry(t, Entry{Change: ChangeUpdate, After: tg.snap(n)}); err != nil {
					t.Fatal(err)
				}
			}
			// Another object does not disturb the numbering or the list.
			if _, err := tg.appendEntry(t, Entry{ObjectID: "obj2", Change: ChangeCreate, After: tg.snap(1)}); err != nil {
				t.Fatal(err)
			}
			var got []int64
			var cursor int64
			pages := 0
			for {
				p, err := List(ctx, tg.reader(), tg.kind, "obj1", cursor, 3)
				if err != nil {
					t.Fatal(err)
				}
				pages++
				for _, v := range p.Versions {
					got = append(got, v.Number)
				}
				if p.Next == 0 {
					break
				}
				cursor = p.Next
			}
			if want := []int64{7, 6, 5, 4, 3, 2, 1}; !slices.Equal(got, want) || pages != 3 {
				t.Errorf("List gave %v in %d pages, want %v in 3", got, pages, want)
			}
			if p, err := List(ctx, tg.reader(), tg.kind, "none", 0, 0); err != nil || len(p.Versions) != 0 || p.Next != 0 {
				t.Errorf("List of an unknown object = %+v, %v", p, err)
			}
			if _, err := Get(ctx, tg.reader(), tg.kind, "obj1", 8); !errors.Is(err, ErrNotFound) {
				t.Errorf("Get(8): %v, want ErrNotFound", err)
			}
			if _, err := Get(ctx, tg.reader(), tg.kind, "obj1", 0); !errors.Is(err, ErrInvalid) {
				t.Errorf("Get(0): %v, want ErrInvalid", err)
			}
			latest, err := tg.reader().LatestOfKind(ctx, tg.kind)
			if err != nil || len(latest) != 2 || latest[0].ObjectID != "obj1" || latest[0].Number != 7 || latest[1].Number != 1 {
				t.Errorf("LatestOfKind = %+v, %v", latest, err)
			}
		})
	}
}

func TestExpectedVersionConflict(t *testing.T) {
	t.Parallel()
	for _, tg := range targets(t) {
		t.Run(tg.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()
			zero, one, two := int64(0), int64(1), int64(2)
			// 0 = "no version yet" is a valid expectation for the first change.
			if _, err := tg.appendEntry(t, Entry{Change: ChangeCreate, After: tg.snap(1), ExpectedVersion: &zero, Actor: user("alice")}); err != nil {
				t.Fatal(err)
			}
			// Now 0 is stale.
			_, err := tg.appendEntry(t, Entry{Change: ChangeUpdate, After: tg.snap(2), ExpectedVersion: &zero, Actor: user("bob")})
			var ce *ConflictError
			if !errors.Is(err, ErrConflict) || !errors.As(err, &ce) || ce.Expected != 0 || ce.Latest.Number != 1 || ce.Latest.Actor.Name != "alice" {
				t.Fatalf("stale expectation: %v", err)
			}
			if n, _ := Current(ctx, tg.reader(), tg.kind, "obj1"); n != 1 {
				t.Fatalf("a conflict wrote version %d", n)
			}
			// A future number is just as wrong.
			if _, err = tg.appendEntry(t, Entry{Change: ChangeUpdate, After: tg.snap(2), ExpectedVersion: &two}); !errors.Is(err, ErrConflict) {
				t.Errorf("expected 2 while at 1: %v", err)
			}
			if _, err = tg.appendEntry(t, Entry{Change: ChangeUpdate, After: tg.snap(2), ExpectedVersion: &one}); err != nil {
				t.Errorf("right expectation refused: %v", err)
			}
			// The same check on its own, for the writer that checks before it changes anything.
			err = tg.do(t, func(ctx context.Context, b Backend) error { return CheckExpected(ctx, b, tg.kind, "obj1", &one) })
			if !errors.Is(err, ErrConflict) {
				t.Errorf("CheckExpected(1) at 2: %v", err)
			}
			err = tg.do(t, func(ctx context.Context, b Backend) error { return CheckExpected(ctx, b, tg.kind, "obj1", &two) })
			if err != nil {
				t.Errorf("CheckExpected(2) at 2: %v", err)
			}
			err = tg.do(t, func(ctx context.Context, b Backend) error { return CheckExpected(ctx, b, tg.kind, "obj1", nil) })
			if err != nil {
				t.Errorf("CheckExpected(nil): %v", err)
			}
		})
	}
}

// Two writers read version 1 and both try to write version 2: SQLite has one
// writer, the check runs inside the writer's transaction, so exactly one
// wins and the numbers stay contiguous.
func TestConcurrentWritersExactlyOneWins(t *testing.T) {
	t.Parallel()
	for _, tg := range targets(t) {
		t.Run(tg.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()
			if _, err := tg.appendEntry(t, Entry{Change: ChangeCreate, After: tg.snap(1)}); err != nil {
				t.Fatal(err)
			}
			const writers = 8
			one := int64(1)
			var wg sync.WaitGroup
			errs := make([]error, writers)
			for i := range writers {
				wg.Go(func() {
					errs[i] = tg.do(t, func(ctx context.Context, b Backend) error {
						if err := CheckExpected(ctx, b, tg.kind, "obj1", &one); err != nil {
							return err
						}
						_, err := Append(ctx, b, Entry{Kind: tg.kind, ObjectID: "obj1", Change: ChangeUpdate, After: tg.snap(10 + i),
							Actor: user("w"), ExpectedVersion: &one, Now: t0})
						return err
					})
				})
			}
			wg.Wait()
			wins, conflicts := 0, 0
			for _, err := range errs {
				switch {
				case err == nil:
					wins++
				case errors.Is(err, ErrConflict):
					conflicts++
				default:
					t.Errorf("unexpected error: %v", err)
				}
			}
			if wins != 1 || conflicts != writers-1 {
				t.Errorf("%d wins and %d conflicts, want 1 and %d", wins, conflicts, writers-1)
			}
			p, err := List(ctx, tg.reader(), tg.kind, "obj1", 0, 0)
			if err != nil || len(p.Versions) != 2 || p.Versions[0].Number != 2 || p.Versions[1].Number != 1 {
				t.Errorf("history after the race: %+v, %v", p, err)
			}
		})
	}
}

// Without the check, the UNIQUE constraint still refuses a second version
// with the same number, and it surfaces as ErrConflict.
func TestUniqueBackstop(t *testing.T) {
	t.Parallel()
	for _, tg := range targets(t) {
		t.Run(tg.name, func(t *testing.T) {
			t.Parallel()
			if _, err := tg.appendEntry(t, Entry{Change: ChangeCreate, After: tg.snap(1)}); err != nil {
				t.Fatal(err)
			}
			data, sum, _ := Canonical(tg.snap(2))
			err := tg.do(t, func(ctx context.Context, b Backend) error {
				_, err := b.Insert(ctx, Version{Kind: tg.kind, ObjectID: "obj1", Number: 1, Change: ChangeUpdate, Schema: 1,
					Snapshot: data, SHA256: sum, Actor: user("x"), CreatedAt: t0})
				return err
			})
			if !errors.Is(err, ErrConflict) {
				t.Errorf("duplicate number: %v, want ErrConflict", err)
			}
		})
	}
}

// A failed business step rolls the version back with it: nothing is half recorded.
func TestRollbackLeavesNoVersion(t *testing.T) {
	t.Parallel()
	for _, tg := range targets(t) {
		t.Run(tg.name, func(t *testing.T) {
			t.Parallel()
			boom := errors.New("audit write failed")
			err := tg.do(t, func(ctx context.Context, b Backend) error {
				if _, err := Append(ctx, b, Entry{Kind: tg.kind, ObjectID: "obj1", Change: ChangeUpdate, Before: tg.snap(1), After: tg.snap(2), Actor: user("a"), Now: t0}); err != nil {
					return err
				}
				return boom
			})
			if !errors.Is(err, boom) {
				t.Fatal(err)
			}
			if n, _ := Current(t.Context(), tg.reader(), tg.kind, "obj1"); n != 0 {
				t.Errorf("a rolled-back change left version %d (baseline included)", n)
			}
		})
	}
}

func TestAppendRefusesBadInput(t *testing.T) {
	t.Parallel()
	for _, tg := range targets(t) {
		t.Run(tg.name, func(t *testing.T) {
			t.Parallel()
			other := Snapshot(TenantSnapshot{})
			if tg.kind == KindTenant {
				other = DomainSnapshot{}
			}
			longReason := strings.Repeat("x", MaxReason+1)
			for name, e := range map[string]Entry{
				"unknown kind":       {Kind: "ca", Change: ChangeCreate, After: tg.snap(1)},
				"object too long":    {ObjectID: strings.Repeat("o", 129), Change: ChangeCreate, After: tg.snap(1)},
				"control in object":  {ObjectID: "a\nb", Change: ChangeCreate, After: tg.snap(1)},
				"baseline":           {Change: ChangeBaseline, After: tg.snap(1)},
				"no snapshot":        {Change: ChangeCreate},
				"wrong snapshot":     {Change: ChangeCreate, After: other},
				"wrong before":       {Change: ChangeUpdate, Before: other, After: tg.snap(1)},
				"create with before": {Change: ChangeCreate, Before: tg.snap(1), After: tg.snap(1)},
				"actor":              {Change: ChangeCreate, After: tg.snap(1), Actor: Actor{Type: "root"}},
				"reason too long":    {Change: ChangeCreate, After: tg.snap(1), Reason: longReason},
				"reason newline":     {Change: ChangeCreate, After: tg.snap(1), Reason: "a\nb"},
				"reason escape":      {Change: ChangeCreate, After: tg.snap(1), Reason: "a\x1b[31mb"},
				"reason NUL":         {Change: ChangeCreate, After: tg.snap(1), Reason: "a\x00b"},
				"reason bad UTF-8":   {Change: ChangeCreate, After: tg.snap(1), Reason: "a\xffb"},
			} {
				if e.Actor.Type == "" {
					e.Actor = user("alice")
				}
				e.Now = t0
				if e.Kind == "" {
					e.Kind = tg.kind
				}
				if e.ObjectID == "" {
					e.ObjectID = "obj1"
				}
				err := tg.do(t, func(ctx context.Context, b Backend) error { _, err := Append(ctx, b, e); return err })
				if !errors.Is(err, ErrInvalid) {
					t.Errorf("%s: %v, want ErrInvalid", name, err)
				}
			}
			if n, _ := Current(t.Context(), tg.reader(), tg.kind, "obj1"); n != 0 {
				t.Errorf("refused input left version %d", n)
			}
			// The longest reason, counted in characters, is fine.
			ok := strings.Repeat("é", MaxReason)
			if _, err := tg.appendEntry(t, Entry{Change: ChangeCreate, After: tg.snap(1), Reason: ok}); err != nil {
				t.Errorf("a reason of %d characters: %v", MaxReason, err)
			}
		})
	}
}

// Hostile strings are data end to end: in the snapshot, the reason and the
// actor they are stored, hashed and returned byte for byte, and a SQL
// fragment does nothing.
func TestHostileStringsStayData(t *testing.T) {
	t.Parallel()
	hostile := []string{
		`<script>alert(1)</script>`,
		`'; DROP TABLE settings_versions; --`,
		`" onmouseover="x" {{template "x"}} ${jndi:ldap://x} %s %!d`,
		"line\nbreak and " + string(rune(0x202e)) + " bidi",
		"\x00nul",
		`</textarea><img src=x onerror=1>&amp;`,
	}
	for _, tg := range targets(t) {
		t.Run(tg.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()
			for i, h := range hostile {
				var snap Snapshot
				if tg.kind == KindDomain {
					d := baseDomain()
					d.Name, d.Preset, d.ChallengeTypes, d.IPRanges = h, h, []string{h, "dns-01"}, []string{h}
					snap = d
				} else {
					s := baseTenant()
					s.Organization, s.Locality, s.State, s.AgentEnrollment = h, h, h, h
					snap = s
				}
				id := "obj" + string(rune('A'+i))
				// The actor is hostile too; the reason must be clean (control and format characters are refused).
				reason := strings.Map(func(r rune) rune {
					if r < 0x20 || unicode.Is(unicode.Cf, r) {
						return -1
					}
					return r
				}, h)
				if len(reason) > MaxReason || strings.ContainsRune(h, 0) {
					reason = ""
				}
				if _, err := tg.appendEntry(t, Entry{ObjectID: id, Change: ChangeCreate, After: snap, Reason: reason, Actor: Actor{Type: ActorUser, ID: h, Name: h}}); err != nil {
					t.Fatalf("%q: %v", h, err)
				}
				v, err := Get(ctx, tg.reader(), tg.kind, id, 1)
				if err != nil {
					t.Fatal(err)
				}
				if v.Actor.Name != h || v.Actor.ID != h || v.Reason != reason {
					t.Errorf("%q: actor or reason changed: %+v", h, v)
				}
				got, err := v.Decoded()
				if err != nil {
					t.Fatalf("%q: %v", h, err)
				}
				if !reflectEqual(got, snap.normalized()) {
					t.Errorf("%q: snapshot changed on the way: %+v", h, got)
				}
			}
			// The table is still there and holds exactly the rows written.
			p, err := tg.reader().LatestOfKind(ctx, tg.kind)
			if err != nil || len(p) != len(hostile) {
				t.Errorf("rows after the hostile writes: %d, %v, want %d", len(p), err, len(hostile))
			}
		})
	}
}

func TestStoredSnapshotsAreCheckedOnRead(t *testing.T) {
	t.Parallel()
	for _, tg := range targets(t) {
		t.Run(tg.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()
			if _, err := tg.appendEntry(t, Entry{Change: ChangeCreate, After: tg.snap(1)}); err != nil {
				t.Fatal(err)
			}
			v, err := tg.reader().Latest(ctx, tg.kind, "obj1")
			if err != nil {
				t.Fatal(err)
			}
			bad := v
			bad.Snapshot = []byte(strings.Replace(string(v.Snapshot), "1", "2", 1))
			if _, err = bad.Decoded(); !errors.Is(err, ErrCorrupt) {
				t.Errorf("changed bytes: %v, want ErrCorrupt", err)
			}
			// Right hash, wrong shape: an unknown field or trailing data.
			for name, raw := range map[string]string{
				"unknown field": strings.Replace(string(v.Snapshot), "{", `{"secret":"x",`, 1),
				"trailing data": string(v.Snapshot) + `{}`,
				"not an object": `[]`,
				"truncated":     string(v.Snapshot[:len(v.Snapshot)-1]),
			} {
				w := v
				w.Snapshot, w.SHA256 = []byte(raw), hashHex([]byte(raw))
				if _, err = w.Decoded(); !errors.Is(err, ErrCorrupt) {
					t.Errorf("%s: %v, want ErrCorrupt", name, err)
				}
			}
			w := v
			w.Schema = 2
			if _, err = w.Decoded(); !errors.Is(err, ErrUnknownSchema) {
				t.Errorf("schema 2: %v, want ErrUnknownSchema", err)
			}
		})
	}
}

func TestDiffVersionsFromNothing(t *testing.T) {
	t.Parallel()
	for _, tg := range targets(t) {
		t.Run(tg.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()
			if _, err := tg.appendEntry(t, Entry{Change: ChangeCreate, After: tg.snap(1)}); err != nil {
				t.Fatal(err)
			}
			d, err := DiffVersions(ctx, tg.reader(), tg.kind, "obj1", 0, 1)
			if err != nil || len(d) == 0 {
				t.Fatalf("DiffVersions(0, 1) = %+v, %v", d, err)
			}
			for _, c := range d {
				if c.Kind != Added {
					t.Errorf("%s is %s, want added", c.Key, c.Kind)
				}
			}
			if _, err = DiffVersions(ctx, tg.reader(), tg.kind, "obj1", 1, 5); !errors.Is(err, ErrNotFound) {
				t.Errorf("DiffVersions(1, 5): %v, want ErrNotFound", err)
			}
			if _, err = DiffVersions(ctx, tg.reader(), tg.kind, "obj1", -1, 1); !errors.Is(err, ErrInvalid) {
				t.Errorf("DiffVersions(-1, 1): %v, want ErrInvalid", err)
			}
		})
	}
}

func TestCanonicalIsStable(t *testing.T) {
	t.Parallel()
	a, b := baseDomain(), baseDomain()
	a.IPRanges, b.IPRanges = nil, []string{}
	da, sa, err := Canonical(a)
	if err != nil {
		t.Fatal(err)
	}
	db, sb, _ := Canonical(b)
	if string(da) != string(db) || sa != sb {
		t.Errorf("nil and empty lists differ:\n%s\n%s", da, db)
	}
	want := `{"name":"homelab.example","ca_id":"ca_1","include_subdomains":true,"wildcards":false,"challenge_types":["http-01","dns-01"],"approval":"account","preset":"server","validity_days":0,"address_policy":"internal","ip_ranges":[]}`
	if string(da) != want {
		t.Errorf("canonical form changed (stored hashes depend on it):\n got %s\nwant %s", da, want)
	}
	if h, _, _ := Canonical(DomainSnapshot{Name: "<&>"}); !strings.Contains(string(h), `"<&>"`) {
		t.Errorf("HTML characters are escaped: %s", h)
	}
	huge := DomainSnapshot{IPRanges: make([]string, 20000)}
	for i := range huge.IPRanges {
		huge.IPRanges[i] = "2001:db8::/32"
	}
	if _, _, err = Canonical(huge); !errors.Is(err, ErrInvalid) {
		t.Errorf("an oversized snapshot: %v, want ErrInvalid", err)
	}
	if _, _, err = Canonical(nil); !errors.Is(err, ErrInvalid) {
		t.Errorf("nil snapshot: %v", err)
	}
	// Round trip through Decode.
	for _, s := range []Snapshot{baseDomain().normalized(), baseTenant()} {
		data, _, _ := Canonical(s)
		got, err := Decode(s.Kind(), SchemaVersion, data)
		if err != nil || !reflectEqual(got, s) {
			t.Errorf("round trip of %s: %+v, %v", s.Kind(), got, err)
		}
	}
}

func reflectEqual(a, b any) bool { return reflect.DeepEqual(a, b) }

func TestCheckReason(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		reason string
		ok     bool
	}{
		"empty":               {"", true},
		"plain text":          {"renewed the wildcard – Müller & Söhne, 日本語", true},
		"newline":             {"a\nb", false},
		"tab":                 {"a\tb", false},
		"escape":              {"a\x1bb", false},
		"bidi override":       {"safe " + string(rune(0x202e)) + "gnp.exe", false},
		"bidi isolate":        {"a" + string(rune(0x2066)) + "b", false},
		"zero width space":    {"a" + string(rune(0x200b)) + "b", false},
		"zero width joiner":   {"a" + string(rune(0x200d)) + "b", false},
		"byte order mark":     {string(rune(0xfeff)) + "reason", false},
		"soft hyphen":         {"a" + string(rune(0xad)) + "b", false},
		"invalid UTF-8":       {"a\xffb", false},
		"200 characters":      {strings.Repeat("ä", MaxReason), true},
		"more than 200":       {strings.Repeat("ä", MaxReason+1), false},
		"no-break space":      {"a" + string(rune(0xa0)) + "b", true},
		"emoji without joins": {"done 🎉", true},
	} {
		err := CheckReason(tc.reason)
		if tc.ok != (err == nil) {
			t.Errorf("%s: CheckReason = %v", name, err)
		}
		if err != nil && !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v does not wrap ErrInvalid", name, err)
		}
	}
}
