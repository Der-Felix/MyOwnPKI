package ca

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/Der-Felix/MyOwnPKI/internal/settingsver"
	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
)

// Step 62 of PHASE3 section 16: every writer of a domain appends a version in
// the transaction of the change and its audit entry.

// domainHistory returns the versions of a domain, oldest first.
func (v *env) domainHistory(t *testing.T, id string) []settingsver.Version {
	t.Helper()
	page, err := settingsver.List(t.Context(), settingsver.PKIBackend(pkidb.New(v.pki)), settingsver.KindDomain, id, 0, settingsver.MaxListLimit)
	if err != nil {
		t.Fatal(err)
	}
	slices.Reverse(page.Versions)
	return page.Versions
}

// snapshotOf decodes the stored snapshot of a version (the hash is checked).
func snapshotOf(t *testing.T, ver settingsver.Version) settingsver.DomainSnapshot {
	t.Helper()
	s, err := ver.Decoded()
	if err != nil {
		t.Fatal(err)
	}
	return s.(settingsver.DomainSnapshot)
}

// assertContiguous checks that the numbers run 1, 2, 3 ... without a gap.
func assertContiguous(t *testing.T, vs []settingsver.Version) {
	t.Helper()
	for i, ver := range vs {
		if ver.Number != int64(i+1) {
			t.Fatalf("version numbers are not contiguous: position %d has number %d", i, ver.Number)
		}
	}
}

// auditFor returns the details of the last success entry of an action.
func (v *env) auditFor(t *testing.T, action, target string) map[string]any {
	t.Helper()
	var found map[string]any
	for _, r := range v.auditRows(t) {
		if r.action == action && r.target == target && r.result == "success" {
			found = r.details
		}
	}
	if found == nil {
		t.Fatalf("no successful %s entry for %s", action, target)
	}
	return found
}

func TestDomainWritersAppendVersions(t *testing.T) {
	t.Parallel()
	v := domainEnv(t)
	ctx := t.Context()
	const reason = "needed for the new wiki"
	d, err := v.e.CreateDomain(ctx, DomainRequest{Name: "homelab.lan", Who: tester,
		DomainSettings: DomainSettings{CA: ptr("issuing"), Options: ChangeOptions{Reason: reason}}})
	if err != nil {
		t.Fatal(err)
	}
	if d.Version != 1 {
		t.Errorf("created domain: version %d, want 1", d.Version)
	}
	v.clk.Advance(1)
	d2, err := v.e.UpdateDomain(ctx, d.ID, DomainSettings{Wildcards: ptr(true), ValidityDays: ptr(30)}, tester)
	if err != nil || d2.Version != 2 {
		t.Fatalf("update: %+v %v", d2, err)
	}
	if err = v.e.DeleteDomainWith(ctx, d.ID, ChangeOptions{Reason: "retired"}, tester); err != nil {
		t.Fatal(err)
	}

	vs := v.domainHistory(t, d.ID)
	if len(vs) != 3 {
		t.Fatalf("%d versions, want 3 (create, update, delete)", len(vs))
	}
	assertContiguous(t, vs)
	for i, want := range []string{settingsver.ChangeCreate, settingsver.ChangeUpdate, settingsver.ChangeDelete} {
		if vs[i].Change != want {
			t.Errorf("version %d: change %q, want %q", vs[i].Number, vs[i].Change, want)
		}
		if vs[i].Actor.Type != "user" || vs[i].Actor.ID != "u-1" || vs[i].Actor.Name != "it-admin" {
			t.Errorf("version %d: actor %+v", vs[i].Number, vs[i].Actor)
		}
	}
	if vs[0].Reason != reason || vs[1].Reason != "" || vs[2].Reason != "retired" {
		t.Errorf("reasons: %q %q %q", vs[0].Reason, vs[1].Reason, vs[2].Reason)
	}
	if first, second, last := snapshotOf(t, vs[0]), snapshotOf(t, vs[1]), snapshotOf(t, vs[2]); first.Wildcards || !second.Wildcards || second.ValidityDays != 30 || !reflect.DeepEqual(last, second) {
		t.Errorf("snapshots: create %+v, update %+v, delete %+v (a delete stores the deleted state)", first, second, last)
	}

	// The audit entries name their version and the hash of the snapshot; the
	// free-text reason never reaches the audit log.
	for i, action := range []string{ActionDomainCreate, ActionDomainUpdate, ActionDomainDelete} {
		details := v.auditFor(t, action, d.ID)
		if got, _ := details["version"].(float64); int64(got) != vs[i].Number {
			t.Errorf("%s: audit version %v, want %d", action, details["version"], vs[i].Number)
		}
		if details["snapshot_sha256"] != vs[i].SHA256 {
			t.Errorf("%s: audit snapshot_sha256 %v, want %s", action, details["snapshot_sha256"], vs[i].SHA256)
		}
	}
	for _, r := range v.auditRows(t) {
		if text, _ := json.Marshal(r.details); strings.Contains(string(text), reason) || strings.Contains(string(text), "retired") {
			t.Errorf("the reason is in the audit log: %s %v", r.action, r.details)
		}
	}
}

// legacyDomain stores a domain without a history, as an upgrade leaves it.
func (v *env) legacyDomain(t *testing.T, name string) *Domain {
	t.Helper()
	q := pkidb.New(v.pki)
	var caID string
	if err := v.pki.QueryRowContext(t.Context(), `SELECT id FROM cas WHERE name = 'open'`).Scan(&caID); err != nil {
		t.Fatal(err)
	}
	d := domainDefaults()
	d.ID, d.Name, d.CAID, d.CreatedAt, d.UpdatedAt = "dom-legacy-"+name, name, caID, t0, t0
	if err := q.InsertDomain(t.Context(), domainRow(&d)); err != nil {
		t.Fatal(err)
	}
	return &d
}

func TestFirstChangeWritesTheBaseline(t *testing.T) {
	t.Parallel()
	v := domainEnv(t)
	ctx := t.Context()

	d := v.legacyDomain(t, "update.lan")
	if n, err := v.e.DomainVersion(ctx, tester, d.ID); err != nil || n != 0 {
		t.Fatalf("a domain without history has ETag 0, got %d %v", n, err)
	}
	got, err := v.e.GetDomain(ctx, tester, d.ID)
	if err != nil || got.Version != 0 {
		t.Fatalf("GetDomain: version %d %v", got.Version, err)
	}
	up, err := v.e.UpdateDomain(ctx, d.ID, DomainSettings{Approval: ptr(ApprovalOpen)}, tester)
	if err != nil || up.Version != 2 {
		t.Fatalf("update: %+v %v", up, err)
	}
	vs := v.domainHistory(t, d.ID)
	if len(vs) != 2 {
		t.Fatalf("%d versions, want baseline and update", len(vs))
	}
	assertContiguous(t, vs)
	if vs[0].Change != settingsver.ChangeBaseline || vs[0].Actor != settingsver.BaselineActor || vs[1].Change != settingsver.ChangeUpdate {
		t.Errorf("changes %q %q, actor of the baseline %+v", vs[0].Change, vs[1].Change, vs[0].Actor)
	}
	if base, after := snapshotOf(t, vs[0]), snapshotOf(t, vs[1]); base.Approval != ApprovalAccount || after.Approval != ApprovalOpen {
		t.Errorf("the baseline is the state before the change: %q, then %q", base.Approval, after.Approval)
	}
	if n, _ := v.e.DomainVersion(ctx, tester, d.ID); n != 2 {
		t.Errorf("ETag after the first change: %d, want 2", n)
	}
	if details := v.auditFor(t, ActionDomainUpdate, d.ID); details["version"] != float64(2) || details["snapshot_sha256"] != vs[1].SHA256 {
		t.Errorf("audit of the update: %v", details)
	}

	// A delete of a domain without history records the baseline and the deleted state.
	d2 := v.legacyDomain(t, "delete.lan")
	if err = v.e.DeleteDomain(ctx, d2.ID, tester); err != nil {
		t.Fatal(err)
	}
	vs = v.domainHistory(t, d2.ID)
	if len(vs) != 2 || vs[0].Change != settingsver.ChangeBaseline || vs[1].Change != settingsver.ChangeDelete {
		t.Fatalf("history of a deleted legacy domain: %+v", vs)
	}
	if snapshotOf(t, vs[1]).Name != "delete.lan" {
		t.Errorf("the delete must keep the deleted state: %+v", snapshotOf(t, vs[1]))
	}
}

func TestDomainExpectedVersion(t *testing.T) {
	t.Parallel()
	v := domainEnv(t)
	ctx := t.Context()
	d, err := v.e.CreateDomain(ctx, DomainRequest{Name: "homelab.lan", DomainSettings: DomainSettings{CA: ptr("issuing")}, Who: tester})
	if err != nil {
		t.Fatal(err)
	}
	var ce *settingsver.ConflictError

	// A stale number changes nothing and names the newest version.
	_, err = v.e.UpdateDomain(ctx, d.ID, DomainSettings{Wildcards: ptr(true), Options: ChangeOptions{ExpectedVersion: ptr(int64(0))}}, tester)
	if !errors.Is(err, settingsver.ErrConflict) || !errors.As(err, &ce) || ce.Latest.Number != 1 || ce.Expected != 0 || ce.Latest.Actor.Name != "it-admin" {
		t.Fatalf("stale update: %v", err)
	}
	if got, _ := v.e.GetDomain(ctx, tester, d.ID); got.Wildcards || got.Version != 1 {
		t.Errorf("a refused update changed the domain: %+v", got)
	}
	err = v.e.DeleteDomainWith(ctx, d.ID, ChangeOptions{ExpectedVersion: ptr(int64(7))}, tester)
	if !errors.Is(err, settingsver.ErrConflict) {
		t.Fatalf("stale delete: %v", err)
	}
	if _, gerr := v.e.GetDomain(ctx, tester, d.ID); gerr != nil {
		t.Errorf("a refused delete removed the domain: %v", gerr)
	}
	_, err = v.e.CreateDomain(ctx, DomainRequest{Name: "other.lan", Who: tester,
		DomainSettings: DomainSettings{CA: ptr("open"), Options: ChangeOptions{ExpectedVersion: ptr(int64(3))}}})
	if !errors.Is(err, settingsver.ErrConflict) {
		t.Fatalf("a create expects no history: %v", err)
	}
	if list, _ := v.e.ListDomains(ctx, tester); len(list) != 1 {
		t.Errorf("a refused create stored a domain: %d domains", len(list))
	}
	if vs := v.domainHistory(t, d.ID); len(vs) != 1 {
		t.Errorf("refusals wrote versions: %d", len(vs))
	}

	// The current number lets the change through, and the next one needs the new number.
	up, err := v.e.UpdateDomain(ctx, d.ID, DomainSettings{Wildcards: ptr(true), Options: ChangeOptions{ExpectedVersion: ptr(int64(1))}}, tester)
	if err != nil || up.Version != 2 {
		t.Fatalf("update with the current version: %+v %v", up, err)
	}
	if _, err = v.e.UpdateDomain(ctx, d.ID, DomainSettings{Wildcards: ptr(false), Options: ChangeOptions{ExpectedVersion: ptr(int64(1))}}, tester); !errors.Is(err, settingsver.ErrConflict) {
		t.Fatalf("second update with the old number: %v", err)
	}
	// The refusal is audited like another refused domain change.
	var refused bool
	for _, r := range v.auditRows(t) {
		refused = refused || (r.action == ActionDomainUpdate && r.result == "failure")
	}
	if !refused {
		t.Error("the refused update is not in the audit log")
	}

	// A domain that is not there for the writer stays not found (no history row for a ghost).
	if _, err = v.e.UpdateDomain(ctx, "dom-nope", DomainSettings{Wildcards: ptr(true), Options: ChangeOptions{ExpectedVersion: ptr(int64(0))}}, tester); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown domain: %v", err)
	}
}

func TestDomainConcurrentWritersHaveOneWinner(t *testing.T) {
	t.Parallel()
	v := domainEnv(t)
	ctx := t.Context()
	d, err := v.e.CreateDomain(ctx, DomainRequest{Name: "homelab.lan", DomainSettings: DomainSettings{CA: ptr("issuing")}, Who: tester})
	if err != nil {
		t.Fatal(err)
	}
	const writers = 6
	errs := make([]error, writers)
	var wg sync.WaitGroup
	for i := range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[i] = v.e.UpdateDomain(ctx, d.ID, DomainSettings{ValidityDays: ptr(10 + i), Options: ChangeOptions{ExpectedVersion: ptr(int64(1))}}, tester)
		}()
	}
	wg.Wait()
	var won, lost int
	for _, e := range errs {
		switch {
		case e == nil:
			won++
		case errors.Is(e, settingsver.ErrConflict):
			lost++
		default:
			t.Errorf("unexpected error: %v", e)
		}
	}
	if won != 1 || lost != writers-1 {
		t.Fatalf("%d winners and %d conflicts, want 1 and %d", won, lost, writers-1)
	}
	vs := v.domainHistory(t, d.ID)
	if len(vs) != 2 {
		t.Fatalf("%d versions, want create and one update", len(vs))
	}
	assertContiguous(t, vs)

	// Without the check every writer goes through, one version each, no gaps.
	for i := range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[i] = v.e.UpdateDomain(ctx, d.ID, DomainSettings{ValidityDays: ptr(40 + i)}, tester)
		}()
	}
	wg.Wait()
	for _, e := range errs {
		if e != nil {
			t.Errorf("update without a check: %v", e)
		}
	}
	vs = v.domainHistory(t, d.ID)
	if len(vs) != 2+writers {
		t.Fatalf("%d versions, want %d", len(vs), 2+writers)
	}
	assertContiguous(t, vs)
}

// A failing audit entry or a failing version append rolls the whole change back.
func TestDomainChangeRollsBackWhenAuditOrVersionFails(t *testing.T) {
	t.Parallel()
	for name, table := range map[string]string{"audit": "outbox", "version": "settings_versions"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			v := domainEnv(t)
			ctx := t.Context()
			d, err := v.e.CreateDomain(ctx, DomainRequest{Name: "homelab.lan", DomainSettings: DomainSettings{CA: ptr("issuing")}, Who: tester})
			if err != nil {
				t.Fatal(err)
			}
			legacy := v.legacyDomain(t, "legacy.lan")
			before := len(v.domainHistory(t, d.ID))
			v.failInserts(t, table)

			if _, err = v.e.CreateDomain(ctx, DomainRequest{Name: "new.lan", DomainSettings: DomainSettings{CA: ptr("open")}, Who: tester}); !injected(err) {
				t.Error("create succeeded although its audit entry or version could not be written")
			}
			if _, err = v.e.UpdateDomain(ctx, d.ID, DomainSettings{Wildcards: ptr(true)}, tester); !injected(err) {
				t.Error("update succeeded")
			}
			if _, err = v.e.UpdateDomain(ctx, legacy.ID, DomainSettings{Wildcards: ptr(true)}, tester); !injected(err) {
				t.Error("update of a domain without history succeeded")
			}
			if err = v.e.DeleteDomain(ctx, d.ID, tester); !injected(err) {
				t.Error("delete succeeded")
			}

			list, err := v.e.ListDomains(ctx, tester)
			if err != nil || len(list) != 2 {
				t.Fatalf("domains after the failures: %d %v, want the two that existed", len(list), err)
			}
			for _, got := range list {
				if got.Wildcards {
					t.Errorf("%s: a failed update changed the row", got.Name)
				}
			}
			if after := len(v.domainHistory(t, d.ID)); after != before {
				t.Errorf("history grew from %d to %d versions", before, after)
			}
			if vs := v.domainHistory(t, legacy.ID); len(vs) != 0 {
				t.Errorf("the baseline of a failed first change was kept: %+v", vs)
			}
		})
	}
}

// failInserts makes every INSERT into table fail with a SQL error.
func (v *env) failInserts(t *testing.T, table string) {
	t.Helper()
	// settings_versions has a trigger of its own; a second BEFORE INSERT trigger is allowed.
	if _, err := v.pki.ExecContext(context.Background(),
		`CREATE TRIGGER test_fail_`+table+` BEFORE INSERT ON `+table+` BEGIN SELECT RAISE(ABORT, 'injected failure'); END`); err != nil {
		t.Fatal(err)
	}
}

func TestDomainReasonIsChecked(t *testing.T) {
	t.Parallel()
	v := domainEnv(t)
	ctx := t.Context()
	long := strings.Repeat("x", settingsver.MaxReason+1)
	for name, reason := range map[string]string{"too long": long, "newline": "a\nb"} {
		_, err := v.e.CreateDomain(ctx, DomainRequest{Name: "homelab.lan", Who: tester, DomainSettings: DomainSettings{CA: ptr("issuing"), Options: ChangeOptions{Reason: reason}}})
		if !deniedWith(err, "reason") {
			t.Errorf("create, %s: %v", name, err)
		}
	}
	d, err := v.e.CreateDomain(ctx, DomainRequest{Name: "homelab.lan", DomainSettings: DomainSettings{CA: ptr("issuing")}, Who: tester})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = v.e.UpdateDomain(ctx, d.ID, DomainSettings{Options: ChangeOptions{Reason: long}}, tester); !deniedWith(err, "reason") {
		t.Errorf("update: %v", err)
	}
	if err = v.e.DeleteDomainWith(ctx, d.ID, ChangeOptions{Reason: "a\tb"}, tester); !deniedWith(err, "reason") {
		t.Errorf("delete: %v", err)
	}
	if vs := v.domainHistory(t, d.ID); len(vs) != 1 {
		t.Errorf("refused reasons wrote versions: %d", len(vs))
	}
}

// injected reports whether err is the failure failInserts causes.
func injected(err error) bool { return err != nil && strings.Contains(err.Error(), "injected failure") }
