package tenant

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/Der-Felix/MyOwnPKI/internal/audit"
	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/settingsver"
	"github.com/Der-Felix/MyOwnPKI/internal/store"
	"github.com/Der-Felix/MyOwnPKI/internal/store/systemdb"
	"github.com/Der-Felix/MyOwnPKI/internal/testinstance"
)

// Step 62 of PHASE3 section 16: tenant.Store.Set appends a version in the
// transaction of the change and its audit entry.

func ptr[T any](v T) *T { return &v }

// history returns the versions of the tenant settings, oldest first.
func history(t *testing.T, db *sql.DB) []settingsver.Version {
	t.Helper()
	page, err := settingsver.List(t.Context(), settingsver.SystemBackend(systemdb.New(db)), settingsver.KindTenant, store.DefaultTenant, 0, settingsver.MaxListLimit)
	if err != nil {
		t.Fatal(err)
	}
	slices.Reverse(page.Versions)
	return page.Versions
}

func decoded(t *testing.T, v settingsver.Version) settingsver.TenantSnapshot {
	t.Helper()
	s, err := v.Decoded()
	if err != nil {
		t.Fatal(err)
	}
	return s.(settingsver.TenantSnapshot)
}

// tenantAudit returns the details of the settings audit entries, oldest
// first. The entries wait in the outbox of system.db until the deliverer runs.
func tenantAudit(t *testing.T, db *sql.DB) []map[string]any {
	t.Helper()
	rows, err := db.QueryContext(t.Context(), "SELECT payload_json FROM outbox ORDER BY id")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []map[string]any
	for rows.Next() {
		var p string
		if err = rows.Scan(&p); err != nil {
			t.Fatal(err)
		}
		var e struct {
			Action  string         `json:"action"`
			Details map[string]any `json:"details"`
		}
		if err = json.Unmarshal([]byte(p), &e); err != nil {
			t.Fatal(err)
		}
		if e.Action == ActionSettings {
			out = append(out, e.Details)
		}
	}
	if err = rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func adminWho() keys.Who {
	return keys.Who{Actor: audit.Actor{Type: audit.ActorUser, Name: "tenant-admin"},
		Principal: &authz.Principal{Kind: authz.KindUser, Bindings: []authz.Binding{{Tenant: store.DefaultTenant, Role: authz.Admin}}}}
}

func TestSetAppendsVersions(t *testing.T) {
	t.Parallel()
	v := testinstance.New(t, testinstance.Options{})
	s := &Store{DB: v.SystemDB.Write, Clock: v.Clock}
	ctx := t.Context()
	who := keys.Who{Actor: audit.Actor{Type: audit.ActorUser, ID: "u-7", Name: "tenant-admin"}, Principal: authz.Console()}

	got, err := s.Get(ctx, store.DefaultTenant, who)
	if err != nil || got.Version != 0 {
		t.Fatalf("a tenant that was never changed has ETag 0: %+v %v", got, err)
	}
	if n, verr := s.Version(ctx, store.DefaultTenant, who); verr != nil || n != 0 {
		t.Fatalf("Version: %d %v", n, verr)
	}
	before := *got.ACME

	// The first change writes the baseline (the state before) and the version.
	got.Organization = "Homelab"
	got.ACME = &ACMELimits{OrdersPerAccount: 42, FailedPerName: before.FailedPerName, AccountsPerIP: before.AccountsPerIP}
	n, err := s.SetWith(ctx, store.DefaultTenant, *got, ChangeOptions{Reason: "smaller limits"}, who)
	if err != nil || n != 2 {
		t.Fatalf("first change: version %d %v, want 2", n, err)
	}
	got.AgentEnrollment = ptr(EnrollManual)
	if n, err = s.SetWith(ctx, store.DefaultTenant, *got, ChangeOptions{}, who); err != nil || n != 3 {
		t.Fatalf("second change: version %d %v, want 3", n, err)
	}
	if err = s.Set(ctx, store.DefaultTenant, *got, who); err != nil {
		t.Fatal(err)
	}

	vs := history(t, v.SystemDB.Write)
	if len(vs) != 4 {
		t.Fatalf("%d versions, want baseline and three changes", len(vs))
	}
	for i, ver := range vs {
		if ver.Number != int64(i+1) {
			t.Fatalf("not contiguous: position %d has number %d", i, ver.Number)
		}
	}
	if vs[0].Change != settingsver.ChangeBaseline || vs[0].Actor != settingsver.BaselineActor || vs[1].Change != settingsver.ChangeUpdate {
		t.Errorf("baseline and change: %+v %+v", vs[0], vs[1])
	}
	if vs[1].Actor != (settingsver.Actor{Type: "user", ID: "u-7", Name: "tenant-admin"}) || vs[1].Reason != "smaller limits" || vs[2].Reason != "" {
		t.Errorf("actor and reason: %+v", vs[1])
	}
	if b, a := decoded(t, vs[0]), decoded(t, vs[1]); b.Organization != "" || b.ACME.OrdersPerAccount != before.OrdersPerAccount || a.Organization != "Homelab" || a.ACME.OrdersPerAccount != 42 {
		t.Errorf("baseline %+v, after the first change %+v", b, a)
	}
	if decoded(t, vs[2]).AgentEnrollment != EnrollManual || decoded(t, vs[1]).AgentEnrollment != EnrollVerified {
		t.Errorf("the enrollment mode is part of the snapshot")
	}
	if n, _ = s.Version(ctx, store.DefaultTenant, who); n != 4 {
		t.Errorf("ETag: %d, want 4", n)
	}
	if latest, _ := s.Get(ctx, store.DefaultTenant, who); latest.Version != 4 {
		t.Errorf("Get: version %d, want 4", latest.Version)
	}

	// The audit entries carry the version and the hash; the reason stays out.
	entries := tenantAudit(t, v.SystemDB.Write)
	if len(entries) != 3 {
		t.Fatalf("%d audit entries, want 3", len(entries))
	}
	for i, d := range entries {
		ver := vs[i+1]
		if d["version"] != float64(ver.Number) || d["snapshot_sha256"] != ver.SHA256 {
			t.Errorf("audit entry %d: %v, want version %d and hash %s", i, d["version"], ver.Number, ver.SHA256)
		}
		if text, _ := json.Marshal(d); strings.Contains(string(text), "smaller limits") {
			t.Errorf("the reason is in the audit log: %s", text)
		}
	}
}

func TestSetExpectedVersion(t *testing.T) {
	t.Parallel()
	v := testinstance.New(t, testinstance.Options{})
	s := &Store{DB: v.SystemDB.Write, Clock: v.Clock}
	ctx := t.Context()
	who := testinstance.Console
	got, err := s.Get(ctx, store.DefaultTenant, who)
	if err != nil {
		t.Fatal(err)
	}

	// ETag 0 = never changed: the first change with it works, the same number again does not.
	got.Organization = "One"
	n, err := s.SetWith(ctx, store.DefaultTenant, *got, ChangeOptions{ExpectedVersion: ptr(int64(0))}, who)
	if err != nil || n != 2 {
		t.Fatalf("expected 0: %d %v", n, err)
	}
	got.Organization = "Two"
	_, err = s.SetWith(ctx, store.DefaultTenant, *got, ChangeOptions{ExpectedVersion: ptr(int64(0))}, who)
	var ce *settingsver.ConflictError
	if !errors.Is(err, settingsver.ErrConflict) || !errors.As(err, &ce) || ce.Latest.Number != 2 || ce.Expected != 0 || ce.Latest.Actor.Name != who.Actor.Name {
		t.Fatalf("stale change: %v", err)
	}
	now, err := s.Get(ctx, store.DefaultTenant, who)
	if err != nil || now.Organization != "One" || now.Version != 2 {
		t.Fatalf("a refused change must not change anything: %+v %v", now, err)
	}
	if len(history(t, v.SystemDB.Write)) != 2 || len(tenantAudit(t, v.SystemDB.Write)) != 1 {
		t.Errorf("a refused change wrote a version or an audit entry")
	}
	if _, err = s.SetWith(ctx, store.DefaultTenant, *got, ChangeOptions{ExpectedVersion: ptr(int64(2))}, who); err != nil {
		t.Errorf("the current version: %v", err)
	}
	// A conflict is reported before a missing second factor: an old form should
	// say so before it asks for a confirmation that would be wasted.
	got.AgentEnrollment = ptr(EnrollAuto)
	if _, err = s.SetWith(ctx, store.DefaultTenant, *got, ChangeOptions{ExpectedVersion: ptr(int64(1))}, adminWho()); !errors.Is(err, settingsver.ErrConflict) {
		t.Errorf("stale mode change without step-up: %v, want a conflict", err)
	}
	if _, err = s.SetWith(ctx, store.DefaultTenant, *got, ChangeOptions{ExpectedVersion: ptr(int64(3))}, adminWho()); !errors.Is(err, authz.ErrStepUpRequired) {
		t.Errorf("current mode change without step-up: %v, want ErrStepUpRequired", err)
	}
	if vs := history(t, v.SystemDB.Write); len(vs) != 3 {
		t.Errorf("refusals wrote versions: %d", len(vs))
	}
}

func TestSetConcurrentWritersHaveOneWinner(t *testing.T) {
	t.Parallel()
	v := testinstance.New(t, testinstance.Options{})
	s := &Store{DB: v.SystemDB.Write, Clock: v.Clock}
	ctx := t.Context()
	got, err := s.Get(ctx, store.DefaultTenant, testinstance.Console)
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
			mine := *got
			mine.Organization = strings.Repeat("o", i+1)
			_, errs[i] = s.SetWith(ctx, store.DefaultTenant, mine, ChangeOptions{ExpectedVersion: ptr(int64(0))}, testinstance.Console)
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
	vs := history(t, v.SystemDB.Write)
	if len(vs) != 2 || vs[0].Number != 1 || vs[1].Number != 2 {
		t.Fatalf("history after the race: %+v", vs)
	}
}

// A failing audit entry or a failing version append rolls the change back.
func TestSetRollsBackWhenAuditOrVersionFails(t *testing.T) {
	t.Parallel()
	for name, table := range map[string]string{"audit": "outbox", "version": "settings_versions"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			v := testinstance.New(t, testinstance.Options{})
			s := &Store{DB: v.SystemDB.Write, Clock: v.Clock}
			ctx := t.Context()
			got, err := s.Get(ctx, store.DefaultTenant, testinstance.Console)
			if err != nil {
				t.Fatal(err)
			}
			wasOrg := got.Organization
			auditBefore := len(tenantAudit(t, v.SystemDB.Write))
			trigger := "CREATE TRIGGER test_fail BEFORE INSERT ON " + table + " BEGIN SELECT RAISE(ABORT, 'injected failure'); END"
			if _, err = v.SystemDB.Write.ExecContext(context.Background(), trigger); err != nil {
				t.Fatal(err)
			}
			got.Organization = "Changed"
			if err = s.Set(ctx, store.DefaultTenant, *got, testinstance.Console); err == nil || !strings.Contains(err.Error(), "injected failure") {
				t.Fatalf("Set: %v, want the injected failure", err)
			}
			now, err := s.Get(ctx, store.DefaultTenant, testinstance.Console)
			if err != nil || now.Organization != wasOrg || now.Version != 0 {
				t.Errorf("the failed change left traces: %+v %v", now, err)
			}
			if vs := history(t, v.SystemDB.Write); len(vs) != 0 {
				t.Errorf("the baseline of a failed first change was kept: %+v", vs)
			}
			if n := len(tenantAudit(t, v.SystemDB.Write)); n != auditBefore {
				t.Errorf("audit entries: %d, want %d", n, auditBefore)
			}
		})
	}
}

func TestSetReasonIsChecked(t *testing.T) {
	t.Parallel()
	v := testinstance.New(t, testinstance.Options{})
	s := &Store{DB: v.SystemDB.Write, Clock: v.Clock}
	ctx := t.Context()
	got, err := s.Get(ctx, store.DefaultTenant, testinstance.Console)
	if err != nil {
		t.Fatal(err)
	}
	for _, reason := range []string{strings.Repeat("x", settingsver.MaxReason+1), "a\nb"} {
		if _, err = s.SetWith(ctx, store.DefaultTenant, *got, ChangeOptions{Reason: reason}, testinstance.Console); !errors.Is(err, ErrInvalid) {
			t.Errorf("reason %q: %v, want ErrInvalid", reason, err)
		}
	}
	if vs := history(t, v.SystemDB.Write); len(vs) != 0 {
		t.Errorf("refused reasons wrote versions: %d", len(vs))
	}
}

// A refused mode change (no fresh second factor) is not recorded.
func TestRefusedChangeIsNotRecorded(t *testing.T) {
	t.Parallel()
	v := testinstance.New(t, testinstance.Options{})
	s := &Store{DB: v.SystemDB.Write, Clock: v.Clock}
	ctx := t.Context()
	got, err := s.Get(ctx, store.DefaultTenant, testinstance.Console)
	if err != nil {
		t.Fatal(err)
	}
	got.AgentEnrollment = ptr(EnrollAuto)
	if err = s.Set(ctx, store.DefaultTenant, *got, adminWho()); !errors.Is(err, authz.ErrStepUpRequired) {
		t.Fatalf("Set: %v", err)
	}
	if vs := history(t, v.SystemDB.Write); len(vs) != 0 {
		t.Errorf("a refused change was recorded: %+v", vs)
	}
}
