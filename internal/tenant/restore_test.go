package tenant

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/audit"
	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/settingsver"
	"github.com/Der-Felix/MyOwnPKI/internal/store"
	"github.com/Der-Felix/MyOwnPKI/internal/store/systemdb"
	"github.com/Der-Felix/MyOwnPKI/internal/testinstance"
)

// Step 63 of PHASE3 section 16: history and restore of the tenant settings.

// auditEntry is one entry of the outbox of system.db.
type auditEntry struct {
	Action  string         `json:"action"`
	Result  string         `json:"result"`
	Details map[string]any `json:"details"`
}

// entriesOf returns the outbox entries of an action, oldest first.
func entriesOf(t *testing.T, db *sql.DB, action string) []auditEntry {
	t.Helper()
	rows, err := db.QueryContext(t.Context(), "SELECT payload_json FROM outbox ORDER BY id")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []auditEntry
	for rows.Next() {
		var p string
		if err = rows.Scan(&p); err != nil {
			t.Fatal(err)
		}
		var e auditEntry
		if err = json.Unmarshal([]byte(p), &e); err != nil {
			t.Fatal(err)
		}
		if e.Action == action {
			out = append(out, e)
		}
	}
	if err = rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// userWho is a signed-in user with the bindings; fresh = a second factor of now.
func userWho(v *testinstance.Instance, name string, fresh, token bool, bindings ...authz.Binding) keys.Who {
	for i := range bindings {
		bindings[i].Tenant = store.DefaultTenant
	}
	p := &authz.Principal{Kind: authz.KindUser, UserID: "u-" + name, Username: name, Bindings: bindings, ViaToken: token}
	if fresh {
		p.StepUpAt = v.Clock.Now()
	}
	return keys.Who{Actor: audit.Actor{Type: audit.ActorUser, ID: "u-" + name, Name: name}, SourceIP: "192.0.2.5", Principal: p}
}

// change stores new settings through the ordinary writer and returns the new version.
func change(t *testing.T, s *Store, who keys.Who, edit func(*Settings)) int64 {
	t.Helper()
	got, err := s.Get(t.Context(), store.DefaultTenant, who)
	if err != nil {
		t.Fatal(err)
	}
	edit(got)
	n, err := s.SetWith(t.Context(), store.DefaultTenant, *got, ChangeOptions{}, who)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func opts(expected int64, reason string) ChangeOptions {
	return ChangeOptions{ExpectedVersion: ptr(expected), Reason: reason}
}

func TestRestoreCreatesANewVersion(t *testing.T) {
	t.Parallel()
	v := testinstance.New(t, testinstance.Options{})
	s := &Store{DB: v.SystemDB.Write, Clock: v.Clock}
	ctx := t.Context()
	who := testinstance.Console
	change(t, s, who, func(x *Settings) {
		x.Organization = "Homelab"
		x.ACME = &ACMELimits{OrdersPerAccount: 42, FailedPerName: 5, AccountsPerIP: 10}
	})
	change(t, s, who, func(x *Settings) {
		x.Organization = "Other"
		x.Country = "DE"
		x.TrustPage = ptr(false)
		x.StepUpMinutes = ptr(30)
		x.ACME = &ACMELimits{OrdersPerAccount: 7, FailedPerName: 5, AccountsPerIP: 10}
	})
	old := history(t, v.SystemDB.Write)
	if len(old) != 3 {
		t.Fatalf("%d versions, want baseline and two changes", len(old))
	}
	const reason = "back to Homelab <i>please</i>"
	n, err := s.Restore(ctx, store.DefaultTenant, 2, opts(3, reason), who)
	if err != nil || n != 4 {
		t.Fatalf("restore: version %d, %v", n, err)
	}
	all := history(t, v.SystemDB.Write)
	if len(all) != 4 {
		t.Fatalf("%d versions after the restore, want 4", len(all))
	}
	for i := range old {
		if all[i].SHA256 != old[i].SHA256 || all[i].Change != old[i].Change || all[i].Reason != old[i].Reason {
			t.Errorf("version %d was edited by the restore", i+1)
		}
	}
	last := all[3]
	if last.Change != settingsver.ChangeRestore || last.RestoredFrom != 2 || last.Reason != reason || last.Number != 4 {
		t.Errorf("the new version: %+v", last)
	}
	if !settingsver.Same(decoded(t, last), decoded(t, all[1])) {
		t.Errorf("the restored state %+v differs from the snapshot of version 2 %+v", decoded(t, last), decoded(t, all[1]))
	}
	got, err := s.Get(ctx, store.DefaultTenant, who)
	if err != nil || got.Version != 4 || got.Organization != "Homelab" || got.Country != "" || !*got.TrustPage || *got.StepUpMinutes != DefaultStepUpMinutes || got.ACME.OrdersPerAccount != 42 {
		t.Errorf("settings after the restore: %+v %v", got, err)
	}

	// The audit entry: version, restored_from, the changed keys, the hash; no reason.
	entries := entriesOf(t, v.SystemDB.Write, ActionSettingsRestore)
	if len(entries) != 1 || entries[0].Result != "success" {
		t.Fatalf("restore audit entries: %+v", entries)
	}
	d := entries[0].Details
	keysText, _ := d["changed_keys"].(string)
	for _, k := range []string{"organization", "country", "trust_page", "step_up_minutes", "acme.orders_per_account"} {
		if !slices.Contains(strings.Split(keysText, ","), k) {
			t.Errorf("changed_keys %q lacks %q", keysText, k)
		}
	}
	if d["version"] != float64(4) || d["restored_from"] != float64(2) || d["snapshot_sha256"] != last.SHA256 {
		t.Errorf("audit details: %v", d)
	}
	if text, _ := json.Marshal(d); strings.Contains(string(text), "please") {
		t.Errorf("the reason is in the audit log: %s", text)
	}
	if n := len(entriesOf(t, v.SystemDB.Write, ActionSettings)); n != 2 {
		t.Errorf("a restore must not write a tenant.settings entry too: %d", n)
	}

	// The same state again: refused, and nothing is written.
	for _, from := range []int64{2, 4} {
		if _, err = s.Restore(ctx, store.DefaultTenant, from, opts(4, ""), who); !errors.Is(err, settingsver.ErrIdentical) {
			t.Errorf("restore of version %d when it is current: %v", from, err)
		}
	}
	if len(history(t, v.SystemDB.Write)) != 4 {
		t.Error("a refused restore wrote a version")
	}
}

func TestRestoreNeedsTheNewestVersion(t *testing.T) {
	t.Parallel()
	v := testinstance.New(t, testinstance.Options{})
	s := &Store{DB: v.SystemDB.Write, Clock: v.Clock}
	ctx := t.Context()
	who := testinstance.Console
	change(t, s, who, func(x *Settings) { x.Organization = "One" }) // versions 1 (baseline) and 2
	if _, err := s.Restore(ctx, store.DefaultTenant, 1, ChangeOptions{}, who); !errors.Is(err, settingsver.ErrPreconditionRequired) {
		t.Errorf("no expected version: %v", err)
	}
	var ce *settingsver.ConflictError
	if _, err := s.Restore(ctx, store.DefaultTenant, 1, opts(1, ""), who); !errors.As(err, &ce) || ce.Latest.Number != 2 || ce.Expected != 1 {
		t.Errorf("stale number: %v", err)
	}
	if _, err := s.Restore(ctx, store.DefaultTenant, 9, opts(2, ""), who); !errors.Is(err, settingsver.ErrNotFound) {
		t.Errorf("unknown version: %v", err)
	}
	if _, err := s.Restore(ctx, store.DefaultTenant, 0, opts(2, ""), who); err == nil {
		t.Error("version 0")
	}
	if got, _ := s.Get(ctx, store.DefaultTenant, who); got.Organization != "One" || len(history(t, v.SystemDB.Write)) != 2 {
		t.Error("a refused restore changed something")
	}
	// A refusal is audited; a missing version (nothing to say about it) is not.
	var failed int
	for _, e := range entriesOf(t, v.SystemDB.Write, ActionSettingsRestore) {
		if e.Result == "failure" && e.Details["restored_from"] != nil && e.Details["error"] != nil {
			failed++
		}
	}
	if failed != 3 {
		t.Errorf("%d failure entries, want 3 (no number, stale number, version 0)", failed)
	}
}

func TestRestorePermissions(t *testing.T) {
	t.Parallel()
	v := testinstance.New(t, testinstance.Options{})
	s := &Store{DB: v.SystemDB.Write, Clock: v.Clock}
	ctx := t.Context()
	admin := userWho(v, "admin", true, false, authz.Binding{Role: authz.Admin})
	noStepUp := userWho(v, "admin2", false, false, authz.Binding{Role: authz.Admin})
	token := userWho(v, "bot", true, true, authz.Binding{Role: authz.Admin})
	operator := userWho(v, "op", true, false, authz.Binding{Role: authz.Operator})
	viewer := userWho(v, "view", true, false, authz.Binding{Role: authz.Viewer})
	caAdmin := userWho(v, "caadmin", true, false, authz.Binding{CA: "issuing", Role: authz.Admin})
	change(t, s, testinstance.Console, func(x *Settings) { x.Organization = "One" }) // versions 1 and 2, mode verified

	// Reading the history: the audit right, tenant-wide (versions name users).
	for name, tc := range map[string]struct {
		who     keys.Who
		allowed bool
	}{"admin": {admin, true}, "admin without step-up": {noStepUp, true}, "token": {token, true},
		"operator": {operator, false}, "viewer": {viewer, false}, "admin of one CA": {caAdmin, false}} {
		_, lerr := s.Versions(ctx, store.DefaultTenant, tc.who, 0, 0)
		_, derr := s.VersionDetail(ctx, store.DefaultTenant, tc.who, 1, settingsver.AgainstPrevious)
		_, cerr := s.RestoreCheck(ctx, store.DefaultTenant, tc.who, 1)
		for what, err := range map[string]error{"list": lerr, "detail": derr, "check": cerr} {
			if tc.allowed != (err == nil) || (!tc.allowed && !errors.Is(err, authz.ErrDenied)) {
				t.Errorf("%s reads the %s: %v, allowed %v", name, what, err, tc.allowed)
			}
		}
	}

	// A restore that leaves the enrollment mode alone needs ManageTenant and nothing more.
	restoreOne := func(who keys.Who) error {
		cur, _ := s.Version(ctx, store.DefaultTenant, testinstance.Console)
		_, err := s.Restore(ctx, store.DefaultTenant, 1, opts(cur, ""), who)
		if err == nil {
			// The settings are version 1 again; make them differ for the next caller.
			change(t, s, testinstance.Console, func(x *Settings) { x.Organization = fmt.Sprint("Again", cur) })
		}
		return err
	}
	for name, tc := range map[string]struct {
		who  keys.Who
		want error
	}{"admin": {admin, nil}, "admin without step-up": {noStepUp, nil}, "token": {token, nil},
		"operator": {operator, authz.ErrDenied}, "viewer": {viewer, authz.ErrDenied}, "admin of one CA": {caAdmin, authz.ErrDenied}} {
		err := restoreOne(tc.who)
		if tc.want == nil && err != nil || tc.want != nil && !errors.Is(err, tc.want) {
			t.Errorf("%s restores (mode unchanged): %v, want %v", name, err, tc.want)
		}
	}

	// A restore that changes the mode needs what changing it needs: a fresh second
	// factor, never an API token.
	change(t, s, testinstance.Console, func(x *Settings) { x.AgentEnrollment = ptr(EnrollManual) })
	modeVersion, _ := s.Version(ctx, store.DefaultTenant, testinstance.Console) // the state with mode manual
	change(t, s, testinstance.Console, func(x *Settings) { x.AgentEnrollment = ptr(EnrollVerified) })
	latest, _ := s.Version(ctx, store.DefaultTenant, testinstance.Console)
	before := len(history(t, v.SystemDB.Write))
	for name, tc := range map[string]struct {
		who  keys.Who
		want error
	}{"admin without step-up": {noStepUp, authz.ErrStepUpRequired}, "token": {token, authz.ErrDenied}, "operator": {operator, authz.ErrDenied}} {
		if _, err := s.Restore(ctx, store.DefaultTenant, modeVersion, opts(latest, ""), tc.who); !errors.Is(err, tc.want) {
			t.Errorf("%s restores a mode change: %v, want %v", name, err, tc.want)
		}
	}
	if len(history(t, v.SystemDB.Write)) != before {
		t.Error("a refused mode restore wrote a version")
	}
	var tokenErr *authz.TokenStepUpError
	if _, err := s.Restore(ctx, store.DefaultTenant, modeVersion, opts(latest, ""), token); !errors.As(err, &tokenErr) {
		t.Errorf("a token must get the token refusal, not a prompt: %v", err)
	}
	// The dry run: a missing second factor is no problem, a token's refusal is one.
	if c, err := s.RestoreCheck(ctx, store.DefaultTenant, noStepUp, modeVersion); err != nil || !c.Restorable {
		t.Errorf("dry run without step-up: %+v %v", c, err)
	}
	if c, err := s.RestoreCheck(ctx, store.DefaultTenant, token, modeVersion); err != nil || c.Restorable || len(c.Problems) != 1 || !strings.Contains(c.Problems[0], "token") {
		t.Errorf("dry run as a token: %+v %v", c, err)
	}
	if n, err := s.Restore(ctx, store.DefaultTenant, modeVersion, opts(latest, ""), admin); err != nil || n != latest+1 {
		t.Errorf("admin with step-up restores the mode: %d %v", n, err)
	}
	got, _ := s.Get(ctx, store.DefaultTenant, admin)
	if *got.AgentEnrollment != EnrollManual {
		t.Errorf("the mode after the restore: %s", *got.AgentEnrollment)
	}
	// The denied attempts are in the audit log.
	var denied int
	for _, e := range entriesOf(t, v.SystemDB.Write, ActionSettingsRestore) {
		if e.Result == "denied" {
			denied++
		}
	}
	if denied < 7 {
		t.Errorf("%d denied restore entries", denied)
	}
}

func TestRestoreRefusesWhatAChangeRefuses(t *testing.T) {
	t.Parallel()
	v := testinstance.New(t, testinstance.Options{})
	s := &Store{DB: v.SystemDB.Write, Clock: v.Clock}
	ctx := t.Context()
	who := testinstance.Console
	change(t, s, who, func(x *Settings) { x.Organization = "One" })
	b := settingsver.SystemBackend(systemdb.New(v.SystemDB.Write))
	live, _ := s.Get(ctx, store.DefaultTenant, who)

	// Versions as an older release (or a DBA) could have left them.
	appendRaw := func(mutate func(*settingsver.TenantSnapshot)) int64 {
		t.Helper()
		snap := snapshot(live)
		mutate(&snap)
		data, sum, err := settingsver.Canonical(snap)
		if err != nil {
			t.Fatal(err)
		}
		latest, err := b.Latest(ctx, settingsver.KindTenant, store.DefaultTenant)
		if err != nil {
			t.Fatal(err)
		}
		ver, err := b.Insert(ctx, settingsver.Version{Kind: settingsver.KindTenant, ObjectID: store.DefaultTenant, Number: latest.Number + 1,
			Change: settingsver.ChangeUpdate, Schema: 1, Snapshot: data, SHA256: sum, Actor: settingsver.Actor{Type: "user", ID: "u", Name: "raw"}, CreatedAt: v.Clock.Now()})
		if err != nil {
			t.Fatal(err)
		}
		return ver.Number
	}
	for name, tc := range map[string]struct {
		mutate func(*settingsver.TenantSnapshot)
		want   string
	}{
		"country":        {func(x *settingsver.TenantSnapshot) { x.Country = "xx" }, "country"},
		"organization":   {func(x *settingsver.TenantSnapshot) { x.Organization = strings.Repeat("o", 65) }, "organization"},
		"limits":         {func(x *settingsver.TenantSnapshot) { x.ACME.OrdersPerAccount = 0 }, "orders_per_account"},
		"mode":           {func(x *settingsver.TenantSnapshot) { x.AgentEnrollment = "everybody" }, "agent_enrollment"},
		"step-up":        {func(x *settingsver.TenantSnapshot) { x.StepUpMinutes = 7 }, "step_up_minutes"},
		"predecessor":    {func(x *settingsver.TenantSnapshot) { x.AgentPredecessor.Choice = "burn" }, "agent_predecessor"},
		"control chars":  {func(x *settingsver.TenantSnapshot) { x.Locality = "a\nb" }, "locality"},
		"hostile string": {func(x *settingsver.TenantSnapshot) { x.Organization = "<script>alert(1)</script>" }, ""},
	} {
		n := appendRaw(tc.mutate)
		_, err := s.Restore(ctx, store.DefaultTenant, n, opts(n, ""), who)
		if tc.want == "" {
			// Data that the ordinary writer accepts is restored as data, escaped by whoever shows it.
			if err != nil {
				t.Errorf("%s: %v", name, err)
			}
			continue
		}
		if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want ErrInvalid naming %s", name, err, tc.want)
		}
		c, cerr := s.RestoreCheck(ctx, store.DefaultTenant, who, n)
		if cerr != nil || c.Restorable || len(c.Problems) == 0 || !strings.Contains(strings.Join(c.Problems, "|"), tc.want) {
			t.Errorf("%s dry run: %+v %v", name, c, cerr)
		}
	}
	// Unreadable snapshots: a clear error, never a guess.
	latest, _ := b.Latest(ctx, settingsver.KindTenant, store.DefaultTenant)
	data, sum, _ := settingsver.Canonical(snapshot(live))
	for i, row := range []settingsver.Version{
		{Schema: 9, Snapshot: data, SHA256: sum},
		{Schema: 1, Snapshot: data, SHA256: strings.Repeat("0", 64)},
	} {
		row.Kind, row.ObjectID, row.Number, row.Change = settingsver.KindTenant, store.DefaultTenant, latest.Number+int64(i)+1, settingsver.ChangeUpdate
		row.Actor, row.CreatedAt = settingsver.Actor{Type: "user", ID: "u", Name: "raw"}, v.Clock.Now()
		if _, err := b.Insert(ctx, row); err != nil {
			t.Fatal(err)
		}
		want := []error{settingsver.ErrUnknownSchema, settingsver.ErrCorrupt}[i]
		if _, err := s.Restore(ctx, store.DefaultTenant, row.Number, opts(row.Number, ""), who); !errors.Is(err, want) {
			t.Errorf("version %d: %v, want %v", row.Number, err, want)
		}
		if _, err := s.VersionDetail(ctx, store.DefaultTenant, who, row.Number, settingsver.AgainstPrevious); !errors.Is(err, want) {
			t.Errorf("detail of version %d: %v, want %v", row.Number, err, want)
		}
		if c, err := s.RestoreCheck(ctx, store.DefaultTenant, who, row.Number); err != nil || c.Restorable || len(c.Problems) != 1 {
			t.Errorf("dry run of version %d: %+v %v", row.Number, c, err)
		}
	}
	// A refused restore wrote nothing but the raw rows of the test.
	after, _ := s.Get(ctx, store.DefaultTenant, who)
	if after.Country != "" || after.ACME.OrdersPerAccount == 0 {
		t.Errorf("a refused restore changed the settings: %+v", after)
	}
}

func TestVersionsListAndDetail(t *testing.T) {
	t.Parallel()
	v := testinstance.New(t, testinstance.Options{})
	s := &Store{DB: v.SystemDB.Write, Clock: v.Clock}
	ctx := t.Context()
	who := testinstance.Console
	empty, err := s.Versions(ctx, store.DefaultTenant, who, 0, 0)
	if err != nil || empty.Current != 0 || len(empty.Versions) != 0 {
		t.Fatalf("no history yet: %+v %v", empty, err)
	}
	if _, err = s.VersionDetail(ctx, store.DefaultTenant, who, 1, settingsver.AgainstPrevious); !errors.Is(err, settingsver.ErrNotFound) {
		t.Errorf("detail without history: %v", err)
	}
	for i := range 4 {
		v.Clock.Advance(time.Minute)
		change(t, s, who, func(x *Settings) { x.Organization = strings.Repeat("o", i+1) })
	}
	// 5 versions: the baseline and four changes of the organization.
	p1, err := s.Versions(ctx, store.DefaultTenant, who, 0, 2)
	if err != nil || len(p1.Versions) != 2 || p1.Versions[0].Number != 5 || p1.Next != 4 || p1.Current != 5 {
		t.Fatalf("first page: %+v %v", p1, err)
	}
	if !slices.Equal(p1.Changed[0], []string{"organization"}) {
		t.Errorf("keys of version 5: %v", p1.Changed[0])
	}
	last, err := s.Versions(ctx, store.DefaultTenant, who, 2, 5)
	if err != nil || len(last.Versions) != 1 || last.Versions[0].Number != 1 || last.Next != 0 || len(last.Changed[0]) < 8 {
		t.Fatalf("last page: %+v %v", last, err)
	}
	d, err := s.VersionDetail(ctx, store.DefaultTenant, who, 3, settingsver.AgainstPrevious)
	if err != nil || d.Comparison.From != 2 || len(d.Comparison.Changes) != 1 || d.Comparison.Changes[0].Key != "organization" ||
		d.Comparison.Changes[0].Before[0] != "o" || d.Comparison.Changes[0].After[0] != "oo" || d.Snapshot.Organization != "oo" || d.Current != 5 || !d.Restore.Restorable {
		t.Fatalf("previous: %+v %v", d, err)
	}
	if d, err = s.VersionDetail(ctx, store.DefaultTenant, who, 3, settingsver.AgainstCurrent); err != nil || d.Comparison.From != 5 || len(d.Comparison.Changes) != 1 || d.Comparison.Changes[0].Before[0] != "oooo" {
		t.Fatalf("current: %+v %v", d, err)
	}
	if d, err = s.VersionDetail(ctx, store.DefaultTenant, who, 1, 0); err != nil || d.Comparison.From != 0 || len(d.Comparison.Changes) < 8 {
		t.Fatalf("from 0: %+v %v", d, err)
	}
	if d, err = s.VersionDetail(ctx, store.DefaultTenant, who, 5, settingsver.AgainstPrevious); err != nil || d.Restore.Restorable ||
		!strings.Contains(strings.Join(d.Restore.Problems, "|"), "already have") {
		t.Errorf("the newest version: %+v %v", d, err)
	}
	if _, err = s.VersionDetail(ctx, store.DefaultTenant, who, 3, 99); !errors.Is(err, settingsver.ErrNotFound) {
		t.Errorf("against a version that does not exist: %v", err)
	}
	// Reading does not write.
	if n := len(entriesOf(t, v.SystemDB.Write, ActionSettingsRestore)); n != 0 {
		t.Errorf("a read left %d restore entries", n)
	}
	if n := len(history(t, v.SystemDB.Write)); n != 5 {
		t.Errorf("%d versions, want 5", n)
	}
}

func TestConcurrentRestoresHaveOneWinner(t *testing.T) {
	t.Parallel()
	v := testinstance.New(t, testinstance.Options{})
	s := &Store{DB: v.SystemDB.Write, Clock: v.Clock}
	ctx := t.Context()
	change(t, s, testinstance.Console, func(x *Settings) { x.Organization = "One" })
	const writers = 6
	errs := make([]error, writers)
	var wg sync.WaitGroup
	for i := range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[i] = s.Restore(ctx, store.DefaultTenant, 1, opts(2, ""), testinstance.Console)
		}()
	}
	wg.Wait()
	var won, lost int
	for _, err := range errs {
		switch {
		case err == nil:
			won++
		case errors.Is(err, settingsver.ErrConflict):
			lost++
		default:
			t.Errorf("unexpected: %v", err)
		}
	}
	if won != 1 || lost != writers-1 {
		t.Fatalf("%d winners and %d conflicts, want 1 and %d", won, lost, writers-1)
	}
	if vs := history(t, v.SystemDB.Write); len(vs) != 3 || vs[2].Change != settingsver.ChangeRestore {
		t.Fatalf("history: %+v", vs)
	}
}

func TestRestoreFailureRollsEverythingBack(t *testing.T) {
	t.Parallel()
	for name, table := range map[string]string{"audit": "outbox", "version": "settings_versions"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			v := testinstance.New(t, testinstance.Options{})
			s := &Store{DB: v.SystemDB.Write, Clock: v.Clock}
			ctx := t.Context()
			change(t, s, testinstance.Console, func(x *Settings) { x.Organization = "One" })
			if _, err := v.SystemDB.Write.ExecContext(ctx, failTriggers[table]); err != nil {
				t.Fatal(err)
			}
			if _, err := s.Restore(ctx, store.DefaultTenant, 1, opts(2, ""), testinstance.Console); err == nil || !strings.Contains(err.Error(), "injected failure") {
				t.Fatalf("restore: %v, want the injected failure", err)
			}
			if got, _ := s.Get(ctx, store.DefaultTenant, testinstance.Console); got.Organization != "One" || got.Version != 2 {
				t.Errorf("a failed restore changed the settings: %+v", got)
			}
			if n := len(history(t, v.SystemDB.Write)); n != 2 {
				t.Errorf("%d versions, want 2", n)
			}
		})
	}
}

func TestRestoreReasonIsChecked(t *testing.T) {
	t.Parallel()
	v := testinstance.New(t, testinstance.Options{})
	s := &Store{DB: v.SystemDB.Write, Clock: v.Clock}
	ctx := t.Context()
	change(t, s, testinstance.Console, func(x *Settings) { x.Organization = "One" })
	for _, reason := range []string{strings.Repeat("x", settingsver.MaxReason+1), "a\nb"} {
		if _, err := s.Restore(ctx, store.DefaultTenant, 1, opts(2, reason), testinstance.Console); !errors.Is(err, ErrInvalid) {
			t.Errorf("reason %q: %v", reason, err)
		}
	}
	hostile := `<script>alert(1)</script> '; DROP TABLE tenants; --`
	if _, err := s.Restore(ctx, store.DefaultTenant, 1, opts(2, hostile), testinstance.Console); err != nil {
		t.Fatal(err)
	}
	if vs := history(t, v.SystemDB.Write); vs[2].Reason != hostile {
		t.Errorf("reason %q", vs[2].Reason)
	}
}
