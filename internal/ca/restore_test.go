package ca

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/settingsver"
	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
)

// Step 63 of PHASE3 section 16: history and restore of domains.

// newDomain creates a domain on a CA and returns it.
func (v *env) newDomain(t *testing.T, name, caName string, s DomainSettings) *Domain {
	t.Helper()
	s.CA = &caName
	d, err := v.e.CreateDomain(t.Context(), DomainRequest{Name: name, DomainSettings: s, Who: tester})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// restoreOpts expects the given newest version.
func restoreOpts(expected int64, reason string) ChangeOptions {
	return ChangeOptions{ExpectedVersion: ptr(expected), Reason: reason}
}

func TestRestoreDomainUpdateCreatesANewVersion(t *testing.T) {
	t.Parallel()
	v := domainEnv(t)
	ctx := t.Context()
	d := v.newDomain(t, "homelab.lan", "issuing", DomainSettings{})
	v.clk.Advance(time.Minute)
	if _, err := v.e.UpdateDomain(ctx, d.ID, DomainSettings{Wildcards: ptr(true), ValidityDays: ptr(30), IPRanges: []string{"10.1.0.0/16"}}, tester); err != nil {
		t.Fatal(err)
	}
	v.clk.Advance(time.Minute)
	if _, err := v.e.UpdateDomain(ctx, d.ID, DomainSettings{Approval: ptr(ApprovalOpen), Wildcards: ptr(false), IPRanges: []string{}, CA: ptr("open")}, tester); err != nil {
		t.Fatal(err)
	}
	old := v.domainHistory(t, d.ID)
	if len(old) != 3 {
		t.Fatalf("%d versions, want 3", len(old))
	}
	const reason = "back to the first wildcard setup <b>x</b>"
	v.clk.Advance(time.Minute)
	got, err := v.e.RestoreDomain(ctx, d.ID, 2, restoreOpts(3, reason), tester)
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != 4 || !got.Wildcards || got.ValidityDays != 30 || got.CA != "issuing" || got.Approval != ApprovalAccount || len(got.IPRanges) != 1 {
		t.Fatalf("restored domain: %+v", got)
	}
	all := v.domainHistory(t, d.ID)
	assertContiguous(t, all)
	if len(all) != 4 {
		t.Fatalf("%d versions after the restore, want 4", len(all))
	}
	// The restore is a new version; no earlier one was touched.
	for i := range old {
		if all[i].SHA256 != old[i].SHA256 || all[i].Change != old[i].Change || all[i].Reason != old[i].Reason || !all[i].CreatedAt.Equal(old[i].CreatedAt) {
			t.Errorf("version %d was edited by the restore: %+v -> %+v", i+1, old[i], all[i])
		}
	}
	last := all[3]
	if last.Change != settingsver.ChangeRestore || last.RestoredFrom != 2 || last.Reason != reason || last.Actor.Name != "it-admin" {
		t.Errorf("the new version: %+v", last)
	}
	// The domain equals the old snapshot.
	if now, want := snapshotOf(t, last), snapshotOf(t, all[1]); !settingsver.Same(now, want) {
		t.Errorf("the restored state %+v differs from the old snapshot %+v", now, want)
	}
	// The stored row is what the engine reads back, too.
	if back, gerr := v.e.GetDomain(ctx, tester, d.ID); gerr != nil || !settingsver.Same(domainSnapshot(back), snapshotOf(t, all[1])) || back.Version != 4 {
		t.Errorf("read back: %+v %v", back, gerr)
	}

	// Audit: domain.restore with the version, restored_from, the changed keys and
	// the hash; the free-text reason stays out.
	details := v.auditFor(t, ActionDomainRestore, d.ID)
	if details["version"] != float64(4) || details["restored_from"] != float64(2) || details["snapshot_sha256"] != last.SHA256 {
		t.Errorf("audit details: %v", details)
	}
	keysText, _ := details["changed_keys"].(string)
	for _, k := range []string{"wildcards", "ca_id", "approval", "ip_ranges"} {
		if !slices.Contains(strings.Split(keysText, ","), k) {
			t.Errorf("changed_keys %q lacks %q", keysText, k)
		}
	}
	for _, r := range v.auditRows(t) {
		if text, _ := json.Marshal(r.details); strings.Contains(string(text), "wildcard setup") {
			t.Errorf("the reason is in the audit log: %s %v", r.action, r.details)
		}
	}
	// A second restore of the same version is refused: the state is current.
	if _, err = v.e.RestoreDomain(ctx, d.ID, 2, restoreOpts(4, ""), tester); !errors.Is(err, settingsver.ErrIdentical) {
		t.Errorf("restoring the current state: %v", err)
	}
	if _, err = v.e.RestoreDomain(ctx, d.ID, 4, restoreOpts(4, ""), tester); !errors.Is(err, settingsver.ErrIdentical) {
		t.Errorf("restoring the restore: %v", err)
	}
	if n := len(v.domainHistory(t, d.ID)); n != 4 {
		t.Errorf("a refused restore wrote a version: %d", n)
	}
}

func TestRestoreNeedsTheNewestVersion(t *testing.T) {
	t.Parallel()
	v := domainEnv(t)
	ctx := t.Context()
	d := v.newDomain(t, "homelab.lan", "issuing", DomainSettings{})
	if _, err := v.e.UpdateDomain(ctx, d.ID, DomainSettings{Wildcards: ptr(true)}, tester); err != nil {
		t.Fatal(err)
	}
	// No number at all: the caller must say what it based the restore on.
	if _, err := v.e.RestoreDomain(ctx, d.ID, 1, ChangeOptions{}, tester); !errors.Is(err, settingsver.ErrPreconditionRequired) {
		t.Errorf("no expected version: %v", err)
	}
	var ce *settingsver.ConflictError
	if _, err := v.e.RestoreDomain(ctx, d.ID, 1, restoreOpts(1, ""), tester); !errors.As(err, &ce) || ce.Latest.Number != 2 {
		t.Errorf("stale number: %v", err)
	}
	if got, _ := v.e.GetDomain(ctx, tester, d.ID); !got.Wildcards {
		t.Error("a refused restore changed the domain")
	}
	if n := len(v.domainHistory(t, d.ID)); n != 2 {
		t.Errorf("%d versions after the refusals, want 2", n)
	}
	// Unknown versions and domains.
	if _, err := v.e.RestoreDomain(ctx, d.ID, 9, restoreOpts(2, ""), tester); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown version: %v", err)
	}
	if _, err := v.e.RestoreDomain(ctx, "dom-nope", 1, restoreOpts(0, ""), tester); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown domain: %v", err)
	}
	// The refusals are audited (a stale restore is a failure, like a stale update).
	var failed int
	for _, r := range v.auditRows(t) {
		if r.action == ActionDomainRestore && r.result == "failure" {
			failed++
		}
	}
	if failed < 2 {
		t.Errorf("%d refused restores in the audit log, want at least 2", failed)
	}
}

func TestRestoreADeletedDomain(t *testing.T) {
	t.Parallel()
	v := domainEnv(t)
	ctx := t.Context()
	d := v.newDomain(t, "homelab.lan", "issuing", DomainSettings{Approval: ptr(ApprovalOpen)})
	if _, err := v.e.UpdateDomain(ctx, d.ID, DomainSettings{ValidityDays: ptr(45)}, tester); err != nil {
		t.Fatal(err)
	}
	v.clk.Advance(time.Hour)
	if err := v.e.DeleteDomainWith(ctx, d.ID, ChangeOptions{Reason: "oops"}, tester); err != nil {
		t.Fatal(err)
	}
	list, err := v.e.ListDeletedDomains(ctx, tester)
	if err != nil || len(list) != 1 || list[0].ID != d.ID || list[0].Name != "homelab.lan" || list[0].Version != 3 ||
		list[0].CAName != "issuing" || list[0].DeletedBy != "it-admin" || list[0].Reason != "oops" {
		t.Fatalf("deleted domains: %+v %v", list, err)
	}
	// The history of a deleted domain can be read; its last version is the deletion.
	page, err := v.e.ListDomainVersions(ctx, tester, d.ID, 0, 0)
	if err != nil || page.Current != 3 || len(page.Versions) != 3 || page.Versions[0].Change != settingsver.ChangeDelete {
		t.Fatalf("history of a deleted domain: %+v %v", page, err)
	}

	v.clk.Advance(time.Minute)
	got, err := v.e.RestoreDomain(ctx, d.ID, 2, restoreOpts(3, "undelete"), tester)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != d.ID || got.Name != "homelab.lan" || got.ValidityDays != 45 || got.Approval != ApprovalOpen || got.Version != 4 {
		t.Fatalf("recreated domain: %+v", got)
	}
	vs := v.domainHistory(t, d.ID)
	if len(vs) != 4 || vs[3].Change != settingsver.ChangeRestore || vs[3].RestoredFrom != 2 {
		t.Fatalf("history after the undelete: %+v", vs)
	}
	assertContiguous(t, vs)
	if domains, lerr := v.e.ListDomains(ctx, tester); lerr != nil || len(domains) != 1 || domains[0].ID != d.ID {
		t.Errorf("domains: %+v %v", domains, lerr)
	}
	if list, lerr := v.e.ListDeletedDomains(ctx, tester); lerr != nil || len(list) != 0 {
		t.Errorf("a restored domain is still listed as deleted: %+v %v", list, lerr)
	}
	details := v.auditFor(t, ActionDomainRestore, d.ID)
	if details["version"] != float64(4) || details["restored_from"] != float64(2) || details["snapshot_sha256"] != vs[3].SHA256 {
		t.Errorf("audit details: %v", details)
	}
}

func TestRestoreRefusalsNameTheirReasons(t *testing.T) {
	t.Parallel()
	v := domainEnv(t)
	ctx := t.Context()

	// The name is taken by another domain.
	d := v.newDomain(t, "homelab.lan", "issuing", DomainSettings{})
	if err := v.e.DeleteDomain(ctx, d.ID, tester); err != nil {
		t.Fatal(err)
	}
	v.newDomain(t, "homelab.lan", "issuing", DomainSettings{})
	if _, err := v.e.RestoreDomain(ctx, d.ID, 1, restoreOpts(2, ""), tester); !deniedWith(err, `"homelab.lan" exists already`) {
		t.Errorf("a taken name: %v", err)
	}
	if check, err := v.e.DomainRestoreCheck(ctx, tester, d.ID, 1); err != nil || check.Restorable || !strings.Contains(strings.Join(check.Problems, "|"), "exists already") {
		t.Errorf("the dry run says %+v %v", check, err)
	}

	// The CA of the version is retired.
	e := v.newDomain(t, "sub.homelab.lan", "open", DomainSettings{})
	if _, err := v.e.UpdateDomain(ctx, e.ID, DomainSettings{CA: ptr("issuing"), ValidityDays: ptr(10)}, tester); err != nil {
		t.Fatal(err)
	}
	if _, err := v.e.UpdateDomain(ctx, e.ID, DomainSettings{CA: ptr("open")}, tester); err != nil {
		t.Fatal(err)
	}
	if err := v.e.RetireCA(ctx, "issuing", tester); err != nil {
		t.Fatal(err)
	}
	_, err := v.e.RestoreDomain(ctx, e.ID, 2, restoreOpts(3, ""), tester)
	if !deniedWith(err, `CA "issuing" is retired, not active`) {
		t.Errorf("a retired CA: %v", err)
	}
	if got, _ := v.e.GetDomain(ctx, tester, e.ID); got.CA != "open" {
		t.Errorf("a refused restore moved the domain to %q", got.CA)
	}
	check, err := v.e.DomainRestoreCheck(ctx, tester, e.ID, 2)
	if err != nil || check.Restorable || len(check.Problems) == 0 || !strings.Contains(check.Problems[0], "retired") {
		t.Errorf("the dry run of a retired CA: %+v %v", check, err)
	}

	// A version that points at a preset or a CA that is gone: written as the
	// database would hold it (an old row), restored through the ordinary checks.
	f := v.newDomain(t, "third.lan", "open", DomainSettings{})
	for name, mutate := range map[string]func(*settingsver.DomainSnapshot){
		"missing preset": func(s *settingsver.DomainSnapshot) { s.Preset = "no-such-preset" },
		"missing CA":     func(s *settingsver.DomainSnapshot) { s.CAID = "ca-gone" },
		"bad range":      func(s *settingsver.DomainSnapshot) { s.IPRanges = []string{"not an ip"} },
		"no challenge":   func(s *settingsver.DomainSnapshot) { s.ChallengeTypes = nil },
	} {
		snap := domainSnapshot(f)
		mutate(&snap)
		n := v.appendRaw(t, f.ID, snap)
		_, rerr := v.e.RestoreDomain(ctx, f.ID, n, restoreOpts(n, ""), tester)
		var denied *DeniedError
		if !errors.As(rerr, &denied) || len(denied.Reasons) == 0 {
			t.Errorf("%s: %v", name, rerr)
			continue
		}
		t.Logf("%s: %v", name, denied.Reasons)
		// The refusal leaves everything as it was: the next row is a plain append of the test.
		if got, _ := v.e.GetDomain(ctx, tester, f.ID); got.Preset != "server" || got.CAID != f.CAID {
			t.Errorf("%s: a refused restore changed the domain: %+v", name, got)
		}
	}
	// And the reasons of those are the reasons of an ordinary change.
	if _, uerr := v.e.UpdateDomain(ctx, f.ID, DomainSettings{Preset: ptr("no-such-preset")}, tester); !deniedWith(uerr, `no preset named "no-such-preset"`) {
		t.Errorf("ordinary change with a missing preset: %v", uerr)
	}
}

// appendRaw adds a version row for a domain as a later release (or a DBA) could
// have written it; it returns the number. The domain itself is not touched.
func (v *env) appendRaw(t *testing.T, id string, snap settingsver.DomainSnapshot) int64 {
	t.Helper()
	b := settingsver.PKIBackend(pkidb.New(v.pki))
	latest, err := b.Latest(t.Context(), settingsver.KindDomain, id)
	var next int64 = 1
	if err == nil {
		next = latest.Number + 1
	}
	data, sum, err := settingsver.Canonical(snap)
	if err != nil {
		t.Fatal(err)
	}
	ver, err := b.Insert(t.Context(), settingsver.Version{
		Kind: settingsver.KindDomain, ObjectID: id, Number: next, Change: settingsver.ChangeUpdate, Schema: 1, Snapshot: data, SHA256: sum,
		Actor: settingsver.Actor{Type: "user", ID: "u-raw", Name: "raw"}, CreatedAt: v.clk.Now(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return ver.Number
}

func TestRestoreOfAnUnreadableSnapshotIsRefusedClearly(t *testing.T) {
	t.Parallel()
	v := domainEnv(t)
	ctx := t.Context()
	d := v.newDomain(t, "homelab.lan", "issuing", DomainSettings{})
	b := settingsver.PKIBackend(pkidb.New(v.pki))
	data, sum, err := settingsver.Canonical(domainSnapshot(d))
	if err != nil {
		t.Fatal(err)
	}
	insert := func(n int64, schema int, snapshot, hash string) {
		t.Helper()
		_, ierr := b.Insert(ctx, settingsver.Version{Kind: settingsver.KindDomain, ObjectID: d.ID, Number: n, Change: settingsver.ChangeUpdate,
			Schema: schema, Snapshot: []byte(snapshot), SHA256: hash, Actor: settingsver.Actor{Type: "user", ID: "u", Name: "x"}, CreatedAt: v.clk.Now()})
		if ierr != nil {
			t.Fatal(ierr)
		}
	}
	insert(2, 9, string(data), sum)                                         // a schema of a later release
	insert(3, 1, string(data), strings.Repeat("0", 64))                     // the hash does not match
	extra := strings.Replace(string(data), `"name"`, `"extra":1,"name"`, 1) // not the closed type
	sumExtra := sha256.Sum256([]byte(extra))
	insert(4, 1, extra, hex.EncodeToString(sumExtra[:])) // a correct hash of bytes that are not the closed type
	for n, want := range map[int64]error{2: settingsver.ErrUnknownSchema, 3: settingsver.ErrCorrupt, 4: settingsver.ErrCorrupt} {
		if _, rerr := v.e.RestoreDomain(ctx, d.ID, n, restoreOpts(4, ""), tester); !errors.Is(rerr, want) {
			t.Errorf("version %d: %v, want %v", n, rerr, want)
		}
		if check, cerr := v.e.DomainRestoreCheck(ctx, tester, d.ID, n); cerr != nil || check.Restorable || len(check.Problems) != 1 {
			t.Errorf("version %d dry run: %+v %v", n, check, cerr)
		}
		if _, gerr := v.e.GetDomainVersion(ctx, tester, d.ID, n, settingsver.AgainstPrevious); !errors.Is(gerr, want) {
			t.Errorf("version %d detail: %v", n, gerr)
		}
	}
	// The list still works and shows the damaged versions without keys.
	page, err := v.e.ListDomainVersions(ctx, tester, d.ID, 0, 0)
	if err != nil || len(page.Versions) != 4 || page.Changed[0] != nil || page.Changed[1] != nil || page.Changed[2] != nil {
		t.Errorf("list: %+v %v", page, err)
	}
}

func TestDomainHistoryReadsAndDiffs(t *testing.T) {
	t.Parallel()
	v := domainEnv(t)
	ctx := t.Context()
	// A domain that was never changed since the history began: an empty history.
	legacy := v.legacyDomain(t, "legacy.lan")
	page, err := v.e.ListDomainVersions(ctx, tester, legacy.ID, 0, 0)
	if err != nil || page.Current != 0 || len(page.Versions) != 0 || page.Next != 0 {
		t.Fatalf("history of a legacy domain: %+v %v", page, err)
	}
	if _, err = v.e.GetDomainVersion(ctx, tester, legacy.ID, 1, settingsver.AgainstPrevious); !errors.Is(err, ErrNotFound) {
		t.Errorf("version of a legacy domain: %v", err)
	}
	if _, err = v.e.ListDomainVersions(ctx, tester, "dom-nope", 0, 0); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown domain: %v", err)
	}

	d := v.newDomain(t, "homelab.lan", "issuing", DomainSettings{})
	for i := range 4 {
		v.clk.Advance(time.Minute)
		if _, err = v.e.UpdateDomain(ctx, d.ID, DomainSettings{ValidityDays: ptr(10 + i)}, tester); err != nil {
			t.Fatal(err)
		}
	}
	// Paging: newest first, a cursor, and the keys each version changed.
	p1, err := v.e.ListDomainVersions(ctx, tester, d.ID, 0, 2)
	if err != nil || len(p1.Versions) != 2 || p1.Versions[0].Number != 5 || p1.Next != 4 || p1.Current != 5 {
		t.Fatalf("first page: %+v %v", p1, err)
	}
	if !slices.Equal(p1.Changed[0], []string{"validity_days"}) {
		t.Errorf("keys of version 5: %v", p1.Changed[0])
	}
	p3, err := v.e.ListDomainVersions(ctx, tester, d.ID, 2, 2)
	if err != nil || len(p3.Versions) != 1 || p3.Versions[0].Number != 1 || p3.Next != 0 {
		t.Fatalf("last page: %+v %v", p3, err)
	}
	if len(p3.Changed[0]) < 5 {
		t.Errorf("version 1 compared with nothing lists every set setting: %v", p3.Changed[0])
	}

	// Diffs: previous, current, an explicit number, and from = 0.
	det, err := v.e.GetDomainVersion(ctx, tester, d.ID, 3, settingsver.AgainstPrevious)
	if err != nil || det.Comparison.From != 2 || det.Comparison.To != 3 || len(det.Comparison.Changes) != 1 ||
		det.Comparison.Changes[0].Key != "validity_days" || det.Comparison.Changes[0].Before[0] != "10" || det.Comparison.Changes[0].After[0] != "11" {
		t.Fatalf("previous: %+v %v", det, err)
	}
	if det.Snapshot.ValidityDays != 11 || det.Current != 5 || !det.Restore.Restorable {
		t.Errorf("detail: %+v", det)
	}
	if det, err = v.e.GetDomainVersion(ctx, tester, d.ID, 1, settingsver.AgainstCurrent); err != nil || det.Comparison.From != 5 || det.Comparison.Against != "current" ||
		len(det.Comparison.Changes) != 1 || det.Comparison.Changes[0].Before[0] != "13" {
		t.Fatalf("current: %+v %v", det, err)
	}
	if det, err = v.e.GetDomainVersion(ctx, tester, d.ID, 4, 1); err != nil || det.Comparison.From != 1 || len(det.Comparison.Changes) != 1 {
		t.Fatalf("against 1: %+v %v", det, err)
	}
	if det, err = v.e.GetDomainVersion(ctx, tester, d.ID, 1, 0); err != nil || det.Comparison.From != 0 || len(det.Comparison.Changes) < 5 {
		t.Fatalf("from 0: %+v %v", det, err)
	}
	if _, err = v.e.GetDomainVersion(ctx, tester, d.ID, 1, 99); !errors.Is(err, ErrNotFound) {
		t.Errorf("against a version that does not exist: %v", err)
	}
	// The newest version is the state the domain has: nothing to restore.
	if det, err = v.e.GetDomainVersion(ctx, tester, d.ID, 5, settingsver.AgainstPrevious); err != nil || det.Restore.Restorable ||
		!strings.Contains(strings.Join(det.Restore.Problems, "|"), "already has") {
		t.Errorf("restorable newest: %+v %v", det, err)
	}

	// A deleted domain: "current" is nothing, so a restore would add everything.
	if err = v.e.DeleteDomain(ctx, d.ID, tester); err != nil {
		t.Fatal(err)
	}
	det, err = v.e.GetDomainVersion(ctx, tester, d.ID, 2, settingsver.AgainstCurrent)
	if err != nil || det.Comparison.From != 0 || len(det.Comparison.Changes) < 5 || !det.Restore.Restorable || det.Current != 6 {
		t.Fatalf("a deleted domain against current: %+v %v", det, err)
	}
	for _, c := range det.Comparison.Changes {
		if c.Kind != settingsver.Added {
			t.Errorf("%s is %s, want added", c.Key, c.Kind)
		}
	}

	// Reading changes nothing: no version, no audit entry of a restore.
	for _, r := range v.auditRows(t) {
		if r.action == ActionDomainRestore {
			t.Errorf("a read left an audit entry: %+v", r)
		}
	}
	if n := len(v.domainHistory(t, d.ID)); n != 6 {
		t.Errorf("%d versions, want 6", n)
	}
}

func TestDomainHistoryAndRestorePermissions(t *testing.T) {
	t.Parallel()
	v := domainEnv(t)
	ctx := t.Context()
	d := v.newDomain(t, "homelab.lan", "issuing", DomainSettings{})
	if _, err := v.e.UpdateDomain(ctx, d.ID, DomainSettings{Wildcards: ptr(true)}, tester); err != nil {
		t.Fatal(err)
	}
	fresh, stale := v.clk.Now(), time.Time{}
	admin := signedIn("admin", fresh, authz.Binding{Role: authz.Admin})
	noStepUp := signedIn("admin2", stale, authz.Binding{Role: authz.Admin})
	token := signedIn("bot", fresh, authz.Binding{Role: authz.Admin})
	token.Principal.ViaToken = true
	operator := signedIn("op", fresh, authz.Binding{Role: authz.Operator})
	viewer := signedIn("view", fresh, authz.Binding{Role: authz.Viewer})
	caAdmin := signedIn("caadmin", fresh, authz.Binding{CA: "issuing", Role: authz.Admin})
	otherCA := signedIn("other", fresh, authz.Binding{CA: "open", Role: authz.Admin})

	// Reading the history: the audit right (admin, tenant-wide) and a readable CA.
	for name, tc := range map[string]struct {
		who  keys.Who
		want error // nil = allowed
	}{
		"admin": {admin, nil}, "admin without step-up": {noStepUp, nil}, "token with an admin role": {token, nil},
		"operator": {operator, authz.ErrDenied}, "viewer": {viewer, authz.ErrDenied},
		"admin of that CA only": {caAdmin, authz.ErrDenied}, "admin of another CA": {otherCA, ErrNotFound},
	} {
		_, err := v.e.ListDomainVersions(ctx, tc.who, d.ID, 0, 0)
		_, derr := v.e.GetDomainVersion(ctx, tc.who, d.ID, 1, settingsver.AgainstPrevious)
		_, lerr := v.e.ListDeletedDomains(ctx, tc.who)
		for what, got := range map[string]error{"list": err, "detail": derr} {
			if tc.want == nil && got != nil || tc.want != nil && !errors.Is(got, tc.want) {
				t.Errorf("%s reads the %s: %v, want %v", name, what, got, tc.want)
			}
		}
		if (tc.want == nil) != (lerr == nil) {
			t.Errorf("%s lists deleted domains: %v", name, lerr)
		}
	}

	// A restore needs what the same change needs.
	for name, tc := range map[string]struct {
		who  keys.Who
		want error
	}{
		"admin with step-up": {admin, nil}, "admin of that CA with step-up": {caAdmin, nil},
		"admin without step-up": {noStepUp, authz.ErrStepUpRequired}, "token": {token, authz.ErrDenied},
		"operator": {operator, authz.ErrDenied}, "viewer": {viewer, authz.ErrDenied}, "admin of another CA": {otherCA, ErrNotFound},
	} {
		cur := int64(len(v.domainHistory(t, d.ID)))
		if _, err := v.e.UpdateDomain(ctx, d.ID, DomainSettings{ValidityDays: ptr(int(cur) + 20)}, tester); err != nil {
			t.Fatal(err)
		}
		_, err := v.e.RestoreDomain(ctx, d.ID, 1, restoreOpts(cur+1, ""), tc.who)
		if tc.want == nil && err != nil || tc.want != nil && !errors.Is(err, tc.want) {
			t.Errorf("%s restores: %v, want %v", name, err, tc.want)
		}
		if tc.want != nil {
			if after := int64(len(v.domainHistory(t, d.ID))); after != cur+1 {
				t.Errorf("%s: a refused restore wrote a version (%d -> %d)", name, cur+1, after)
			}
		}
	}
	if _, err := v.e.UpdateDomain(ctx, d.ID, DomainSettings{ValidityDays: ptr(77)}, tester); err != nil {
		t.Fatal(err)
	}
	// The dry run does not ask for the second factor, and tells a token it cannot.
	if check, err := v.e.DomainRestoreCheck(ctx, noStepUp, d.ID, 1); err != nil || !check.Restorable {
		t.Errorf("dry run without step-up: %+v %v", check, err)
	}
	if check, err := v.e.DomainRestoreCheck(ctx, token, d.ID, 1); err != nil || check.Restorable || len(check.Problems) != 1 || !strings.Contains(check.Problems[0], "token") {
		t.Errorf("dry run as a token: %+v %v", check, err)
	}

	// A deleted domain is created again: that is a tenant-wide right, as creating one is.
	last := int64(len(v.domainHistory(t, d.ID)))
	if err := v.e.DeleteDomain(ctx, d.ID, tester); err != nil {
		t.Fatal(err)
	}
	if _, err := v.e.RestoreDomain(ctx, d.ID, 1, restoreOpts(last+1, ""), caAdmin); !errors.Is(err, authz.ErrDenied) {
		t.Errorf("an admin of one CA recreates a domain: %v", err)
	}
	if _, err := v.e.RestoreDomain(ctx, d.ID, 1, restoreOpts(last+1, ""), admin); err != nil {
		t.Errorf("a tenant admin recreates it: %v", err)
	}
	// Refusals are audited (denied).
	var denied bool
	for _, r := range v.auditRows(t) {
		denied = denied || (r.action == ActionDomainRestore && r.result == "denied")
	}
	if !denied {
		t.Error("no denied domain.restore entry")
	}
}

func TestConcurrentRestoresHaveOneWinner(t *testing.T) {
	t.Parallel()
	v := domainEnv(t)
	ctx := t.Context()
	d := v.newDomain(t, "homelab.lan", "issuing", DomainSettings{})
	if _, err := v.e.UpdateDomain(ctx, d.ID, DomainSettings{Wildcards: ptr(true)}, tester); err != nil {
		t.Fatal(err)
	}
	const writers = 6
	errs := make([]error, writers)
	var wg sync.WaitGroup
	for i := range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[i] = v.e.RestoreDomain(ctx, d.ID, 1, restoreOpts(2, ""), tester)
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
	vs := v.domainHistory(t, d.ID)
	if len(vs) != 3 || vs[2].Change != settingsver.ChangeRestore {
		t.Fatalf("history: %+v", vs)
	}
	assertContiguous(t, vs)
}

func TestRestoreFailureRollsEverythingBack(t *testing.T) {
	t.Parallel()
	for name, table := range map[string]string{"audit": "outbox", "version": "settings_versions"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			v := domainEnv(t)
			ctx := t.Context()
			d := v.newDomain(t, "homelab.lan", "issuing", DomainSettings{})
			if _, err := v.e.UpdateDomain(ctx, d.ID, DomainSettings{Wildcards: ptr(true)}, tester); err != nil {
				t.Fatal(err)
			}
			gone := v.newDomain(t, "gone.lan", "open", DomainSettings{})
			if err := v.e.DeleteDomain(ctx, gone.ID, tester); err != nil {
				t.Fatal(err)
			}
			v.failInserts(t, table)
			if _, err := v.e.RestoreDomain(ctx, d.ID, 1, restoreOpts(2, ""), tester); !injected(err) {
				t.Errorf("restore of an update: %v", err)
			}
			if _, err := v.e.RestoreDomain(ctx, gone.ID, 1, restoreOpts(2, ""), tester); !injected(err) {
				t.Errorf("restore of a delete: %v", err)
			}
			if got, _ := v.e.GetDomain(ctx, tester, d.ID); !got.Wildcards {
				t.Error("a failed restore changed the domain")
			}
			if _, err := v.e.GetDomain(ctx, tester, gone.ID); !errors.Is(err, ErrNotFound) {
				t.Errorf("a failed restore created the domain: %v", err)
			}
			if n := len(v.domainHistory(t, d.ID)); n != 2 {
				t.Errorf("%d versions, want 2", n)
			}
		})
	}
}

func TestRestoreReasonIsChecked(t *testing.T) {
	t.Parallel()
	v := domainEnv(t)
	ctx := t.Context()
	d := v.newDomain(t, "homelab.lan", "issuing", DomainSettings{})
	if _, err := v.e.UpdateDomain(ctx, d.ID, DomainSettings{Wildcards: ptr(true)}, tester); err != nil {
		t.Fatal(err)
	}
	for name, reason := range map[string]string{"too long": strings.Repeat("x", settingsver.MaxReason+1), "newline": "a\nb"} {
		if _, err := v.e.RestoreDomain(ctx, d.ID, 1, restoreOpts(2, reason), tester); !deniedWith(err, "reason") {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Hostile text is data: stored as it came.
	hostile := `<script>alert(1)</script> "; DROP TABLE domains; --`
	if _, err := v.e.RestoreDomain(ctx, d.ID, 1, restoreOpts(2, hostile), tester); err != nil {
		t.Fatal(err)
	}
	if vs := v.domainHistory(t, d.ID); vs[2].Reason != hostile {
		t.Errorf("reason %q", vs[2].Reason)
	}
}
