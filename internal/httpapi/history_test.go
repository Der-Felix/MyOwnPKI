package httpapi

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/settingsver"
	"github.com/Der-Felix/MyOwnPKI/internal/store"
	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
)

// Step 63 of PHASE3 section 16: the history and restore endpoints.

// historyEnv is an unsealed instance with an admin whose second factor is fresh.
type historyEnv struct {
	*env
	s     *contract
	admin *client
}

func newHistoryEnv(t *testing.T) *historyEnv {
	t.Helper()
	v := newEnv(t)
	v.unseal(t)
	h := &historyEnv{env: v, s: loadContract(t), admin: v.client("192.0.2.1")}
	h.admin.signIn(t, "demo", v.demoPass)
	h.admin.stepUp(t, "demo")
	return h
}

// call runs a request and checks the answer against the spec.
func (h *historyEnv) call(t *testing.T, c *client, op, method, path string, body any, header ...string) *resp {
	t.Helper()
	r := c.do(t, method, path, body, header...)
	h.s.check(t, h.s.routeOf(t, h.api, op), r)
	return r
}

func (h *historyEnv) newDomain(t *testing.T, name string, extra map[string]any) string {
	t.Helper()
	body := map[string]any{"name": name, "ca_id": h.caIDs["issuing"], "approval": "open", "ip_ranges": []string{}}
	for k, v := range extra {
		body[k] = v
	}
	r := h.call(t, h.admin, "createDomain", http.MethodPost, "/domains", body)
	if r.Code != http.StatusCreated {
		t.Fatalf("create domain %s: %d %s", name, r.Code, r.Body.String())
	}
	id, _ := r.body["id"].(string)
	return id
}

func ifMatch(n int64) []string { return []string{"If-Match", `"` + strconv.FormatInt(n, 10) + `"`} }

// token creates an API token of the admin with the admin role.
func (h *historyEnv) token(t *testing.T) (secret string, bot *client) {
	t.Helper()
	r := h.admin.do(t, http.MethodPost, "/tokens", map[string]any{"name": "history", "expires_at": h.clk.Now().Add(24 * time.Hour).Format(time.RFC3339),
		"roles": []map[string]any{{"role": "admin", "scope": map[string]string{"type": "tenant"}}}})
	if r.Code != http.StatusCreated {
		t.Fatalf("token: %d %s", r.Code, r.Body.String())
	}
	secret, _ = r.body["secret"].(string)
	return secret, h.client("192.0.2.77")
}

func bearer(secret string) []string { return []string{"Authorization", "Bearer " + secret} }

// versionRows reads the stored versions of an object, oldest first.
func (h *historyEnv) versionRows(t *testing.T, kind, id string) []settingsver.Version {
	t.Helper()
	var b settingsver.Backend
	if kind == settingsver.KindDomain {
		b = settingsver.PKIBackend(pkidb.New(h.in.PKIDB.Read))
	} else {
		b = settingsver.SystemBackend(systemdbQueries(h.env))
	}
	page, err := settingsver.List(t.Context(), b, kind, id, 0, settingsver.MaxListLimit)
	if err != nil {
		t.Fatal(err)
	}
	slices.Reverse(page.Versions)
	return page.Versions
}

// auditRows lists the tenant audit entries of an action.
func (h *historyEnv) auditRows(t *testing.T, action string) []map[string]any {
	t.Helper()
	h.deliver(t)
	var out []map[string]any
	// Domain entries are in the tenant log, settings entries in the instance log.
	for _, db := range []*store.DB{h.ta, h.ia} {
		out = append(out, auditRowsIn(t, db, action)...)
	}
	return out
}

func auditRowsIn(t *testing.T, db *store.DB, action string) []map[string]any {
	t.Helper()
	rows, err := db.Read.QueryContext(t.Context(), `SELECT result, target_id, details_json FROM audit_entries WHERE action = ? ORDER BY seq`, action)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []map[string]any
	for rows.Next() {
		var result, target, details string
		if err = rows.Scan(&result, &target, &details); err != nil {
			t.Fatal(err)
		}
		m := map[string]any{}
		if err = json.Unmarshal([]byte(details), &m); err != nil {
			t.Fatal(err)
		}
		m["_result"], m["_target"] = result, target
		out = append(out, m)
	}
	if err = rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func asStr(v any) string {
	s, _ := v.(string)
	return s
}

func toList(t *testing.T, v any) []any {
	t.Helper()
	l, ok := v.([]any)
	if !ok {
		t.Fatalf("%v is not a list", v)
	}
	return l
}

func keysOf(t *testing.T, v any) []string {
	t.Helper()
	var out []string
	for _, k := range toList(t, v) {
		s, _ := k.(string)
		out = append(out, s)
	}
	return out
}

func TestHistoryAndRestoreOfADomain(t *testing.T) {
	t.Parallel()
	h := newHistoryEnv(t)
	id := h.newDomain(t, "homelab.lan", nil)
	path := "/domains/" + id
	if r := h.call(t, h.admin, "updateDomain", http.MethodPatch, path, map[string]any{"wildcards": true, "validity_days": 30, "reason": "wildcards for the wiki"}); r.Code != http.StatusOK {
		t.Fatalf("update: %d %s", r.Code, r.Body.String())
	}
	if r := h.call(t, h.admin, "updateDomain", http.MethodPatch, path, map[string]any{"wildcards": false, "approval": "account"}); r.Code != http.StatusOK {
		t.Fatalf("update: %d %s", r.Code, r.Body.String())
	}
	old := h.versionRows(t, settingsver.KindDomain, id)

	// The list: newest first, who, why, which settings, and the ETag.
	r := h.call(t, h.admin, "listDomainVersions", http.MethodGet, path+"/versions", nil)
	if r.Code != http.StatusOK || r.Header().Get("ETag") != `"3"` {
		t.Fatalf("list: %d ETag %q %s", r.Code, r.Header().Get("ETag"), r.Body.String())
	}
	items := toList(t, r.body["items"])
	if len(items) != 3 || r.body["next_before"] != nil {
		t.Fatalf("items: %s", r.Body.String())
	}
	newest, _ := items[0].(map[string]any)
	if newest["version"] != float64(3) || newest["change"] != "update" || newest["actor_name"] != "demo" || newest["actor_type"] != "user" ||
		newest["restored_from"] != nil || !slices.Equal(keysOf(t, newest["changed_keys"]), []string{"wildcards", "approval"}) {
		t.Errorf("newest: %v", newest)
	}
	second, _ := items[1].(map[string]any)
	if second["reason"] != "wildcards for the wiki" || !slices.Equal(keysOf(t, second["changed_keys"]), []string{"wildcards", "validity_days"}) {
		t.Errorf("second: %v", second)
	}
	if first, _ := items[2].(map[string]any); first["change"] != "create" || len(toList(t, first["changed_keys"])) < 6 || first["snapshot_sha256"] != old[0].SHA256 {
		t.Errorf("first: %v", first)
	}

	// Paging: a cursor and a limit.
	p1 := h.call(t, h.admin, "listDomainVersions", http.MethodGet, path+"/versions?limit=2", nil)
	if len(toList(t, p1.body["items"])) != 2 || p1.body["next_before"] != float64(2) {
		t.Fatalf("first page: %s", p1.Body.String())
	}
	p2 := h.call(t, h.admin, "listDomainVersions", http.MethodGet, path+"/versions?limit=2&before=2", nil)
	if l := toList(t, p2.body["items"]); len(l) != 1 || asMap(l[0])["version"] != float64(1) || p2.body["next_before"] != nil {
		t.Fatalf("second page: %s", p2.Body.String())
	}

	// A version: its state, the diff to the version before it, restorable.
	d := h.call(t, h.admin, "getDomainVersion", http.MethodGet, path+"/versions/2", nil)
	snap, _ := d.body["snapshot"].(map[string]any)
	diff, _ := d.body["diff"].(map[string]any)
	if d.Code != http.StatusOK || d.Header().Get("ETag") != `"3"` || snap["wildcards"] != true || snap["validity_days"] != float64(30) ||
		diff["from"] != float64(1) || diff["to"] != float64(2) || diff["against"] != "previous" || d.body["restorable"] != true || len(toList(t, d.body["restore_problems"])) != 0 {
		t.Fatalf("version 2: %s", d.Body.String())
	}
	changes := toList(t, diff["changes"])
	if len(changes) != 2 {
		t.Fatalf("diff: %v", changes)
	}
	if c, _ := changes[0].(map[string]any); c["key"] != "wildcards" || c["kind"] != "changed" || !slices.Equal(keysOf(t, c["before"]), []string{"no"}) || !slices.Equal(keysOf(t, c["after"]), []string{"yes"}) {
		t.Errorf("first change: %v", c)
	}
	if c, _ := changes[1].(map[string]any); c["key"] != "validity_days" || c["kind"] != "added" || len(toList(t, c["before"])) != 0 {
		t.Errorf("second change: %v", c)
	}
	// from = 0 is "nothing before"; current and a number work; the newest is not restorable.
	if r = h.call(t, h.admin, "getDomainVersion", http.MethodGet, path+"/versions/1?against=0", nil); r.Code != http.StatusOK || asMap(r.body["diff"])["from"] != float64(0) || len(toList(t, asMap(r.body["diff"])["changes"])) < 6 {
		t.Errorf("against 0: %s", r.Body.String())
	}
	if r = h.call(t, h.admin, "getDomainVersion", http.MethodGet, path+"/versions/2?against=current", nil); asMap(r.body["diff"])["from"] != float64(3) || len(toList(t, asMap(r.body["diff"])["changes"])) != 2 {
		t.Errorf("against current: %s", r.Body.String())
	}
	if r = h.call(t, h.admin, "getDomainVersion", http.MethodGet, path+"/versions/3?against=1", nil); asMap(r.body["diff"])["against"] != "version" {
		t.Errorf("against 1: %s", r.Body.String())
	}
	if r = h.call(t, h.admin, "getDomainVersion", http.MethodGet, path+"/versions/3", nil); r.body["restorable"] != false || !strings.Contains(r.Body.String(), "already has") {
		t.Errorf("the newest version: %s", r.Body.String())
	}

	// Restore version 2: a new version 4, the domain equals version 2, nothing earlier changed.
	rr := h.call(t, h.admin, "restoreDomainVersion", http.MethodPost, path+"/versions/2/restore", map[string]any{"reason": "undo <b>the</b> undo"}, ifMatch(3)...)
	if rr.Code != http.StatusOK || rr.Header().Get("ETag") != `"4"` || rr.body["wildcards"] != true || rr.body["validity_days"] != float64(30) || rr.body["id"] != id {
		t.Fatalf("restore: %d ETag %q %s", rr.Code, rr.Header().Get("ETag"), rr.Body.String())
	}
	rows := h.versionRows(t, settingsver.KindDomain, id)
	if len(rows) != 4 || rows[3].Change != settingsver.ChangeRestore || rows[3].RestoredFrom != 2 || rows[3].Reason != "undo <b>the</b> undo" || rows[3].Actor.Name != "demo" {
		t.Fatalf("versions after the restore: %+v", rows)
	}
	for i := range old {
		if rows[i].SHA256 != old[i].SHA256 || rows[i].Reason != old[i].Reason || rows[i].Change != old[i].Change {
			t.Errorf("version %d changed", i+1)
		}
	}
	if rows[3].SHA256 != rows[1].SHA256 {
		t.Errorf("the restored state must equal the old snapshot: %s %s", rows[3].SHA256, rows[1].SHA256)
	}
	if g := h.call(t, h.admin, "getDomain", http.MethodGet, path, nil); g.body["wildcards"] != true || g.body["approval"] != "open" || g.Header().Get("ETag") != `"4"` {
		t.Errorf("domain after the restore: %s", g.Body.String())
	}
	// In the list it says what it is.
	l := h.call(t, h.admin, "listDomainVersions", http.MethodGet, path+"/versions?limit=1", nil)
	if it := asMap(toList(t, l.body["items"])[0]); it["change"] != "restore" || it["restored_from"] != float64(2) {
		t.Errorf("newest item: %v", it)
	}

	// The audit entry: version, restored_from, snapshot hash, changed keys; no reason.
	entries := h.auditRows(t, "domain.restore")
	if len(entries) != 1 || entries[0]["_result"] != "success" || entries[0]["_target"] != id || entries[0]["version"] != float64(4) ||
		entries[0]["restored_from"] != float64(2) || entries[0]["snapshot_sha256"] != rows[3].SHA256 {
		t.Fatalf("audit: %v", entries)
	}
	if text, _ := json.Marshal(entries); strings.Contains(string(text), "undo") {
		t.Errorf("the reason is in the audit log: %s", text)
	}

	// Restoring the state that is current is a conflict; the same restore again too.
	if r = h.call(t, h.admin, "restoreDomainVersion", http.MethodPost, path+"/versions/2/restore", map[string]any{}, ifMatch(4)...); r.Code != http.StatusConflict || r.problemType() != "conflict" || !strings.Contains(r.Body.String(), "nothing to restore") {
		t.Errorf("identical: %d %s", r.Code, r.Body.String())
	}
	if n := len(h.versionRows(t, settingsver.KindDomain, id)); n != 4 {
		t.Errorf("a refused restore wrote a version: %d", n)
	}
}

func TestRestoreNeedsIfMatch(t *testing.T) {
	t.Parallel()
	h := newHistoryEnv(t)
	id := h.newDomain(t, "homelab.lan", nil)
	path := "/domains/" + id
	h.call(t, h.admin, "updateDomain", http.MethodPatch, path, map[string]any{"wildcards": true})
	restore := path + "/versions/1/restore"

	r := h.call(t, h.admin, "restoreDomainVersion", http.MethodPost, restore, map[string]any{})
	if r.Code != http.StatusPreconditionRequired || r.problemType() != "precondition-required" {
		t.Errorf("no If-Match: %d %s", r.Code, r.Body.String())
	}
	r = h.call(t, h.admin, "restoreDomainVersion", http.MethodPost, restore, map[string]any{}, ifMatch(1)...)
	if r.Code != http.StatusPreconditionFailed || r.problemType() != "precondition-failed" || r.body["current_version"] != float64(2) || r.body["changed_by"] != "demo" || r.body["changed_at"] == nil {
		t.Errorf("stale If-Match: %d %s", r.Code, r.Body.String())
	}
	for _, bad := range []string{`2`, `W/2`, `*`, `"2", "3"`, `"x"`} {
		if r = h.call(t, h.admin, "restoreDomainVersion", http.MethodPost, restore, map[string]any{}, "If-Match", bad); r.Code != http.StatusBadRequest {
			t.Errorf("If-Match %s: %d %s", bad, r.Code, r.Body.String())
		}
	}
	// A body with unknown fields and a long reason are refused too.
	if r = h.call(t, h.admin, "restoreDomainVersion", http.MethodPost, restore, map[string]any{"why": "x"}, ifMatch(2)...); r.Code != http.StatusBadRequest {
		t.Errorf("unknown field: %d", r.Code)
	}
	if r = h.call(t, h.admin, "restoreDomainVersion", http.MethodPost, restore, map[string]any{"reason": strings.Repeat("x", 201)}, ifMatch(2)...); r.Code != http.StatusUnprocessableEntity || r.problemType() != "policy-violation" {
		t.Errorf("reason too long: %d %s", r.Code, r.Body.String())
	}
	if g := h.call(t, h.admin, "getDomain", http.MethodGet, path, nil); g.body["wildcards"] != true || g.Header().Get("ETag") != `"2"` {
		t.Errorf("a refused restore changed the domain: %s", g.Body.String())
	}
	// Refusals are audited like other refused domain changes.
	var failed int
	for _, e := range h.auditRows(t, "domain.restore") {
		if e["_result"] == "failure" {
			failed++
		}
	}
	if failed < 2 {
		t.Errorf("%d refused restores in the audit log", failed)
	}
}

func TestRestoreRefusalsNameTheirReasons(t *testing.T) {
	t.Parallel()
	h := newHistoryEnv(t)
	ctx := t.Context()

	// A deleted domain whose name was taken meanwhile.
	id := h.newDomain(t, "homelab.lan", nil)
	if r := h.call(t, h.admin, "deleteDomain", http.MethodDelete, "/domains/"+id, nil); r.Code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", r.Code, r.Body.String())
	}
	h.newDomain(t, "homelab.lan", nil)
	taken := h.call(t, h.admin, "restoreDomainVersion", http.MethodPost, "/domains/"+id+"/versions/1/restore", map[string]any{}, ifMatch(2)...)
	if taken.Code != http.StatusUnprocessableEntity || taken.problemType() != "policy-violation" || !strings.Contains(taken.Body.String(), "exists already") {
		t.Errorf("a taken name: %d %s", taken.Code, taken.Body.String())
	}
	d := h.call(t, h.admin, "getDomainVersion", http.MethodGet, "/domains/"+id+"/versions/1?against=current", nil)
	if d.body["restorable"] != false || !strings.Contains(d.Body.String(), "exists already") {
		t.Errorf("the dry run must say it too: %s", d.Body.String())
	}

	// The CA of the version is retired: the reasons name it.
	other := h.newDomain(t, "sub.homelab.lan", nil)
	h.call(t, h.admin, "updateDomain", http.MethodPatch, "/domains/"+other, map[string]any{"validity_days": 20})
	// A later version points at a preset that no longer exists, and one at a CA that is gone.
	b := settingsver.PKIBackend(pkidb.New(h.in.PKIDB.Write))
	latest, err := b.Latest(ctx, settingsver.KindDomain, other)
	if err != nil {
		t.Fatal(err)
	}
	snap := settingsver.DomainSnapshot{Name: "sub.homelab.lan", CAID: h.caIDs["issuing"], IncludeSubdomains: true, ChallengeTypes: []string{"http-01"},
		Approval: "open", Preset: "gone-preset", AddressPolicy: "internal", IPRanges: []string{}}
	next := latest.Number
	add := func(s settingsver.DomainSnapshot) int64 {
		t.Helper()
		next++
		data, sum, cerr := settingsver.Canonical(s)
		if cerr != nil {
			t.Fatal(cerr)
		}
		if _, ierr := b.Insert(ctx, settingsver.Version{Kind: settingsver.KindDomain, ObjectID: other, Number: next, Change: settingsver.ChangeUpdate, Schema: 1,
			Snapshot: data, SHA256: sum, Actor: settingsver.Actor{Type: "user", ID: "u", Name: "raw"}, CreatedAt: h.clk.Now()}); ierr != nil {
			t.Fatal(ierr)
		}
		return next
	}
	missingPreset := add(snap)
	snap.Preset = "server"
	snap.CAID = "cas_gone"
	missingCA := add(snap)
	snap.CAID = h.caIDs["issuing"]
	if err = h.engine.RetireCA(ctx, "issuing", console); err != nil {
		t.Fatal(err)
	}
	retired := add(snap)
	for name, tc := range map[string]struct {
		version int64
		want    string
	}{"missing preset": {missingPreset, `no preset named \"gone-preset\"`}, "missing CA": {missingCA, "no longer exists"}, "retired CA": {retired, `is retired, not active`}} {
		r := h.call(t, h.admin, "restoreDomainVersion", http.MethodPost, "/domains/"+other+"/versions/"+strconv.FormatInt(tc.version, 10)+"/restore", map[string]any{}, ifMatch(next)...)
		if r.Code != http.StatusUnprocessableEntity || r.problemType() != "policy-violation" || !strings.Contains(r.Body.String(), tc.want) {
			t.Errorf("%s: %d %s", name, r.Code, r.Body.String())
		}
		dr := h.call(t, h.admin, "getDomainVersion", http.MethodGet, "/domains/"+other+"/versions/"+strconv.FormatInt(tc.version, 10), nil)
		if dr.body["restorable"] != false || !strings.Contains(dr.Body.String(), tc.want) {
			t.Errorf("%s: the dry run says %s", name, dr.Body.String())
		}
	}
	if g := h.call(t, h.admin, "getDomain", http.MethodGet, "/domains/"+other, nil); g.body["validity_days"] != float64(20) {
		t.Errorf("a refused restore changed the domain: %s", g.Body.String())
	}
}

func TestRestoreOfAnUnreadableVersion(t *testing.T) {
	t.Parallel()
	h := newHistoryEnv(t)
	ctx := t.Context()
	id := h.newDomain(t, "homelab.lan", nil)
	b := settingsver.PKIBackend(pkidb.New(h.in.PKIDB.Write))
	data := `{"name":"homelab.lan","extra":1}`
	sum := sha256.Sum256([]byte(data))
	for n, row := range []settingsver.Version{
		{Schema: 9, Snapshot: []byte(data), SHA256: hex.EncodeToString(sum[:])},
		{Schema: 1, Snapshot: []byte(data), SHA256: strings.Repeat("0", 64)},
		{Schema: 1, Snapshot: []byte(data), SHA256: hex.EncodeToString(sum[:])}, // right hash, but not the closed type
	} {
		row.Kind, row.ObjectID, row.Number, row.Change = settingsver.KindDomain, id, int64(n+2), settingsver.ChangeUpdate
		row.Actor, row.CreatedAt = settingsver.Actor{Type: "user", ID: "u", Name: "raw"}, h.clk.Now()
		if _, err := b.Insert(ctx, row); err != nil {
			t.Fatal(err)
		}
	}
	for n, want := range map[int]string{2: "format that this release does not know", 3: "damaged", 4: "damaged"} {
		num := strconv.Itoa(n)
		r := h.call(t, h.admin, "restoreDomainVersion", http.MethodPost, "/domains/"+id+"/versions/"+num+"/restore", map[string]any{}, ifMatch(4)...)
		if r.Code != http.StatusConflict || r.problemType() != "conflict" || !strings.Contains(r.Body.String(), want) {
			t.Errorf("restore of version %d: %d %s", n, r.Code, r.Body.String())
		}
		if g := h.call(t, h.admin, "getDomainVersion", http.MethodGet, "/domains/"+id+"/versions/"+num, nil); g.Code != http.StatusConflict || !strings.Contains(g.Body.String(), want) {
			t.Errorf("detail of version %d: %d %s", n, g.Code, g.Body.String())
		}
	}
	// The list still works; the damaged versions have no keys.
	l := h.call(t, h.admin, "listDomainVersions", http.MethodGet, "/domains/"+id+"/versions", nil)
	if l.Code != http.StatusOK || len(toList(t, l.body["items"])) != 4 || asMap(toList(t, l.body["items"])[0])["changed_keys"] != nil {
		t.Errorf("list: %d %s", l.Code, l.Body.String())
	}
}
