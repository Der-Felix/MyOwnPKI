package httpapi

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/settingsver"
	"github.com/Der-Felix/MyOwnPKI/internal/store/systemdb"
)

// Step 63 of PHASE3 section 16, continued: deleted domains, the permission
// matrix, the tenant settings, races and what must never appear.

// jsonArray parses an answer that is a JSON array.
func jsonArray(t *testing.T, r *resp) []map[string]any {
	t.Helper()
	var out []map[string]any
	if err := json.Unmarshal(r.Body.Bytes(), &out); err != nil {
		t.Fatalf("not a list: %v\n%s", err, r.Body.String())
	}
	return out
}

func TestRestoreADeletedDomain(t *testing.T) {
	t.Parallel()
	h := newHistoryEnv(t)
	id := h.newDomain(t, "homelab.lan", map[string]any{"validity_days": 45})
	path := "/domains/" + id
	h.call(t, h.admin, "updateDomain", http.MethodPatch, path, map[string]any{"wildcards": true})
	if del := h.call(t, h.admin, "deleteDomain", http.MethodDelete, path, nil, ifMatch(2)...); del.Code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", del.Code, del.Body.String())
	}

	// It is listed, and the history of the deleted domain can be read.
	deleted := jsonArray(t, h.call(t, h.admin, "listDeletedDomains", http.MethodGet, "/domains/deleted", nil))
	if len(deleted) != 1 || deleted[0]["id"] != id || deleted[0]["name"] != "homelab.lan" || deleted[0]["ca_id"] != h.caIDs["issuing"] ||
		deleted[0]["ca_name"] != "issuing" || deleted[0]["version"] != float64(3) || deleted[0]["deleted_by"] != "demo" {
		t.Fatalf("deleted domains: %v", deleted)
	}
	if g := h.call(t, h.admin, "getDomain", http.MethodGet, path, nil); g.Code != http.StatusNotFound {
		t.Errorf("the domain is gone: %d", g.Code)
	}
	l := h.call(t, h.admin, "listDomainVersions", http.MethodGet, path+"/versions", nil)
	if l.Code != http.StatusOK || l.Header().Get("ETag") != `"3"` || asMap(toList(t, l.body["items"])[0])["change"] != "delete" {
		t.Fatalf("history of a deleted domain: %d ETag %q %s", l.Code, l.Header().Get("ETag"), l.Body.String())
	}
	// Against "current" a deleted domain is nothing: a restore adds every setting.
	d := h.call(t, h.admin, "getDomainVersion", http.MethodGet, path+"/versions/2?against=current", nil)
	diff, _ := d.body["diff"].(map[string]any)
	if d.Code != http.StatusOK || diff["from"] != float64(0) || d.body["restorable"] != true || len(toList(t, diff["changes"])) < 6 {
		t.Fatalf("version 2 against the deleted domain: %s", d.Body.String())
	}
	for _, c := range toList(t, diff["changes"]) {
		if asMap(c)["kind"] != "added" {
			t.Errorf("change %v is not an addition", c)
		}
	}

	rr := h.call(t, h.admin, "restoreDomainVersion", http.MethodPost, path+"/versions/2/restore", map[string]any{"reason": "undelete"}, ifMatch(3)...)
	if rr.Code != http.StatusOK || rr.Header().Get("ETag") != `"4"` || rr.body["id"] != id || rr.body["name"] != "homelab.lan" ||
		rr.body["wildcards"] != true || rr.body["validity_days"] != float64(45) || rr.body["ca_name"] != "issuing" {
		t.Fatalf("restore of a deleted domain: %d %s", rr.Code, rr.Body.String())
	}
	if g := h.call(t, h.admin, "getDomain", http.MethodGet, path, nil); g.Code != http.StatusOK || g.Header().Get("ETag") != `"4"` {
		t.Errorf("the domain is back: %d %s", g.Code, g.Body.String())
	}
	if again := jsonArray(t, h.call(t, h.admin, "listDeletedDomains", http.MethodGet, "/domains/deleted", nil)); len(again) != 0 {
		t.Errorf("still listed as deleted: %v", again)
	}
	rows := h.versionRows(t, settingsver.KindDomain, id)
	if len(rows) != 4 || rows[3].Change != settingsver.ChangeRestore || rows[3].RestoredFrom != 2 || rows[3].SHA256 != rows[1].SHA256 {
		t.Fatalf("history after the undelete: %+v", rows)
	}
	e := h.auditRows(t, "domain.restore")
	if len(e) != 1 || e[0]["version"] != float64(4) || e[0]["restored_from"] != float64(2) || e[0]["snapshot_sha256"] != rows[3].SHA256 {
		t.Errorf("audit: %v", e)
	}
}

// who is a signed-in test user.
type who struct {
	name string
	c    *client
}

func TestHistoryReadPermissions(t *testing.T) {
	t.Parallel()
	h := newHistoryEnv(t)
	id := h.newDomain(t, "homelab.lan", nil)
	path := "/domains/" + id
	h.call(t, h.admin, "updateDomain", http.MethodPatch, path, map[string]any{"wildcards": true})
	h.call(t, h.admin, "updateSettings", http.MethodPut, "/settings", map[string]any{"allow_server_keygen": true,
		"subject_defaults": map[string]string{"organization": "One", "organizational_unit": "", "locality": "", "state": "", "country": ""}})

	h.user(t, "viewer", false, authz.Binding{Role: authz.Viewer})
	h.user(t, "tenantop", false, authz.Binding{Role: authz.Operator})
	h.user(t, "caadmin", false, authz.Binding{CA: "issuing", Role: authz.Admin})
	h.user(t, "rootview", false, authz.Binding{CA: "root", Role: authz.Viewer})
	secret, bot := h.token(t)
	people := map[string]who{"viewer": {name: "viewer"}, "tenantop": {name: "tenantop"}, "caadmin": {name: "caadmin"}, "rootview": {name: "rootview"}}
	for i, p := range []string{"viewer", "tenantop", "caadmin", "rootview"} {
		w := people[p]
		w.c = h.client("192.0.2." + strconv.Itoa(10+i))
		w.c.signIn(t, p, testPassword)
		people[p] = w
	}
	anon := h.client("192.0.2.99")

	type op struct {
		id, path string
		domain   bool // governed by the CA of the domain
	}
	ops := []op{
		{"listDomainVersions", path + "/versions", true}, {"getDomainVersion", path + "/versions/1", true},
		{"listDeletedDomains", "/domains/deleted", false},
		{"listSettingsVersions", "/settings/versions", false}, {"getSettingsVersion", "/settings/versions/1", false},
	}
	for _, o := range ops {
		for name, tc := range map[string]struct {
			c      *client
			header []string
			want   int
		}{
			"admin": {h.admin, nil, 200}, "token with the admin role": {bot, bearer(secret), 200},
			"viewer": {people["viewer"].c, nil, 403}, "operator": {people["tenantop"].c, nil, 403}, "admin of one CA": {people["caadmin"].c, nil, 403},
			"viewer of another CA": {people["rootview"].c, nil, map[bool]int{true: 404, false: 403}[o.domain]}, "nobody": {anon, nil, 401},
		} {
			r := h.call(t, tc.c, o.id, http.MethodGet, o.path, nil, tc.header...)
			if r.Code != tc.want {
				t.Errorf("%s as %s: %d, want %d: %s", o.id, name, r.Code, tc.want, r.Body.String())
			}
		}
	}
	// Nothing of a refused read is in the answer.
	if r := h.call(t, people["viewer"].c, "listDomainVersions", http.MethodGet, path+"/versions", nil); strings.Contains(r.Body.String(), "demo") {
		t.Errorf("a refused read names a user: %s", r.Body.String())
	}
}

func TestDomainRestorePermissions(t *testing.T) {
	t.Parallel()
	h := newHistoryEnv(t)
	id := h.newDomain(t, "homelab.lan", nil)
	path := "/domains/" + id
	h.call(t, h.admin, "updateDomain", http.MethodPatch, path, map[string]any{"wildcards": true})
	restore := path + "/versions/1/restore"

	h.user(t, "viewer", false, authz.Binding{Role: authz.Viewer})
	h.user(t, "tenantop", false, authz.Binding{Role: authz.Operator})
	h.user(t, "caadmin", false, authz.Binding{CA: "issuing", Role: authz.Admin})
	h.user(t, "rootadmin", false, authz.Binding{CA: "root", Role: authz.Admin})
	h.user(t, "admin2", false, authz.Binding{Role: authz.Admin})
	secret, bot := h.token(t)
	clients := map[string]*client{}
	for i, p := range []string{"viewer", "tenantop", "caadmin", "rootadmin", "admin2"} {
		clients[p] = h.client("192.0.2." + strconv.Itoa(10+i))
		clients[p].signIn(t, p, testPassword)
	}
	// Every second factor of the sign-ins runs out.
	h.clk.Advance(authz.StepUpWindow + time.Second)

	for name, tc := range map[string]struct {
		c      *client
		header []string
		want   int
		kind   string
	}{
		"viewer":                              {clients["viewer"], nil, 403, "forbidden"},
		"operator":                            {clients["tenantop"], nil, 403, "forbidden"},
		"CA admin of another CA":              {clients["rootadmin"], nil, 404, "not-found"},
		"admin without a fresh second factor": {clients["admin2"], nil, 403, "step-up-required"},
		"API token":                           {bot, bearer(secret), 403, "forbidden"},
	} {
		r := h.call(t, tc.c, "restoreDomainVersion", http.MethodPost, restore, map[string]any{}, append(ifMatch(2), tc.header...)...)
		if r.Code != tc.want || r.problemType() != tc.kind {
			t.Errorf("%s: %d %s, want %d %s", name, r.Code, r.problemType(), tc.want, tc.kind)
		}
		if name == "API token" && !strings.HasPrefix(asStr(r.body["detail"]), "an API token can't ") {
			t.Errorf("the token is told why: %v", r.body["detail"])
		}
	}
	if n := len(h.versionRows(t, settingsver.KindDomain, id)); n != 2 {
		t.Fatalf("refused restores wrote versions: %d", n)
	}
	denied := 0
	for _, e := range h.auditRows(t, "domain.restore") {
		if e["_result"] == "denied" {
			denied++
		}
	}
	if denied != 4 {
		t.Errorf("%d denied restores in the audit log, want 4 (a 404 says nothing about what exists)", denied)
	}

	// An admin of the domain's own CA may restore it, with the second factor.
	clients["caadmin"].stepUp(t, "caadmin")
	if r := h.call(t, clients["caadmin"], "restoreDomainVersion", http.MethodPost, restore, map[string]any{}, ifMatch(2)...); r.Code != http.StatusOK || r.body["wildcards"] != false {
		t.Fatalf("CA admin: %d %s", r.Code, r.Body.String())
	}
	// ... but not create a deleted domain again: that is a tenant-wide right, as creating one is.
	h.admin.stepUp(t, "demo")
	if r := h.call(t, h.admin, "deleteDomain", http.MethodDelete, path, nil, ifMatch(3)...); r.Code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", r.Code, r.Body.String())
	}
	clients["caadmin"].stepUp(t, "caadmin")
	if r := h.call(t, clients["caadmin"], "restoreDomainVersion", http.MethodPost, restore, map[string]any{}, ifMatch(4)...); r.Code != http.StatusForbidden || r.problemType() != "forbidden" {
		t.Errorf("CA admin recreates: %d %s", r.Code, r.Body.String())
	}
	clients["admin2"].stepUp(t, "admin2")
	if r := h.call(t, clients["admin2"], "restoreDomainVersion", http.MethodPost, restore, map[string]any{"reason": "back"}, ifMatch(4)...); r.Code != http.StatusOK || r.body["id"] != id {
		t.Errorf("tenant admin recreates: %d %s", r.Code, r.Body.String())
	}
}

func TestSettingsHistoryAndRestore(t *testing.T) {
	t.Parallel()
	h := newHistoryEnv(t)
	body := func(org, country string, trust bool) map[string]any {
		return map[string]any{"allow_server_keygen": false, "trust_page": trust, "acme_limits": map[string]int{"orders_per_account": 42, "failed_per_name": 5, "accounts_per_ip": 10},
			"subject_defaults": map[string]string{"organization": org, "organizational_unit": "", "locality": "", "state": "", "country": country}}
	}
	put := func(b map[string]any, n int64) {
		t.Helper()
		if r := h.call(t, h.admin, "updateSettings", http.MethodPut, "/settings", b, ifMatch(n)...); r.Code != http.StatusOK {
			t.Fatalf("put: %d %s", r.Code, r.Body.String())
		}
	}
	// No history yet: an empty list and the ETag 0.
	if r := h.call(t, h.admin, "listSettingsVersions", http.MethodGet, "/settings/versions", nil); r.Code != http.StatusOK || r.Header().Get("ETag") != `"0"` || len(toList(t, r.body["items"])) != 0 {
		t.Fatalf("empty history: %d ETag %q %s", r.Code, r.Header().Get("ETag"), r.Body.String())
	}
	put(body("One", "", true), 0)    // versions 1 (baseline) and 2
	put(body("Two", "DE", false), 2) // version 3
	old := h.versionRows(t, settingsver.KindTenant, "default")
	if len(old) != 3 {
		t.Fatalf("%d versions", len(old))
	}
	if r := h.call(t, h.admin, "listSettingsVersions", http.MethodGet, "/settings/versions?limit=2", nil); r.Code != http.StatusOK || r.Header().Get("ETag") != `"3"` ||
		len(toList(t, r.body["items"])) != 2 || r.body["next_before"] != float64(2) {
		t.Fatalf("list: %s", r.Body.String())
	}
	d := h.call(t, h.admin, "getSettingsVersion", http.MethodGet, "/settings/versions/2", nil)
	snap, _ := d.body["snapshot"].(map[string]any)
	diff, _ := d.body["diff"].(map[string]any)
	if d.Code != http.StatusOK || snap["organization"] != "One" || diff["from"] != float64(1) || d.body["restorable"] != true ||
		!strings.Contains(d.Body.String(), `"acme":{"orders_per_account":42`) {
		t.Fatalf("version 2: %s", d.Body.String())
	}
	if r := h.call(t, h.admin, "getSettingsVersion", http.MethodGet, "/settings/versions/2?against=current", nil); asMap(r.body["diff"])["from"] != float64(3) {
		t.Errorf("against current: %s", r.Body.String())
	}

	// Restore version 2: version 4, the settings equal it, the audit entry has the fields.
	r := h.call(t, h.admin, "restoreSettingsVersion", http.MethodPost, "/settings/versions/2/restore", map[string]any{"reason": "back to One"}, ifMatch(3)...)
	defaults, _ := r.body["subject_defaults"].(map[string]any)
	if r.Code != http.StatusOK || r.Header().Get("ETag") != `"4"` || defaults["organization"] != "One" || defaults["country"] != "" || r.body["trust_page"] != true {
		t.Fatalf("restore: %d ETag %q %s", r.Code, r.Header().Get("ETag"), r.Body.String())
	}
	rows := h.versionRows(t, settingsver.KindTenant, "default")
	if len(rows) != 4 || rows[3].Change != settingsver.ChangeRestore || rows[3].RestoredFrom != 2 || rows[3].Reason != "back to One" || rows[3].SHA256 != rows[1].SHA256 {
		t.Fatalf("versions: %+v", rows)
	}
	for i := range old {
		if rows[i].SHA256 != old[i].SHA256 {
			t.Errorf("version %d changed", i+1)
		}
	}
	e := h.auditRows(t, "tenant.settings_restore")
	if len(e) != 1 || e[0]["_result"] != "success" || e[0]["version"] != float64(4) || e[0]["restored_from"] != float64(2) || e[0]["snapshot_sha256"] != rows[3].SHA256 ||
		!strings.Contains(asStr(e[0]["changed_keys"]), "organization") {
		t.Errorf("audit: %v", e)
	}
	if text, _ := json.Marshal(e); strings.Contains(string(text), "back to One") {
		t.Errorf("the reason is in the audit log: %s", text)
	}

	// Refusals: the identical state, no If-Match, a stale one, no such version.
	for name, tc := range map[string]struct {
		path   string
		header []string
		want   int
		kind   string
	}{
		"identical":    {"/settings/versions/2/restore", ifMatch(4), 409, "conflict"},
		"no If-Match":  {"/settings/versions/1/restore", nil, 428, "precondition-required"},
		"stale":        {"/settings/versions/1/restore", ifMatch(3), 412, "precondition-failed"},
		"no version":   {"/settings/versions/99/restore", ifMatch(4), 404, "not-found"},
		"not a number": {"/settings/versions/x/restore", ifMatch(4), 404, "not-found"},
	} {
		if r = h.call(t, h.admin, "restoreSettingsVersion", http.MethodPost, tc.path, map[string]any{}, tc.header...); r.Code != tc.want || r.problemType() != tc.kind {
			t.Errorf("%s: %d %s", name, r.Code, r.Body.String())
		}
	}
	if len(h.versionRows(t, settingsver.KindTenant, "default")) != 4 {
		t.Error("a refused restore wrote a version")
	}

	// Settings that are not valid now are refused with the reasons of PUT /settings.
	bad := settingsver.TenantSnapshot{Country: "xx", ACME: settingsver.ACMELimitsSnapshot{OrdersPerAccount: 42, FailedPerName: 5, AccountsPerIP: 10}, TrustPage: true,
		AgentEnrollment: "verified", StepUpMinutes: 5, AgentPredecessor: settingsver.PredecessorSnapshot{Choice: "after", Days: 7}, OtherPredecessor: settingsver.PredecessorSnapshot{Choice: "after", Days: 7}}
	data, sum, err := settingsver.Canonical(bad)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = settingsver.SystemBackend(systemdb.New(h.in.SystemDB.Write)).Insert(t.Context(), settingsver.Version{Kind: settingsver.KindTenant, ObjectID: "default", Number: 5,
		Change: settingsver.ChangeUpdate, Schema: 1, Snapshot: data, SHA256: sum, Actor: settingsver.Actor{Type: "user", ID: "u", Name: "raw"}, CreatedAt: h.clk.Now()}); err != nil {
		t.Fatal(err)
	}
	if r = h.call(t, h.admin, "restoreSettingsVersion", http.MethodPost, "/settings/versions/5/restore", map[string]any{}, ifMatch(5)...); r.Code != http.StatusUnprocessableEntity ||
		r.problemType() != "policy-violation" || !strings.Contains(r.Body.String(), "country") {
		t.Errorf("invalid settings: %d %s", r.Code, r.Body.String())
	}
	if g := h.call(t, h.admin, "getSettingsVersion", http.MethodGet, "/settings/versions/5", nil); g.body["restorable"] != false || !strings.Contains(g.Body.String(), "country") {
		t.Errorf("the dry run says %s", g.Body.String())
	}
}

func TestSettingsRestorePermissions(t *testing.T) {
	t.Parallel()
	h := newHistoryEnv(t)
	settings := func(org, mode string) map[string]any {
		return map[string]any{"allow_server_keygen": false, "agent_enrollment": mode,
			"subject_defaults": map[string]string{"organization": org, "organizational_unit": "", "locality": "", "state": "", "country": ""}}
	}
	put := func(org, mode string, n int64) {
		t.Helper()
		if r := h.call(t, h.admin, "updateSettings", http.MethodPut, "/settings", settings(org, mode), ifMatch(n)...); r.Code != http.StatusOK {
			t.Fatalf("put: %d %s", r.Code, r.Body.String())
		}
	}
	put("One", "verified", 0) // versions 1 and 2
	h.user(t, "viewer", false, authz.Binding{Role: authz.Viewer})
	h.user(t, "tenantop", false, authz.Binding{Role: authz.Operator})
	h.user(t, "caadmin", false, authz.Binding{CA: "issuing", Role: authz.Admin})
	h.user(t, "admin2", false, authz.Binding{Role: authz.Admin})
	secret, bot := h.token(t)
	clients := map[string]*client{}
	for i, p := range []string{"viewer", "tenantop", "caadmin", "admin2"} {
		clients[p] = h.client("192.0.2." + strconv.Itoa(10+i))
		clients[p].signIn(t, p, testPassword)
	}
	h.clk.Advance(authz.StepUpWindow + time.Second)
	restore := func(c *client, n int, expected int64, header ...string) *resp {
		return h.call(t, c, "restoreSettingsVersion", http.MethodPost, "/settings/versions/"+strconv.Itoa(n)+"/restore", map[string]any{}, append(ifMatch(expected), header...)...)
	}

	// The role: ManageTenant (a tenant-wide admin); nothing needs the second factor while the mode stays.
	for name, tc := range map[string]struct {
		c    *client
		want int
	}{"viewer": {clients["viewer"], 403}, "operator": {clients["tenantop"], 403}, "admin of one CA": {clients["caadmin"], 403}} {
		if r := restore(tc.c, 1, 2); r.Code != tc.want || r.problemType() != "forbidden" {
			t.Errorf("%s: %d %s", name, r.Code, r.Body.String())
		}
	}
	// A tenant admin without a fresh second factor and a token may restore what leaves the mode alone.
	if r := restore(clients["admin2"], 1, 2); r.Code != http.StatusOK {
		t.Fatalf("admin without step-up, mode unchanged: %d %s", r.Code, r.Body.String())
	}
	h.admin.stepUp(t, "demo")
	put("Two", "verified", 3)
	if r := h.call(t, bot, "restoreSettingsVersion", http.MethodPost, "/settings/versions/1/restore", map[string]any{}, append(ifMatch(4), bearer(secret)...)...); r.Code != http.StatusOK {
		t.Fatalf("a token, mode unchanged: %d %s", r.Code, r.Body.String())
	}

	// The mode: a fresh second factor, never a token (the same rule as PUT /settings).
	put("Two", "manual", 5) // version 6 has the mode manual
	put("Two", "verified", 6)
	h.clk.Advance(authz.StepUpWindow + time.Second)
	before := len(h.versionRows(t, settingsver.KindTenant, "default"))
	if r := restore(h.admin, 6, 7); r.Code != http.StatusForbidden || r.problemType() != "step-up-required" {
		t.Errorf("admin without step-up restores the mode: %d %s", r.Code, r.Body.String())
	}
	if r := h.call(t, bot, "restoreSettingsVersion", http.MethodPost, "/settings/versions/6/restore", map[string]any{}, append(ifMatch(7), bearer(secret)...)...); r.Code != http.StatusForbidden ||
		r.problemType() != "forbidden" || !strings.HasPrefix(asStr(r.body["detail"]), "an API token can't ") {
		t.Errorf("a token restores the mode: %d %s", r.Code, r.Body.String())
	}
	if len(h.versionRows(t, settingsver.KindTenant, "default")) != before {
		t.Error("a refused mode restore wrote a version")
	}
	if g := h.call(t, h.admin, "getSettings", http.MethodGet, "/settings", nil); g.body["agent_enrollment"] != "verified" {
		t.Errorf("the mode changed: %s", g.Body.String())
	}
	// The dry run: no second factor is asked for, a token is told it cannot.
	if g := h.call(t, h.admin, "getSettingsVersion", http.MethodGet, "/settings/versions/6", nil); g.body["restorable"] != true {
		t.Errorf("dry run without step-up: %s", g.Body.String())
	}
	if g := h.call(t, bot, "getSettingsVersion", http.MethodGet, "/settings/versions/6", nil, bearer(secret)...); g.body["restorable"] != false || !strings.Contains(g.Body.String(), "token") {
		t.Errorf("dry run as a token: %s", g.Body.String())
	}
	h.admin.stepUp(t, "demo")
	if r := restore(h.admin, 6, 7); r.Code != http.StatusOK || r.body["agent_enrollment"] != "manual" {
		t.Fatalf("admin with step-up restores the mode: %d %s", r.Code, r.Body.String())
	}
	denied := 0
	for _, e := range h.auditRows(t, "tenant.settings_restore") {
		if e["_result"] == "denied" {
			denied++
		}
	}
	if denied != 5 {
		t.Errorf("%d denied restores in the audit log, want 5", denied)
	}
}

func TestConcurrentRestoresHaveOneWinner(t *testing.T) {
	t.Parallel()
	h := newHistoryEnv(t)
	id := h.newDomain(t, "homelab.lan", nil)
	h.call(t, h.admin, "updateDomain", http.MethodPatch, "/domains/"+id, map[string]any{"wildcards": true})
	h.call(t, h.admin, "updateSettings", http.MethodPut, "/settings", map[string]any{"allow_server_keygen": true,
		"subject_defaults": map[string]string{"organization": "One", "organizational_unit": "", "locality": "", "state": "", "country": ""}}, ifMatch(0)...)
	const clients = 4
	cs := make([]*client, clients)
	for i := range cs {
		cs[i] = h.client("192.0.2." + strconv.Itoa(20+i))
		cs[i].signIn(t, "demo", h.demoPass)
		cs[i].stepUp(t, "demo")
	}
	for _, tc := range []struct{ op, path string }{
		{"restoreDomainVersion", "/domains/" + id + "/versions/1/restore"}, {"restoreSettingsVersion", "/settings/versions/1/restore"},
	} {
		codes := make([]int, clients)
		var wg sync.WaitGroup
		for i, c := range cs {
			wg.Add(1)
			go func() {
				defer wg.Done()
				codes[i] = c.do(t, http.MethodPost, tc.path, map[string]any{}, ifMatch(2)...).Code
			}()
		}
		wg.Wait()
		ok, stale := 0, 0
		for _, c := range codes {
			switch c {
			case http.StatusOK:
				ok++
			case http.StatusPreconditionFailed:
				stale++
			}
		}
		if ok != 1 || stale != clients-1 {
			t.Errorf("%s: answers %v, want one 200 and %d 412", tc.op, codes, clients-1)
		}
	}
	if n := len(h.versionRows(t, settingsver.KindDomain, id)); n != 3 {
		t.Errorf("%d domain versions, want 3", n)
	}
	if n := len(h.versionRows(t, settingsver.KindTenant, "default")); n != 3 {
		t.Errorf("%d settings versions, want 3 (baseline, change, one restore)", n)
	}
}

func TestHistoryHoldsNoSecretsAndHostileTextStaysData(t *testing.T) {
	t.Parallel()
	h := newHistoryEnv(t)
	secret, _ := h.token(t)
	id := h.newDomain(t, "homelab.lan", nil)
	hostile := "<script>alert(1)</script> \"><img src=x onerror=alert(1)> " + string(rune(0x202E)) + "{{7*7}} ${jndi:x}"
	h.call(t, h.admin, "updateDomain", http.MethodPatch, "/domains/"+id, map[string]any{"wildcards": true, "reason": hostile})
	h.call(t, h.admin, "updateSettings", http.MethodPut, "/settings", map[string]any{"allow_server_keygen": false, "reason": hostile,
		"subject_defaults": map[string]string{"organization": "<b>Org</b>", "organizational_unit": "", "locality": "", "state": "", "country": ""}})
	rr := h.call(t, h.admin, "restoreDomainVersion", http.MethodPost, "/domains/"+id+"/versions/1/restore", map[string]any{"reason": hostile}, ifMatch(2)...)
	if rr.Code != http.StatusOK {
		t.Fatalf("restore: %d %s", rr.Code, rr.Body.String())
	}
	var bodies []string
	for _, p := range []struct{ op, path string }{
		{"listDomainVersions", "/domains/" + id + "/versions"}, {"getDomainVersion", "/domains/" + id + "/versions/2"},
		{"getDomainVersion", "/domains/" + id + "/versions/3?against=current"}, {"listSettingsVersions", "/settings/versions"},
		{"getSettingsVersion", "/settings/versions/2"}, {"listDeletedDomains", "/domains/deleted"},
	} {
		r := h.call(t, h.admin, p.op, http.MethodGet, p.path, nil)
		if r.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", p.path, r.Code, r.Body.String())
		}
		// Always JSON, never something a browser renders.
		if ct := r.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
			t.Errorf("%s: content type %q", p.path, ct)
		}
		bodies = append(bodies, r.Body.String())
	}
	all := strings.Join(bodies, "\n")
	// The hostile reason is data: it comes back unchanged once decoded.
	var page struct {
		Items []struct {
			Reason string `json:"reason"`
		} `json:"items"`
	}
	r := h.call(t, h.admin, "listDomainVersions", http.MethodGet, "/domains/"+id+"/versions", nil)
	if err := json.Unmarshal(r.Body.Bytes(), &page); err != nil || len(page.Items) != 3 || page.Items[0].Reason != hostile || page.Items[1].Reason != hostile {
		t.Errorf("the reason must come back as it went in: %+v %v", page.Items, err)
	}
	// No secret in any history answer: the token, the passwords, the passphrase, key material.
	for _, bad := range []string{secret, h.demoPass, testPassword, h.passphrase, "PRIVATE KEY", "BEGIN ", "password", "passphrase", "totp", "\"secret\""} {
		if bad != "" && strings.Contains(all, bad) {
			t.Errorf("a history answer contains %q", bad)
		}
	}
	// The audit log has neither the reason nor the raw text of it.
	for _, action := range []string{"domain.update", "domain.restore", "tenant.settings"} {
		for _, e := range h.auditRows(t, action) {
			if text, _ := json.Marshal(e); strings.Contains(string(text), "alert(1)") || strings.Contains(string(text), "jndi") {
				t.Errorf("%s: the reason is in the audit log: %s", action, text)
			}
		}
	}
}
