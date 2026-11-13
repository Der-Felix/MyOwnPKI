package httpapi

import (
	"net/http"
	"strings"
	"testing"

	"github.com/Der-Felix/MyOwnPKI/internal/settingsver"
	"github.com/Der-Felix/MyOwnPKI/internal/store"
	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
	"github.com/Der-Felix/MyOwnPKI/internal/store/systemdb"
)

// Step 62 of PHASE3 section 16: ETag and the optional If-Match on the writers
// of domains and tenant settings, the optional reason, and 412.

func TestIfMatchOnSettings(t *testing.T) {
	t.Parallel()
	s := loadContract(t)
	v := newEnv(t)
	v.unseal(t)
	admin := v.client("192.0.2.1")
	admin.signIn(t, "demo", v.demoPass)
	put := s.routeOf(t, v.api, "updateSettings")
	body := func(org string) map[string]any {
		return map[string]any{"allow_server_keygen": false, "subject_defaults": map[string]string{"organization": org, "organizational_unit": "", "locality": "", "state": "", "country": ""}}
	}

	r := admin.do(t, http.MethodGet, "/settings", nil)
	if r.Code != http.StatusOK || r.Header().Get("ETag") != `"0"` {
		t.Fatalf("settings that were never changed: %d ETag %q", r.Code, r.Header().Get("ETag"))
	}
	// The first change with the ETag of the read: baseline and change, so version 2.
	r = admin.do(t, http.MethodPut, "/settings", body("One"), "If-Match", `"0"`)
	s.check(t, put, r)
	if r.Code != http.StatusOK || r.Header().Get("ETag") != `"2"` {
		t.Fatalf("put with the current ETag: %d ETag %q %s", r.Code, r.Header().Get("ETag"), r.Body.String())
	}
	if _, leaked := r.body["reason"]; leaked {
		t.Errorf("the reason is in the answer: %s", r.Body.String())
	}
	// The same ETag again: somebody (here: the first call) changed the settings in between.
	r = admin.do(t, http.MethodPut, "/settings", body("Two"), "If-Match", `"0"`)
	s.check(t, put, r)
	if r.Code != http.StatusPreconditionFailed || r.problemType() != "precondition-failed" {
		t.Fatalf("stale put: %d %s", r.Code, r.Body.String())
	}
	if r.body["current_version"] != float64(2) || r.body["changed_by"] == "" || r.body["changed_at"] == nil {
		t.Errorf("the 412 must name the current version, who and when: %s", r.Body.String())
	}
	got := admin.do(t, http.MethodGet, "/settings", nil)
	defaults, _ := got.body["subject_defaults"].(map[string]any)
	if org := defaults["organization"]; org != "One" || got.Header().Get("ETag") != `"2"` {
		t.Errorf("a refused put changed the settings: %v ETag %q", org, got.Header().Get("ETag"))
	}
	// Without the header the last writer wins, as before 0.3.10.
	r = admin.do(t, http.MethodPut, "/settings", body("Three"))
	if r.Code != http.StatusOK || r.Header().Get("ETag") != `"3"` {
		t.Errorf("put without If-Match: %d ETag %q", r.Code, r.Header().Get("ETag"))
	}
	// A reason is kept with the version, not echoed (the audit log is checked in the tenant tests).
	withReason := body("Four")
	withReason["reason"] = "tidy up"
	if r = admin.do(t, http.MethodPut, "/settings", withReason, "If-Match", `"3"`); r.Code != http.StatusOK || r.body["reason"] != nil {
		t.Fatalf("put with a reason: %d %s", r.Code, r.Body.String())
	}
	page, err := settingsver.List(t.Context(), settingsver.SystemBackend(systemdbQueries(v)), settingsver.KindTenant, store.DefaultTenant, 0, 10)
	if err != nil || len(page.Versions) != 4 || page.Versions[0].Reason != "tidy up" || page.Versions[0].Actor.Name != "demo" {
		t.Errorf("newest version: %+v %v", page.Versions, err)
	}
	tooLong := body("Five")
	tooLong["reason"] = strings.Repeat("x", settingsver.MaxReason+1)
	if r = admin.do(t, http.MethodPut, "/settings", tooLong); r.Code != http.StatusUnprocessableEntity || r.problemType() != "policy-violation" {
		t.Errorf("reason that is too long: %d %s", r.Code, r.Body.String())
	}
}

func TestIfMatchOnDomains(t *testing.T) {
	t.Parallel()
	s := loadContract(t)
	v := newEnv(t)
	v.unseal(t)
	issuing := v.caIDs["issuing"]
	admin := v.client("192.0.2.1")
	admin.signIn(t, "demo", v.demoPass)
	admin.stepUp(t, "demo")
	patch, del := s.routeOf(t, v.api, "updateDomain"), s.routeOf(t, v.api, "deleteDomain")

	r := admin.do(t, http.MethodPost, "/domains", map[string]any{"name": "homelab.lan", "ca_id": issuing, "approval": "open", "ip_ranges": []string{}})
	s.check(t, s.routeOf(t, v.api, "createDomain"), r)
	if r.Code != http.StatusCreated || r.Header().Get("ETag") != `"1"` {
		t.Fatalf("create: %d ETag %q %s", r.Code, r.Header().Get("ETag"), r.Body.String())
	}
	id, _ := r.body["id"].(string)
	path := "/domains/" + id
	if r = admin.do(t, http.MethodGet, path, nil); r.Header().Get("ETag") != `"1"` {
		t.Errorf("get: ETag %q", r.Header().Get("ETag"))
	}

	r = admin.do(t, http.MethodPatch, path, map[string]any{"wildcards": true}, "If-Match", `"1"`)
	s.check(t, patch, r)
	if r.Code != http.StatusOK || r.Header().Get("ETag") != `"2"` {
		t.Fatalf("patch with the current ETag: %d ETag %q %s", r.Code, r.Header().Get("ETag"), r.Body.String())
	}
	// A stale ETag changes nothing and names the current version.
	r = admin.do(t, http.MethodPatch, path, map[string]any{"wildcards": false}, "If-Match", `"1"`)
	s.check(t, patch, r)
	if r.Code != http.StatusPreconditionFailed || r.problemType() != "precondition-failed" || r.body["current_version"] != float64(2) || r.body["changed_by"] == "" {
		t.Fatalf("stale patch: %d %s", r.Code, r.Body.String())
	}
	if got := admin.do(t, http.MethodGet, path, nil); got.body["wildcards"] != true {
		t.Errorf("a refused patch changed the domain: %s", got.Body.String())
	}
	r = admin.do(t, http.MethodDelete, path, nil, "If-Match", `"1"`)
	s.check(t, del, r)
	if r.Code != http.StatusPreconditionFailed || admin.do(t, http.MethodGet, path, nil).Code != http.StatusOK {
		t.Fatalf("stale delete: %d %s", r.Code, r.Body.String())
	}
	// No header: the released behavior, the last writer wins.
	if r = admin.do(t, http.MethodPatch, path, map[string]any{"wildcards": false, "reason": "no wildcards after all"}); r.Code != http.StatusOK || r.Header().Get("ETag") != `"3"` || r.body["reason"] != nil {
		t.Fatalf("patch without If-Match: %d ETag %q %s", r.Code, r.Header().Get("ETag"), r.Body.String())
	}
	page, err := settingsver.List(t.Context(), settingsver.PKIBackend(pkidbQueries(v)), settingsver.KindDomain, id, 0, 10)
	if err != nil || len(page.Versions) != 3 || page.Versions[0].Reason != "no wildcards after all" || page.Versions[0].Actor.Name != "demo" {
		t.Errorf("history: %+v %v", page.Versions, err)
	}
	if r = admin.do(t, http.MethodPatch, path, map[string]any{"reason": strings.Repeat("x", settingsver.MaxReason+1)}); r.Code != http.StatusUnprocessableEntity || r.problemType() != "policy-violation" {
		t.Errorf("reason that is too long: %d %s", r.Code, r.Body.String())
	}
	if r = admin.do(t, http.MethodDelete, path, nil, "If-Match", `"3"`); r.Code != http.StatusNoContent {
		t.Fatalf("delete with the current ETag: %d %s", r.Code, r.Body.String())
	}
	page, err = settingsver.List(t.Context(), settingsver.PKIBackend(pkidbQueries(v)), settingsver.KindDomain, id, 0, 10)
	if err != nil || len(page.Versions) != 4 || page.Versions[0].Change != settingsver.ChangeDelete {
		t.Errorf("a delete is recorded: %+v %v", page.Versions, err)
	}
}

// A malformed If-Match is a bad request, never guessed at.
func TestIfMatchMustBeOneQuotedNumber(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	v.unseal(t)
	admin := v.client("192.0.2.1")
	admin.signIn(t, "demo", v.demoPass)
	settings := map[string]any{"allow_server_keygen": false, "subject_defaults": map[string]string{"organization": "", "organizational_unit": "", "locality": "", "state": "", "country": ""}}
	for _, bad := range []string{`1`, `W/"1"`, `*`, `"1", "2"`, `"x"`, `""`, `"-1"`, `"99999999999999999999"`} {
		if r := admin.do(t, http.MethodPut, "/settings", settings, "If-Match", bad); r.Code != http.StatusBadRequest || r.problemType() != "bad-request" {
			t.Errorf("If-Match %s: %d %s, want 400", bad, r.Code, r.Body.String())
		}
	}
	if r := admin.do(t, http.MethodGet, "/settings", nil); r.Header().Get("ETag") != `"0"` {
		t.Errorf("refused headers changed the settings: ETag %q", r.Header().Get("ETag"))
	}
}

func systemdbQueries(v *env) *systemdb.Queries { return systemdb.New(v.in.SystemDB.Read) }

func pkidbQueries(v *env) *pkidb.Queries { return pkidb.New(v.in.PKIDB.Read) }
