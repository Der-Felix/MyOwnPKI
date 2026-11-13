package web

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// Step 62 of PHASE3 section 16: the edit forms of a domain and of the tenant
// settings carry the version they show (hidden base_version) and refuse a
// change that is based on an older one.

func TestDomainFormsRefuseALostUpdate(t *testing.T) {
	t.Parallel()
	v := newUIEnv(t)
	v.Unseal(t)
	b := v.browser("192.0.2.1")
	b.signIn(t, "demo", v.DemoPassword)
	token := b.csrf(t)
	create := url.Values{"csrf_token": {token}, "name": {"homelab.lan"}, "ca": {"issuing"}, "subdomains": {"yes"}, "http01": {"yes"},
		"approval": {"open"}, "preset": {"server"}, "address": {"internal"}}
	r := b.post(t, "/domains", create)
	if r.Code != http.StatusSeeOther || !strings.HasPrefix(r.location(), "/domains/dom_") {
		t.Fatalf("create: %d %q", r.Code, r.location())
	}
	detail := r.location()

	// Both forms of the page carry the version (the creation is version 1).
	page := b.get(t, detail).html()
	if n := strings.Count(page, `name="base_version" value="1"`); n != 2 {
		t.Fatalf("the change and the delete form need base_version 1, found %d:\n%s", n, page)
	}
	change := func(version, approval string) url.Values {
		f := url.Values{"csrf_token": {token}, "ca": {"issuing"}, "subdomains": {"yes"}, "http01": {"yes"}, "approval": {approval},
			"preset": {"server"}, "address": {"internal"}}
		if version != "" {
			f.Set("base_version", version)
		}
		return f
	}

	// The version of the form: saved. The next form shows version 2.
	if rr := b.post(t, detail, change("1", "account")); rr.Code != http.StatusSeeOther || !strings.Contains(flashOf(t, b, detail), "saved") {
		t.Fatalf("change with the current version: %d", rr.Code)
	}
	if page = b.get(t, detail).html(); !strings.Contains(page, `name="base_version" value="2"`) {
		t.Errorf("the page after the change does not carry version 2:\n%s", page)
	}
	// Somebody else saved in between: the old form is refused and says who and when.
	rr := b.post(t, detail, change("1", "new_name"))
	if body := rr.html(); rr.Code != http.StatusConflict || !strings.Contains(body, "This object was changed by demo at ") ||
		!strings.Contains(body, "after you opened this page. Reload the history and look again.") || !strings.Contains(body, "Nothing was saved.") ||
		!strings.Contains(body, `href="`+detail+`/history">Back to the history</a>`) {
		t.Fatalf("stale change: %d %s", rr.Code, body)
	}
	if got := b.get(t, detail).html(); !strings.Contains(got, `value="account" selected`) || strings.Contains(got, `value="new_name" selected`) {
		t.Errorf("a refused change was stored:\n%s", got)
	}
	// A form without the field (from before the upgrade) is not checked.
	if rr = b.post(t, detail, change("", "open")); rr.Code != http.StatusSeeOther || !strings.Contains(flashOf(t, b, detail), "saved") {
		t.Errorf("change without base_version: %d", rr.Code)
	}
	// A changed field is refused, not guessed at.
	if rr = b.post(t, detail, change("abc", "open")); rr.Code != http.StatusSeeOther || !strings.Contains(flashOf(t, b, detail), "out of date") {
		t.Errorf("change with a bad base_version: %d", rr.Code)
	}
	// The same for the deletion: the old number is refused, the domain stays.
	if rr = b.post(t, detail+"/delete", url.Values{"csrf_token": {token}, "base_version": {"1"}}); rr.Code != http.StatusConflict ||
		!strings.Contains(rr.html(), "This object was changed by demo at ") {
		t.Fatalf("stale delete: %d %q", rr.Code, rr.location())
	}
	if rr = b.post(t, detail+"/delete", url.Values{"csrf_token": {token}, "base_version": {"3"}}); rr.Code != http.StatusSeeOther || rr.location() != "/domains" {
		t.Errorf("delete with the current version: %d %q", rr.Code, rr.location())
	}
}

func TestSettingsFormRefusesALostUpdate(t *testing.T) {
	t.Parallel()
	v := newUIEnv(t)
	v.Unseal(t)
	b := v.browser("192.0.2.1")
	b.signIn(t, "demo", v.DemoPassword)
	token := b.csrf(t)
	if page := b.get(t, "/admin/settings").html(); !strings.Contains(page, `name="base_version" value="0"`) {
		t.Fatalf("the settings form of a tenant that was never changed carries version 0:\n%s", page)
	}
	save := func(version, org string) url.Values {
		f := url.Values{"csrf_token": {token}, "o": {org}, "acme_orders": {"300"}, "acme_failed": {"5"}, "acme_accounts": {"10"},
			"agent_predecessor": {"now"}, "other_predecessor": {"after"}, "other_predecessor_days": {"7"}}
		if version != "" {
			f.Set("base_version", version)
		}
		return f
	}
	// The first change writes the baseline and the version: the next form shows 2.
	if r := b.post(t, "/admin/settings", save("0", "One")); r.Code != http.StatusSeeOther || !strings.Contains(flashOf(t, b, "/admin/settings"), "saved") {
		t.Fatalf("save with the current version: %d", r.Code)
	}
	if page := b.get(t, "/admin/settings").html(); !strings.Contains(page, `name="base_version" value="2"`) || !strings.Contains(page, `value="One"`) {
		t.Fatalf("the form after the change:\n%s", page)
	}
	r := b.post(t, "/admin/settings", save("0", "Two"))
	if body := r.html(); r.Code != http.StatusConflict || !strings.Contains(body, "This object was changed by demo at ") ||
		!strings.Contains(body, `href="/admin/settings/history">Back to the history</a>`) {
		t.Fatalf("stale save: %d %s", r.Code, body)
	}
	if page := b.get(t, "/admin/settings").html(); !strings.Contains(page, `value="One"`) || strings.Contains(page, `value="Two"`) {
		t.Errorf("a refused save was stored:\n%s", page)
	}
	if r = b.post(t, "/admin/settings", save("", "Three")); r.Code != http.StatusSeeOther || !strings.Contains(flashOf(t, b, "/admin/settings"), "saved") {
		t.Errorf("save without base_version: %d", r.Code)
	}
	if r = b.post(t, "/admin/settings", save("-1", "Four")); r.Code != http.StatusSeeOther || !strings.Contains(flashOf(t, b, "/admin/settings"), "out of date") {
		t.Errorf("save with a bad base_version: %d", r.Code)
	}
}
