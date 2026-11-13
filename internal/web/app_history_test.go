package web

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/audit"
	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/settingsver"
	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
	"github.com/Der-Felix/MyOwnPKI/internal/testinstance"
)

// Step 64 of PHASE3 section 16: the History pages of the domains and of the
// tenant settings, the restore form and its way through the second factor.

const (
	historyHostile = `<script>alert(1)</script>`
	historyReason  = `<b>"x"</b> & y`
	historyEscaped = `&lt;script&gt;alert(1)&lt;/script&gt;`
)

// historyDomain is a domain with four versions: 1 created (http-01), 2 opened
// up, 3 both challenges (by a hostile name), 4 dns-01 only with wildcards.
type historyDomain struct {
	v    *uiEnv
	b    *browser
	csrf string
	id   string
	base string // "/domains/{id}"
}

func str(s string) *string { return &s }

func newHistoryDomain(t *testing.T) *historyDomain {
	t.Helper()
	v := newUIEnv(t)
	v.Unseal(t)
	ctx := t.Context()
	hostile := keys.Who{Actor: audit.Actor{Type: audit.ActorUser, Name: historyHostile}, Principal: authz.Console()}
	d, err := v.Engine.CreateDomain(ctx, ca.DomainRequest{Name: "homelab.lan", Who: testinstance.Console, DomainSettings: ca.DomainSettings{
		CA: str("issuing"), ChallengeTypes: []string{ca.ChallengeHTTP01}, Approval: str(ca.ApprovalAccount)}})
	if err != nil {
		t.Fatal(err)
	}
	update := func(who keys.Who, s ca.DomainSettings) {
		t.Helper()
		v.Clock.Advance(time.Minute)
		if _, uerr := v.Engine.UpdateDomain(ctx, d.ID, s, who); uerr != nil {
			t.Fatal(uerr)
		}
	}
	update(testinstance.Console, ca.DomainSettings{Approval: str(ca.ApprovalOpen), Options: ca.ChangeOptions{Reason: "open for the lab"}})
	update(hostile, ca.DomainSettings{ChallengeTypes: []string{ca.ChallengeHTTP01, ca.ChallengeDNS01}, Options: ca.ChangeOptions{Reason: historyReason}})
	wild := true
	update(testinstance.Console, ca.DomainSettings{ChallengeTypes: []string{ca.ChallengeDNS01}, Wildcards: &wild, Options: ca.ChangeOptions{Reason: "wildcards only"}})
	b := v.browser("192.0.2.1")
	b.signIn(t, "demo", v.DemoPassword)
	return &historyDomain{v: v, b: b, csrf: b.csrf(t), id: d.ID, base: "/domains/" + d.ID}
}

// newest is the newest version number of the domain.
func (h *historyDomain) newest(t *testing.T) int64 {
	t.Helper()
	page, err := h.v.Engine.ListDomainVersions(t.Context(), testinstance.Console, h.id, 0, 1)
	if err != nil {
		t.Fatal(err)
	}
	return page.Current
}

func (h *historyDomain) restore(t *testing.T, version int, base, reason string) page {
	t.Helper()
	f := url.Values{"csrf_token": {h.csrf}}
	if base != "" {
		f.Set("base_version", base)
	}
	if reason != "" {
		f.Set("reason", reason)
	}
	return h.b.post(t, h.base+"/history/"+strconv.Itoa(version)+"/restore", f)
}

func TestDomainHistoryList(t *testing.T) {
	t.Parallel()
	h := newHistoryDomain(t)
	versions, _ := h.v.Engine.ListDomainVersions(t.Context(), testinstance.Console, h.id, 0, 0)
	r := h.b.get(t, h.base+"/history")
	html := r.html()
	if r.Code != http.StatusOK {
		t.Fatalf("history: %d %s", r.Code, html)
	}
	for _, want := range []string{
		`<th scope="col" class="num">Version</th>`, `>When</th>`, `>Who</th>`, `>Change</th>`, `>Reason</th>`, `>Restored from</th>`, `>Changed settings</th>`,
		`href="` + h.base + `/history/4"`, `href="` + h.base + `/history/1"`, "console:test", `<span class="rel">user</span>`, "Created", "Changed",
		"open for the lab", "Approval", "Wildcards, Challenge types", "all settings", "UTC",
		// the tab row: History is the current page, Settings links back
		`<a class="tab" href="` + h.base + `">Settings</a>`, `aria-current="page">History</a>`,
	} {
		if !strings.Contains(html, want) {
			t.Errorf("history lacks %q:\n%s", want, html)
		}
	}
	if len(versions.Versions) != 4 || !strings.Contains(html, ">current</span>") {
		t.Errorf("four versions and the current one marked: %d", len(versions.Versions))
	}
	// Names and reasons come from the database: escaped, never raw.
	if !strings.Contains(html, historyEscaped) || strings.Contains(html, "<script>alert(1)") || !strings.Contains(html, "&lt;b&gt;&#34;x&#34;&lt;/b&gt; &amp; y") {
		t.Errorf("hostile name and reason must be escaped:\n%s", html)
	}
	// Viewing writes nothing.
	if got := h.newest(t); got != 4 {
		t.Errorf("viewing the history changed the versions: %d", got)
	}
	// The domain page offers the tab; a missing domain is a 404.
	if page := h.b.get(t, h.base).html(); !strings.Contains(page, `href="`+h.base+`/history"`) {
		t.Errorf("domain page has no History tab:\n%s", page)
	}
	if r = h.b.get(t, "/domains/dom_missing/history"); r.Code != http.StatusNotFound {
		t.Errorf("history of a missing domain: %d", r.Code)
	}
	if r = h.b.get(t, h.base+"/history/99"); r.Code != http.StatusNotFound {
		t.Errorf("a missing version: %d", r.Code)
	}
	if r = h.b.get(t, h.base+"/history/abc"); r.Code != http.StatusNotFound {
		t.Errorf("a bad version: %d", r.Code)
	}
}

func TestDomainVersionPageShowsTheDiff(t *testing.T) {
	t.Parallel()
	h := newHistoryDomain(t)
	// Version 4 against the version before it: a list as a set, a plain change.
	html := h.b.get(t, h.base+"/history/4").html()
	for _, want := range []string{
		"Version 4", "Compare version 4 with:", "What this version changed", "Before (version 3)", "Version 4</th>", "Challenge types", "Wildcards",
		`<span class="muted">removed: </span> http-01`, "dns-01", ">no<", ">yes<",
		"wildcards only", "Restored from", "This is the current version.",
		"Settings that differ",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("version 4 lacks %q:\n%s", want, html)
		}
	}
	if strings.Contains(html, `<span class="muted">added: </span> dns-01`) {
		t.Errorf("dns-01 is in both sets, it is not added:\n%s", html)
	}
	// Version 3 added dns-01 to the set.
	if html = h.b.get(t, h.base+"/history/3").html(); !strings.Contains(html, `<span class="muted">added: </span> dns-01`) || !strings.Contains(html, historyEscaped) {
		t.Errorf("version 3:\n%s", html)
	}
	// Version 1 is the first one: every set value is new.
	if html = h.b.get(t, h.base+"/history/1").html(); !strings.Contains(html, "Before (nothing)") || !strings.Contains(html, `class="muted">not set</span>`) {
		t.Errorf("version 1:\n%s", html)
	}
	// Against the current state: what a restore would change, with the switch as links.
	html = h.b.get(t, h.base+"/history/2?against=current").html()
	for _, want := range []string{"Now (version 4)", "What restoring this version would change now", `href="` + h.base + `/history/2"`,
		`aria-current="page">The current state</a>`, `removed: </span> dns-01`, `added: </span> http-01`} {
		if !strings.Contains(html, want) {
			t.Errorf("version 2 against current lacks %q:\n%s", want, html)
		}
	}
	// A restorable version: the dry run says what changes, then the form with the
	// newest version number, an optional reason and no JavaScript.
	for _, want := range []string{"Restoring would change: Wildcards, Challenge types.", "stays as it is", "fresh second factor",
		`action="` + h.base + `/history/2/restore"`, `name="base_version" value="4"`, `name="reason"`, "Reason (optional)", ">Restore this version</button>"} {
		if !strings.Contains(html, want) {
			t.Errorf("restore form lacks %q:\n%s", want, html)
		}
	}
	// The current version cannot be restored: the reason why, and no form.
	html = strings.ReplaceAll(h.b.get(t, h.base+"/history/4").html(), "&#39;", "'")
	if !strings.Contains(html, "can't be restored now") || !strings.Contains(html, "the state the domain already has") || strings.Contains(html, "/restore") {
		t.Errorf("version 4 must say why it can't be restored:\n%s", html)
	}
	if got := h.newest(t); got != 4 {
		t.Errorf("viewing wrote a version: %d", got)
	}
}

func TestDomainRestoreGoesThroughTheSecondFactor(t *testing.T) {
	t.Parallel()
	h := newHistoryDomain(t)
	h.v.Clock.Advance(authz.StepUpWindow + time.Second)
	// No second factor yet: the confirmation page, and nothing changed.
	r := h.restore(t, 2, "4", historyReason)
	if r.Code != http.StatusSeeOther || r.location() != "/step-up" {
		t.Fatalf("restore without a fresh second factor: %d %q %s", r.Code, r.location(), r.html())
	}
	if got := h.newest(t); got != 4 {
		t.Fatalf("a version was written before the second factor: %d", got)
	}
	if challenge := h.b.get(t, "/step-up").html(); !strings.Contains(challenge, "Restore domain homelab.lan on CA issuing from version 2") {
		t.Errorf("summary of the confirmation:\n%s", challenge)
	}
	r = confirmPending(t, h.b, h.csrf, "demo")
	if r.Code != http.StatusSeeOther || r.location() != h.base+"/history" {
		t.Fatalf("continued restore: %d %q %s", r.Code, r.location(), r.html())
	}
	html := h.b.get(t, h.base+"/history").html()
	for _, want := range []string{"Domain restored from version 2 as version 5.", "Restored", "version 2", "&lt;b&gt;&#34;x&#34;&lt;/b&gt; &amp; y", `demo <span class="rel">user</span>`} {
		if !strings.Contains(html, want) {
			t.Errorf("history after the restore lacks %q:\n%s", want, html)
		}
	}
	d, err := h.v.Engine.GetDomain(t.Context(), testinstance.Console, h.id)
	if err != nil || d.Approval != ca.ApprovalOpen || d.Wildcards || len(d.ChallengeTypes) != 1 || d.ChallengeTypes[0] != ca.ChallengeHTTP01 || d.Version != 5 {
		t.Fatalf("the restored domain: %+v %v", d, err)
	}
	// Version 2 itself is untouched.
	if got := h.b.get(t, h.base+"/history/2").html(); !strings.Contains(got, "open for the lab") || !strings.Contains(got, "Version 2") {
		t.Errorf("version 2 changed:\n%s", got)
	}

	// A second form from before the restore: the newest version is 5 now.
	r = h.restore(t, 3, "4", "")
	body := strings.ReplaceAll(r.html(), "&#39;", "'")
	if r.Code != http.StatusConflict || !strings.Contains(body, "This object was changed by demo at ") ||
		!strings.Contains(body, "after you opened this page. Reload the history and look again.") || !strings.Contains(body, `href="`+h.base+`/history">Back to the history</a>`) {
		t.Fatalf("stale restore: %d %s", r.Code, body)
	}
	if got := h.newest(t); got != 5 {
		t.Errorf("a stale restore wrote a version: %d", got)
	}
	// Restoring what is current: the notice of the identical state.
	r = h.restore(t, 5, "5", "")
	if r.Code != http.StatusSeeOther || r.location() != h.base+"/history/5" ||
		!strings.Contains(flashOf(t, h.b, r.location()), "The current state already equals this version.") {
		t.Errorf("identical restore: %d %q", r.Code, r.location())
	}
	// A form without the number (not from this page) is refused, not guessed.
	r = h.restore(t, 3, "", "")
	if r.Code != http.StatusSeeOther || !strings.Contains(flashOf(t, h.b, r.location()), "out of date") {
		t.Errorf("restore without base_version: %d %q", r.Code, r.location())
	}
	// A reason that is too long is refused with the limit.
	r = h.restore(t, 3, "5", strings.Repeat("x", settingsver.MaxReason+1))
	if r.Code != http.StatusSeeOther || !strings.Contains(flashOf(t, h.b, r.location()), strconv.Itoa(settingsver.MaxReason)) {
		t.Errorf("a long reason: %d %q", r.Code, r.location())
	}
	if got := h.newest(t); got != 5 {
		t.Errorf("a refused restore wrote a version: %d", got)
	}
}

func TestDeletedDomainsAreListedAndRestored(t *testing.T) {
	t.Parallel()
	h := newHistoryDomain(t)
	ctx := t.Context()
	if page := h.b.get(t, "/domains/deleted").html(); !strings.Contains(page, "No deleted domains.") {
		t.Errorf("no deleted domains yet:\n%s", page)
	}
	if err := h.v.Engine.DeleteDomainWith(ctx, h.id, ca.ChangeOptions{Reason: "scratch"}, testinstance.Console); err != nil {
		t.Fatal(err)
	}
	if r := h.b.get(t, h.base); r.Code != http.StatusNotFound {
		t.Fatalf("a deleted domain has no page: %d", r.Code)
	}
	html := h.b.get(t, "/domains/deleted").html()
	for _, want := range []string{"homelab.lan", "issuing", "scratch", "console:test", `href="` + h.base + `/history/5">Restore</a>`, `href="` + h.base + `/history"`} {
		if !strings.Contains(html, want) {
			t.Errorf("deleted list lacks %q:\n%s", want, html)
		}
	}
	if page := h.b.get(t, "/domains").html(); !strings.Contains(page, `href="/domains/deleted">Deleted domains</a>`) {
		t.Errorf("the domain list does not link the deleted ones:\n%s", page)
	}
	// The history of a deleted domain: no Settings tab (nothing to link), the deletion is the newest version.
	html = h.b.get(t, h.base+"/history").html()
	if !strings.Contains(html, "Deleted") || strings.Contains(html, `class="tabs"`) || !strings.Contains(html, "homelab.lan (deleted)") {
		t.Errorf("history of a deleted domain:\n%s", html)
	}
	// The deletion's page restores it, under the same ID.
	html = h.b.get(t, h.base+"/history/5").html()
	if !strings.Contains(html, `name="base_version" value="5"`) || !strings.Contains(html, "Restore this version") {
		t.Fatalf("restore form of the deleted domain:\n%s", html)
	}
	h.v.Clock.Advance(authz.StepUpWindow + time.Second)
	if r := h.restore(t, 5, "5", ""); r.Code != http.StatusSeeOther || r.location() != "/step-up" {
		t.Fatalf("restore of a deleted domain: %d %q", r.Code, r.location())
	}
	if challenge := h.b.get(t, "/step-up").html(); !strings.Contains(challenge, "Restore deleted domain homelab.lan from version 5") {
		t.Errorf("summary:\n%s", challenge)
	}
	if r := confirmPending(t, h.b, h.csrf, "demo"); r.Code != http.StatusSeeOther || r.location() != h.base+"/history" {
		t.Fatalf("continued restore: %d %q %s", r.Code, r.location(), r.html())
	}
	if r := h.b.get(t, h.base); r.Code != http.StatusOK || !strings.Contains(r.html(), "wildcards") && !strings.Contains(r.html(), "homelab.lan") {
		t.Errorf("the domain is back under its ID: %d", r.Code)
	}
	if page := h.b.get(t, "/domains/deleted").html(); !strings.Contains(page, "No deleted domains.") {
		t.Errorf("a restored domain is no longer listed:\n%s", page)
	}
	if got := h.newest(t); got != 6 {
		t.Errorf("the restore is version 6: %d", got)
	}
}

func TestHistoryIsForTenantAdminsOnly(t *testing.T) {
	t.Parallel()
	h := newHistoryDomain(t)
	h.v.User(t, "operator", false, authz.Binding{Role: authz.Operator})
	h.v.User(t, "viewer", false, authz.Binding{Role: authz.Viewer})
	h.v.User(t, "caadmin", false, authz.Binding{CA: "issuing", Role: authz.Admin})
	paths := []string{h.base + "/history", h.base + "/history/2", h.base + "/history/2?against=current", "/domains/deleted", "/admin/settings/history"}
	for i, who := range []string{"operator", "viewer", "caadmin"} {
		b := h.v.browser("192.0.2." + strconv.Itoa(10+i))
		b.signIn(t, who, testinstance.Password)
		for _, p := range paths {
			if r := b.get(t, p); r.Code != http.StatusForbidden {
				t.Errorf("%s GET %s: %d, want 403", who, p, r.Code)
			}
		}
		// No tab and no link on the pages they may see.
		for _, p := range []string{"/domains", h.base, "/admin/settings"} {
			r := b.get(t, p)
			if r.Code != http.StatusOK {
				continue
			}
			if html := r.html(); strings.Contains(html, "/history") || strings.Contains(html, "/domains/deleted") || strings.Contains(html, "Deleted domains") {
				t.Errorf("%s sees a history link on %s:\n%s", who, p, html)
			}
		}
		// A restore posted by hand changes nothing, also for an admin of the domain's own
		// CA with a fresh second factor: a restore is made from the history, which needs
		// the tenant-wide audit right.
		before := h.newest(t)
		token := b.csrf(t)
		r := b.post(t, h.base+"/history/2/restore", url.Values{"csrf_token": {token}, "base_version": {strconv.FormatInt(before, 10)}})
		if r.Code == http.StatusOK || h.newest(t) != before {
			t.Errorf("%s restored a version: %d", who, r.Code)
		}
	}
	// The admin has everything.
	for _, p := range paths {
		if r := h.b.get(t, p); r.Code != http.StatusOK {
			t.Errorf("admin GET %s: %d", p, r.Code)
		}
	}
}

func TestUnreadableVersionIsShownWithoutRestore(t *testing.T) {
	t.Parallel()
	h := newHistoryDomain(t)
	be := settingsver.PKIBackend(pkidb.New(h.v.PKIDB.Write))
	if _, err := be.Insert(t.Context(), settingsver.Version{Kind: settingsver.KindDomain, ObjectID: h.id, Number: 5, Change: settingsver.ChangeUpdate,
		Schema: 9, Snapshot: []byte(`{}`), SHA256: strings.Repeat("0", 64), Actor: settingsver.Actor{Type: "user", ID: "u", Name: "x"}, CreatedAt: h.v.Clock.Now()}); err != nil {
		t.Fatal(err)
	}
	r := h.b.get(t, h.base+"/history/5")
	body := strings.ReplaceAll(r.html(), "&#39;", "'")
	if r.Code != http.StatusConflict || !strings.Contains(body, "can't be shown or restored") || strings.Contains(body, "Restore this version") ||
		!strings.Contains(body, `href="`+h.base+`/history">Back to the history</a>`) {
		t.Errorf("unreadable version: %d %s", r.Code, body)
	}
	if html := h.b.get(t, h.base+"/history").html(); !strings.Contains(html, "the version can&#39;t be read") && !strings.Contains(html, "the version can't be read") {
		t.Errorf("the list must still render and say that version 5 can't be read:\n%s", html)
	}
	// A version before it is still restorable only against a current state that exists; the restore of the bad one is refused.
	rr := h.restore(t, 5, "5", "")
	if rr.Code != http.StatusSeeOther || !strings.Contains(strings.ReplaceAll(flashOf(t, h.b, rr.location()), "&#39;", "'"), "can't be read by this release") {
		t.Errorf("restore of the unreadable version: %d %q %q", rr.Code, rr.location(), flashOf(t, h.b, rr.location()))
	}
}

// ---------------------------------------------------------------- tenant settings

func settingsForm(csrf, base, org, mode string) url.Values {
	f := url.Values{"csrf_token": {csrf}, "o": {org}, "acme_orders": {"300"}, "acme_failed": {"5"}, "acme_accounts": {"10"},
		"agent_predecessor": {"now"}, "other_predecessor": {"after"}, "other_predecessor_days": {"7"}}
	if base != "" {
		f.Set("base_version", base)
	}
	if mode != "" {
		f.Set("agent_enrollment", mode)
	}
	return f
}

func TestSettingsHistoryAndRestore(t *testing.T) {
	t.Parallel()
	v := newUIEnv(t)
	v.Unseal(t)
	b := v.browser("192.0.2.1")
	b.signIn(t, "demo", v.DemoPassword)
	csrf := b.csrf(t)
	if html := b.get(t, "/admin/settings/history").html(); !strings.Contains(html, "No changes recorded yet.") || !strings.Contains(html, `href="/admin/settings"`) {
		t.Fatalf("no history yet:\n%s", html)
	}
	if html := b.get(t, "/admin/settings").html(); !strings.Contains(html, `href="/admin/settings/history"`) || !strings.Contains(html, "Reason (optional)") {
		t.Errorf("the settings page has no History tab or reason field:\n%s", html)
	}
	// Version 1 is the baseline, 2 the change to "One", 3 to a hostile value.
	for i, org := range []string{"One", historyHostile} {
		base := []string{"0", "2"}[i]
		if r := b.post(t, "/admin/settings", settingsForm(csrf, base, org, "")); r.Code != http.StatusSeeOther || !strings.Contains(flashOf(t, b, "/admin/settings"), "saved") {
			t.Fatalf("save %q: %d", org, r.Code)
		}
	}
	html := b.get(t, "/admin/settings/history").html()
	for _, want := range []string{"State before the history began", "system, before history", `<span class="rel">system</span>`, "Organization (O)", `demo <span class="rel">user</span>`, `href="/admin/settings/history/3"`} {
		if !strings.Contains(html, want) {
			t.Errorf("settings history lacks %q:\n%s", want, html)
		}
	}
	html = b.get(t, "/admin/settings/history/3").html()
	if !strings.Contains(html, historyEscaped) || strings.Contains(html, "<script>alert(1)") || !strings.Contains(html, "Organization (O)") || !strings.Contains(html, "This is the current version.") {
		t.Errorf("settings version 3:\n%s", html)
	}
	// A restore that leaves the enrollment mode alone needs no second factor.
	v.Clock.Advance(authz.StepUpWindow + time.Second)
	html = b.get(t, "/admin/settings/history/2").html()
	for _, want := range []string{`action="/admin/settings/history/2/restore"`, `name="base_version" value="3"`, "Restoring would change: Organization (O).", "Changing the agent enrollment mode asks for a fresh second factor"} {
		if !strings.Contains(html, want) {
			t.Errorf("settings version 2 lacks %q:\n%s", want, html)
		}
	}
	restore := func(version, base string) page {
		return b.post(t, "/admin/settings/history/"+version+"/restore", url.Values{"csrf_token": {csrf}, "base_version": {base}, "reason": {"undo " + version}})
	}
	if r := restore("2", "3"); r.Code != http.StatusSeeOther || r.location() != "/admin/settings/history" ||
		!strings.Contains(flashOf(t, b, r.location()), "Settings restored from version 2 as version 4.") {
		t.Fatalf("restore without a mode change: %d %q", r.Code, r.location())
	}
	if html = b.get(t, "/admin/settings").html(); !strings.Contains(html, `value="One"`) || !strings.Contains(html, `name="base_version" value="4"`) {
		t.Errorf("the restored settings:\n%s", html)
	}
	if html = b.get(t, "/admin/settings/history").html(); !strings.Contains(html, "undo 2") || !strings.Contains(html, "Restored") {
		t.Errorf("history after the restore:\n%s", html)
	}
	// A stale form and the identical state.
	if r := restore("3", "3"); r.Code != http.StatusConflict || !strings.Contains(r.html(), `href="/admin/settings/history">Back to the history</a>`) {
		t.Errorf("stale settings restore: %d", r.Code)
	}
	if r := restore("4", "4"); r.Code != http.StatusSeeOther || !strings.Contains(flashOf(t, b, r.location()), "The current state already equals this version.") {
		t.Errorf("identical settings restore: %d", r.Code)
	}
	// A restore that changes the enrollment mode asks for the second factor.
	if r := b.post(t, "/admin/settings", settingsForm(csrf, "4", "One", "auto")); r.Code != http.StatusSeeOther || r.location() != "/step-up" {
		t.Fatalf("mode change: %d %q", r.Code, r.location())
	}
	confirmPending(t, b, csrf, "demo") // version 5: mode auto
	v.Clock.Advance(authz.StepUpWindow + time.Second)
	if r := restore("4", "5"); r.Code != http.StatusSeeOther || r.location() != "/step-up" {
		t.Fatalf("restore with a mode change: %d %q %s", r.Code, r.location(), r.html())
	}
	if challenge := b.get(t, "/step-up").html(); !strings.Contains(challenge, "Restore the tenant settings from version 4") {
		t.Errorf("summary:\n%s", challenge)
	}
	if got := b.get(t, "/admin/settings/history").html(); strings.Contains(got, "as version 6") {
		t.Error("the restore ran before the second factor")
	}
	if r := confirmPending(t, b, csrf, "demo"); r.Code != http.StatusSeeOther || r.location() != "/admin/settings/history" {
		t.Fatalf("continued restore: %d %q %s", r.Code, r.location(), r.html())
	}
	if got := b.get(t, "/admin/settings/history").html(); !strings.Contains(got, "Settings restored from version 4 as version 6.") {
		t.Errorf("history after the restore with a mode change:\n%s", got)
	}
	if r := b.get(t, "/admin/settings/history/99"); r.Code != http.StatusNotFound {
		t.Errorf("a missing settings version: %d", r.Code)
	}
}

// ---------------------------------------------------------------- the rules for every rendered page

var (
	historyPagesOnce sync.Once
	historyPagesHTML map[string]string
)

// historyPages renders the history pages once for the HTML rules of
// server_test.go (inline styles, classes, tokens, images).
func historyPages(t *testing.T) map[string]string {
	t.Helper()
	historyPagesOnce.Do(func() {
		h := newHistoryDomain(t)
		out := map[string]string{}
		for _, p := range []string{"/domains", h.base, "/admin/settings", h.base + "/history", h.base + "/history/1", h.base + "/history/2", h.base + "/history/3",
			h.base + "/history/4", h.base + "/history/2?against=current", "/admin/settings/history"} {
			out["history env "+p] = h.b.get(t, p).html()
		}
		for i, org := range []string{"One", "Two"} {
			h.b.post(t, "/admin/settings", settingsForm(h.csrf, []string{"0", "2"}[i], org, ""))
		}
		out["history env settings list"] = h.b.get(t, "/admin/settings/history").html()
		out["history env settings v3"] = h.b.get(t, "/admin/settings/history/3").html()
		out["history env settings v2 current"] = h.b.get(t, "/admin/settings/history/2?against=current").html()
		out["history env stale"] = h.restore(t, 2, "1", "").html()
		_ = h.v.Engine.DeleteDomainWith(t.Context(), h.id, ca.ChangeOptions{}, testinstance.Console)
		out["history env deleted list"] = h.b.get(t, "/domains/deleted").html()
		out["history env deleted history"] = h.b.get(t, h.base+"/history").html()
		out["history env deleted version"] = h.b.get(t, h.base+"/history/5").html()
		historyPagesHTML = out
	})
	if historyPagesHTML == nil {
		t.Fatal("the history pages could not be rendered")
	}
	return historyPagesHTML
}

func TestHistoryPagesRender(t *testing.T) {
	t.Parallel()
	for name, html := range historyPages(t) {
		if len(html) < 300 {
			t.Errorf("%s is not a page:\n%.300s", name, html)
		}
	}
}
