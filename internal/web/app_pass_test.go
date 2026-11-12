package web

import (
	stdhtml "html"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/agents"
	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/testinstance"
)

var rePassSecret = regexp.MustCompile(`mjp_[A-Za-z0-9_-]{43}`)

func passForm(csrf, label, names, uses, hours string) url.Values {
	return url.Values{"csrf_token": {csrf}, "label": {label}, "names": {names}, "uses": {uses}, "hours": {hours}}
}

// TestEnrollmentPassPage: the pass section of Agents -> Join tokens. The
// secret is in the answer of the POST only (no-store) and comes with the
// ready command lines; the list shows state, uses and the hosts the pass
// admitted, escapes a hostile label, and keeps the secret out; revoking ends
// use and leaves the hosts alone; a used-up and an expired pass are shown as
// such; a viewer sees the section without the forms.
func TestEnrollmentPassPage(t *testing.T) {
	t.Parallel()
	v, svc := newAgentsUIEnv(t)
	b := v.browser("192.0.2.1")
	b.signIn(t, "demo", v.DemoPassword)
	csrf := b.csrf(t)

	page := b.get(t, "/agents/tokens").html()
	for _, want := range []string{"Enrollment passes", "New enrollment pass", `action="/agents/tokens/pass"`, "Create pass", "2 to 25", "1 to 168",
		"a leaked pass admits at most that many hosts", "API tokens cannot create or revoke a pass", "No enrollment passes yet."} {
		if !strings.Contains(page, want) {
			t.Errorf("join tokens page lacks %q", want)
		}
	}
	// The UI ships no htmx and no script, and the pass section adds none.
	for _, banned := range []string{"hx-", "<script", "style=", "onclick"} {
		if strings.Contains(page, banned) {
			t.Errorf("join tokens page contains %q", banned)
		}
	}

	// Create: the secret once, with the commands.
	const label = `<b>salt</b> "rollout"`
	r := b.post(t, "/agents/tokens/pass", passForm(csrf, label, "*.homelab.lan\nmail.homelab.lan", "3", "2"))
	secret := rePassSecret.FindString(r.html())
	if r.Code != http.StatusOK || secret == "" || r.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("new pass: %d %q %s", r.Code, r.Header().Get("Cache-Control"), r.html())
	}
	created := stdhtml.UnescapeString(r.html())
	checkAgentCalls(t, created, "setup --server 'https://pki.homelab.lan:8444' --ca-bundle /root/myownpki-root.pem --root-sha256 ")
	for _, want := range []string{
		"cat > /root/myownpki-join-token <<'MYOWNPKI_TOKEN'\n" + secret + "\nMYOWNPKI_TOKEN\n",
		`--package-format "$format" --hostname "$(hostname -f)" --token-file /root/myownpki-join-token )`,
		"up to 3 hosts for *.homelab.lan, mail.homelab.lan", "On each host", "http-01 check",
	} {
		if !strings.Contains(created, want) {
			t.Errorf("new pass page lacks %q", want)
		}
	}
	if strings.Contains(created, "'"+secret+"'") || strings.Contains(created, "--token "+secret) || strings.Contains(r.location(), secret) {
		t.Error("the pass is an argument or in a URL")
	}
	if strings.Contains(created, "<b>salt</b>") {
		t.Error("the label is not escaped")
	}
	// Even a pass for a name that is a single exact host takes the host's own name.
	single := stdhtml.UnescapeString(b.post(t, "/agents/tokens/pass", passForm(csrf, "one", "mail.homelab.lan", "2", "1")).html())
	if !strings.Contains(single, `--hostname "$(hostname -f)"`) || strings.Contains(single, "--hostname 'mail.homelab.lan'") {
		t.Errorf("a pass names its host by itself:\n%s", single)
	}

	// The list: no secret, the label escaped, state and uses, a Revoke form.
	list := b.get(t, "/agents/tokens").html()
	if strings.Contains(list, secret) || strings.Contains(list, secret[len("mjp_"):]) {
		t.Error("the pass secret is on the list")
	}
	for _, want := range []string{"&lt;b&gt;salt&lt;/b&gt; &#34;rollout&#34;", "active 0 of 3", "*.homelab.lan, mail.homelab.lan", `action="/agents/tokens/revoke"`, ">Revoke</button>", "No host has used a pass yet."} {
		if !strings.Contains(list, want) {
			t.Errorf("pass list lacks %q", want)
		}
	}
	if strings.Contains(list, "<b>salt</b>") {
		t.Error("the label is not escaped on the list")
	}

	// Refused: out of range, a name no domain covers, too many names.
	for _, tt := range []struct {
		name string
		form url.Values
		want string
	}{
		{"one use", passForm(csrf, "x", "*.homelab.lan", "1", "2"), "uses 2 to 25"},
		{"26 uses", passForm(csrf, "x", "*.homelab.lan", "26", "2"), "uses 2 to 25"},
		{"zero hours", passForm(csrf, "x", "*.homelab.lan", "5", "0"), "hours 1 to 168"},
		{"eight days", passForm(csrf, "x", "*.homelab.lan", "5", "169"), "hours 1 to 168"},
		{"text", passForm(csrf, "x", "*.homelab.lan", "many", "2"), "uses 2 to 25"},
		{"no domain", passForm(csrf, "x", "*.nodomain.lan", "5", "2"), "no domain covers *.nodomain.lan"},
		{"no label", passForm(csrf, "", "*.homelab.lan", "5", "2"), "label: required"},
		{"six names", passForm(csrf, "x", "a.homelab.lan b.homelab.lan c.homelab.lan d.homelab.lan e.homelab.lan f.homelab.lan", "5", "2"), "1 to 5 names"},
	} {
		if bad := b.post(t, "/agents/tokens/pass", tt.form); bad.Code != http.StatusSeeOther || !strings.Contains(flashOf(t, b, "/agents/tokens"), tt.want) {
			t.Errorf("%s: %d", tt.name, bad.Code)
		}
	}
	// Extra fields are not part of the action.
	if extra := b.post(t, "/agents/tokens/pass", url.Values{"csrf_token": {csrf}, "label": {"x"}, "names": {"a.homelab.lan"}, "uses": {"3"}, "hours": {"2"}, "kind": {"token"}}); extra.Code != http.StatusBadRequest {
		t.Errorf("an unknown field: %d", extra.Code)
	}

	// Two hosts use the pass (verified mode and a passed check admit them), a
	// third name is not covered by its patterns.
	enroll(t, svc, "minion-01.homelab.lan", secret, "0.3.5")
	enroll(t, svc, "mail.homelab.lan", secret, "0.3.5")
	enroll(t, svc, "other.apps.example", secret, "0.3.5") // matches no pattern: waits in the queue, no use
	list = b.get(t, "/agents/tokens").html()
	for _, want := range []string{"active 2 of 3", "minion-01.homelab.lan", "mail.homelab.lan", "admitted"} {
		if !strings.Contains(list, want) {
			t.Errorf("pass list after two uses lacks %q", want)
		}
	}
	if strings.Contains(list, "other.apps.example") {
		t.Error("a host the pass did not admit is listed under it")
	}
	enroll(t, svc, "minion-02.homelab.lan", secret, "0.3.5")
	list = b.get(t, "/agents/tokens").html()
	if !strings.Contains(list, "used up 3 of 3") || strings.Count(list, ">Revoke</button>") != 1 {
		t.Errorf("used-up pass: %s", list)
	}

	// Revoke the other pass (the one of the second form), then check it.
	passes, err := svc.ListJoinTokens(t.Context(), testinstance.Console)
	if err != nil {
		t.Fatal(err)
	}
	var oneID string
	for _, j := range passes {
		if j.Label == "one" {
			oneID = j.ID
		}
	}
	r = b.post(t, "/agents/tokens/revoke", url.Values{"csrf_token": {csrf}, "id": {oneID}})
	if r.Code != http.StatusSeeOther || !strings.Contains(flashOf(t, b, "/agents/tokens"), "Revoked.") {
		t.Fatalf("revoke: %d", r.Code)
	}
	list = b.get(t, "/agents/tokens").html()
	if !strings.Contains(list, "revoked 0 of 2") || strings.Contains(list, ">Revoke</button>") {
		t.Errorf("revoked pass: %s", list)
	}
	if r := b.post(t, "/agents/tokens/revoke", url.Values{"csrf_token": {csrf}, "id": {oneID}}); r.Code != http.StatusSeeOther || !strings.Contains(flashOf(t, b, "/agents/tokens"), "nothing to revoke") {
		t.Errorf("revoke twice: %d", r.Code)
	}
	if r := b.post(t, "/agents/tokens/revoke", url.Values{"csrf_token": {csrf}, "id": {"jtk_nothere"}}); r.Code != http.StatusNotFound {
		t.Errorf("revoke unknown: %d", r.Code)
	}

	// Expired: shown as such, no button.
	if _, _, err = svc.CreateEnrollmentPass(t.Context(), testinstance.Console, "short", []string{"*.homelab.lan"}, 2, 5*time.Minute); err != nil {
		t.Fatal(err)
	}
	v.Clock.Advance(5*time.Minute + time.Second)
	list = b.get(t, "/agents/tokens").html()
	if !strings.Contains(list, "expired 0 of 2") || strings.Contains(list, ">Revoke</button>") {
		t.Errorf("expired pass: %s", list)
	}
	// What the revoked and the used-up pass produced is still there.
	if !strings.Contains(list, "minion-02.homelab.lan") || !strings.Contains(b.get(t, "/agents").html(), "minion-01.homelab.lan") {
		t.Error("the hosts of the passes are gone")
	}
}

// TestEnrollmentPassPageRoles: viewers and operators see the pass section
// but no forms and no buttons, and their POSTs are refused by the service.
func TestEnrollmentPassPageRoles(t *testing.T) {
	t.Parallel()
	v, svc := newAgentsUIEnv(t)
	_, pass, err := svc.CreateEnrollmentPass(t.Context(), testinstance.Console, "visible", []string{"*.homelab.lan"}, 4, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	for _, role := range []authz.Role{authz.Viewer, authz.Operator} {
		name := string(role)
		v.User(t, name, false, authz.Binding{Role: role})
		b := v.browser("192.0.2.2")
		b.signIn(t, name, testinstance.Password)
		pg := b.get(t, "/agents/tokens")
		for _, banned := range []string{"Create pass", "Create token", "Revoke</button>", "/agents/tokens/pass", "/agents/tokens/revoke"} {
			if strings.Contains(pg.html(), banned) {
				t.Errorf("%s sees %q", name, banned)
			}
		}
		if pg.Code != http.StatusOK || !strings.Contains(pg.html(), "visible") || !strings.Contains(pg.html(), "active 0 of 4") {
			t.Errorf("%s: %d %s", name, pg.Code, pg.html())
		}
		csrf := b.csrf(t)
		b.post(t, "/agents/tokens/pass", passForm(csrf, "mine", "*.homelab.lan", "3", "2"))
		if msg := flashOf(t, b, "/agents/tokens"); !strings.Contains(msg, "role doesn") {
			t.Errorf("%s created a pass: %q", name, msg)
		}
		b.post(t, "/agents/tokens/revoke", url.Values{"csrf_token": {csrf}, "id": {pass.ID}})
		if msg := flashOf(t, b, "/agents/tokens"); !strings.Contains(msg, "role doesn") {
			t.Errorf("%s revoked a pass: %q", name, msg)
		}
	}
	list, _ := svc.ListJoinTokens(t.Context(), testinstance.Console)
	if len(list) != 1 || !list[0].RevokedAt.IsZero() {
		t.Errorf("a refused POST changed something: %+v", list)
	}
}

// TestEnrollmentPassStepUp: without a fresh second factor the POST goes to the
// challenge, whose summary names the pass but never a secret; after the
// code the action runs once, the secret is shown once, and the revocation
// takes the same way.
func TestEnrollmentPassStepUp(t *testing.T) {
	t.Parallel()
	v, svc := newAgentsUIEnv(t)
	b := v.browser("192.0.2.1")
	b.signIn(t, "demo", v.DemoPassword)
	csrf := b.csrf(t)
	v.Clock.Advance(authz.StepUpWindow + time.Second)

	r := b.post(t, "/agents/tokens/pass", passForm(csrf, "salt rollout", "*.homelab.lan", "4", "6"))
	if r.Code != http.StatusSeeOther || r.location() != "/step-up" {
		t.Fatalf("pass challenge: %d %q", r.Code, r.location())
	}
	if list, _ := svc.ListJoinTokens(t.Context(), testinstance.Console); len(list) != 0 {
		t.Fatalf("a pass exists before the second factor: %+v", list)
	}
	challenge := b.get(t, "/step-up").html()
	for _, want := range []string{"Create enrollment pass salt rollout for *.homelab.lan", "admits up to 4 hosts", "valid for 6 hours"} {
		if !strings.Contains(challenge, want) {
			t.Errorf("pass summary lacks %q:\n%s", want, challenge)
		}
	}
	if strings.Contains(challenge, "mjp_") {
		t.Error("a secret is in the summary")
	}
	r = confirmPending(t, b, csrf, "demo")
	secret := rePassSecret.FindString(r.html())
	if r.Code != http.StatusOK || secret == "" || r.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("continued pass: %d %s", r.Code, r.html())
	}
	if strings.Contains(b.get(t, "/agents/tokens").html(), secret) || strings.Contains(v.logs.String(), secret) {
		t.Error("the pass secret was shown again or logged")
	}
	list, _ := svc.ListJoinTokens(t.Context(), testinstance.Console)
	if len(list) != 1 || list[0].Kind != agents.KindPass || list[0].MaxUses != 4 {
		t.Fatalf("passes after the continuation: %+v", list)
	}

	// The same for the revocation; the continuation runs once.
	v.Clock.Advance(authz.StepUpWindow + time.Second)
	r = b.post(t, "/agents/tokens/revoke", url.Values{"csrf_token": {csrf}, "id": {list[0].ID}})
	if r.Code != http.StatusSeeOther || r.location() != "/step-up" {
		t.Fatalf("revoke challenge: %d %q", r.Code, r.location())
	}
	if challenge = b.get(t, "/step-up").html(); !strings.Contains(challenge, "Revoke join token or pass salt rollout for *.homelab.lan") {
		t.Errorf("revoke summary:\n%s", challenge)
	}
	id := pendingID(t, b)
	r = confirmPending(t, b, csrf, "demo")
	if r.Code != http.StatusSeeOther || r.location() != "/agents/tokens" {
		t.Fatalf("continued revoke: %d %q", r.Code, r.location())
	}
	if after, _ := svc.ListJoinTokens(t.Context(), testinstance.Console); len(after) != 1 || after[0].RevokedAt.IsZero() {
		t.Errorf("not revoked: %+v", after)
	}
	v.Clock.Advance(30 * time.Second)
	if again := b.post(t, "/step-up", url.Values{"csrf_token": {csrf}, "pending_id": {id}, "code": {v.Code("demo")}}); again.Code == http.StatusOK && strings.Contains(again.html(), "Revoked") {
		t.Errorf("the continuation ran twice: %d", again.Code)
	}
}
