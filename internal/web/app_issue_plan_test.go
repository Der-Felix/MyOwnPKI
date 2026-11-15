package web

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/testinstance"
)

// wizardRequest is an engine request the wizard built: op is "review" (the
// plan of the review step) or "issue" (the final submit).
type wizardRequest struct {
	op  string
	req ca.Request
}

func (v *uiEnv) wizardRequests() []wizardRequest {
	v.reqMu.Lock()
	defer v.reqMu.Unlock()
	return append([]wizardRequest(nil), v.requests...)
}

// reviewEnv is a signed-in operator at the wizard.
type reviewEnv struct {
	*uiEnv
	b     *browser
	token string
}

func newReviewEnv(t *testing.T, unsealed bool) *reviewEnv {
	t.Helper()
	v := newUIEnv(t)
	if unsealed {
		v.Unseal(t)
	}
	v.Engine.ServerKeygen = func(context.Context) (bool, error) { return true, nil }
	b := v.browser("192.0.2.1")
	b.signIn(t, "demo", v.DemoPassword)
	return &reviewEnv{uiEnv: v, b: b, token: b.csrf(t)}
}

// step posts one wizard step; extra overrides single fields.
func (e *reviewEnv) step(t *testing.T, from int, goTo string, extra url.Values) page {
	t.Helper()
	f := url.Values{
		"csrf_token": {e.token}, "from": {strconv.Itoa(from)}, "go": {goTo}, "preset": {"server"}, "ca": {e.CAIDs["issuing"]},
		"keymode": {"server"}, "alg": {"ecdsa-p256"}, "days": {"90"}, "cn": {"web.homelab.lan"}, "dns": {"web.homelab.lan"},
	}
	for k, vs := range extra {
		f[k] = vs
	}
	return e.b.post(t, "/certificates/new", f)
}

func (e *reviewEnv) csrForm(t *testing.T) url.Values {
	t.Helper()
	csrPEM, _ := testCSRWith(t, "web.homelab.lan", []string{"web.homelab.lan", "other.homelab.lan"}, nil)
	return url.Values{"keymode": {"csr"}, "csr": {csrPEM}}
}

// reasonEmail is the engine's reason for an e-mail name at the server preset, as the page escapes it.
const reasonEmail = `preset &#34;server&#34; doesn&#39;t take email names`

var reIssueButton = regexp.MustCompile(`<button type="submit" class="btn btn-primary" name="go" value="issue"( disabled)?>Issue certificate</button>`)

// issueButton reports whether the page has the "Issue certificate" button and
// whether it is switched off.
func issueButton(t *testing.T, html string) (present, disabled bool) {
	t.Helper()
	m := reIssueButton.FindStringSubmatch(html)
	return m != nil, m != nil && m[1] != ""
}

func mustContain(t *testing.T, html string, want ...string) {
	t.Helper()
	for _, w := range want {
		if !strings.Contains(html, w) {
			t.Errorf("the page lacks %q", w)
		}
	}
}

// TestReviewShowsTheAllowedPlan: the review step of the wizard lists what the
// engine would issue – verdict, checks, subject, names, key, validity, usages,
// extensions, chain and URLs – and leaves the button on.
func TestReviewShowsTheAllowedPlan(t *testing.T) {
	t.Parallel()
	e := newReviewEnv(t, true)
	for name, extra := range map[string]url.Values{"server key": nil, "csr": e.csrForm(t)} {
		r := e.step(t, 3, "next", extra)
		html := r.html()
		if r.Code != http.StatusOK {
			t.Fatalf("%s: %d", name, r.Code)
		}
		mustContain(t, html,
			`aria-current="step">Review`,
			`<span class="st st-ok"><span class="st-dot" aria-hidden="true"></span>Allowed</span>`, "The policy would issue this certificate.",
			"Prepared at ", "forecast, not a promise",
			">Policy checks</h2>", ">Preset</td>", ">Issuing CA</td>", ">Subject and names</td>", ">Name constraints</td>", ">Validity</td>",
			`<span class="st st-ok"><span class="st-dot" aria-hidden="true"></span>Passed</span>`,
			">What would be issued</h2>", "server – ", "CN=web.homelab.lan", ">DNS name</dt>", "web.homelab.lan",
			">Not before</dt>", ">Not after</dt>", ">90 days</dd>", "the CA state may change before you submit",
			">Key usage</dt>", "digitalSignature", "digitalSignature (critical)", ">Extended key usage</dt>", "serverAuth",
			">Extensions</h2>", "basicConstraints", "2.5.29.19", "CA:FALSE", "subjectAltName", "authorityInfoAccess", "cRLDistributionPoints",
			">Who signs</h2>", ">issuing</dd>", ">Chain</h2>", ">Issuing CA</td>", ">Root</td>", "http://pki.homelab.lan/",
		)
		if present, disabled := issueButton(t, html); !present || disabled {
			t.Errorf("%s: the Issue certificate button must be on (present %v, disabled %v)", name, present, disabled)
		}
		if !strings.Contains(html, `name="go" value="back"`) {
			t.Errorf("%s: no Back button", name)
		}
		if name == "csr" && strings.Contains(html, "other.homelab.lan") {
			t.Error("the names of the CSR must not appear: the wizard ignores them")
		}
		// The fingerprints are colon-separated SHA-256 of the CA certificates.
		if got := regexp.MustCompile(`<div>([0-9A-F]{2}(:[0-9A-F]{2}){15}):?</div>`).FindAllString(html, -1); len(got) != 4 {
			t.Errorf("%s: %d SHA-256 fingerprint lines in the chain, want 4 (two per CA)", name, len(got))
		}
		if strings.Index(html, ">Issuing CA</td>") > strings.Index(html, ">Root</td>") {
			t.Errorf("%s: the chain must list the issuing CA before the root", name)
		}
	}
}

// TestReviewShowsTheRefusedPlan: a refused request shows every reason, the
// failed checks and the way out; the button is off, Back stays.
func TestReviewShowsTheRefusedPlan(t *testing.T) {
	t.Parallel()
	e := newReviewEnv(t, true)
	r := e.step(t, 3, "next", url.Values{"email": {"ops@homelab.lan"}})
	html := r.html()
	if r.Code != http.StatusOK {
		t.Fatalf("status %d", r.Code)
	}
	mustContain(t, html,
		`<span class="st st-crit"><span class="st-dot" aria-hidden="true"></span>Refused</span>`, "The policy would refuse this request.",
		reasonEmail,
		`<span class="st-dot" aria-hidden="true"></span>Refused</span>`, "Every check ran and each one lists every problem it found.",
		"Use Back to change",
	)
	if strings.Contains(html, "digitalSignature") || strings.Contains(html, ">Extensions</h2>") {
		t.Error("a refused plan must not show usages or extensions")
	}
	present, disabled := issueButton(t, html)
	if !present || !disabled {
		t.Errorf("the Issue certificate button must be off (present %v, disabled %v)", present, disabled)
	}
	if !strings.Contains(html, `name="go" value="back"`) {
		t.Error("Back must stay")
	}
	// A reason is one line, listed once where the plan lists it.
	if n := strings.Count(html, reasonEmail); n != 2 {
		t.Errorf("a reason appears %d times, want 2 (message line and checks table)", n)
	}

	// The same request sent to issue is refused by the engine; the page keeps
	// the reasons once as message lines and says so.
	r = e.step(t, 4, "issue", url.Values{"email": {"ops@homelab.lan"}})
	html = r.html()
	if r.Code != http.StatusUnprocessableEntity {
		t.Fatalf("issue: %d", r.Code)
	}
	mustContain(t, html, "Nothing was issued – the policy refused the request.", reasonEmail)
	if n := strings.Count(html, reasonEmail); n != 2 {
		t.Errorf("after a refused issue a reason appears %d times, want 2 (the plan lists it once as a line, once in the table)", n)
	}
	if present, disabled := issueButton(t, html); !present || !disabled {
		t.Errorf("after a refused issue the button must be off (present %v, disabled %v)", present, disabled)
	}
}

// TestReviewSaysWhereTheChecksStopped: a gate ends the plan; the page names it
// and says that later checks were not run.
func TestReviewSaysWhereTheChecksStopped(t *testing.T) {
	t.Parallel()
	e := newReviewEnv(t, true)
	key, err := rsa.GenerateKey(rand.Reader, 1024) // #nosec G403 -- a weak key on purpose: the key policy must refuse it
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "weak.homelab.lan"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	csr := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
	r := e.step(t, 3, "next", url.Values{"keymode": {"csr"}, "csr": {csr}})
	html := r.html()
	mustContain(t, html, "Refused, stopped here", `The checks stopped at &#34;Key&#34;.`, "The checks after it were not run")
	if _, disabled := issueButton(t, html); !disabled {
		t.Error("the button must be off")
	}
	if strings.Contains(html, ">Name constraints</td>") {
		t.Error("a check after the stopped gate must not be listed as run")
	}
}

// TestReviewOfASealedServer: the plan says allowed and sealed; the button is off
// until an unseal.
func TestReviewOfASealedServer(t *testing.T) {
	t.Parallel()
	e := newReviewEnv(t, false)
	r := e.step(t, 3, "next", nil)
	html := r.html()
	if r.Code != http.StatusOK {
		t.Fatalf("status %d", r.Code)
	}
	mustContain(t, html, "Allowed</span>", "The server is sealed – issuing is possible after an unseal.", "digitalSignature")
	if n := strings.Count(html, "The server is sealed"); n != 1 {
		t.Errorf("the sealed notice appears %d times, want 1", n)
	}
	if present, disabled := issueButton(t, html); !present || !disabled {
		t.Errorf("sealed: the button must be off (present %v, disabled %v)", present, disabled)
	}
}

// TestReviewEscapesAttackerText: names, reasons and subjects are text.
func TestReviewEscapesAttackerText(t *testing.T) {
	t.Parallel()
	e := newReviewEnv(t, true)
	const cn = `<img src=x onerror=alert(1)>`
	r := e.step(t, 3, "next", url.Values{"cn": {cn}, "dns": {"<script>alert(1)</script>.homelab.lan\nok.homelab.lan"}, "email": {`"><svg onload=alert(2)>@homelab.lan`}})
	html := r.html()
	if r.Code != http.StatusOK {
		t.Fatalf("status %d", r.Code)
	}
	for _, bad := range []string{"<script>alert", "<img src=x", "<svg onload", `"><svg`} {
		if strings.Contains(html, bad) {
			t.Errorf("unescaped attacker text %q in the page", bad)
		}
	}
	mustContain(t, html, "&lt;script&gt;alert(1)&lt;/script&gt;.homelab.lan", `<span class="st st-crit">`)
	if present, disabled := issueButton(t, html); !present || !disabled {
		t.Errorf("the hostile request must be refused (present %v, disabled %v)", present, disabled)
	}
}

// TestReviewAndIssueSendTheSameRequest: for every wizard mode the plan is made
// for exactly the request the final submit issues, and that request is what
// the wizard has always sent: no tenant subject defaults, and a CSR is used for
// its key only.
func TestReviewAndIssueSendTheSameRequest(t *testing.T) {
	t.Parallel()
	for name, extra := range map[string]url.Values{
		"server key":       nil,
		"csr":              nil, // filled below: needs a CSR of the test's own
		"csr, ip and days": {"ip": {"10.0.0.7"}, "days": {"30"}},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := newReviewEnv(t, true)
			if name != "server key" {
				extra = mergeValues(e.csrForm(t), extra)
			}
			if r := e.step(t, 3, "next", extra); r.Code != http.StatusOK {
				t.Fatalf("review: %d", r.Code)
			}
			r := e.step(t, 4, "issue", extra)
			if r.Code != http.StatusSeeOther {
				t.Fatalf("issue: %d\n%s", r.Code, r.html())
			}
			got := e.wizardRequests()
			if len(got) != 2 || got[0].op != "review" || got[1].op != "issue" {
				t.Fatalf("requests: %+v", got)
			}
			if !reflect.DeepEqual(got[0].req, got[1].req) {
				t.Errorf("the review plans another request than the submit issues:\nreview %+v\nissue  %+v", got[0].req, got[1].req)
			}
			req := got[1].req
			if !reflect.DeepEqual(req.SubjectDefaults, ca.Subject{}) {
				t.Errorf("the wizard must not fill the tenant's subject defaults: %+v", req.SubjectDefaults)
			}
			if req.IgnoreCSRNames != (req.CSR != nil) {
				t.Errorf("IgnoreCSRNames %v with CSR %v: the names of a CSR are never taken", req.IgnoreCSRNames, req.CSR != nil)
			}
			if req.Who.Actor.Name == "" {
				t.Error("the request carries no requester")
			}
		})
	}
}

func mergeValues(a, b url.Values) url.Values {
	out := url.Values{}
	for _, m := range []url.Values{a, b} {
		for k, vs := range m {
			out[k] = vs
		}
	}
	return out
}

// TestReviewWritesNothing: the review step leaves no certificate (and so no
// serial), name, key, outbox row or audit entry – not even a denied one – for
// an allowed and for a refused request.
func TestReviewWritesNothing(t *testing.T) {
	t.Parallel()
	e := newReviewEnv(t, true)
	count := func() map[string]int {
		out := map[string]int{}
		for _, tb := range []struct {
			db    *sql.DB
			table string
		}{
			{e.PKIDB.Read, "certificates"}, {e.PKIDB.Read, "certificate_sans"}, {e.PKIDB.Read, "keys"}, {e.PKIDB.Read, "outbox"},
			{e.PKIDB.Read, "blocked_keys"}, {e.TenantAudit.Read, "audit_entries"}, {e.InstanceAudit.Read, "audit_entries"},
		} {
			var n int
			if err := tb.db.QueryRowContext(t.Context(), "SELECT count(*) FROM "+tb.table).Scan(&n); err != nil {
				t.Fatalf("count %s: %v", tb.table, err)
			}
			out[tb.table+fmt.Sprintf("/%p", tb.db)] = n
		}
		return out
	}
	before := count()
	for name, extra := range map[string]url.Values{
		"server key": nil, "csr": e.csrForm(t), "refused": {"email": {"ops@homelab.lan"}},
	} {
		if r := e.step(t, 3, "next", extra); r.Code != http.StatusOK || !strings.Contains(r.html(), "Policy checks") {
			t.Fatalf("%s: %d", name, r.Code)
		}
	}
	if after := count(); !reflect.DeepEqual(before, after) {
		t.Errorf("the review step wrote rows:\nbefore %v\nafter  %v", before, after)
	}
	if got := e.wizardRequests(); len(got) != 3 {
		t.Errorf("%d requests planned, want 3", len(got))
	}
}

// TestReviewPermissionIsTheWizardsOwn: who may open the wizard may see its
// review, nobody else; the preview opens no second door.
func TestReviewPermissionIsTheWizardsOwn(t *testing.T) {
	t.Parallel()
	v := newUIEnv(t)
	v.Unseal(t)
	v.User(t, "viewer", false, authz.Binding{Role: authz.Viewer})
	v.User(t, "op", false, authz.Binding{CA: "issuing", Role: authz.Operator})
	v.User(t, "rootop", false, authz.Binding{CA: "root", Role: authz.Operator})
	review := func(name string, caID string) page {
		b := v.browser("192.0.2.1")
		b.signIn(t, name, testinstance.Password)
		return b.post(t, "/certificates/new", url.Values{
			"csrf_token": {b.csrf(t)}, "from": {"3"}, "go": {"next"}, "preset": {"server"}, "ca": {caID},
			"keymode": {"server"}, "alg": {"ecdsa-p256"}, "days": {"90"}, "cn": {"web.homelab.lan"}, "dns": {"web.homelab.lan"},
		})
	}
	if r := review("viewer", v.CAIDs["issuing"]); strings.Contains(r.html(), "Policy checks") {
		t.Errorf("a viewer got the review: %d", r.Code)
	}
	if r := review("rootop", v.CAIDs["issuing"]); strings.Contains(r.html(), "Policy checks") {
		t.Errorf("an operator of another CA got the review: %d", r.Code)
	}
	if got := v.wizardRequests(); len(got) != 0 {
		t.Errorf("a refused user's request reached the engine: %+v", got)
	}
	if r := review("op", v.CAIDs["issuing"]); !strings.Contains(r.html(), "Policy checks") {
		t.Errorf("an operator of the CA must see the review: %d", r.Code)
	}
}
