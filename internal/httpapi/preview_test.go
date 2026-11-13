package httpapi

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"maps"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/ca"
)

// previewEnv is an unsealed instance with the people the preview tests need.
type previewEnv struct {
	*env
	admin, viewer, rootview, nobody, op, anon *client
	issuing, root                             string
}

func newPreviewEnv(t *testing.T) *previewEnv {
	t.Helper()
	v := newEnv(t)
	v.unseal(t)
	v.user(t, "viewer", false, authz.Binding{Role: authz.Viewer})
	v.user(t, "rootview", false, authz.Binding{CA: "root", Role: authz.Viewer}) // may not read "issuing"
	v.user(t, "op", false, authz.Binding{CA: "issuing", Role: authz.Operator})
	v.user(t, "nobody", false)
	p := &previewEnv{env: v, issuing: v.caIDs["issuing"], root: v.caIDs["root"]}
	p.admin, p.viewer, p.rootview, p.nobody, p.op, p.anon = v.client("192.0.2.1"), v.client("192.0.2.2"), v.client("192.0.2.3"), v.client("192.0.2.4"), v.client("192.0.2.5"), v.client("192.0.2.9")
	p.admin.signIn(t, "demo", v.demoPass)
	p.viewer.signIn(t, "viewer", testPassword)
	p.rootview.signIn(t, "rootview", testPassword)
	p.nobody.signIn(t, "nobody", testPassword)
	p.op.signIn(t, "op", testPassword)
	return p
}

// csr makes a PEM certificate request.
func previewCSR(t *testing.T, cn string, dns ...string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}, DNSNames: dns}, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

// keyed is the body of a request with a server-generated key.
func (p *previewEnv) keyed(preset string, dns ...string) map[string]any {
	return map[string]any{"ca_id": p.issuing, "preset": preset, "sans": map[string]any{"dns": dns}, "key": map[string]string{"algorithm": "ecdsa-p256"}}
}

// rowCounts counts what an issuance writes: certificates, their names, keys,
// blocked keys, the outbox, and the two audit logs (refusals are written there
// directly); the audit entries themselves are compared by their action.
func (p *previewEnv) rowCounts(t *testing.T) map[string]int {
	t.Helper()
	out := map[string]int{}
	for _, tb := range []struct {
		name, table string
	}{
		{"pki", "certificates"}, {"pki", "certificate_sans"}, {"pki", "keys"}, {"pki", "outbox"}, {"pki", "blocked_keys"},
		{"tenant-audit", "audit_entries"}, {"instance-audit", "audit_entries"},
	} {
		db := p.in.PKIDB.Read
		switch tb.name {
		case "tenant-audit":
			db = p.in.TenantAudit.Read
		case "instance-audit":
			db = p.in.InstanceAudit.Read
		}
		var n int
		if err := db.QueryRowContext(t.Context(), "SELECT count(*) FROM "+tb.table).Scan(&n); err != nil {
			t.Fatalf("count %s: %v", tb.table, err)
		}
		out[tb.name+"."+tb.table] = n
	}
	return out
}

// problemErrors is the field messages of a problem answer.
func problemErrors(r *resp) []string {
	var out []string
	list, _ := r.body["errors"].([]any)
	for _, e := range list {
		m, _ := e.(map[string]any)
		s, _ := m["message"].(string)
		out = append(out, s)
	}
	return out
}

func stringsOf(v any) []string {
	var out []string
	list, _ := v.([]any)
	for _, e := range list {
		s, _ := e.(string)
		out = append(out, s)
	}
	return out
}

// TestPreviewAgreesWithIssuance (PHASE3 step 59): the same body goes to both
// endpoints. "allowed" is exactly "issued", the reasons of a refusal are the
// field messages of the 422, and what the plan says is in the certificate.
func TestPreviewAgreesWithIssuance(t *testing.T) {
	t.Parallel()
	p := newPreviewEnv(t)
	good := previewCSR(t, "web.homelab.lan", "web.homelab.lan", "www.homelab.lan")
	rows := []struct {
		name string
		body map[string]any
	}{
		{"server key", p.keyed("server", "nas.homelab.lan")},
		{"wildcard", p.keyed("wildcard", "*.apps.homelab.lan")},
		{"csr", map[string]any{"ca_id": p.issuing, "preset": "server", "csr_pem": good}},
		{"csr, names ignored", map[string]any{"ca_id": p.issuing, "preset": "server", "csr_pem": good, "use_csr_sans": false, "sans": map[string]any{"dns": []string{"other.homelab.lan"}}}},
		{"explicit validity", map[string]any{"ca_id": p.issuing, "preset": "server", "sans": map[string]any{"dns": []string{"v.homelab.lan"}}, "validity_days": 30, "key": map[string]string{"algorithm": "ecdsa-p384"}}},
		{"validity beyond the CA", map[string]any{"ca_id": p.issuing, "preset": "server", "sans": map[string]any{"dns": []string{"long.homelab.lan"}}, "validity_days": 100000, "key": map[string]string{"algorithm": "ecdsa-p256"}}},
		{"subject given", map[string]any{"ca_id": p.issuing, "preset": "server", "subject": map[string]string{"common_name": "mail.homelab.lan", "organization": "Homelab", "country": "DE"}, "key": map[string]string{"algorithm": "ecdsa-p256"}}},
		{"two bad names", p.keyed("server", "a.example.org.invalid..name", "b..homelab.lan")},
		{"unknown preset", p.keyed("nosuchpreset", "nas.homelab.lan")},
		{"root CA", map[string]any{"ca_id": p.root, "preset": "server", "sans": map[string]any{"dns": []string{"leaf.homelab.lan"}}, "key": map[string]string{"algorithm": "ecdsa-p256"}}},
		{"no names at all", map[string]any{"ca_id": p.issuing, "preset": "server", "key": map[string]string{"algorithm": "ecdsa-p256"}}},
		{"algorithm that can't be generated", map[string]any{"ca_id": p.issuing, "preset": "server", "sans": map[string]any{"dns": []string{"x.homelab.lan"}}, "key": map[string]string{"algorithm": "rsa-1024"}}},
		{"malformed CSR", map[string]any{"ca_id": p.issuing, "preset": "server", "csr_pem": "-----BEGIN CERTIFICATE REQUEST-----\nAAAA\n-----END CERTIFICATE REQUEST-----\n"}},
		{"preset not customizable", map[string]any{"ca_id": p.issuing, "preset": "server", "sans": map[string]any{"dns": []string{"c.homelab.lan"}}, "key": map[string]string{"algorithm": "ecdsa-p256"}, "key_usage": []string{"digitalSignature"}}},
	}
	var allowed, refused int
	for _, row := range rows {
		prev := p.admin.do(t, http.MethodPost, "/certificates/preview", row.body)
		if prev.Code != http.StatusOK {
			t.Errorf("%s: preview %d %s", row.name, prev.Code, prev.Body.String())
			continue
		}
		issued := p.admin.do(t, http.MethodPost, "/certificates", row.body)
		ok, _ := prev.body["allowed"].(bool)
		if ok != (issued.Code == http.StatusCreated) {
			t.Errorf("%s: preview allowed=%v, issuance %d %s", row.name, ok, issued.Code, issued.Body.String())
			continue
		}
		if !ok {
			refused++
			reasons := stringsOf(prev.body["reasons"])
			if issued.Code != http.StatusUnprocessableEntity || issued.problemType() != "policy-violation" {
				t.Errorf("%s: issuance %d %s", row.name, issued.Code, issued.Body.String())
			}
			if len(reasons) == 0 || !slices.Equal(reasons, problemErrors(issued)) {
				t.Errorf("%s: reasons %q, issuance says %q", row.name, reasons, problemErrors(issued))
			}
			if prev.body["validity"] != nil || prev.body["aia_url"] != nil || len(jsonList(prev.body["extensions"])) != 0 {
				t.Errorf("%s: a refused plan must not describe a certificate: %s", row.name, prev.Body.String())
			}
			continue
		}
		allowed++
		if len(stringsOf(prev.body["reasons"])) != 0 || prev.body["stopped_at"] != nil {
			t.Errorf("%s: an allowed plan with reasons: %s", row.name, prev.Body.String())
		}
		// The plan is the certificate.
		validity, _ := prev.body["validity"].(map[string]any)
		if validity["not_before"] != issued.body["not_before"] || validity["not_after"] != issued.body["not_after"] {
			t.Errorf("%s: validity %v, issued %v – %v", row.name, validity, issued.body["not_before"], issued.body["not_after"])
		}
		if key, _ := prev.body["key"].(map[string]any); key["algorithm"] != issued.body["key_algorithm"] {
			t.Errorf("%s: key %v, issued %v", row.name, key, issued.body["key_algorithm"])
		}
		if preset, _ := prev.body["preset"].(map[string]any); preset["name"] != issued.body["preset"] {
			t.Errorf("%s: preset %v, issued %v", row.name, preset, issued.body["preset"])
		}
		if subj, _ := prev.body["subject"].(map[string]any); subj["common_name"] != issued.body["common_name"] {
			t.Errorf("%s: common name %v, issued %v", row.name, subj, issued.body["common_name"])
		}
		var names []string
		for _, n := range jsonList(prev.body["names"]) {
			m := jsonObj(n)
			names = append(names, fmt.Sprintf("%v:%v", m["type"], m["value"]))
		}
		var got []string
		sans, _ := issued.body["sans"].(map[string]any)
		for _, kind := range []string{"dns", "ip", "email", "uri"} {
			for _, v := range stringsOf(sans[kind]) {
				got = append(got, kind+":"+v)
			}
		}
		slices.Sort(names)
		slices.Sort(got)
		if !slices.Equal(names, got) {
			t.Errorf("%s: names %q, issued %q", row.name, names, got)
		}
		if notes := stringsOf(prev.body["notes"]); !slices.Equal(notes, stringsOf(issued.body["notes"])) {
			t.Errorf("%s: notes %q, issued %q", row.name, notes, issued.body["notes"])
		}
		if dropped := stringsOf(prev.body["dropped_csr_names"]); !slices.Equal(dropped, stringsOf(issued.body["dropped_csr_names"])) {
			t.Errorf("%s: dropped names %q, issued %q", row.name, dropped, issued.body["dropped_csr_names"])
		}
		if len(jsonList(prev.body["extensions"])) == 0 || len(jsonList(prev.body["chain"])) == 0 || prev.body["aia_url"] == nil || prev.body["cdp_url"] == nil {
			t.Errorf("%s: an allowed plan without extensions, chain or URLs: %s", row.name, prev.Body.String())
		}
	}
	if allowed < 4 || refused < 5 {
		t.Errorf("the table lost its meaning: %d allowed, %d refused", allowed, refused)
	}
}

// TestPreviewAnswersAsIssuanceDoes: who may not do something, and what is no
// request at all, gets the same answer from both endpoints.
func TestPreviewAnswersAsIssuanceDoes(t *testing.T) {
	t.Parallel()
	p := newPreviewEnv(t)
	ok := p.keyed("server", "nas.homelab.lan")
	big := strings.Repeat("A", 65537)
	pad := `{"ca_id":"` + p.issuing + `","preset":"server","pad":"` + strings.Repeat("a", 129<<10) + `"}`
	cases := []struct {
		name   string
		as     *client
		body   any
		header []string
		want   int
		kind   string
	}{
		{"operator", p.op, ok, nil, 200, ""},
		{"admin", p.admin, ok, nil, 200, ""},
		{"viewer may read, not issue", p.viewer, ok, nil, 403, "forbidden"},
		{"may not read the CA", p.rootview, ok, nil, 404, "not-found"},
		{"no role at all", p.nobody, ok, nil, 404, "not-found"},
		{"operator of another CA", p.op, map[string]any{"ca_id": p.root, "preset": "server", "key": map[string]string{"algorithm": "ecdsa-p256"}}, nil, 404, "not-found"},
		{"no session", p.anon, ok, nil, 401, "unauthorized"},
		{"unknown CA", p.admin, map[string]any{"ca_id": "ca_nothere", "preset": "server", "key": map[string]string{"algorithm": "ecdsa-p256"}}, nil, 404, "not-found"},
		{"no CA", p.admin, map[string]any{"preset": "server", "key": map[string]string{"algorithm": "ecdsa-p256"}}, nil, 400, "bad-request"},
		{"CSR and key", p.admin, map[string]any{"ca_id": p.issuing, "preset": "server", "csr_pem": "x", "key": map[string]string{"algorithm": "ecdsa-p256"}}, nil, 400, "bad-request"},
		{"neither CSR nor key", p.admin, map[string]any{"ca_id": p.issuing, "preset": "server"}, nil, 400, "bad-request"},
		{"validity below one day", p.admin, map[string]any{"ca_id": p.issuing, "preset": "server", "validity_days": 0, "key": map[string]string{"algorithm": "ecdsa-p256"}}, nil, 400, "bad-request"},
		{"unknown field", p.admin, map[string]any{"ca_id": p.issuing, "preset": "server", "valdity_days": 3, "key": map[string]string{"algorithm": "ecdsa-p256"}}, nil, 400, "bad-request"},
		{"not JSON", p.admin, `{"ca_id":`, []string{"Content-Type", "application/json"}, 400, "bad-request"},
		{"empty body", p.admin, ``, []string{"Content-Type", "application/json"}, 400, "bad-request"},
		{"two objects", p.admin, `{} {}`, []string{"Content-Type", "application/json"}, 400, "bad-request"},
		{"form body", p.admin, "ca_id=x", []string{"Content-Type", "application/x-www-form-urlencoded"}, 415, "unsupported-media-type"},
		{"no content type", p.admin, `{}`, nil, 415, "unsupported-media-type"},
		{"CSR over 64 KiB", p.admin, map[string]any{"ca_id": p.issuing, "preset": "server", "csr_pem": big}, nil, 400, "bad-request"},
		{"body over the limit", p.admin, pad, []string{"Content-Type", "application/json"}, 413, "too-large"},
	}
	for _, tc := range cases {
		prev := tc.as.do(t, http.MethodPost, "/certificates/preview", tc.body, tc.header...)
		issued := tc.as.do(t, http.MethodPost, "/certificates", tc.body, tc.header...)
		if prev.Code != tc.want || prev.problemType() != tc.kind {
			t.Errorf("%s: preview %d %q, want %d %q\n%s", tc.name, prev.Code, prev.problemType(), tc.want, tc.kind, prev.Body.String())
		}
		wantIssue := tc.want
		if wantIssue == 200 {
			wantIssue = 201
		}
		if issued.Code != wantIssue {
			t.Errorf("%s: issuance %d, want %d\n%s", tc.name, issued.Code, wantIssue, issued.Body.String())
		}
		if prev.Code >= 400 && (prev.Code != issued.Code || prev.problemType() != issued.problemType() ||
			fmt.Sprint(prev.body["errors"]) != fmt.Sprint(issued.body["errors"]) || prev.body["detail"] != issued.body["detail"]) {
			t.Errorf("%s: preview says %d %v, issuance %d %v", tc.name, prev.Code, prev.body, issued.Code, issued.body)
		}
	}
}

// TestPreviewNeedsNoStepUpAndWorksWithAToken: a token with the operator role on
// the CA previews; one for another CA does not see this CA.
func TestPreviewNeedsNoStepUpAndWorksWithAToken(t *testing.T) {
	t.Parallel()
	p := newPreviewEnv(t)
	p.admin.stepUp(t, "demo")
	token := func(ca string) []string {
		r := p.admin.do(t, http.MethodPost, "/tokens", map[string]any{"name": "t-" + ca, "expires_at": p.clk.Now().Add(24 * time.Hour).Format(time.RFC3339),
			"roles": []map[string]any{{"role": "operator", "scope": map[string]string{"type": "ca", "id": ca}}}})
		if r.Code != http.StatusCreated {
			t.Fatalf("token: %d %s", r.Code, r.Body.String())
		}
		return []string{"Authorization", "Bearer " + jsonStr(r.body["secret"])}
	}
	issuingToken, rootToken := token(p.issuing), token(p.root)
	p.clk.Advance(authz.StepUpWindow + time.Second) // the step-up is gone; a token never had one
	bot := p.client("192.0.2.40")
	if r := bot.do(t, http.MethodPost, "/certificates/preview", p.keyed("server", "ci.homelab.lan"), issuingToken...); r.Code != http.StatusOK || r.body["allowed"] != true {
		t.Errorf("preview with a token: %d %s", r.Code, r.Body.String())
	}
	if r := bot.do(t, http.MethodPost, "/certificates/preview", p.keyed("server", "ci.homelab.lan"), rootToken...); r.Code != http.StatusNotFound {
		t.Errorf("preview with a token of another CA: %d %s", r.Code, r.Body.String())
	}
}

// TestPreviewWritesNothing: a preview leaves no row and no audit entry – an
// allowed one, a refused one, one by someone who may not issue, a malformed
// one, and one on a sealed server.
func TestPreviewWritesNothing(t *testing.T) {
	t.Parallel()
	p := newPreviewEnv(t)
	// One real issuance first, so that "nothing changed" isn't "nothing exists".
	if r := p.admin.do(t, http.MethodPost, "/certificates", p.keyed("server", "first.homelab.lan")); r.Code != http.StatusCreated {
		t.Fatalf("issue: %d %s", r.Code, r.Body.String())
	}
	check := func(name string, c *client, body any, want int) {
		t.Helper()
		before, auditT, auditI := p.rowCounts(t), p.audit(t, p.ta), p.audit(t, p.ia)
		r := c.do(t, http.MethodPost, "/certificates/preview", body)
		if r.Code != want {
			t.Errorf("%s: %d %s, want %d", name, r.Code, r.Body.String(), want)
		}
		if after := p.rowCounts(t); !maps.Equal(before, after) {
			t.Errorf("%s: rows changed: before %v, after %v", name, before, after)
		}
		if got := p.audit(t, p.ta); !slices.Equal(got, auditT) {
			t.Errorf("%s: tenant audit changed: %v -> %v", name, auditT, got)
		}
		if got := p.audit(t, p.ia); !slices.Equal(got, auditI) {
			t.Errorf("%s: instance audit changed: %v -> %v", name, auditI, got)
		}
	}
	check("allowed, key on the server", p.admin, p.keyed("server", "second.homelab.lan"), 200)
	check("allowed, CSR", p.admin, map[string]any{"ca_id": p.issuing, "preset": "server", "csr_pem": previewCSR(t, "c.homelab.lan", "c.homelab.lan")}, 200)
	check("refused", p.admin, p.keyed("server", "a.example.org.invalid..name"), 200)
	check("refused, root CA", p.admin, map[string]any{"ca_id": p.root, "preset": "server", "key": map[string]string{"algorithm": "ecdsa-p256"}}, 200)
	check("viewer may not issue", p.viewer, p.keyed("server", "v.homelab.lan"), 403)
	check("may not read the CA", p.rootview, p.keyed("server", "v.homelab.lan"), 404)
	check("malformed", p.admin, map[string]any{"ca_id": p.issuing}, 400)
	check("malformed CSR", p.admin, map[string]any{"ca_id": p.issuing, "preset": "server", "csr_pem": "garbage"}, 200)

	if r := p.admin.do(t, http.MethodPost, "/system/seal", nil); r.Code != http.StatusOK {
		t.Fatalf("seal: %d %s", r.Code, r.Body.String())
	}
	check("sealed", p.admin, p.keyed("server", "sealed.homelab.lan"), 200)
}

// TestPreviewOfASealedServer: the plan is made and says so; issuing is 503.
func TestPreviewOfASealedServer(t *testing.T) {
	t.Parallel()
	p := newPreviewEnv(t)
	if r := p.admin.do(t, http.MethodPost, "/system/seal", nil); r.Code != http.StatusOK {
		t.Fatalf("seal: %d %s", r.Code, r.Body.String())
	}
	body := p.keyed("server", "nas.homelab.lan")
	r := p.admin.do(t, http.MethodPost, "/certificates/preview", body)
	if r.Code != http.StatusOK || r.body["sealed"] != true || r.body["allowed"] != true {
		t.Errorf("sealed preview: %d %s", r.Code, r.Body.String())
	}
	if iss := p.admin.do(t, http.MethodPost, "/certificates", body); iss.Code != http.StatusServiceUnavailable || iss.problemType() != "sealed" {
		t.Errorf("sealed issuance: %d %s", iss.Code, iss.Body.String())
	}
	// A refusal while sealed is still a refusal with its reasons.
	r = p.admin.do(t, http.MethodPost, "/certificates/preview", p.keyed("server", "a.example.org.invalid..name"))
	if r.Code != http.StatusOK || r.body["sealed"] != true || r.body["allowed"] != false || len(stringsOf(r.body["reasons"])) == 0 {
		t.Errorf("sealed refusal: %d %s", r.Code, r.Body.String())
	}
	// And an unsealed server says false.
	p.unseal(t)
	if r := p.admin.do(t, http.MethodPost, "/certificates/preview", body); r.body["sealed"] != false {
		t.Errorf("unsealed preview: %s", r.Body.String())
	}
}

// TestPreviewShowsEveryReason: all the collected checks run, so two problems
// in two checks are both listed – and a gate hides what comes after it.
func TestPreviewShowsEveryReason(t *testing.T) {
	t.Parallel()
	p := newPreviewEnv(t)
	r := p.admin.do(t, http.MethodPost, "/certificates/preview", p.keyed("server", "a.example.org.invalid..name", "b..homelab.lan"))
	if r.Code != http.StatusOK || r.body["allowed"] != false {
		t.Fatalf("%d %s", r.Code, r.Body.String())
	}
	if got := stringsOf(r.body["reasons"]); len(got) < 2 {
		t.Errorf("reasons %q, want one per bad name", got)
	}
	if r.body["stopped_at"] != nil {
		t.Errorf("the plan ran through, stopped_at %v", r.body["stopped_at"])
	}
	// The same list is in the checks, in order, and the collected checks say so.
	var fromChecks []string
	for _, c := range jsonList(r.body["checks"]) {
		m := jsonObj(c)
		fromChecks = append(fromChecks, stringsOf(m["problems"])...)
		if m["passed"] != (len(stringsOf(m["problems"])) == 0) {
			t.Errorf("check %v: passed %v with problems %v", m["name"], m["passed"], m["problems"])
		}
		if m["name"] == "names" && m["collected"] != true {
			t.Errorf("the names check is collected: %v", m)
		}
	}
	if !slices.Equal(fromChecks, stringsOf(r.body["reasons"])) {
		t.Errorf("reasons %q, checks %q", r.body["reasons"], fromChecks)
	}
	// A gate: a root CA ends the plan at "ca", the later checks don't run.
	r = p.admin.do(t, http.MethodPost, "/certificates/preview", map[string]any{"ca_id": p.root, "preset": "server", "sans": map[string]any{"dns": []string{"a..b"}}, "key": map[string]string{"algorithm": "ecdsa-p256"}})
	if r.body["allowed"] != false || r.body["stopped_at"] != "ca" {
		t.Errorf("root CA: %s", r.Body.String())
	}
	for _, c := range jsonList(r.body["checks"]) {
		if jsonObj(c)["name"] == "names" {
			t.Errorf("the names check ran after the gate: %s", r.Body.String())
		}
	}
	if r.body["chain"] == nil || r.body["ca"] != nil && jsonObj(r.body["ca"])["name"] == "" {
		t.Errorf("the CA is known at the gate: %s", r.Body.String())
	}
}

// TestPreviewEscapesHostileNames: a hostile name in the request or in the CSR
// comes back as JSON data with markup characters escaped, and the CSR itself
// is never in the answer.
func TestPreviewEscapesHostileNames(t *testing.T) {
	t.Parallel()
	p := newPreviewEnv(t)
	const script = `<script>alert(1)</script>.homelab.lan`
	r := p.admin.do(t, http.MethodPost, "/certificates/preview", p.keyed("server", script))
	if r.Code != http.StatusOK || r.body["allowed"] != false {
		t.Fatalf("%d %s", r.Code, r.Body.String())
	}
	raw := r.Body.String()
	if strings.ContainsAny(raw, "<>") || strings.Contains(raw, "<script") || !strings.Contains(raw, `\u003cscript\u003e`) {
		t.Errorf("hostile name in the reasons is not escaped: %s", raw)
	}
	if got := strings.Join(stringsOf(r.body["reasons"]), "\n"); !strings.Contains(got, "<script>") {
		t.Errorf("the decoded reason lost the name: %q", got)
	}

	// A CSR whose subject and names are hostile: allowed or not, only escaped data comes back.
	const cn = `<img src=x onerror=alert(1)>`
	csr := previewCSR(t, cn, "web.homelab.lan", `"><svg onload=alert(1)>.homelab.lan`)
	r = p.admin.do(t, http.MethodPost, "/certificates/preview", map[string]any{"ca_id": p.issuing, "preset": "server", "csr_pem": csr})
	if r.Code != http.StatusOK {
		t.Fatalf("%d %s", r.Code, r.Body.String())
	}
	raw = r.Body.String()
	if strings.ContainsAny(raw, "<>") {
		t.Errorf("hostile CSR text is not escaped: %s", raw)
	}
	// The CSR is never echoed: neither its PEM nor its DER in any encoding.
	block, _ := pem.Decode([]byte(csr))
	b64 := base64.StdEncoding.EncodeToString(block.Bytes)
	for _, leak := range []string{"CERTIFICATE REQUEST", "BEGIN", b64[:60]} {
		if strings.Contains(raw, leak) {
			t.Errorf("the answer echoes the CSR (%q): %s", leak, raw)
		}
	}
}

// TestPreviewBuildsTheIssueRequest: for the same body, issueCertificate and
// previewCertificate hand the engine the very same ca.Request – tenant subject
// defaults, use_csr_sans, key usages and all. (The two share
// API.certificateRequest; this test fails if one of them stops using it.)
func TestPreviewBuildsTheIssueRequest(t *testing.T) {
	t.Parallel()
	p := newPreviewEnv(t)
	p.admin.stepUp(t, "demo")
	settings := map[string]any{"allow_server_keygen": true, "subject_defaults": map[string]string{"organization": "Homelab", "organizational_unit": "IT", "locality": "Kiel", "state": "SH", "country": "DE"}}
	if r := p.admin.do(t, http.MethodPut, "/settings", settings); r.Code != http.StatusOK {
		t.Fatalf("settings: %d %s", r.Code, r.Body.String())
	}
	var seen []struct {
		op string
		r  ca.Request
	}
	p.api.onRequest = func(op string, r ca.Request) {
		seen = append(seen, struct {
			op string
			r  ca.Request
		}{op, r})
	}
	csr := previewCSR(t, "web.homelab.lan", "web.homelab.lan", "www.homelab.lan")
	bodies := []map[string]any{
		p.keyed("server", "nas.homelab.lan"),
		{"ca_id": p.issuing, "preset": "server", "csr_pem": csr},
		{"ca_id": p.issuing, "preset": "server", "csr_pem": csr, "use_csr_sans": false, "sans": map[string]any{"dns": []string{"x.homelab.lan"}}},
		{"ca_id": p.issuing, "preset": "server", "csr_pem": csr, "use_csr_sans": true},
		{"ca_id": p.issuing, "preset": "custom", "key": map[string]string{"algorithm": "ed25519"}, "key_usage": []string{"digitalSignature"}, "ext_key_usage": []string{"clientAuth"}, "sans": map[string]any{"email": []string{"me@homelab.lan"}}},
		{"ca_id": p.issuing, "preset": "server", "subject": map[string]string{"common_name": "svc.homelab.lan", "organization": "Own Org", "state": "NI"}, "validity_days": 14, "sans": map[string]any{"dns": []string{"svc.homelab.lan"}, "ip": []string{"192.0.2.7"}, "uri": []string{"https://svc.homelab.lan"}}, "key": map[string]string{"algorithm": "rsa-3072"}},
		{"ca_id": p.issuing, "preset": "nosuchpreset", "key": map[string]string{"algorithm": "ecdsa-p256"}},
	}
	for i, body := range bodies {
		seen = nil
		if r := p.admin.do(t, http.MethodPost, "/certificates/preview", body); r.Code != http.StatusOK {
			t.Errorf("body %d: preview %d %s", i, r.Code, r.Body.String())
		}
		p.admin.do(t, http.MethodPost, "/certificates", body)
		if len(seen) != 2 || seen[0].op != "previewCertificate" || seen[1].op != "issueCertificate" {
			t.Fatalf("body %d: the handlers handed the engine %d request(s)", i, len(seen))
		}
		if !reflect.DeepEqual(seen[0].r, seen[1].r) {
			t.Errorf("body %d: preview built\n%+v\nissuance built\n%+v", i, seen[0].r, seen[1].r)
		}
	}
	// The builder really applies what the two must agree on.
	seen = nil
	p.admin.do(t, http.MethodPost, "/certificates/preview", bodies[2])
	r := seen[0].r
	if r.SubjectDefaults.Organization != "Homelab" || r.SubjectDefaults.Province != "SH" || r.SubjectDefaults.Country != "DE" || !r.IgnoreCSRNames {
		t.Errorf("tenant defaults or use_csr_sans lost: %+v", r)
	}
	// And a preview of such a request shows the defaults in the plan.
	prev := p.admin.do(t, http.MethodPost, "/certificates/preview", p.keyed("server", "nas.homelab.lan"))
	if subj, _ := prev.body["subject"].(map[string]any); subj["organization"] != "Homelab" || subj["country"] != "DE" {
		t.Errorf("the plan lacks the tenant subject defaults: %s", prev.Body.String())
	}
}

// TestPreviewListsWhatIssuanceBuilds: the extensions of the plan carry the
// preset's rules, and the chain ends in the root.
func TestPreviewListsWhatIssuanceBuilds(t *testing.T) {
	t.Parallel()
	p := newPreviewEnv(t)
	r := p.admin.do(t, http.MethodPost, "/certificates/preview", p.keyed("server", "nas.homelab.lan"))
	if r.Code != http.StatusOK || r.body["allowed"] != true {
		t.Fatalf("%d %s", r.Code, r.Body.String())
	}
	exts := map[string]map[string]any{}
	for _, e := range jsonList(r.body["extensions"]) {
		m := jsonObj(e)
		exts[jsonStr(m["name"])] = m
	}
	for _, want := range []string{"basicConstraints", "keyUsage", "extKeyUsage", "subjectKeyIdentifier", "authorityKeyIdentifier", "subjectAltName", "authorityInfoAccess", "cRLDistributionPoints"} {
		if exts[want] == nil {
			t.Errorf("extension %s missing: %s", want, r.Body.String())
		}
	}
	chain := jsonList(r.body["chain"])
	if len(chain) < 2 || jsonObj(chain[0])["root"] != false || jsonObj(chain[len(chain)-1])["root"] != true {
		t.Errorf("chain: %v", chain)
	}
	if ca, _ := r.body["ca"].(map[string]any); ca["name"] != "issuing" {
		t.Errorf("ca: %v", r.body["ca"])
	}
	if _, ok := r.body["serial"]; ok {
		t.Errorf("a preview has no serial: %s", r.Body.String())
	}
	if gen, _ := r.body["generated_at"].(string); gen != p.clk.Now().UTC().Truncate(time.Second).Format(time.RFC3339) {
		t.Errorf("generated_at %q, clock %s", gen, p.clk.Now())
	}
}

// arr, obj and str read a decoded JSON value; a wrong type is the zero value,
// and the comparison that follows fails.
func jsonList(v any) []any {
	l, _ := v.([]any)
	return l
}

func jsonObj(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func jsonStr(v any) string {
	s, _ := v.(string)
	return s
}
