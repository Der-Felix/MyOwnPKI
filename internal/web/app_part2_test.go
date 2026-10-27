package web

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha1" // #nosec G505 -- verifies the display-only Windows dialog value
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"io/fs"
	"maps"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/ca/legacy/legacytest"
	"github.com/Der-Felix/MyOwnPKI/internal/testinstance"
	"github.com/Der-Felix/MyOwnPKI/internal/testutil"
	"github.com/Der-Felix/MyOwnPKI/internal/web/view"
)

// Part 2 of the real UI (step 19): every action ends with 303 on a page
// (PRG), shows what happened, and the services decide.

func flashOf(t *testing.T, b *browser, target string) string {
	t.Helper()
	return strings.Join(messages(b.get(t, target).html()), " | ")
}

func TestCertificateActions(t *testing.T) {
	t.Parallel()
	v := newUIEnv(t)
	v.Unseal(t)
	b := v.browser("192.0.2.1")
	b.signIn(t, "demo", v.DemoPassword)
	token := b.csrf(t)
	issued, err := v.Engine.Issue(t.Context(), ca.Request{CA: "issuing", Preset: "server", DNSNames: []string{"nas.homelab.lan"}, Who: testinstance.Console})
	if err != nil {
		t.Fatal(err)
	}
	detail := "/certificates/" + issued.ID

	// Renew: 303 to the successor.
	r := b.post(t, detail+"/renew", url.Values{"csrf_token": {token}, "alg": {"ecdsa-p256"}, "predecessor": {"never"}})
	if r.Code != http.StatusSeeOther || !strings.HasPrefix(r.location(), "/certificates/crt_") || r.location() == detail {
		t.Fatalf("renew: %d %q", r.Code, r.location())
	}
	successor := r.location()
	if got := flashOf(t, b, successor); !strings.Contains(got, "successor") {
		t.Errorf("renew message: %s", got)
	}

	// Export as PKCS#12 with "delete the key": the file, then the key is gone.
	testutil.OpenSSL(t) // skip early without OpenSSL 3
	r = b.post(t, successor+"/export", url.Values{"csrf_token": {token}, "format": {"pkcs12"}, "password": {"short"}, "password2": {"short"}})
	if r.Code != http.StatusSeeOther || r.location() != successor+"/export" {
		t.Errorf("short password: %d %q", r.Code, r.location())
	}
	pw := "a password for the p12 file"
	r = b.post(t, successor+"/export", url.Values{"csrf_token": {token}, "format": {"pkcs12"}, "password": {pw}, "password2": {pw}, "delete": {"yes"}})
	if r.Code != http.StatusOK || r.Header().Get("Content-Type") != "application/x-pkcs12" {
		t.Fatalf("export: %d %v %s", r.Code, r.Header(), r.html())
	}
	p12 := filepath.Join(t.TempDir(), "x.p12")
	if werr := os.WriteFile(p12, r.Body.Bytes(), 0o600); werr != nil {
		t.Fatal(werr)
	}
	// What OpenSSL read: exactly the successor and its chain, and its key.
	certDER, chainDER, err := v.Engine.CertificateChain(t.Context(), testinstance.Console, strings.TrimPrefix(successor, "/certificates/"))
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}
	var chain []*x509.Certificate
	for _, der := range chainDER {
		c, perr := x509.ParseCertificate(der)
		if perr != nil {
			t.Fatal(perr)
		}
		chain = append(chain, c)
	}
	got, err := testutil.OpenSSLPKCS12(t, p12, pw, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range got.Problems(leaf, chain, "nas.homelab.lan") {
		t.Errorf("PKCS#12 export as OpenSSL read it: %s\n%s", p, got.Text)
	}
	r = b.post(t, successor+"/export", url.Values{"csrf_token": {token}, "format": {"pkcs8-pem"}})
	if r.Code != http.StatusSeeOther || !strings.Contains(flashOf(t, b, r.location()), "deleted") {
		t.Errorf("export after deletion: %d", r.Code)
	}

	// Revoke: confirmation needed, then 303 with the CRL message.
	if rr := b.post(t, detail+"/revoke", url.Values{"csrf_token": {token}, "reason": {"superseded"}}); rr.Code != http.StatusSeeOther || rr.location() != detail+"/revoke" {
		t.Errorf("revoke without confirmation: %d %q", r.Code, r.location())
	}
	r = b.post(t, detail+"/revoke", url.Values{"csrf_token": {token}, "reason": {"superseded"}, "confirm": {"yes"}})
	if r.Code != http.StatusSeeOther || r.location() != detail {
		t.Fatalf("revoke: %d %q", r.Code, r.location())
	}
	if page := b.get(t, detail).html(); !strings.Contains(page, "Revoked") || strings.Contains(page, `href="`+detail+`/revoke"`) {
		t.Error("the revoked certificate still offers Revoke or doesn't say Revoked")
	}

	// Without a fresh second factor a revocation goes to the step-up page.
	other, _ := v.Engine.Issue(t.Context(), ca.Request{CA: "issuing", Preset: "server", DNSNames: []string{"git.homelab.lan"}, Who: testinstance.Console})
	v.Clock.Advance(authz.StepUpWindow + time.Second)
	r = b.post(t, "/certificates/"+other.ID+"/revoke", url.Values{"csrf_token": {token}, "reason": {"superseded"}, "confirm": {"yes"}})
	if r.Code != http.StatusSeeOther || r.location() != "/step-up" {
		t.Errorf("revoke without step-up: %d %q", r.Code, r.location())
	}
}

func TestViewerSeesNoCommands(t *testing.T) {
	t.Parallel()
	v := newUIEnv(t)
	v.Unseal(t)
	v.User(t, "watcher", false, authz.Binding{Role: authz.Viewer})
	b := v.browser("192.0.2.2")
	b.signIn(t, "watcher", testinstance.Password)
	issued, _ := v.Engine.Issue(t.Context(), ca.Request{CA: "issuing", Preset: "server", DNSNames: []string{"nas.homelab.lan"}, Who: testinstance.Console})
	page := b.get(t, "/certificates/"+issued.ID).html()
	for _, cmd := range []string{"/revoke", "/renew", "/export"} {
		if strings.Contains(page, `/certificates/`+issued.ID+cmd+`"`) {
			t.Errorf("a viewer is offered %s", cmd)
		}
	}
	nav := b.get(t, "/").html()
	for _, link := range []string{`href="/admin/users"`, `href="/admin/audit"`, `href="/admin/import"`} {
		if strings.Contains(nav, link) {
			t.Errorf("a viewer sees %s", link)
		}
	}
	if r := b.get(t, "/admin/users"); r.Code != http.StatusForbidden {
		t.Errorf("users page for a viewer: %d", r.Code)
	}
	token := b.csrf(t)
	if rr := b.post(t, "/certificates/"+issued.ID+"/revoke", url.Values{"csrf_token": {token}, "reason": {"superseded"}, "confirm": {"yes"}}); rr.Code != http.StatusSeeOther ||
		!strings.Contains(flashOf(t, b, rr.location()), "needs the role operator") {
		t.Errorf("revoke by a viewer: %d %q", rr.Code, rr.location())
	}
}

func TestCAFingerprintDisplay(t *testing.T) {
	t.Parallel()
	v := newUIEnv(t)
	b := v.browser("192.0.2.1")
	b.signIn(t, "demo", v.DemoPassword)
	chain, err := v.Engine.CAChain(t.Context(), testinstance.Console, v.CAIDs["issuing"])
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"root", "issuing"} {
		der := chain[0]
		if name == "root" {
			der = chain[len(chain)-1]
		}
		sha256Sum := sha256.Sum256(der)
		sha1Sum := sha1.Sum(der) // #nosec G401 -- expected display-only value
		page := b.get(t, "/authorities/"+v.CAIDs[name]).html()
		for _, want := range []string{
			"SHA-256 fingerprint (authoritative)", view.Fingerprint(strings.ToUpper(hex.EncodeToString(sha256Sum[:]))),
			"SHA-1 fingerprint (Windows certificate dialog comparison only)", view.Fingerprint(strings.ToUpper(hex.EncodeToString(sha1Sum[:]))),
		} {
			if !strings.Contains(page, want) {
				t.Errorf("%s page lacks %q", name, want)
			}
		}
		automation := strings.ToLower(hex.EncodeToString(sha256Sum[:]))
		if name == "root" && (!strings.Contains(page, "Root SHA-256 for automation (exact 64 hex)") || !strings.Contains(page, ">"+automation+"<")) {
			t.Errorf("root page has no exact 64-hex automation value: %s", page)
		}
		if name != "root" && strings.Contains(page, "Root SHA-256 for automation") {
			t.Error("intermediate page exposes a root automation value")
		}
	}
}

func TestCAOfflineFlowInTheUI(t *testing.T) {
	t.Parallel()
	v := newUIEnv(t)
	v.Unseal(t)
	b := v.browser("192.0.2.1")
	b.signIn(t, "demo", v.DemoPassword)
	token := b.csrf(t)
	// An intermediate under the online root: signed at once.
	r := b.post(t, "/authorities/new", url.Values{"csrf_token": {token}, "parent": {v.CAIDs["root"]}, "name": {"lab-ca"}, "cn": {"Lab CA"}, "alg": {"ecdsa-p384"},
		"pathlen": {"0"}, "dns": {"homelab.example"}, "base": {"http://pki.homelab.example"}})
	if r.Code != http.StatusSeeOther || !strings.HasPrefix(r.location(), "/authorities/ca_") || strings.HasSuffix(r.location(), "/offline") {
		t.Fatalf("new CA: %d %q %s", r.Code, r.location(), flashOf(t, b, "/authorities/new"))
	}
	lab := r.location()
	// Manage: limits, CRL, retire.
	if rr := b.post(t, lab+"/limits", url.Values{"csrf_token": {token}, "crl_days": {"5"}, "max_days": {"90"}}); rr.Code != http.StatusSeeOther || rr.location() != lab {
		t.Errorf("limits: %d %q", r.Code, r.location())
	}
	if rr := b.post(t, lab+"/crl", url.Values{"csrf_token": {token}}); rr.Code != http.StatusSeeOther || !strings.Contains(flashOf(t, b, rr.location()), "CRL number") {
		t.Errorf("sign CRL: %d", r.Code)
	}
	if rr := b.post(t, lab+"/retire", url.Values{"csrf_token": {token}, "confirm": {"yes"}}); rr.Code != http.StatusSeeOther || !strings.Contains(flashOf(t, b, rr.location()), "retired") {
		t.Errorf("retire: %d", r.Code)
	}

	// An offline root and an intermediate below it: the offline page, then
	// the certificate signed by "the offline root" (this test) comes back.
	off := newOfflineRoot(t, v.Clock.Now())
	r = b.post(t, "/authorities/import", url.Values{"csrf_token": {token}, "name": {"offline"}, "cert": {off.pem}, "base": {"http://pki.homelab.example"}})
	if r.Code != http.StatusSeeOther || !strings.HasPrefix(r.location(), "/authorities/ca_") {
		t.Fatalf("import root: %d %q %s", r.Code, r.location(), flashOf(t, b, "/authorities/import"))
	}
	offID := strings.TrimPrefix(r.location(), "/authorities/")
	r = b.post(t, "/authorities/new", url.Values{"csrf_token": {token}, "parent": {offID}, "name": {"below"}, "cn": {"Below Offline"}, "alg": {"ecdsa-p384"}, "pathlen": {"0"}, "base": {"http://pki.homelab.example"}})
	if r.Code != http.StatusSeeOther || !strings.HasSuffix(r.location(), "/offline") {
		t.Fatalf("intermediate below the offline root: %d %q", r.Code, r.location())
	}
	page := b.get(t, r.location()).html()
	if !strings.Contains(page, "BEGIN CERTIFICATE REQUEST") || !strings.Contains(page, "v3_myownpki_ca") || !strings.Contains(page, "copy_extensions") {
		t.Fatalf("offline page:\n%s", page)
	}
	belowID := strings.TrimSuffix(strings.TrimPrefix(r.location(), "/authorities/"), "/offline")
	pending := b.get(t, "/authorities/"+belowID).html()
	if strings.Contains(pending, "SHA-256 fingerprint") || strings.Contains(pending, "SHA-1 fingerprint") {
		t.Error("pending CA generation displays an empty fingerprint")
	}
	b2, err := v.Engine.OfflineBundleFor(t.Context(), "below")
	if err != nil {
		t.Fatal(err)
	}
	signed := off.sign(t, b2, v.Clock.Now())
	r = b.post(t, "/authorities/"+belowID+"/certificate", url.Values{"csrf_token": {token}, "cert": {signed}})
	if r.Code != http.StatusSeeOther || !strings.Contains(flashOf(t, b, r.location()), "is active") {
		t.Errorf("install: %d %q", r.Code, r.location())
	}
	// The offline root's CRL upload.
	r = b.post(t, "/authorities/"+offID+"/crl-upload", url.Values{"csrf_token": {token}, "crl": {off.crl(t, v.Clock.Now())}})
	if r.Code != http.StatusSeeOther || !strings.Contains(flashOf(t, b, r.location()), "uploaded") {
		t.Errorf("CRL upload: %d", r.Code)
	}
}

func TestAdministrationPages(t *testing.T) {
	t.Parallel()
	v := newUIEnv(t)
	v.Unseal(t)
	b := v.browser("192.0.2.1")
	b.signIn(t, "demo", v.DemoPassword)
	token := b.csrf(t)

	// Settings: the subject default reaches the next certificate.
	// A tenant starts with the defaults of migration 0009.
	if page := b.get(t, "/admin/settings").html(); !strings.Contains(page, `value="300"`) || !strings.Contains(page, `value="5"`) || !strings.Contains(page, `value="10"`) {
		t.Errorf("default limits not shown")
	}
	limits := url.Values{"acme_orders": {"120"}, "acme_failed": {"4"}, "acme_accounts": {"8"},
		"agent_predecessor": {"now"}, "other_predecessor": {"after"}, "other_predecessor_days": {"7"}}
	form := func(extra url.Values) url.Values {
		out := url.Values{"csrf_token": {token}}
		maps.Copy(out, limits)
		maps.Copy(out, extra)
		return out
	}
	r := b.post(t, "/admin/settings", form(url.Values{"keygen": {"yes"}, "o": {"Homelab"}, "c": {"DE"}, "step_up_minutes": {"30"}}))
	if r.Code != http.StatusSeeOther || !strings.Contains(flashOf(t, b, "/admin/settings"), "saved") {
		t.Fatalf("settings: %d", r.Code)
	}
	// The ACME limits (PHASE2 step 11) and step-up lifetime are stored and shown.
	if page := b.get(t, "/admin/settings").html(); !strings.Contains(page, `value="120"`) || !strings.Contains(page, `value="8"`) ||
		!strings.Contains(page, `name="step_up_minutes"`) || !strings.Contains(page, `value="30" selected>30 minutes</option>`) {
		t.Errorf("limits or step-up lifetime not shown: %s", page)
	}
	for _, bad := range []url.Values{{"acme_orders": {"0"}}, {"acme_failed": {"101"}}, {"acme_accounts": {"many"}}} {
		if rr := b.post(t, "/admin/settings", form(bad)); rr.Code != http.StatusSeeOther || !strings.Contains(flashOf(t, b, "/admin/settings"), "per hour") {
			t.Errorf("bad limit %v: %d", bad, rr.Code)
		}
	}
	if rr := b.post(t, "/admin/settings", form(url.Values{"c": {"Germany"}})); rr.Code != http.StatusSeeOther || !strings.Contains(flashOf(t, b, "/admin/settings"), "country") {
		t.Errorf("bad country: %d", r.Code)
	}

	// Users: create (shown once), role, disable.
	r = b.post(t, "/admin/users/new", url.Values{"csrf_token": {token}, "username": {"carol"}, "password": {"a long password for the new colleague"}, "role": {"operator"}, "scope": {"issuing"}})
	if r.Code != http.StatusOK || !strings.Contains(r.html(), "otpauth://") || r.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("new user: %d %s", r.Code, r.html())
	}
	carol := "/admin/users/" + v.UserID(t, "carol")
	if rr := b.post(t, carol+"/roles", url.Values{"csrf_token": {token}, "role": {"viewer"}, "scope": {""}}); rr.Code != http.StatusSeeOther || !strings.Contains(flashOf(t, b, carol), "Role given") {
		t.Errorf("give role: %d", r.Code)
	}
	if rr := b.post(t, carol+"/disable", url.Values{"csrf_token": {token}}); rr.Code != http.StatusSeeOther || !strings.Contains(b.get(t, carol).html(), "disabled") {
		t.Errorf("disable: %d", r.Code)
	}

	// Own account: a token (shown once) and its revocation.
	r = b.post(t, "/account/tokens", url.Values{"csrf_token": {token}, "name": {"backup-job"}, "role": {"viewer"}, "scope": {""}, "days": {"30"}})
	if r.Code != http.StatusOK || !strings.Contains(r.html(), "mop_") {
		t.Fatalf("new token: %d %s", r.Code, flashOf(t, b, "/account"))
	}
	if !strings.Contains(b.get(t, "/account").html(), "backup-job") {
		t.Error("the token is not listed")
	}

	// Audit: the instance log shows the user creation.
	v.Deliver(t)
	if page := b.get(t, "/admin/audit?scope=instance&action=user.create").html(); !strings.Contains(page, "user.create") {
		t.Errorf("audit page lacks user.create")
	}

	// Legacy import over the page: the fixture's CA names exist here, so the
	// dry run is refused with a report.
	fx := legacytest.Write(t, filepath.Join(t.TempDir(), "pki"), v.Clock.Now())
	r = b.postFile(t, "/admin/import", url.Values{"csrf_token": {token}, "dry_run": {"yes"}, "root_key": {"offline"}}, "archive", "pki.tar.gz", tarGz(t, fx.Dir))
	if r.Code != http.StatusSeeOther || !strings.HasPrefix(r.location(), "/admin/import/imp_") {
		t.Fatalf("import: %d %q %s", r.Code, r.location(), flashOf(t, b, "/admin/import"))
	}
	if page := b.get(t, r.location()).html(); !strings.Contains(page, "refused") || !strings.Contains(page, "exists already") {
		t.Errorf("import report:\n%s", page)
	}
}

// tarGz packs a directory with its name as the top folder.
func tarGz(t *testing.T, dir string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, werr error) error {
		if werr != nil {
			return werr
		}
		rel, _ := filepath.Rel(filepath.Dir(dir), p)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			return tw.WriteHeader(&tar.Header{Name: rel + "/", Typeflag: tar.TypeDir, Mode: 0o700})
		}
		body, rerr := os.ReadFile(p) // #nosec G304 G122 -- the test's own fixture in a temp dir
		if rerr != nil {
			return rerr
		}
		if herr := tw.WriteHeader(&tar.Header{Name: rel, Typeflag: tar.TypeReg, Mode: 0o600, Size: int64(len(body))}); herr != nil {
			return herr
		}
		_, werr = tw.Write(body)
		return werr
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = tw.Close()
	_ = zw.Close()
	return buf.Bytes()
}

func TestDomainFormOffersOnlyServerAuthCAs(t *testing.T) {
	t.Parallel()
	v := newUIEnv(t)
	v.Unseal(t)
	if _, err := v.Engine.CreateIntermediate(t.Context(), ca.IntermediateRequest{
		CASettings: ca.CASettings{Name: "agent-ca", BaseURL: "http://pki.homelab.lan"}, Parent: "root",
		Subject: ca.Subject{CommonName: "Agent CA"}, EKULimit: []string{"clientAuth"}, Who: testinstance.Console,
	}); err != nil {
		t.Fatal(err)
	}
	b := v.browser("192.0.2.1")
	b.signIn(t, "demo", v.DemoPassword)
	assertChoices := func(page string) {
		t.Helper()
		if !strings.Contains(page, `value=""`) || !strings.Contains(page, `value="issuing"`) {
			t.Errorf("domain form has no neutral placeholder or valid CA: %s", page)
		}
		if strings.Contains(page, `value="agent-ca"`) {
			t.Error("domain form offers a clientAuth-only CA")
		}
	}
	newPage := b.get(t, "/domains/new").html()
	assertChoices(newPage)
	if !strings.Contains(newPage, `value="" selected>Please select</option>`) {
		t.Error("new domain preselects a CA instead of asking for a choice")
	}

	form := url.Values{"csrf_token": {b.csrf(t)}, "name": {"agent-only.lan"}, "ca": {"agent-ca"}, "subdomains": {"yes"}, "http01": {"yes"},
		"approval": {"open"}, "preset": {"server"}, "address": {"internal"}}
	r := b.post(t, "/domains", form)
	if r.Code != http.StatusSeeOther || !strings.Contains(flashOf(t, b, "/domains/new"), "does not allow serverAuth required by preset") {
		t.Errorf("web refusal does not explain serverAuth: %d", r.Code)
	}
	issuing := "issuing"
	domain, err := v.Engine.CreateDomain(t.Context(), ca.DomainRequest{Name: "homelab.lan", DomainSettings: ca.DomainSettings{CA: &issuing}, Who: testinstance.Console})
	if err != nil {
		t.Fatal(err)
	}
	editPage := b.get(t, "/domains/"+domain.ID).html()
	assertChoices(editPage)
	if !strings.Contains(editPage, `value="issuing" selected>issuing</option>`) {
		t.Error("edit domain does not keep its current CA selected")
	}
}

// TestDomainPages (PHASE2 step 1): create, change, a refused change and the
// deletion through the forms; viewers see the list without commands.
func TestDomainPages(t *testing.T) {
	t.Parallel()
	v := newUIEnv(t)
	v.Unseal(t)
	b := v.browser("192.0.2.1")
	b.signIn(t, "demo", v.DemoPassword)
	token := b.csrf(t)
	form := url.Values{"csrf_token": {token}, "name": {"homelab.lan"}, "ca": {"issuing"}, "subdomains": {"yes"}, "http01": {"yes"},
		"approval": {"open"}, "preset": {"server"}, "address": {"internal"}}
	r := b.post(t, "/domains", form)
	if r.Code != http.StatusSeeOther || !strings.HasPrefix(r.location(), "/domains/dom_") {
		t.Fatalf("create: %d %q", r.Code, r.location())
	}
	detail := r.location()
	if got := b.get(t, detail).html(); !strings.Contains(got, "homelab.lan") || !strings.Contains(got, "open – any account") {
		t.Errorf("detail:\n%s", got)
	}
	// Wildcards without dns-01: refused, with the reason on the page.
	form.Del("name")
	form.Set("wildcards", "yes")
	if rr := b.post(t, detail, form); rr.Code != http.StatusSeeOther || !strings.Contains(flashOf(t, b, rr.location()), "dns-01") {
		t.Errorf("refused change: %d", rr.Code)
	}
	form.Set("dns01", "yes")
	if rr := b.post(t, detail, form); rr.Code != http.StatusSeeOther || !strings.Contains(flashOf(t, b, detail), "saved") {
		t.Errorf("change: %d", rr.Code)
	}
	if got := b.get(t, "/domains").html(); !strings.Contains(got, "http-01, dns-01") || !strings.Contains(got, "New domain") {
		t.Errorf("list:\n%s", got)
	}
	v.User(t, "viewer", false, authz.Binding{Tenant: "default", Role: authz.Viewer})
	vb := v.browser("192.0.2.2")
	vb.signIn(t, "viewer", testinstance.Password)
	if got := vb.get(t, "/domains").html(); !strings.Contains(got, "homelab.lan") || strings.Contains(got, "New domain") {
		t.Errorf("viewer list:\n%s", got)
	}
	if got := vb.get(t, detail).html(); strings.Contains(got, "Delete domain") {
		t.Error("the viewer is offered the deletion")
	}
	if rr := b.post(t, detail+"/delete", url.Values{"csrf_token": {token}}); rr.Code != http.StatusSeeOther || rr.location() != "/domains" {
		t.Errorf("delete: %d %q", rr.Code, rr.location())
	}
}
