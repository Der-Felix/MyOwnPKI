package web

import (
	"bytes"
	"html"
	"maps"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/Der-Felix/MyOwnPKI/internal/testinstance"
	"github.com/Der-Felix/MyOwnPKI/internal/trustkit"
	"github.com/Der-Felix/MyOwnPKI/internal/web/pages/authorities"
	"github.com/Der-Felix/MyOwnPKI/internal/web/view"
)

const portalFingerprint = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// TestPortalRow: a usable base URL gives the portal address (the base URL plus
// "/") and the message; a switched-off portal, an empty or hostile base URL
// and a certificate that is not signed yet give a hint and no address.
func TestPortalRow(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, base, fingerprint string
		enabled                 bool
		row                     string // exact row, or "" = a hint without an address
		message                 bool
		hint                    string
	}{
		{name: "plain", base: "http://pki.homelab.lan", fingerprint: portalFingerprint, enabled: true, row: "http://pki.homelab.lan/", message: true},
		{name: "trailing slash", base: "http://pki.homelab.lan/", fingerprint: portalFingerprint, enabled: true, row: "http://pki.homelab.lan/", message: true},
		{name: "port and path", base: "https://pki.homelab.lan:8443/pki", fingerprint: portalFingerprint, enabled: true, row: "https://pki.homelab.lan:8443/pki/", message: true},
		{name: "not signed yet", base: "http://pki.homelab.lan", enabled: true, row: "http://pki.homelab.lan/"},
		{name: "switched off", base: "http://pki.homelab.lan", fingerprint: portalFingerprint, hint: portalOff},
		{name: "empty", base: "", fingerprint: portalFingerprint, enabled: true, hint: "No address"},
		{name: "javascript", base: "javascript:alert(1)", fingerprint: portalFingerprint, enabled: true, hint: "No address"},
		{name: "quote", base: `http://pki.homelab.lan/"><script>alert(1)</script>`, fingerprint: portalFingerprint, enabled: true, hint: "No address"},
		{name: "user info", base: "http://user@pki.homelab.lan", fingerprint: portalFingerprint, enabled: true, hint: "No address"},
		{name: "query", base: "http://pki.homelab.lan/?x=1", fingerprint: portalFingerprint, enabled: true, hint: "No address"},
		{name: "space", base: "http://pki.homelab.lan/a b", fingerprint: portalFingerprint, enabled: true, hint: "No address"},
		{name: "percent", base: "http://pki.homelab.lan/%2e%2e", fingerprint: portalFingerprint, enabled: true, hint: "No address"},
		{name: "ftp", base: "ftp://pki.homelab.lan", fingerprint: portalFingerprint, enabled: true, hint: "No address"},
		{name: "unicode", base: "http://pki.hömelab.lan", fingerprint: portalFingerprint, enabled: true, hint: "No address"},
		{name: "off and hostile", base: `http://x/"><script>`, fingerprint: portalFingerprint, hint: portalOff},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			row, message := portal("root", tc.base, tc.fingerprint, tc.enabled)
			if tc.row != "" && row != tc.row {
				t.Errorf("row = %q, want %q", row, tc.row)
			}
			if tc.hint != "" && !strings.HasPrefix(row, tc.hint) {
				t.Errorf("row = %q, want the hint %q", row, tc.hint)
			}
			if tc.hint != "" && tc.base != "" && strings.Contains(row, tc.base) {
				t.Errorf("the hint %q repeats the base URL", row)
			}
			if (message != "") != tc.message {
				t.Errorf("message present = %v, want %v:\n%s", message != "", tc.message, message)
			}
			if tc.hint != "" && strings.Contains(message, "<") {
				t.Errorf("a message was built from a rejected base URL: %q", message)
			}
		})
	}
}

// TestUserMessage pins the text: the address, the root's name, the SHA-256 in
// the colon form of the certificate dialogs, the sentence to compare it and the
// second step on an iPhone. It never claims a transport protection.
func TestUserMessage(t *testing.T) {
	t.Parallel()
	_, message := portal("lab-root", "http://pki.homelab.lan", portalFingerprint, true)
	for _, want := range []string{
		`our root certificate "lab-root"`,
		"Open this address in your browser: http://pki.homelab.lan/\n",
		"before you install anything; if they differ, stop and tell us.",
		view.Fingerprint(trustkit.ColonHex(portalFingerprint)),
		"Certificate Trust Settings",
	} {
		if !strings.Contains(message, want) {
			t.Errorf("the message lacks %q:\n%s", want, message)
		}
	}
	lower := strings.ToLower(message)
	for _, bad := range []string{"secure", "encrypt", "trusted connection", "https"} {
		if strings.Contains(lower, bad) {
			t.Errorf("the message says %q", bad)
		}
	}
}

// TestPortalBlockEscapes: the message is text, whatever it holds.
func TestPortalBlockEscapes(t *testing.T) {
	t.Parallel()
	const payload = `<script>alert(1)</script><img src=x onerror=alert(2)>"'&`
	d := authorities.DetailData{
		ID: payload, Name: payload, Status: view.StatusOK, StatusText: payload,
		Properties:  []view.KV{{Key: "Trust portal", Value: payload}},
		UserMessage: userMessage(payload, payload, portalFingerprint),
	}
	var buf bytes.Buffer
	if err := authorities.Detail(view.Page{Title: payload}, d).Render(t.Context(), &buf); err != nil {
		t.Fatal(err)
	}
	page := buf.String()
	for _, bad := range []string{"<script", "<img src=x", "onerror=alert(2)>", "alert(1)</script>"} {
		if strings.Contains(strings.ToLower(page), bad) {
			t.Errorf("the page contains %q unescaped", bad)
		}
	}
	if !strings.Contains(page, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Error("the payload should appear as escaped text")
	}
	if !strings.Contains(page, `<pre class="pem">`) || !strings.Contains(page, "Message for your users") {
		t.Error("the block is not a pre with its heading")
	}
	if strings.Contains(page, " style=") || strings.Contains(page, "<script") || strings.Contains(page, "<button") && strings.Contains(page, "clipboard") {
		t.Error("inline style, script or a copy button")
	}
}

// TestRootPagePortal: the real root page shows the portal address, the message
// with the root's SHA-256, follows the tenant setting, and an intermediate shows
// neither. The permission to open the page is the one of the authority pages.
func TestRootPagePortal(t *testing.T) {
	t.Parallel()
	v := newUIEnv(t)
	b := v.browser("192.0.2.1")
	b.signIn(t, "demo", v.DemoPassword)
	chain, err := v.Engine.CAChain(t.Context(), testinstance.Console, v.CAIDs["issuing"])
	if err != nil {
		t.Fatal(err)
	}
	rootFP := view.Fingerprint(trustkit.ColonHex(trustkit.SHA256Hex(chain[len(chain)-1])))

	root := b.get(t, "/authorities/"+v.CAIDs["root"])
	if root.Code != http.StatusOK {
		t.Fatalf("root page: %d", root.Code)
	}
	text := html.UnescapeString(root.html())
	for _, want := range []string{
		"<dt>Trust portal</dt>", "http://pki.homelab.lan/",
		"Message for your users", `<pre class="pem">`,
		"Open this address in your browser: http://pki.homelab.lan/\n", rootFP,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("root page lacks %q", want)
		}
	}
	if strings.Contains(text, "Switched off in Administration") {
		t.Error("the portal is on by default but the page says it is off")
	}

	inter := b.get(t, "/authorities/"+v.CAIDs["issuing"]).html()
	if strings.Contains(inter, "Trust portal") || strings.Contains(inter, "Message for your users") {
		t.Error("an intermediate shows the portal or the message")
	}

	// Switched off: the row says where to switch it on, no block, no address.
	token := b.csrf(t)
	limits := url.Values{"csrf_token": {token}, "acme_orders": {"120"}, "acme_failed": {"4"}, "acme_accounts": {"8"},
		"agent_predecessor": {"now"}, "other_predecessor": {"after"}, "other_predecessor_days": {"7"}}
	if r := b.post(t, "/admin/settings", limits); r.Code != http.StatusSeeOther {
		t.Fatalf("switch the portal off: %d", r.Code)
	}
	off := html.UnescapeString(b.get(t, "/authorities/"+v.CAIDs["root"]).html())
	if !strings.Contains(off, "Switched off in Administration → Tenant settings.") {
		t.Error("the root page does not say the portal is switched off")
	}
	if strings.Contains(off, "Message for your users") || strings.Contains(off, "Open this address in your browser") {
		t.Error("the message is shown while the portal is off")
	}

	// On again.
	on := url.Values{"trust_page": {"yes"}}
	maps.Copy(on, limits)
	if r := b.post(t, "/admin/settings", on); r.Code != http.StatusSeeOther {
		t.Fatalf("switch the portal on: %d", r.Code)
	}
	if !strings.Contains(b.get(t, "/authorities/"+v.CAIDs["root"]).html(), "Message for your users") {
		t.Error("no message after the portal is switched on again")
	}
}

// TestSettingsPageNamesThePortal: the label and the help text of the setting
// say "portal" and list what it covers; the page promises no protection.
func TestSettingsPageNamesThePortal(t *testing.T) {
	t.Parallel()
	v := newUIEnv(t)
	b := v.browser("192.0.2.1")
	b.signIn(t, "demo", v.DemoPassword)
	page := b.get(t, "/admin/settings").html()
	for _, want := range []string{`name="trust_page"`, "Trust portal at / of the public listener", "its ?os= choice", "configuration profile", "Windows helpers", "/ca/ and /crl/ stay served"} {
		if !strings.Contains(html.UnescapeString(page), want) {
			t.Errorf("the settings page lacks %q", want)
		}
	}
	if strings.Contains(page, "Public trust page") {
		t.Error("the old label is still there")
	}
	lower := strings.ToLower(page)
	for _, bad := range []string{"https", "secure", "encrypted"} {
		for _, line := range strings.Split(lower, "\n") {
			if strings.Contains(line, "trust portal") && strings.Contains(line, bad) {
				t.Errorf("the setting says %q: %s", bad, line)
			}
		}
	}
}
