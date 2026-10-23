package web

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Der-Felix/MyOwnPKI/internal/acme"
	"github.com/Der-Felix/MyOwnPKI/internal/audit"
	"github.com/Der-Felix/MyOwnPKI/internal/auth"
	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/ca/legacy"
	"github.com/Der-Felix/MyOwnPKI/internal/ca/preset"
	"github.com/Der-Felix/MyOwnPKI/internal/clock"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/tenant"
	"github.com/Der-Felix/MyOwnPKI/internal/web/pages/notice"
	"github.com/Der-Felix/MyOwnPKI/internal/web/view"
)

// The real UI (PHASE1 step 14): the same pages as the prototype, fed from
// the services – the same ones the REST API calls, with the same permission
// checks in the service layer. Rules of the owner (2026-10-17):
//   - every POST form ends with 303 See Other on a GET page (Post/Redirect/
//     Get), so a reload never repeats an action; only the private key
//     download answers with the file itself;
//   - messages travel to the next page in a short-lived cookie, never in the
//     URL;
//   - next= is a local path only, everything else goes to the dashboard;
//   - before sign-in nothing about the instance is shown.

// AppDeps are the services of the real UI.
type AppDeps struct {
	Auth    *auth.Service
	Engine  *ca.Engine
	Keys    *keys.Keyring
	Presets *preset.Set
	Clock   clock.Clock
	// TrustedProxies may set X-Forwarded-For (auth.trusted_proxies).
	TrustedProxies []netip.Prefix
	Demo           bool
	Tenant         string // the tenant of this instance (phase 1: one)
	// Settings, TenantAudit and InstanceAudit serve the pages of step 19
	// (tenant settings, audit log); nil hides those pages.
	Settings                   *tenant.Store
	TenantAudit, InstanceAudit *sql.DB
	// ACME is the ACME server (PHASE2); nil while ACME is off.
	ACME ACMEAdmin
	// ACMEDirectory is the directory URL clients use (shown with EAB keys).
	ACMEDirectory string
	// TLSAttention reports the certificates the server issues itself for its
	// listeners (admin.tls_issuer, acme.tls_issuer) for the dashboard; nil
	// when there are none.
	TLSAttention func(sealed bool) []view.Message
}

// ACMEAdmin is what the UI uses of the ACME server.
type ACMEAdmin interface {
	// Waiting counts orders whose certificate waits for the unseal.
	Waiting(ctx context.Context) (int64, error)
	// Pending counts accounts and names that wait for an admin.
	Pending(ctx context.Context) (accounts, names int64, err error)
	Accounts(ctx context.Context, who keys.Who) ([]acme.AccountInfo, error)
	Account(ctx context.Context, who keys.Who, id string) (*acme.AccountInfo, error)
	ApproveAccount(ctx context.Context, id string, who keys.Who) error
	Names(ctx context.Context, who keys.Who) ([]acme.NameInfo, error)
	DecideName(ctx context.Context, name string, approve bool, who keys.Who) error
	Orders(ctx context.Context, who keys.Who) ([]acme.OrderInfo, error)
	EABKeys(ctx context.Context, who keys.Who) ([]acme.EABKeyInfo, error)
	CreateEABKey(ctx context.Context, label string, days int, who keys.Who) (*acme.NewEABKey, error)
}

// maxUIForm limits form bodies; a CSR upload is at most 64 KiB.
const (
	maxUIForm  = 256 << 10
	maxCSRFile = 64 << 10
)

type app struct {
	d   AppDeps
	log *slog.Logger
}

func registerApp(mux *http.ServeMux, d AppDeps, log *slog.Logger) {
	if d.Clock == nil {
		d.Clock = clock.System{}
	}
	a := &app{d: d, log: log}
	mux.HandleFunc("GET /login", a.anon(a.loginPage))
	mux.HandleFunc("POST /login", a.anon(a.login))
	mux.HandleFunc("GET /login/code", a.anon(a.codePage))
	mux.HandleFunc("POST /login/code", a.anon(a.code))
	mux.HandleFunc("POST /logout", a.signedIn(a.logout))
	mux.HandleFunc("GET /unseal", a.signedIn(a.unsealPage))
	mux.HandleFunc("POST /unseal", a.signedIn(a.unseal))
	mux.HandleFunc("POST /seal", a.signedIn(a.seal))
	mux.HandleFunc("GET /step-up", a.signedIn(a.stepUpPage))
	mux.HandleFunc("POST /step-up", a.signedIn(a.stepUp))

	mux.HandleFunc("GET /{$}", a.signedIn(a.dashboard))
	mux.HandleFunc("GET /certificates", a.signedIn(a.certificateList))
	mux.HandleFunc("GET /certificates/new", a.signedIn(a.issueStart))
	mux.HandleFunc("POST /certificates/new", a.signedIn(a.issueStep))
	mux.HandleFunc("GET /certificates/{id}", a.signedIn(a.certificateDetail))
	mux.HandleFunc("GET /certificates/{id}/{tab}", a.signedIn(a.certificateDetail))
	mux.HandleFunc("GET /certificates/{id}/download/{format}", a.signedIn(a.certificateDownload))
	mux.HandleFunc("POST /certificates/{id}/key", a.signedIn(a.keyDownload))
	mux.HandleFunc("GET /certificates/{id}/revoke", a.signedIn(a.revokePage))
	mux.HandleFunc("POST /certificates/{id}/revoke", a.signedIn(a.revoke))
	mux.HandleFunc("GET /certificates/{id}/renew", a.signedIn(a.renewPage))
	mux.HandleFunc("POST /certificates/{id}/renew", a.signedIn(a.renew))
	mux.HandleFunc("GET /certificates/{id}/export", a.signedIn(a.exportPage))
	mux.HandleFunc("POST /certificates/{id}/export", a.signedIn(a.export))
	mux.HandleFunc("GET /authorities", a.signedIn(a.authorityList))
	mux.HandleFunc("GET /authorities/{id}", a.signedIn(a.authorityDetail))
	mux.HandleFunc("GET /authorities/new", a.signedIn(a.newCAPage))
	mux.HandleFunc("POST /authorities/new", a.signedIn(a.newCA))
	mux.HandleFunc("GET /authorities/import", a.signedIn(a.importRootPage))
	mux.HandleFunc("POST /authorities/import", a.signedIn(a.importRoot))
	mux.HandleFunc("GET /authorities/{id}/certificate", a.signedIn(a.authorityCertificate))
	mux.HandleFunc("POST /authorities/{id}/certificate", a.signedIn(a.installCertificate))
	mux.HandleFunc("GET /authorities/{id}/offline", a.signedIn(a.offlinePage))
	mux.HandleFunc("GET /authorities/{id}/manage", a.signedIn(a.managePage))
	mux.HandleFunc("POST /authorities/{id}/limits", a.signedIn(a.caLimits))
	mux.HandleFunc("POST /authorities/{id}/crl", a.signedIn(a.caSignCRL))
	mux.HandleFunc("POST /authorities/{id}/crl-upload", a.signedIn(a.caUploadCRL))
	mux.HandleFunc("POST /authorities/{id}/renew", a.signedIn(a.caRenew))
	mux.HandleFunc("POST /authorities/{id}/retire", a.signedIn(a.caRetire))
	mux.HandleFunc("POST /authorities/{id}/revoke", a.signedIn(a.caRevoke))
	mux.HandleFunc("GET /domains", a.signedIn(a.domainList))
	mux.HandleFunc("GET /domains/new", a.signedIn(a.domainNew))
	mux.HandleFunc("POST /domains", a.signedIn(a.domainCreate))
	mux.HandleFunc("GET /domains/{id}", a.signedIn(a.domainDetail))
	mux.HandleFunc("POST /domains/{id}", a.signedIn(a.domainUpdate))
	mux.HandleFunc("POST /domains/{id}/delete", a.signedIn(a.domainDelete))
	mux.HandleFunc("GET /acme/accounts", a.signedIn(a.acmeAccounts))
	mux.HandleFunc("GET /acme/accounts/{id}", a.signedIn(a.acmeAccount))
	mux.HandleFunc("POST /acme/accounts/approve", a.signedIn(a.acmeApprove))
	mux.HandleFunc("GET /acme/names", a.signedIn(a.acmeNames))
	mux.HandleFunc("POST /acme/names/decide", a.signedIn(a.acmeDecide))
	mux.HandleFunc("GET /acme/eab", a.signedIn(a.acmeEAB))
	mux.HandleFunc("POST /acme/eab", a.signedIn(a.acmeEABCreate))
	mux.HandleFunc("GET /acme/orders", a.signedIn(a.acmeOrders))
	mux.HandleFunc("GET /presets", a.signedIn(a.presetList))
	mux.HandleFunc("GET /presets/{name}", a.signedIn(a.presetDetail))
	mux.HandleFunc("GET /admin/users", a.signedIn(a.userList))
	mux.HandleFunc("GET /admin/users/new", a.signedIn(a.newUserPage))
	mux.HandleFunc("POST /admin/users/new", a.signedIn(a.newUser))
	mux.HandleFunc("GET /admin/users/{id}", a.signedIn(a.userDetail))
	mux.HandleFunc("POST /admin/users/{id}/roles", a.signedIn(a.userGiveRole))
	mux.HandleFunc("POST /admin/users/{id}/roles/remove", a.signedIn(a.userRemoveRole))
	mux.HandleFunc("POST /admin/users/{id}/disable", a.signedIn(a.userDisable))
	mux.HandleFunc("POST /admin/users/{id}/enable", a.signedIn(a.userEnable))
	mux.HandleFunc("POST /admin/users/{id}/unlock", a.signedIn(a.userUnlock))
	mux.HandleFunc("GET /admin/settings", a.signedIn(a.settingsPage))
	mux.HandleFunc("POST /admin/settings", a.signedIn(a.saveSettings))
	mux.HandleFunc("GET /admin/audit", a.signedIn(a.auditLog))
	mux.HandleFunc("GET /admin/import", a.signedIn(a.importPage))
	mux.HandleFunc("POST /admin/import", a.signedIn(a.runImport))
	mux.HandleFunc("GET /admin/import/{id}", a.signedIn(a.importReport))
	mux.HandleFunc("GET /account", a.signedIn(a.accountPage))
	mux.HandleFunc("POST /account/password", a.signedIn(a.changePassword))
	mux.HandleFunc("POST /account/totp", a.signedIn(a.startTOTP))
	mux.HandleFunc("POST /account/totp/confirm", a.signedIn(a.confirmTOTP))
	mux.HandleFunc("POST /account/recovery-codes", a.signedIn(a.newCodes))
	mux.HandleFunc("POST /account/tokens", a.signedIn(a.createToken))
	mux.HandleFunc("POST /account/tokens/{id}/revoke", a.signedIn(a.revokeToken))
	mux.HandleFunc("POST /account/passkeys/{id}/remove", a.signedIn(a.removePasskey))
	mux.HandleFunc("GET /admin/appearance", a.signedIn(a.appearance))
	mux.HandleFunc("POST /admin/appearance", a.signedIn(a.saveAppearance))
	mux.HandleFunc("GET /design", a.signedIn(a.design))
}

// rc is one request of the real UI.
type rc struct {
	w      http.ResponseWriter
	r      *http.Request
	a      *app
	client auth.Client
	token  string        // the session cookie value
	sess   *auth.Session // nil before sign-in
	flash  []view.Message
}

func (a *app) newRC(w http.ResponseWriter, r *http.Request) *rc {
	c := &rc{w: w, r: r, a: a}
	c.client = auth.Client{IP: auth.ClientIP(r, a.d.TrustedProxies).String()}
	if ck, err := r.Cookie(auth.DeviceCookieName); err == nil {
		c.client.Device = ck.Value
	}
	if ck, err := r.Cookie(auth.CookieName); err == nil {
		c.token = ck.Value
	}
	c.flash = readFlash(w, r)
	return c
}

// who is the caller as the services want it.
func (c *rc) who() keys.Who {
	w := keys.Who{SourceIP: c.client.IP}
	if c.sess != nil {
		w.Actor = audit.Actor{Type: audit.ActorUser, ID: c.sess.UserID, Name: c.sess.Username}
		w.Principal = c.sess.Principal
	}
	return w
}

// may reports whether the session holds perm on CA name; a missing step-up
// still counts – it is asked for when the action runs. Only for offering
// commands: the services decide.
func (c *rc) may(perm authz.Permission, caName string) bool {
	if c.sess == nil {
		return false
	}
	err := c.sess.Principal.Check(perm, authz.Resource{Tenant: c.a.d.Tenant, CA: caName}, c.a.d.Clock.Now())
	return err == nil || errors.Is(err, authz.ErrStepUpRequired)
}

func (c *rc) instanceAdmin() bool { return c.sess != nil && c.sess.Principal.InstanceAdmin }

// anon serves the sign-in pages: no session needed.
func (a *app) anon(h func(*rc)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c := a.newRC(w, r)
		if r.Method == http.MethodPost && !c.parseForm(8<<10) {
			return
		}
		h(c)
	}
}

// signedIn serves pages that need a full session. Without one a GET goes to
// the sign-in page and comes back afterwards; a POST additionally needs the
// session's CSRF token.
func (a *app) signedIn(h func(*rc)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c := a.newRC(w, r)
		sess, err := a.d.Auth.Authenticate(r.Context(), c.token)
		if err != nil {
			if !errors.Is(err, auth.ErrNoSession) {
				a.log.ErrorContext(r.Context(), "authenticate", slog.Any("error", err))
			}
			if c.token != "" {
				c.setFlash(view.Message{Kind: view.MessageInfo, Text: "Your session has ended – please sign in again."})
			}
			next := ""
			if r.Method == http.MethodGet {
				next = r.URL.RequestURI()
			}
			c.redirect(loginURL("/login", next))
			return
		}
		c.sess = sess
		if r.Method == http.MethodPost {
			limit := int64(maxUIForm)
			if r.URL.Path == "/admin/import" {
				limit = legacy.MaxArchive + 1<<20 // the pki.sh archive (step 19)
			}
			if !c.parseForm(limit) {
				return
			}
			if !auth.SameCSRFToken(r.PostFormValue(auth.CSRFField), sess.CSRFToken) {
				c.notice(http.StatusForbidden, "Refused", view.Message{Kind: view.MessageError, Text: auth.ErrCSRF.Error()})
				return
			}
		}
		h(c)
	}
}

// parseForm reads a urlencoded or multipart body up to limit bytes.
func (c *rc) parseForm(limit int64) bool {
	c.r.Body = http.MaxBytesReader(c.w, c.r.Body, limit)
	var err error
	if strings.HasPrefix(c.r.Header.Get("Content-Type"), "multipart/form-data") {
		err = c.r.ParseMultipartForm(limit) // #nosec G120 -- the body is limited by MaxBytesReader above
	} else {
		err = c.r.ParseForm() // #nosec G120 -- the body is limited by MaxBytesReader above
	}
	if err != nil {
		http.Error(c.w, "invalid form", http.StatusBadRequest)
		return false
	}
	return true
}

// redirect ends a POST (or a refused GET) with 303 See Other.
func (c *rc) redirect(target string) {
	http.Redirect(c.w, c.r, target, http.StatusSeeOther) // #nosec G710 -- targets are fixed paths or passed safeNext
}

func loginURL(path, next string) string {
	if next = safeNext(next); next == "/" {
		return path
	}
	return path + "?" + url.Values{"next": {next}}.Encode()
}

// safeNext returns next if it is a local path, else "/" (owner 2026-10-17).
// Refused: anything that doesn't start with exactly one "/" ("//evil",
// "https://…", "javascript:…"), backslashes ("/\evil" – browsers read it as
// "//"), an encoded "//" ("/%2F%2Fevil", decoded by some proxies) and control
// characters, also encoded ones.
func safeNext(next string) string {
	const home = "/"
	if next == "" || len(next) > 2048 || !utf8.ValidString(next) {
		return home
	}
	if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") || strings.ContainsRune(next, '\\') {
		return home
	}
	for _, r := range next {
		if r < 0x20 || r == 0x7f {
			return home
		}
	}
	u, err := url.Parse(next)
	if err != nil || u.Scheme != "" || u.Host != "" || u.Opaque != "" || u.User != nil {
		return home
	}
	// The decoded path: no "//" anywhere and no dot segments ("/./", "/../"):
	// a proxy or browser that decodes or normalizes must not make "//evil".
	if strings.Contains(u.Path, "//") || strings.ContainsRune(u.Path, '\\') || strings.HasPrefix(u.Path, "/login") {
		return home
	}
	for seg := range strings.SplitSeq(u.Path, "/") {
		if seg == "." || seg == ".." {
			return home
		}
	}
	for _, r := range u.Path {
		if r < 0x20 || r == 0x7f {
			return home
		}
	}
	return next
}

// ---------------------------------------------------------------- flash

// flashCookie carries messages to the next page – never in the URL, so no
// text from a link ever reaches a page. __Host-: only this host sets it.
const flashCookie = "__Host-myownpki_flash"

func (c *rc) setFlash(msgs ...view.Message) {
	data, err := json.Marshal(msgs)
	if err != nil || len(data) > 3000 {
		data, _ = json.Marshal(msgs[:1])
	}
	http.SetCookie(c.w, &http.Cookie{
		Name: flashCookie, Value: base64.RawURLEncoding.EncodeToString(data), Path: "/", MaxAge: 60,
		Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode,
	})
}

// readFlash takes the messages of the previous request and clears them.
func readFlash(w http.ResponseWriter, r *http.Request) []view.Message {
	ck, err := r.Cookie(flashCookie)
	if err != nil {
		return nil
	}
	http.SetCookie(w, &http.Cookie{Name: flashCookie, Value: "", Path: "/", MaxAge: -1, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	data, err := base64.RawURLEncoding.DecodeString(ck.Value)
	if err != nil {
		return nil
	}
	var msgs []view.Message
	if json.Unmarshal(data, &msgs) != nil {
		return nil
	}
	kinds := []view.MessageKind{view.MessageInfo, view.MessageSuccess, view.MessageWarning, view.MessageError}
	out := msgs[:0]
	for _, m := range msgs {
		if slices.Contains(kinds, m.Kind) && len(m.Text) <= 1000 {
			if m.Href != "" && safeNext(m.Href) != m.Href {
				m.Href, m.LinkText = "", ""
			}
			out = append(out, m)
		}
	}
	return out
}

// ---------------------------------------------------------------- pages

// page builds the shell of a signed-in page: the session's user, the demo
// and seal notices, only built navigation entries.
func (c *rc) page(title, section string, crumbs ...view.Crumb) view.Page {
	if section != "dashboard" {
		crumbs = append([]view.Crumb{{Label: "Dashboard", Href: "/"}}, crumbs...)
	}
	p := view.Page{
		Title: title, Section: section, Crumbs: crumbs, Prefs: view.PrefsFromRequest(c.r),
		Tenant: c.a.d.Tenant, Tenants: []string{c.a.d.Tenant}, BuiltOnly: true,
	}
	if c.sess == nil {
		return p
	}
	p.User = c.sess.Username
	p.Session = &view.Session{Username: c.sess.Username, Roles: rolesText(c.sess.Principal), CSRF: c.sess.CSRFToken, CanSeal: c.instanceAdmin()}
	if cas, err := c.a.issuableCAs(c); err == nil && len(cas) > 0 {
		p.Session.CanIssue = true
	}
	if !c.instanceAdmin() {
		p.Session.Hidden = append(p.Session.Hidden, "users")
	}
	if !c.may(authz.ReadAudit, "") {
		p.Session.Hidden = append(p.Session.Hidden, "audit")
	}
	if !c.may(authz.ManageCA, "") {
		p.Session.Hidden = append(p.Session.Hidden, "import")
	}
	if !c.may(authz.ReadPKI, "") && !c.may(authz.ManageTenant, "") {
		p.Session.Hidden = append(p.Session.Hidden, "settings")
	}
	if c.a.d.Demo {
		p.Notices = append(p.Notices, view.Message{Kind: view.MessageWarning, Text: "DEMO instance – all secrets are in one file, do not use it in production."})
	}
	if st := c.a.d.Keys.Status(); st.Sealed {
		m := view.Message{Kind: view.MessageWarning, Text: "Signing is off: the server is sealed since " + view.DateTime(st.SealedSince) + "."}
		if c.instanceAdmin() {
			m.Href, m.LinkText = "/unseal", "Unseal"
		} else {
			m.Text += " An instance admin must unseal it."
		}
		p.Notices = append(p.Notices, m)
	}
	return p
}

// rolesText describes the roles for the user menu.
func rolesText(p *authz.Principal) string {
	if p == nil {
		return ""
	}
	var parts []string
	if p.InstanceAdmin {
		parts = append(parts, "instance admin")
	}
	for _, b := range p.Bindings {
		where := "tenant " + b.Tenant
		if b.CA != "" {
			where = "CA " + b.CA
		}
		parts = append(parts, string(b.Role)+" of "+where)
	}
	if len(parts) == 0 {
		return "no roles"
	}
	return strings.Join(parts, ", ")
}

// notice renders a page that only says something (404, 403, …).
func (c *rc) notice(status int, title string, msgs ...view.Message) {
	render(c.w, c.r, c.a.log, status, notice.Page(c.page(title, ""), msgs))
}

// fail answers a service error on a GET page.
func (c *rc) fail(err error) {
	var denied *ca.DeniedError
	switch {
	case errors.Is(err, ca.ErrNotFound):
		c.notice(http.StatusNotFound, "Not found", view.Message{Kind: view.MessageError, Text: "There is no such object, or you may not see it."})
	case errors.Is(err, authz.ErrDenied):
		text := "Your role doesn't allow this."
		if errors.As(err, &denied) && len(denied.Reasons) > 0 {
			text = denied.Reasons[0]
		}
		c.notice(http.StatusForbidden, "Refused", view.Message{Kind: view.MessageError, Text: text})
	default:
		c.a.log.ErrorContext(c.r.Context(), "ui error", slog.String("path", c.r.URL.Path), slog.Any("error", err))
		c.notice(http.StatusInternalServerError, "Error", view.Message{Kind: view.MessageError, Text: "Something went wrong – the server log has the details."})
	}
}

// messages are the flash messages plus more.
func (c *rc) messages(more ...view.Message) []view.Message {
	return append(slices.Clone(c.flash), more...)
}

func (a *app) now() time.Time { return a.d.Clock.Now().UTC() }
