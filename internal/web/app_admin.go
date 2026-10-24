package web

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/audit"
	"github.com/Der-Felix/MyOwnPKI/internal/auth"
	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/ca/legacy"
	"github.com/Der-Felix/MyOwnPKI/internal/ca/preset"
	"github.com/Der-Felix/MyOwnPKI/internal/store/auditdb"
	"github.com/Der-Felix/MyOwnPKI/internal/tenant"
	"github.com/Der-Felix/MyOwnPKI/internal/web/pages/admin"
	"github.com/Der-Felix/MyOwnPKI/internal/web/view"
)

// Administration in the real UI (PHASE1 step 19): presets, users and
// roles, tenant settings, audit log, legacy import.

// ---------------------------------------------------------------- presets

func (a *app) presetList(c *rc) {
	d := admin.TableData{Messages: c.messages(), Empty: "No presets.",
		Columns: []admin.Column{{Label: "Preset"}, {Label: "Use"}, {Label: "Extended key usage"}, {Label: "Default validity", Num: true}}}
	for _, name := range a.d.Presets.Names() {
		p, _ := a.d.Presets.Get(name)
		d.Rows = append(d.Rows, []admin.Cell{{Text: p.Name, Href: "/presets/" + url.PathEscape(p.Name)}, {Text: p.Description},
			{Text: strings.Join(p.ExtKeyUsage.Usages, ", ")}, {Text: strconv.Itoa(p.ValidityDays) + " days", Num: true}})
	}
	p := c.page("Presets", "presets", view.Crumb{Label: "Certificates", Href: "/certificates"})
	p.Description = "What each kind of certificate gets: key usage, extended key usage, names, validity. Built in, read-only."
	render(c.w, c.r, a.log, http.StatusOK, admin.TablePage(p, d))
}

func (a *app) presetDetail(c *rc) {
	p, ok := a.d.Presets.Get(c.r.PathValue("name"))
	if !ok {
		c.fail(ca.ErrNotFound)
		return
	}
	sans := func(ts []preset.SANType) string {
		var s []string
		for _, t := range ts {
			s = append(s, string(t))
		}
		return strings.Join(s, ", ")
	}
	critical := "no"
	if p.ExtKeyUsage.Critical {
		critical = "yes"
	}
	kv := []view.KV{
		{Key: "Use", Value: p.Description}, {Key: "Deployment", Value: p.Usage}, {Key: "Family", Value: string(p.Family)},
		{Key: "Default validity", Value: strconv.Itoa(p.ValidityDays) + " days"},
		{Key: "Key usage (RSA)", Value: strings.Join(p.KeyUsage.RSA, ", ")}, {Key: "Key usage (ECDSA, Ed25519)", Value: strings.Join(p.KeyUsage.Other, ", ")},
		{Key: "Extended key usage", Value: strings.Join(p.ExtKeyUsage.Usages, ", ")}, {Key: "EKU critical", Value: critical},
		{Key: "Names – one of these is required", Value: sans(p.SubjectAltNames.RequiredAnyOf)}, {Key: "Names offered", Value: sans(p.SubjectAltNames.Offered)},
		{Key: "OpenSSL purpose", Value: p.OpenSSLPurpose, Mono: true},
	}
	if p.Wildcard {
		kv = append(kv, view.KV{Key: "Wildcards", Value: "required; the base domain is added"})
	}
	pg := c.page(p.Name, "presets", view.Crumb{Label: "Certificates", Href: "/certificates"}, view.Crumb{Label: "Presets", Href: "/presets"})
	render(c.w, c.r, a.log, http.StatusOK, admin.DetailPage(pg, admin.DetailData{Messages: c.messages(), Sections: []admin.Section{{KV: kv}}}))
}

// ---------------------------------------------------------------- users

func adminCrumbs() []view.Crumb { return []view.Crumb{{Label: "Administration"}} }

func bindingText(b authz.Binding) string {
	if b.CA != "" {
		return string(b.Role) + " of CA " + b.CA
	}
	return string(b.Role) + " of tenant " + b.Tenant
}

func (a *app) userList(c *rc) {
	users, err := a.d.Auth.ListUsers(c.r.Context(), c.who())
	if err != nil {
		c.fail(err)
		return
	}
	d := admin.TableData{Messages: c.messages(), Commands: []admin.Command{{Label: "New user", Href: "/admin/users/new", Primary: true}}, Empty: "No users.",
		Columns: []admin.Column{{Label: "User"}, {Label: "Status"}, {Label: "Roles"}, {Label: "Second factor"}, {Label: "Created"}}}
	for i := range users {
		u := &users[i]
		st, text := view.StatusOK, "active"
		switch {
		case u.Disabled:
			st, text = view.StatusNeutral, "disabled"
		case !u.LockedUntil.IsZero():
			st, text = view.StatusWarn, "locked"
		}
		var roles []string
		if u.InstanceAdmin {
			roles = append(roles, "instance admin")
		}
		for _, b := range u.Roles {
			roles = append(roles, bindingText(b))
		}
		mfa := "TOTP"
		if !u.TOTPConfirmed {
			mfa = "TOTP (not confirmed yet)"
		}
		if u.Passkeys > 0 {
			mfa += fmt.Sprintf(", %d passkey(s)", u.Passkeys)
		}
		d.Rows = append(d.Rows, []admin.Cell{{Text: u.Username, Href: "/admin/users/" + url.PathEscape(u.ID)}, {Text: text, Status: st},
			{Text: strings.Join(roles, "; ")}, {Text: mfa}, {Text: view.Date(u.CreatedAt)}})
	}
	render(c.w, c.r, a.log, http.StatusOK, admin.TablePage(c.page("Users and roles", "users", adminCrumbs()...), d))
}

func (a *app) roleOptions(c *rc, withNone bool) ([]admin.Option, []admin.Option) {
	roles := []admin.Option{{Value: "viewer", Label: "viewer – reads CAs and certificates"}, {Value: "operator", Label: "operator – issues, revokes, downloads keys"}, {Value: "admin", Label: "admin – also manages CAs and settings"}}
	if withNone {
		roles = append([]admin.Option{{Value: "", Label: "– no role –"}}, roles...)
	}
	scopes := []admin.Option{{Value: "", Label: "the whole tenant"}}
	if cas, err := a.d.Engine.CAs(c.r.Context(), c.who()); err == nil {
		for _, info := range cas {
			scopes = append(scopes, admin.Option{Value: info.Name, Label: "only CA " + info.Name})
		}
	}
	return roles, scopes
}

func (a *app) newUserPage(c *rc) {
	roles, scopes := a.roleOptions(c, true)
	render(c.w, c.r, a.log, http.StatusOK, admin.FormPage(c.page("New user", "users", append(adminCrumbs(), view.Crumb{Label: "Users and roles", Href: "/admin/users"})...), c.form(admin.FormData{
		Intro:  []string{"The second factor is fixed now: the next page shows the authenticator link and the recovery codes once – hand them to the user. The first sign-in confirms the secret."},
		Action: "/admin/users/new", Submit: "Create user", Cancel: "/admin/users",
		Fields: []admin.Field{
			{ID: "username", Label: "User name", Required: true, Hint: "Lower case a-z, 0-9, . _ @ -"},
			{ID: "password", Label: "Initial password", Type: "password", Autocomplete: "new-password", Required: true, Hint: "12 to 256 characters; tell it to the user apart from the authenticator link."},
			{ID: "role", Label: "Role", Type: "select", Options: roles},
			{ID: "scope", Label: "For", Type: "select", Options: scopes},
			{ID: "instance_admin", Label: "Instance admin (users, unseal)", Type: "checkbox"},
		},
	})))
}

func (a *app) newUser(c *rc) {
	f := c.r.PostFormValue
	req := auth.NewUserRequest{Username: strings.TrimSpace(f("username")), Password: f("password"), InstanceAdmin: yes(f("instance_admin")), Who: c.who()}
	if r := f("role"); r != "" {
		req.Roles = []authz.Binding{{Tenant: a.d.Tenant, CA: f("scope"), Role: authz.Role(r)}}
	}
	enr, err := a.d.Auth.CreateUser(c.r.Context(), req)
	if err != nil {
		c.refused(err, "/admin/users/new")
		return
	}
	p := c.page("User "+enr.Username+" created", "users", append(adminCrumbs(), view.Crumb{Label: "Users and roles", Href: "/admin/users"})...)
	c.once(p, admin.DetailData{
		Messages: []view.Message{{Kind: view.MessageWarning, Text: "Shown only now. Hand the link (or the secret) and the recovery codes to " + enr.Username + " over a separate channel; they are not stored readable."}},
		Commands: []admin.Command{{Label: "Back to the users", Href: "/admin/users"}},
		Sections: []admin.Section{
			{Title: "Authenticator app", Text: []string{"Scan the link as a QR code or type the secret into the app (TOTP, 6 digits, 30 seconds)."},
				KV: []view.KV{{Key: "Secret", Value: enr.Secret, Mono: true}}, Pre: []admin.Pre{{Title: "otpauth link", Text: enr.URI}}},
			{Title: "Recovery codes", Text: []string{"Each works once, when the phone is lost."}, Pre: []admin.Pre{{Text: strings.Join(enr.RecoveryCodes, "\n")}}},
		},
	})
}

func (a *app) userDetail(c *rc) {
	u, err := a.d.Auth.UserByID(c.r.Context(), c.who(), c.r.PathValue("id"))
	if err != nil {
		c.refused(err, "/admin/users")
		return
	}
	self := "/admin/users/" + url.PathEscape(u.ID)
	status := "active"
	switch {
	case u.Disabled:
		status = "disabled"
	case !u.LockedUntil.IsZero():
		status = "locked until " + view.DateTime(u.LockedUntil)
	}
	kv := []view.KV{{Key: "User name", Value: u.Username}, {Key: "Status", Value: status}, {Key: "Instance admin", Value: map[bool]string{true: "yes", false: "no"}[u.InstanceAdmin]},
		{Key: "Second factor", Value: map[bool]string{true: "TOTP confirmed", false: "TOTP not confirmed yet"}[u.TOTPConfirmed] + fmt.Sprintf(", %d passkey(s)", u.Passkeys)},
		{Key: "Created", Value: view.DateTime(u.CreatedAt)}}
	rt := &admin.TableData{Title: "Roles in this tenant", Empty: "No roles – the user sees nothing but the own account.", Columns: []admin.Column{{Label: "Role"}, {Label: "For"}}}
	var forms []admin.FormData
	for _, b := range u.Roles {
		scope := "the whole tenant"
		if b.CA != "" {
			scope = "CA " + b.CA
		}
		rt.Rows = append(rt.Rows, []admin.Cell{{Text: string(b.Role)}, {Text: scope}})
		forms = append(forms, c.form(admin.FormData{Action: self + "/roles/remove", Submit: "Remove " + bindingText(b), Danger: true,
			Fields: []admin.Field{{ID: "scope", Type: "hidden", Value: b.CA}}}))
	}
	roles, scopes := a.roleOptions(c, false)
	forms = append(forms, c.form(admin.FormData{Title: "Give a role", Action: self + "/roles", Submit: "Give role",
		Intro:  []string{"The user's sessions end: new rights only with a new sign-in."},
		Fields: []admin.Field{{ID: "role", Label: "Role", Type: "select", Options: roles}, {ID: "scope", Label: "For", Type: "select", Options: scopes}}}))
	if !u.LockedUntil.IsZero() {
		forms = append(forms, c.form(admin.FormData{Title: "Lockout", Action: self + "/unlock", Submit: "Unlock now"}))
	}
	if u.Disabled {
		forms = append(forms, c.form(admin.FormData{Title: "Account", Action: self + "/enable", Submit: "Enable"}))
	} else {
		forms = append(forms, c.form(admin.FormData{Title: "Account", Action: self + "/disable", Submit: "Disable", Danger: true,
			Intro: []string{"A disabled user can't sign in; every session ends. Users are never deleted – their ID stays in the audit log."}}))
	}
	pg := c.page(u.Username, "users", append(adminCrumbs(), view.Crumb{Label: "Users and roles", Href: "/admin/users"})...)
	render(c.w, c.r, a.log, http.StatusOK, admin.DetailPage(pg, admin.DetailData{Messages: c.messages(), Sections: []admin.Section{{KV: kv}, {Table: rt}, {Forms: forms}}}))
}

func (a *app) userAction(c *rc, run func(id string) (string, error)) {
	id := c.r.PathValue("id")
	self := "/admin/users/" + url.PathEscape(id)
	text, err := run(id)
	if err != nil {
		c.refused(err, self)
		return
	}
	c.done(self, text)
}

func (a *app) userGiveRole(c *rc) {
	a.userAction(c, func(id string) (string, error) {
		b := authz.Binding{Tenant: a.d.Tenant, CA: c.r.PostFormValue("scope"), Role: authz.Role(c.r.PostFormValue("role"))}
		return "Role given: " + bindingText(b) + ". The user's sessions ended.", a.d.Auth.SetRole(c.r.Context(), id, b, c.who())
	})
}

func (a *app) userRemoveRole(c *rc) {
	a.userAction(c, func(id string) (string, error) {
		return "Role removed. The user's sessions ended.", a.d.Auth.RemoveRole(c.r.Context(), id, a.d.Tenant, c.r.PostFormValue("scope"), c.who())
	})
}

func (a *app) userDisable(c *rc) {
	a.userAction(c, func(id string) (string, error) {
		return "Disabled; every session of the user ended.", a.d.Auth.DisableUser(c.r.Context(), id, c.who())
	})
}

func (a *app) userEnable(c *rc) {
	a.userAction(c, func(id string) (string, error) { return "Enabled.", a.d.Auth.EnableUser(c.r.Context(), id, c.who()) })
}

func (a *app) userUnlock(c *rc) {
	a.userAction(c, func(id string) (string, error) { return "Unlocked.", a.d.Auth.UnlockByID(c.r.Context(), id, c.who()) })
}

// ---------------------------------------------------------------- settings

func (a *app) settingsPage(c *rc) {
	if a.d.Settings == nil {
		c.fail(ca.ErrNotFound)
		return
	}
	s, err := a.d.Settings.Get(c.r.Context(), a.d.Tenant, c.who())
	if err != nil {
		c.fail(err)
		return
	}
	d := c.form(admin.FormData{
		Intro:  []string{"Subject defaults fill fields that neither a request nor its CSR gives – like pki.conf of pki.sh. The common name is never filled."},
		Action: "/admin/settings", Submit: "Save settings",
		Fields: []admin.Field{
			{ID: "keygen", Label: "Let the server generate keys (a CSR is always possible)", Type: "checkbox", Checked: s.AllowServerKeygen},
			{ID: "o", Label: "Organization (O)", Value: s.Organization},
			{ID: "ou", Label: "Organizational unit (OU)", Value: s.OrganizationalUnit},
			{ID: "l", Label: "Locality (L)", Value: s.Locality},
			{ID: "st", Label: "State (ST)", Value: s.State},
			{ID: "c", Label: "Country (C)", Value: s.Country, Hint: "Two upper-case letters, e.g. DE"},
			{ID: "acme_orders", Label: "ACME: new orders per account and hour", Type: "number", Value: strconv.Itoa(s.ACME.OrdersPerAccount), Hint: "1 to 10000"},
			{ID: "acme_failed", Label: "ACME: failed validations per name and hour", Type: "number", Value: strconv.Itoa(s.ACME.FailedPerName), Hint: "1 to 100 – stops a client that retries a broken setup"},
			{ID: "acme_accounts", Label: "ACME: new accounts per client address and hour", Type: "number", Value: strconv.Itoa(s.ACME.AccountsPerIP), Hint: "1 to 1000; IPv6 counts per /64"},
			{ID: "trust_page", Label: "Public trust page at / of the public listener (CA certificates, fingerprints, install guides)", Type: "checkbox", Checked: s.TrustPage != nil && *s.TrustPage},
		},
	})
	if !c.may(authz.ManageTenant, "") {
		d.Intro = append(d.Intro, "Only a tenant admin can change these.")
	}
	render(c.w, c.r, a.log, http.StatusOK, admin.FormPage(c.page("Tenant settings", "settings", adminCrumbs()...), d))
}

func (a *app) saveSettings(c *rc) {
	if a.d.Settings == nil {
		c.fail(ca.ErrNotFound)
		return
	}
	f := c.r.PostFormValue
	// A number that doesn't parse becomes 0, which the settings refuse.
	num := func(id string) int { n, _ := strconv.Atoi(strings.TrimSpace(f(id))); return n }
	trust := yes(f("trust_page"))
	err := a.d.Settings.Set(c.r.Context(), a.d.Tenant, tenant.Settings{AllowServerKeygen: yes(f("keygen")), Organization: strings.TrimSpace(f("o")),
		OrganizationalUnit: strings.TrimSpace(f("ou")), Locality: strings.TrimSpace(f("l")), State: strings.TrimSpace(f("st")), Country: strings.TrimSpace(f("c")),
		ACME:      &tenant.ACMELimits{OrdersPerAccount: num("acme_orders"), FailedPerName: num("acme_failed"), AccountsPerIP: num("acme_accounts")},
		TrustPage: &trust}, c.who())
	if err != nil {
		c.refused(err, "/admin/settings")
		return
	}
	c.done("/admin/settings", "Settings saved.")
}

// ---------------------------------------------------------------- audit

func (a *app) auditLog(c *rc) {
	q := c.r.URL.Query()
	scope := q.Get("scope")
	db := a.d.TenantAudit
	if scope == "instance" {
		if !c.instanceAdmin() {
			c.fail(authz.ErrDenied)
			return
		}
		db = a.d.InstanceAudit
	} else {
		scope = "tenant"
		if err := c.sess.Principal.Check(authz.ReadAudit, authz.Resource{Tenant: a.d.Tenant}, a.now()); err != nil {
			c.fail(err)
			return
		}
	}
	if db == nil {
		c.fail(ca.ErrNotFound)
		return
	}
	before, _ := strconv.ParseInt(q.Get("before"), 10, 64)
	result := q.Get("result")
	if result != "success" && result != "failure" && result != "denied" {
		result = ""
	}
	action := strings.TrimSpace(q.Get("action"))
	rows, err := auditdb.New(db).ListEntriesPage(c.r.Context(), auditdb.ListEntriesPageParams{Before: max(before, 0), Action: action, Result: result, PageSize: 51})
	if err != nil {
		c.fail(err)
		return
	}
	scopes := []admin.Option{{Value: "tenant", Label: "Tenant", Selected: scope == "tenant"}}
	if c.instanceAdmin() {
		scopes = append(scopes, admin.Option{Value: "instance", Label: "Instance (sign-ins, users, unseal)", Selected: scope == "instance"})
	}
	results := []admin.Option{{Value: "", Label: "any"}}
	for _, r := range []string{"success", "failure", "denied"} {
		results = append(results, admin.Option{Value: r, Label: r, Selected: r == result})
	}
	d := admin.TableData{Messages: c.messages(), Empty: "No entries match.",
		Filters: &admin.FormData{Action: "/admin/audit", Submit: "Filter", Fields: []admin.Field{
			{ID: "scope", Label: "Log", Type: "select", Options: scopes}, {ID: "action", Label: "Action begins with", Value: action},
			{ID: "result", Label: "Result", Type: "select", Options: results}}},
		Columns: []admin.Column{{Label: "#", Num: true}, {Label: "Time"}, {Label: "Actor"}, {Label: "Action"}, {Label: "Target"}, {Label: "Result"}, {Label: "Address"}, {Label: "Details"}}}
	more := len(rows) > 50
	if more {
		rows = rows[:50]
	}
	for _, r := range rows {
		t, _ := time.Parse(audit.TimeFormat, r.Time)
		st := view.StatusOK
		switch r.Result {
		case "failure":
			st = view.StatusWarn
		case "denied":
			st = view.StatusCrit
		}
		d.Rows = append(d.Rows, []admin.Cell{{Text: strconv.FormatInt(r.Seq, 10), Num: true}, {Text: view.DateTime(t), NoWrap: true}, {Text: r.ActorName},
			{Text: r.Action, Mono: true, NoWrap: true}, {Text: targetText(r.TargetType, r.TargetID)}, {Text: r.Result, Status: st, NoWrap: true}, {Text: r.SourceIp}, {Text: detailsText(r.DetailsJson)}})
	}
	if more {
		v := url.Values{"scope": {scope}, "action": {action}, "result": {result}, "before": {strconv.FormatInt(rows[len(rows)-1].Seq, 10)}}
		d.More, d.MoreLabel = "/admin/audit?"+v.Encode(), "Older entries"
	}
	p := c.page("Audit log", "audit", adminCrumbs()...)
	p.Description = "Every change and every refusal, hash-chained and signed at checkpoints; myownpki audit verify checks the chain."
	render(c.w, c.r, a.log, http.StatusOK, admin.TablePage(p, d))
}

// detailsText shows the details of an entry as key=value in key order,
// shortened.
func detailsText(js string) string {
	var m map[string]any
	if json.Unmarshal([]byte(js), &m) != nil {
		return ""
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%v", k, m[k]))
	}
	s := strings.Join(parts, " ")
	if r := []rune(s); len(r) > 160 {
		s = string(r[:160]) + "…"
	}
	return s
}

// ---------------------------------------------------------------- legacy import

func (a *app) importPage(c *rc) {
	render(c.w, c.r, a.log, http.StatusOK, admin.FormPage(c.page("Legacy import", "import", adminCrumbs()...), c.form(admin.FormData{
		Intro: []string{
			"Imports a legacy/pki.sh directory: every CA, certificate, revocation (time and reason) and the CRL numbering. Pack it with tar czf pki.tar.gz pki/ on the old machine.",
			"Run a dry run first – it checks everything and writes only the report. The root becomes an offline root: pki.sh stays the offline root tool.",
		},
		Action: "/admin/import", Multipart: true, Submit: "Start", Cancel: "/",
		Fields: []admin.Field{
			{ID: "archive", Label: "Archive (.tar.gz of ./pki)", Type: "file", Accept: ".gz,.tgz,application/gzip", Required: true},
			{ID: "dry_run", Label: "Dry run – check only", Type: "checkbox", Checked: true},
			{ID: "base", Label: "Public base URL for new certificates", Hint: "Empty: AIA_BASE_URL of pki.conf. With the same URL the old <base>/<name>.crl links keep working."},
			{ID: "root_key", Label: "Root key", Type: "select", Options: []admin.Option{{Value: "offline", Label: "stays offline (recommended)", Selected: true}, {Value: "online", Label: "import it encrypted (tests, homelab)"}}},
			{ID: "ca_pass", Label: "Passphrases of encrypted CA keys", Type: "textarea", Rows: 3, Hint: "One line per CA: name=passphrase. Used once, never stored."},
			{ID: "key_pass", Label: "Passphrase of encrypted leaf keys (PKI_KEY_PASS)", Type: "password"},
		},
	})))
}

func (a *app) runImport(c *rc) {
	file, _, err := c.r.FormFile("archive")
	if err != nil {
		c.setFlash(view.Message{Kind: view.MessageError, Text: "Choose the archive (.tar.gz)."})
		c.redirect("/admin/import")
		return
	}
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(io.LimitReader(file, legacy.MaxArchive+1))
	if err != nil {
		c.refused(err, "/admin/import")
		return
	}
	fsys, err := legacy.FromArchive(data)
	if err != nil {
		c.setFlash(view.Message{Kind: view.MessageError, Text: err.Error()})
		c.redirect("/admin/import")
		return
	}
	caPass := map[string]string{}
	for _, line := range strings.Split(c.r.PostFormValue("ca_pass"), "\n") {
		if k, v, ok := strings.Cut(strings.TrimRight(line, "\r"), "="); ok {
			caPass[strings.TrimSpace(k)] = v
		}
	}
	src, err := legacy.Read(fsys, legacy.Passphrases{Leaf: []byte(c.r.PostFormValue("key_pass")), CA: func(n string) []byte { return []byte(caPass[n]) }})
	if err != nil {
		c.setFlash(view.Message{Kind: view.MessageError, Text: err.Error()})
		c.redirect("/admin/import")
		return
	}
	job, err := a.d.Engine.ImportLegacyJob(c.r.Context(), ca.LegacyImportRequest{PKI: src, BaseURL: strings.TrimSpace(c.r.PostFormValue("base")),
		RootOnline: c.r.PostFormValue("root_key") == "online", DryRun: yes(c.r.PostFormValue("dry_run")), Who: c.who()})
	if job == nil {
		c.refused(err, "/admin/import")
		return
	}
	text := map[string]string{ca.JobSucceeded: "Imported.", ca.JobChecked: "Dry run passed – nothing was written. Run it again without the dry run.", ca.JobFailed: "Not imported – see the problems below."}[job.Status]
	c.done("/admin/import/"+url.PathEscape(job.ID), text)
}

func (a *app) importReport(c *rc) {
	job, err := a.d.Engine.ImportJobByID(c.r.Context(), c.who(), c.r.PathValue("id"))
	if err != nil {
		c.fail(err)
		return
	}
	r := job.Report
	st := map[string]string{ca.JobSucceeded: "imported", ca.JobChecked: "dry run passed", ca.JobFailed: "refused"}[job.Status]
	kv := []view.KV{{Key: "Result", Value: st}, {Key: "Started", Value: view.DateTime(job.StartedAt) + " by " + job.StartedBy},
		{Key: "Base URL for new certificates", Value: r.BaseURL}, {Key: "Certificates", Value: fmt.Sprintf("%d (%d revoked), %d private keys, %d self-signed (external)", r.Certificates, r.Revoked, r.Keys, r.External)}}
	if r.LegacyURLs {
		kv = append(kv, view.KV{Key: "Old URLs", Value: "<base>/<name>.crt and .crl stay served"})
	}
	cas := &admin.TableData{Title: "Certificate authorities", Empty: "None.",
		Columns: []admin.Column{{Label: "Name"}, {Label: "Kind"}, {Label: "Key"}, {Label: "Certificates", Num: true}, {Label: "Revoked", Num: true}, {Label: "Last CRL number", Num: true}}}
	for _, x := range r.CAs {
		cas.Rows = append(cas.Rows, []admin.Cell{{Text: x.Name}, {Text: x.Kind}, {Text: keyStorage(x.KeyMode)}, {Text: strconv.Itoa(x.Certificates), Num: true},
			{Text: strconv.Itoa(x.Revoked), Num: true}, {Text: strconv.FormatInt(x.LastCRLNumber, 10), Num: true}})
	}
	sections := []admin.Section{{KV: kv}, {Table: cas}}
	list := func(title string, items []string) {
		if len(items) > 0 {
			sections = append(sections, admin.Section{Title: fmt.Sprintf("%s (%d)", title, len(items)), Pre: []admin.Pre{{Text: strings.Join(items, "\n")}}})
		}
	}
	list("Problems", r.Problems)
	list("Warnings", r.Warnings)
	render(c.w, c.r, a.log, http.StatusOK, admin.DetailPage(c.page("Import report", "import", append(adminCrumbs(), view.Crumb{Label: "Legacy import", Href: "/admin/import"})...),
		admin.DetailData{Messages: c.messages(), Sections: sections, Commands: []admin.Command{{Label: "New import", Href: "/admin/import"}}}))
}

func targetText(typ, id string) string {
	if id == "" || id == typ {
		return typ
	}
	return typ + " " + id
}
