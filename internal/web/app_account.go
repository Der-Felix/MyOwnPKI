package web

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/web/pages/admin"
	"github.com/Der-Felix/MyOwnPKI/internal/web/view"
)

// The own account (PHASE1 step 19): password, authenticator app, recovery
// codes, API tokens and passkeys. Changes need the current password
// (decision 45); a new secret is shown once, in the answer itself.

func (a *app) accountPage(c *rc) {
	ctx := c.r.Context()
	var sections []admin.Section
	sections = append(sections, admin.Section{KV: []view.KV{{Key: "User name", Value: c.sess.Username}, {Key: "Roles", Value: rolesText(c.sess.Principal)}}})
	sections = append(sections, admin.Section{Forms: []admin.FormData{
		c.form(admin.FormData{Title: "Password", Action: "/account/password", Submit: "Change password",
			Intro: []string{"Needs a fresh second factor; your other sessions end."},
			Fields: []admin.Field{
				{ID: "current", Label: "Current password", Type: "password", Autocomplete: "current-password", Required: true},
				{ID: "new", Label: "New password", Type: "password", Autocomplete: "new-password", Required: true, Hint: "12 to 256 characters, not a common password."},
				{ID: "new2", Label: "New password again", Type: "password", Autocomplete: "new-password", Required: true},
			}}),
		c.form(admin.FormData{Title: "Authenticator app", Action: "/account/totp", Submit: "Set up a new authenticator",
			Intro:  []string{"The next page shows the new secret once; the old one works until you confirm the new one with a code."},
			Fields: []admin.Field{{ID: "password", Label: "Current password", Type: "password", Autocomplete: "current-password", Required: true}}}),
		c.form(admin.FormData{Title: "Recovery codes", Action: "/account/recovery-codes", Submit: "Make new recovery codes",
			Intro:  []string{"Ten new codes, shown once; the old ones stop working."},
			Fields: []admin.Field{{ID: "password", Label: "Current password", Type: "password", Autocomplete: "current-password", Required: true}}}),
	}})

	tokens, err := a.d.Auth.ListTokens(ctx, c.token)
	if err != nil {
		c.fail(err)
		return
	}
	tt := &admin.TableData{Title: "API tokens", Empty: "No API tokens.", Columns: []admin.Column{{Label: "Name"}, {Label: "Roles"}, {Label: "Expires"}, {Label: "Last used"}}}
	var tokenForms []admin.FormData
	for _, t := range tokens {
		var roles []string
		for _, b := range t.Roles {
			roles = append(roles, bindingText(b))
		}
		last := "never"
		if !t.LastUsedAt.IsZero() {
			last = view.DateTime(t.LastUsedAt)
		}
		tt.Rows = append(tt.Rows, []admin.Cell{{Text: t.Name}, {Text: strings.Join(roles, "; ")}, {Text: view.Date(t.ExpiresAt)}, {Text: last}})
		tokenForms = append(tokenForms, c.form(admin.FormData{Action: "/account/tokens/" + url.PathEscape(t.ID) + "/revoke", Submit: "Revoke token " + t.Name, Danger: true}))
	}
	roles, scopes := a.roleOptions(c, false)
	tokenForms = append(tokenForms, c.form(admin.FormData{Title: "New API token", Action: "/account/tokens", Submit: "Create token",
		Intro: []string{"For scripts: Authorization: Bearer <token>. A token gets at most your own roles, ends within a year and never counts as a fresh second factor – no revocations, key downloads or CA changes by token."},
		Fields: []admin.Field{
			{ID: "name", Label: "Name", Required: true, Hint: "What uses it, e.g. backup-job"},
			{ID: "role", Label: "Role", Type: "select", Options: roles}, {ID: "scope", Label: "For", Type: "select", Options: scopes},
			{ID: "days", Label: "Valid for days", Type: "number", Value: "90", Hint: "1 to 366"},
		}}))
	sections = append(sections, admin.Section{Table: tt, Forms: tokenForms})

	if keys, perr := a.d.Auth.ListPasskeys(ctx, c.token); perr == nil {
		pt := &admin.TableData{Title: "Passkeys", Empty: "No passkeys.", Columns: []admin.Column{{Label: "Name"}, {Label: "Added"}, {Label: "Last used"}}}
		var pkForms []admin.FormData
		for _, k := range keys {
			last := "never"
			if !k.LastUsedAt.IsZero() {
				last = view.DateTime(k.LastUsedAt)
			}
			pt.Rows = append(pt.Rows, []admin.Cell{{Text: k.Name}, {Text: view.Date(k.CreatedAt)}, {Text: last}})
			pkForms = append(pkForms, c.form(admin.FormData{Action: "/account/passkeys/" + url.PathEscape(k.ID) + "/remove", Submit: "Remove passkey " + k.Name, Danger: true,
				Fields: []admin.Field{{ID: "password", Label: "Current password", Type: "password", Autocomplete: "current-password", Required: true}}}))
		}
		text := []string{"Adding a passkey needs the browser's passkey dialog, which this page can't open yet (no scripts in the UI so far) – use the REST API (/users/me/webauthn) meanwhile."}
		if a.d.Auth.Passkeys == nil {
			text = []string{"Passkeys are off on this server (auth.passkey_origin is not set)."}
		}
		sections = append(sections, admin.Section{Table: pt, Text: text, Forms: pkForms})
	}
	render(c.w, c.r, a.log, http.StatusOK, admin.DetailPage(c.page("My account", "account"), admin.DetailData{Messages: c.messages(), Sections: sections}))
}

func (a *app) changePassword(c *rc) {
	f := c.r.PostFormValue
	if err := c.sess.Principal.FreshStepUp(a.now()); err != nil {
		c.refused(err, "/account")
		return
	}
	if f("new") != f("new2") {
		c.setFlash(view.Message{Kind: view.MessageError, Text: "The two new passwords differ."})
		c.redirect("/account")
		return
	}
	if err := a.d.Auth.ChangePassword(c.r.Context(), c.token, f("current"), f("new"), c.client.IP); err != nil {
		c.refused(err, "/account")
		return
	}
	c.done("/account", "Password changed; your other sessions ended.")
}

func (a *app) startTOTP(c *rc) {
	enr, err := a.d.Auth.StartTOTPChange(c.r.Context(), c.token, c.r.PostFormValue("password"), c.client.IP)
	if err != nil {
		c.refused(err, "/account")
		return
	}
	c.once(c.page("New authenticator", "account", view.Crumb{Label: "My account", Href: "/account"}), admin.DetailData{
		Messages: []view.Message{{Kind: view.MessageWarning, Text: "Shown only now. Your old authenticator keeps working until you confirm the new one below."}},
		Sections: []admin.Section{
			{Title: "1. Add it to the app", KV: []view.KV{{Key: "Secret", Value: enr.Secret, Mono: true}}, Pre: []admin.Pre{{Title: "otpauth link", Text: enr.URI}}},
			{Title: "2. Confirm with a code from the new entry", Forms: []admin.FormData{c.form(admin.FormData{Action: "/account/totp/confirm", Submit: "Confirm",
				Fields: []admin.Field{{ID: "code", Label: "Code", Required: true, Autocomplete: "one-time-code"}}})}},
		},
	})
}

func (a *app) confirmTOTP(c *rc) {
	if err := a.d.Auth.ConfirmTOTPChange(c.r.Context(), c.token, c.r.PostFormValue("code"), c.client.IP); err != nil {
		c.refused(err, "/account")
		return
	}
	c.done("/account", "The new authenticator is active; your other sessions ended.")
}

func (a *app) newCodes(c *rc) {
	codes, err := a.d.Auth.NewRecoveryCodes(c.r.Context(), c.token, c.r.PostFormValue("password"), c.client.IP)
	if err != nil {
		c.refused(err, "/account")
		return
	}
	c.once(c.page("New recovery codes", "account", view.Crumb{Label: "My account", Href: "/account"}), admin.DetailData{
		Messages: []view.Message{{Kind: view.MessageWarning, Text: "Shown only now – store them apart from the phone. The old codes stopped working."}},
		Commands: []admin.Command{{Label: "Back to my account", Href: "/account"}},
		Sections: []admin.Section{{Pre: []admin.Pre{{Text: strings.Join(codes, "\n")}}}},
	})
}

func (a *app) createToken(c *rc) {
	f := c.r.PostFormValue
	if err := c.sess.Principal.FreshStepUp(a.now()); err != nil {
		c.refused(err, "/account")
		return
	}
	days := atoi(f("days"))
	if days < 1 || days > 366 {
		days = 90
	}
	roles := []authz.Binding{{Tenant: a.d.Tenant, CA: f("scope"), Role: authz.Role(f("role"))}}
	secret, t, err := a.d.Auth.CreateToken(c.r.Context(), c.token, f("name"), roles, a.now().Add(time.Duration(days)*24*time.Hour), c.client.IP)
	if err != nil {
		c.refused(err, "/account")
		return
	}
	c.once(c.page("API token "+t.Name, "account", view.Crumb{Label: "My account", Href: "/account"}), admin.DetailData{
		Messages: []view.Message{{Kind: view.MessageWarning, Text: "Shown only now – the server keeps only a hash. Store it in the script's secret store."}},
		Commands: []admin.Command{{Label: "Back to my account", Href: "/account"}},
		Sections: []admin.Section{{KV: []view.KV{{Key: "Name", Value: t.Name}, {Key: "Expires", Value: view.Date(t.ExpiresAt) + " (" + strconv.Itoa(days) + " days)"}},
			Pre: []admin.Pre{{Title: "Token", Text: secret}}, Text: []string{"Use it as: Authorization: Bearer " + secret[:8] + "…"}}},
	})
}

func (a *app) revokeToken(c *rc) {
	if err := a.d.Auth.RevokeToken(c.r.Context(), c.token, c.r.PathValue("id"), c.client.IP); err != nil {
		c.refused(err, "/account")
		return
	}
	c.done("/account", "Token revoked – it stops working at once.")
}

func (a *app) removePasskey(c *rc) {
	if err := c.sess.Principal.FreshStepUp(a.now()); err != nil {
		c.refused(err, "/account")
		return
	}
	if err := a.d.Auth.DeletePasskey(c.r.Context(), c.token, c.r.PathValue("id"), c.r.PostFormValue("password"), c.client.IP); err != nil {
		c.refused(err, "/account")
		return
	}
	c.done("/account", "Passkey removed.")
}
