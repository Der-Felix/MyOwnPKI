package web

import (
	"cmp"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/auth"
	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/pkcs12"
	"github.com/Der-Felix/MyOwnPKI/internal/tenant"
	"github.com/Der-Felix/MyOwnPKI/internal/web/pages/admin"
	"github.com/Der-Felix/MyOwnPKI/internal/web/view"
)

// Part 2 of the real UI (PHASE1 step 19): the actions on a certificate and
// the helpers every action page uses.

// refused ends a POST that a service refused: back to the form with the
// reasons, or to the step-up page when a fresh second factor is missing.
func (c *rc) refused(err error, back string) {
	var denied *ca.DeniedError
	var ref *auth.RefusedError
	var pol *auth.PolicyError
	var msgs []view.Message
	add := func(text string) { msgs = append(msgs, view.Message{Kind: view.MessageError, Text: text}) }
	switch {
	case errors.Is(err, authz.ErrStepUpRequired):
		c.setFlash(view.Message{Kind: view.MessageInfo, Text: "This needs a fresh second factor – confirm it, then send the form again."})
		c.redirect(loginURL("/step-up", back))
		return
	case errors.Is(err, ca.ErrNotFound), errors.Is(err, auth.ErrNoUser):
		c.fail(ca.ErrNotFound)
		return
	case errors.Is(err, keys.ErrSealed):
		add("The server is sealed – an instance admin must unseal it first.")
	case errors.As(err, &denied):
		for i, r := range denied.Reasons {
			if i == 10 {
				add("… and more")
				break
			}
			add(r)
		}
	case errors.As(err, &ref):
		for _, r := range ref.Reasons {
			add(r)
		}
	case errors.As(err, &pol):
		add(pol.Error())
	case errors.Is(err, authz.ErrDenied):
		add("Your role doesn't allow this.")
	case errors.Is(err, auth.ErrInvalidLogin):
		add("Wrong password.")
	case errors.Is(err, auth.ErrInvalidCode):
		add("Wrong or already used code.")
	case errors.Is(err, tenant.ErrInvalid), errors.Is(err, ca.ErrKeyDeleted), errors.Is(err, ca.ErrNoStoredKey),
		errors.Is(err, auth.ErrNoTOTPChange), errors.Is(err, auth.ErrPasskeysOff), errors.Is(err, auth.ErrNoToken), errors.Is(err, auth.ErrNoPasskey):
		add(err.Error())
	default:
		var locked *auth.LockedError
		if errors.As(err, &locked) {
			add(locked.Error())
			break
		}
		c.a.log.ErrorContext(c.r.Context(), "ui action", slog.String("path", c.r.URL.Path), slog.Any("error", err))
		add("Something went wrong – the server log has the details.")
	}
	c.setFlash(msgs...)
	c.redirect(back)
}

// done ends a successful POST.
func (c *rc) done(target, text string, more ...view.Message) {
	c.setFlash(append([]view.Message{{Kind: view.MessageSuccess, Text: text}}, more...)...)
	c.redirect(target)
}

// once renders a page that shows a secret once: the answer to the POST
// itself (no redirect – the secret must not travel in a cookie or a URL),
// never cached.
func (c *rc) once(p view.Page, d admin.DetailData) {
	c.w.Header().Set("Cache-Control", "no-store")
	render(c.w, c.r, c.a.log, http.StatusOK, admin.DetailPage(p, d))
}

func (c *rc) form(d admin.FormData) admin.FormData {
	d.CSRF = c.sess.CSRFToken
	d.Messages = c.messages(d.Messages...)
	return d
}

func yes(v string) bool { return v == "yes" || v == "on" || v == "true" }

var revocationReasons = []admin.Option{
	{Value: "superseded", Label: "superseded – replaced by a new certificate"},
	{Value: "cessationOfOperation", Label: "cessationOfOperation – no longer used"},
	{Value: "keyCompromise", Label: "keyCompromise – the key may be known to others (blocks the key)"},
	{Value: "affiliationChanged", Label: "affiliationChanged – the subject changed"},
	{Value: "privilegeWithdrawn", Label: "privilegeWithdrawn – the right to it ended"},
	{Value: "unspecified", Label: "unspecified"},
}

// certificateFor reads the certificate of the {id} path for an action page.
func (a *app) certificateFor(c *rc) (*ca.CertificateInfo, string, bool) {
	id := c.r.PathValue("id")
	info, err := a.d.Engine.Certificate(c.r.Context(), c.who(), id)
	if err != nil {
		c.fail(err)
		return nil, "", false
	}
	return info, "/certificates/" + url.PathEscape(info.ID), true
}

func (a *app) certPage(c *rc, info *ca.CertificateInfo, title string) view.Page {
	name := cmp.Or(info.CommonName, info.Serial)
	return c.page(title, "certificates", view.Crumb{Label: "Certificates", Href: "/certificates"}, view.Crumb{Label: name, Href: "/certificates/" + info.ID})
}

func (a *app) revokePage(c *rc) {
	info, detail, ok := a.certificateFor(c)
	if !ok {
		return
	}
	if info.Status == ca.CertRevoked {
		c.setFlash(view.Message{Kind: view.MessageInfo, Text: "This certificate is revoked already – a revocation is final."})
		c.redirect(detail)
		return
	}
	render(c.w, c.r, a.log, http.StatusOK, admin.FormPage(a.certPage(c, info, "Revoke certificate"), c.form(admin.FormData{
		Intro: []string{
			"A revocation is final. Clients see it once the next CRL of " + info.CAName + " is published – at once while the server is unsealed.",
			"Serial " + info.Serial + ", valid until " + view.Date(info.NotAfter) + ".",
		},
		Action: detail + "/revoke", Submit: "Revoke", Danger: true, Cancel: detail,
		Fields: []admin.Field{
			{ID: "reason", Label: "Reason", Type: "select", Options: revocationReasons, Required: true},
			{ID: "invalidity", Label: "Compromised since", Hint: "Only for keyCompromise: when the key was known or suspected to be compromised (YYYY-MM-DD or RFC 3339). Optional."},
			{ID: "confirm", Label: "I understand that this can't be undone", Type: "checkbox"},
		},
	})))
}

func (a *app) revoke(c *rc) {
	info, detail, ok := a.certificateFor(c)
	if !ok {
		return
	}
	back := detail + "/revoke"
	if !yes(c.r.PostFormValue("confirm")) {
		c.setFlash(view.Message{Kind: view.MessageError, Text: "Tick the confirmation – a revocation can't be undone."})
		c.redirect(back)
		return
	}
	req := ca.RevokeRequest{CertificateID: info.ID, Reason: c.r.PostFormValue("reason"), Who: c.who()}
	if s := strings.TrimSpace(c.r.PostFormValue("invalidity")); s != "" {
		t, err := parseDateOrTime(s)
		if err != nil {
			c.setFlash(view.Message{Kind: view.MessageError, Text: "Compromised since: " + err.Error()})
			c.redirect(back)
			return
		}
		req.InvalidityDate = &t
	}
	res, err := a.d.Engine.Revoke(c.r.Context(), req)
	if err != nil {
		c.refused(err, back)
		return
	}
	text := "Revoked. The CRL of " + info.CAName + " lists it now."
	if !res.Published {
		text = "Revoked and stored. The CRL is signed when the server is unsealed – only then clients see it."
	}
	var more []view.Message
	for _, w := range res.Warnings {
		more = append(more, view.Message{Kind: view.MessageWarning, Text: w})
	}
	c.done(detail, text, more...)
}

func parseDateOrTime(s string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.UTC(), nil
	}
	t, err := time.Parse(time.DateOnly, s)
	if err != nil {
		return time.Time{}, errors.New("want YYYY-MM-DD or an RFC 3339 time")
	}
	return t.UTC(), nil
}

func (a *app) renewPage(c *rc) {
	info, detail, ok := a.certificateFor(c)
	if !ok {
		return
	}
	d := admin.FormData{
		Intro:  []string{"The successor gets the same CA, preset, subject and names – and always a new key."},
		Action: detail + "/renew", Submit: "Renew", Cancel: detail,
	}
	if info.KeyStored {
		var opts []admin.Option
		for _, alg := range ca.GeneratedAlgorithms {
			opts = append(opts, admin.Option{Value: alg, Label: alg, Selected: alg == info.KeyAlgorithm})
		}
		d.Fields = append(d.Fields, admin.Field{ID: "alg", Label: "Key algorithm of the new key", Type: "select", Options: opts})
	} else {
		d.Fields = append(d.Fields, admin.Field{ID: "csr", Label: "New CSR (PEM)", Type: "textarea", Rows: 8, Required: true,
			Hint: "The original came from a CSR: create a new key and CSR on the device and paste the CSR here."})
	}
	if c.may(authz.RevokeCert, info.CAName) && info.Status != ca.CertRevoked {
		d.Fields = append(d.Fields, admin.Field{ID: "revoke_previous", Label: "Revoke this certificate afterwards (superseded)", Type: "checkbox"})
	}
	render(c.w, c.r, a.log, http.StatusOK, admin.FormPage(a.certPage(c, info, "Renew certificate"), c.form(d)))
}

func (a *app) renew(c *rc) {
	info, detail, ok := a.certificateFor(c)
	if !ok {
		return
	}
	req := ca.RenewCertRequest{ID: info.ID, KeyAlgorithm: c.r.PostFormValue("alg"), RevokePrevious: yes(c.r.PostFormValue("revoke_previous")), Who: c.who()}
	if csr := strings.TrimSpace(c.r.PostFormValue("csr")); csr != "" {
		req.CSR = []byte(csr)
	}
	res, err := a.d.Engine.RenewCertificate(c.r.Context(), req)
	if res == nil {
		c.refused(err, detail+"/renew")
		return
	}
	var more []view.Message
	if err != nil {
		more = append(more, view.Message{Kind: view.MessageWarning, Text: err.Error()})
	}
	for _, w := range res.Warnings {
		more = append(more, view.Message{Kind: view.MessageWarning, Text: w})
	}
	c.done("/certificates/"+url.PathEscape(res.ID), "Renewed: this is the successor.", more...)
}

func (a *app) exportPage(c *rc) {
	info, detail, ok := a.certificateFor(c)
	if !ok {
		return
	}
	if !info.KeyStored {
		c.setFlash(view.Message{Kind: view.MessageError, Text: ca.ErrNoStoredKey.Error() + "."})
		c.redirect(detail)
		return
	}
	render(c.w, c.r, a.log, http.StatusOK, admin.FormPage(a.certPage(c, info, "Export with key"), c.form(admin.FormData{
		Intro: []string{
			"Needs a fresh second factor; every export is in the audit log. PKCS#12 bundles key, certificate and chain under a password (Windows, macOS, Java).",
		},
		Action: detail + "/export", Submit: "Download", Cancel: detail,
		Fields: []admin.Field{
			{ID: "format", Label: "Format", Type: "select", Options: []admin.Option{
				{Value: ca.ExportPKCS12, Label: "PKCS#12 (.p12) with a password", Selected: true},
				{Value: ca.ExportPKCS8PEM, Label: "Private key only (PKCS#8 PEM, unencrypted)"},
				{Value: ca.ExportCombinedPEM, Label: "Certificate, chain and key in one PEM (HAProxy)"},
			}},
			{ID: "password", Label: "PKCS#12 password", Type: "password", Autocomplete: "new-password", Hint: "At least 12 characters; the importing system asks for it."},
			{ID: "password2", Label: "Password again", Type: "password", Autocomplete: "new-password"},
			{ID: "delete", Label: "Delete the key from the server after this download", Type: "checkbox",
				Hint: "Afterwards the key exists only in your file (and in older backups). Renewals then get a new key anyway."},
		},
	})))
}

func (a *app) export(c *rc) {
	info, detail, ok := a.certificateFor(c)
	if !ok {
		return
	}
	back := detail + "/export"
	format, pw := c.r.PostFormValue("format"), c.r.PostFormValue("password")
	if format == ca.ExportPKCS12 {
		switch {
		case len([]rune(pw)) < pkcs12.MinPassword:
			c.setFlash(view.Message{Kind: view.MessageError, Text: "The PKCS#12 password needs at least 12 characters."})
			c.redirect(back)
			return
		case pw != c.r.PostFormValue("password2"):
			c.setFlash(view.Message{Kind: view.MessageError, Text: "The two passwords differ."})
			c.redirect(back)
			return
		}
	} else {
		pw = ""
	}
	out, err := a.d.Engine.Export(c.r.Context(), ca.ExportRequest{ID: info.ID, Format: format, Password: pw, DeleteKey: yes(c.r.PostFormValue("delete")), Who: c.who()})
	if err != nil {
		c.refused(err, back)
		return
	}
	defer clear(out.Data)
	c.attachment(out.ContentType, out.FileName, out.Data)
}
