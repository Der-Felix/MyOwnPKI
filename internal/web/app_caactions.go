package web

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/web/pages/admin"
	"github.com/Der-Felix/MyOwnPKI/internal/web/view"
)

// CA management in the real UI (PHASE1 step 19): new CA, import of an
// offline root, the offline signing flow, limits, CRLs, renew, retire,
// revoke. Every action goes through the CA engine with its checks; the
// pages only offer what the role allows.

func caCrumbs() []view.Crumb {
	return []view.Crumb{{Label: "Certificate authorities", Href: "/authorities"}}
}

func splitList(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == '\n' || r == ' ' || r == '\r' })
}

func atoi(s string) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n < 0 {
		return 0
	}
	return n
}

func (a *app) newCAPage(c *rc) {
	cas, err := a.d.Engine.CAs(c.r.Context(), c.who())
	if err != nil {
		c.fail(err)
		return
	}
	parents := []admin.Option{{Value: "", Label: "– none: a new root –"}}
	for _, info := range cas {
		if info.Status == ca.StatusActive {
			label := info.Name
			if info.KeyMode == ca.KeyModeOffline {
				label += " (offline – you sign the CSR on the offline root)"
			}
			parents = append(parents, admin.Option{Value: info.ID, Label: label, Selected: info.Kind == ca.KindRoot})
		}
	}
	var algs []admin.Option
	for _, alg := range ca.CAAlgorithms {
		algs = append(algs, admin.Option{Value: alg, Label: alg, Selected: alg == ca.DefaultCAKeyAlgorithm})
	}
	render(c.w, c.r, a.log, http.StatusOK, admin.FormPage(c.page("New certificate authority", "authorities", caCrumbs()...), c.form(admin.FormData{
		Intro: []string{
			"An intermediate below an online CA is signed at once; below an offline root you get a CSR and an extension file for the offline root.",
			"Without a parent you create an online root – for tests and homelabs. A root signs intermediates and CRLs only.",
		},
		Action: "/authorities/new", Submit: "Create CA", Cancel: "/authorities",
		Fields: []admin.Field{
			{ID: "parent", Label: "Parent CA", Type: "select", Options: parents},
			{ID: "name", Label: "Name", Required: true, Hint: "Lower case a-z, 0-9, . _ -; part of every AIA and CRL URL – it never changes."},
			{ID: "cn", Label: "Common name", Required: true, Hint: "e.g. Homelab Issuing CA 2027"},
			{ID: "o", Label: "Organization"},
			{ID: "c", Label: "Country", Hint: "Two letters, e.g. DE"},
			{ID: "alg", Label: "Key algorithm", Type: "select", Options: algs},
			{ID: "days", Label: "Validity in days", Type: "number", Hint: "Empty: 7300 for a root, 3650 for an intermediate – never beyond the parent."},
			{ID: "pathlen", Label: "Path length", Type: "number", Value: "0", Hint: "0 = may only issue end-entity certificates."},
			{ID: "dns", Label: "Permitted DNS names", Hint: "Name constraints, comma-separated, e.g. homelab.example – recommended."},
			{ID: "ip", Label: "Permitted IP ranges", Hint: "CIDR, comma-separated, e.g. 192.0.2.0/24"},
			{ID: "eku", Label: "EKU limit", Hint: "Comma-separated, e.g. serverAuth, clientAuth; empty = no limit."},
			{ID: "base", Label: "Public base URL", Required: true, Hint: "e.g. http://pki.homelab.example – in every certificate below this CA (AIA, CRL), forever."},
			{ID: "crl_days", Label: "CRL lifetime in days", Type: "number", Hint: "Empty: 7 for an intermediate, 30 for an online root."},
			{ID: "max_days", Label: "Maximum certificate validity in days", Type: "number", Hint: "Empty: 397."},
		},
	})))
}

func (a *app) newCA(c *rc) {
	f := c.r.PostFormValue
	ctx := c.r.Context()
	settings := ca.CASettings{Name: strings.TrimSpace(f("name")), BaseURL: strings.TrimSpace(f("base")), CRLDays: atoi(f("crl_days")), MaxValidityDays: atoi(f("max_days"))}
	subj := ca.Subject{CommonName: strings.TrimSpace(f("cn")), Organization: strings.TrimSpace(f("o")), Country: strings.TrimSpace(f("c"))}
	var res *ca.CAResult
	var err error
	if parentID := f("parent"); parentID == "" {
		res, err = a.d.Engine.CreateRoot(ctx, ca.RootRequest{CASettings: settings, Subject: subj, KeyAlgorithm: f("alg"), ValidityDays: atoi(f("days")), Who: c.who()})
	} else {
		parent, perr := a.d.Engine.CAName(ctx, c.who(), parentID)
		if perr != nil {
			c.refused(perr, "/authorities/new")
			return
		}
		res, err = a.d.Engine.CreateIntermediate(ctx, ca.IntermediateRequest{CASettings: settings, Parent: parent, Subject: subj, KeyAlgorithm: f("alg"),
			ValidityDays: atoi(f("days")), PathLen: atoi(f("pathlen")), EKULimit: splitList(f("eku")), Who: c.who(),
			NameConstraints: ca.NameConstraints{PermittedDNS: splitList(f("dns")), PermittedIP: splitList(f("ip"))}})
	}
	if err != nil {
		c.refused(err, "/authorities/new")
		return
	}
	target := "/authorities/" + url.PathEscape(res.ID)
	text := "CA " + res.Name + " created."
	if res.Offline != nil {
		target += "/offline"
		text = "CA " + res.Name + " waits for its signature: take the CSR and the extension file to the offline root."
	}
	c.done(target, text, notesOf(res)...)
}

func notesOf(res *ca.CAResult) []view.Message {
	var out []view.Message
	for _, n := range res.Notes {
		out = append(out, view.Message{Kind: view.MessageInfo, Text: n})
	}
	for _, w := range res.Warnings {
		out = append(out, view.Message{Kind: view.MessageWarning, Text: w})
	}
	return out
}

func (a *app) importRootPage(c *rc) {
	render(c.w, c.r, a.log, http.StatusOK, admin.FormPage(c.page("Import offline root", "authorities", caCrumbs()...), c.form(admin.FormData{
		Intro:  []string{"The root's key stays offline (legacy pki.sh, an air-gapped machine). The server needs its certificate for chains and to check the root's CRLs. A whole pki.sh directory is imported under Administration → Legacy import."},
		Action: "/authorities/import", Submit: "Import", Cancel: "/authorities",
		Fields: []admin.Field{
			{ID: "name", Label: "Name", Required: true, Value: "root", Hint: "The same name as on the offline root keeps the legacy URLs."},
			{ID: "cert", Label: "Root certificate (PEM)", Type: "textarea", Rows: 10, Required: true},
			{ID: "base", Label: "Public base URL", Required: true, Hint: "Where this server publishes the root's certificate and CRL."},
			{ID: "crl_days", Label: "Lifetime of the root's CRLs in days", Type: "number", Hint: "Empty: 180."},
		},
	})))
}

func (a *app) importRoot(c *rc) {
	f := c.r.PostFormValue
	res, err := a.d.Engine.ImportRoot(c.r.Context(), ca.ImportRootRequest{
		CASettings: ca.CASettings{Name: strings.TrimSpace(f("name")), BaseURL: strings.TrimSpace(f("base")), CRLDays: atoi(f("crl_days"))},
		CertPEM:    []byte(strings.TrimSpace(f("cert")) + "\n"), Who: c.who(),
	})
	if err != nil {
		c.refused(err, "/authorities/import")
		return
	}
	c.done("/authorities/"+url.PathEscape(res.ID), "Root "+res.Name+" imported.", notesOf(res)...)
}

// caFor reads the CA of the {id} path.
func (a *app) caFor(c *rc) (*ca.CAInfo, string, bool) {
	info, err := a.d.Engine.CA(c.r.Context(), c.who(), c.r.PathValue("id"))
	if err != nil {
		c.fail(err)
		return nil, "", false
	}
	return info, "/authorities/" + url.PathEscape(info.ID), true
}

func (a *app) caPage(c *rc, info *ca.CAInfo, title string) view.Page {
	return c.page(title, "authorities", append(caCrumbs(), view.Crumb{Label: info.Name, Href: "/authorities/" + info.ID})...)
}

func (a *app) offlinePage(c *rc) {
	info, detail, ok := a.caFor(c)
	if !ok {
		return
	}
	if err := a.d.Engine.CheckManage(c.who(), info.Name); err != nil {
		c.fail(err)
		return
	}
	b, err := a.d.Engine.OfflineBundleFor(c.r.Context(), info.Name)
	if err != nil {
		c.setFlash(view.Message{Kind: view.MessageInfo, Text: "This CA doesn't wait for a signature."})
		c.redirect(detail)
		return
	}
	d := admin.DetailData{Messages: c.messages(), Sections: []admin.Section{
		{Title: "1. Take these to the offline root", Text: []string{"Save both as files with the names shown and sign with exactly this extension file – never with the CSR's extensions."},
			KV:  []view.KV{{Key: "CSR file", Value: b.CSRFile, Mono: true}, {Key: "Extension file", Value: b.ExtFile, Mono: true}, {Key: "Days", Value: strconv.Itoa(b.Days)}, {Key: "Digest", Value: b.Digest}, {Key: "Serial", Value: b.Serial, Mono: true}},
			Pre: []admin.Pre{{Title: b.CSRFile, Text: string(b.CSRPEM)}, {Title: b.ExtFile, Text: b.ExtConfig}}},
		{Title: "2. Sign", Pre: []admin.Pre{{Text: b.Instructions}}},
		{Title: "3. Upload the signed certificate", Forms: []admin.FormData{c.form(admin.FormData{
			Action: detail + "/certificate", Submit: "Install certificate",
			Intro:  []string{"It is checked against the order: key, subject, CA:TRUE, key usage, path length, name constraints, EKU, the parent's signature."},
			Fields: []admin.Field{{ID: "cert", Label: b.CertFile + " (PEM)", Type: "textarea", Rows: 10, Required: true}},
		})}},
	}}
	render(c.w, c.r, a.log, http.StatusOK, admin.DetailPage(a.caPage(c, info, "Offline signing"), d))
}

func (a *app) installCertificate(c *rc) {
	info, detail, ok := a.caFor(c)
	if !ok {
		return
	}
	res, err := a.d.Engine.InstallCACertificate(c.r.Context(), info.Name, []byte(strings.TrimSpace(c.r.PostFormValue("cert"))+"\n"), c.who())
	if err != nil {
		c.refused(err, detail+"/offline")
		return
	}
	c.done(detail, "Certificate installed – "+info.Name+" is active and has signed its first CRL.", notesOf(res)...)
}

func (a *app) managePage(c *rc) {
	info, detail, ok := a.caFor(c)
	if !ok {
		return
	}
	var forms []admin.FormData
	kv := []view.KV{{Key: "Kind", Value: info.Kind}, {Key: "Key storage", Value: keyStorage(info.KeyMode)}, {Key: "Status", Value: info.Status},
		{Key: "CRL lifetime", Value: strconv.FormatInt(info.CRLDays, 10) + " days"}}
	if info.Kind != ca.KindRoot {
		kv = append(kv, view.KV{Key: "Maximum certificate validity", Value: strconv.FormatInt(info.MaxValidityDays, 10) + " days"})
	}
	canManage := c.may(authz.ManageCA, info.Name)
	if canManage {
		forms = append(forms, c.form(admin.FormData{Title: "Limits", Action: detail + "/limits", Submit: "Save limits",
			Fields: []admin.Field{
				{ID: "crl_days", Label: "CRL lifetime in days", Type: "number", Value: strconv.FormatInt(info.CRLDays, 10)},
				{ID: "max_days", Label: "Maximum certificate validity in days", Type: "number", Value: strconv.FormatInt(info.MaxValidityDays, 10)},
			}}))
		if info.KeyMode == ca.KeyModeOnlineEncrypted && info.Status == ca.StatusActive {
			forms = append(forms, c.form(admin.FormData{Title: "CRL", Action: detail + "/crl", Submit: "Sign a new CRL now",
				Intro: []string{"The server renews CRLs on its own after a third of their lifetime; this signs one at once."}}))
		}
		if info.KeyMode == ca.KeyModeOffline {
			forms = append(forms, c.form(admin.FormData{Title: "Upload the root's CRL", Action: detail + "/crl-upload", Submit: "Upload CRL",
				Intro:  []string{"Create it on the offline root (pki crl --ca " + info.Name + ") and paste it here; it must be newer than the one served now."},
				Fields: []admin.Field{{ID: "crl", Label: "CRL (PEM)", Type: "textarea", Rows: 8, Required: true}}}))
		}
		if info.Status == ca.StatusActive && info.KeyMode != ca.KeyModeOffline {
			var algs []admin.Option
			for _, alg := range ca.CAAlgorithms {
				algs = append(algs, admin.Option{Value: alg, Label: alg})
			}
			forms = append(forms, c.form(admin.FormData{Title: "Renew with a new key", Action: detail + "/renew", Submit: "Renew",
				Intro:  []string{"A new key and certificate – the next generation. The old generation keeps its CRL for what it signed."},
				Fields: []admin.Field{{ID: "alg", Label: "Key algorithm", Type: "select", Options: algs}, {ID: "days", Label: "Validity in days", Type: "number"}}}))
		}
		if info.Status == ca.StatusActive {
			forms = append(forms, c.form(admin.FormData{Title: "Retire", Action: detail + "/retire", Submit: "Retire CA", Danger: true,
				Intro:  []string{"A retired CA signs no new certificates; its CRLs go on until everything it signed has expired."},
				Fields: []admin.Field{{ID: "confirm", Label: "Retire " + info.Name, Type: "checkbox"}}}))
		}
	}
	if info.Kind == ca.KindIntermediate && c.may(authz.ManageCA, info.Parent) {
		forms = append(forms, c.form(admin.FormData{Title: "Revoke", Action: detail + "/revoke", Submit: "Revoke CA", Danger: true,
			Intro: []string{"Revoked on the CRL of " + info.Parent + ". Every certificate below this CA stops working for clients that check revocation. A CA below an offline root is revoked on the offline root."},
			Fields: []admin.Field{
				{ID: "reason", Label: "Reason", Type: "select", Options: []admin.Option{
					{Value: "superseded", Label: "superseded"}, {Value: "cessationOfOperation", Label: "cessationOfOperation"},
					{Value: "keyCompromise", Label: "keyCompromise"}, {Value: "cACompromise", Label: "cACompromise"}, {Value: "unspecified", Label: "unspecified"},
				}},
				{ID: "confirm", Label: "I understand that this can't be undone", Type: "checkbox"},
			}}))
	}
	d := admin.DetailData{Messages: c.messages(), Sections: append([]admin.Section{{Title: "This CA", KV: kv}}, admin.Section{Forms: forms})}
	if len(forms) == 0 {
		d.Sections[0].Text = []string{"Your role doesn't allow changes to this CA."}
	}
	render(c.w, c.r, a.log, http.StatusOK, admin.DetailPage(a.caPage(c, info, "Manage "+info.Name), d))
}

// caAction runs one management action and returns to the manage page.
func (a *app) caAction(c *rc, run func(info *ca.CAInfo) (string, []view.Message, error)) {
	info, detail, ok := a.caFor(c)
	if !ok {
		return
	}
	text, more, err := run(info)
	if err != nil {
		c.refused(err, detail+"/manage")
		return
	}
	c.done(detail, text, more...)
}

func (a *app) caLimits(c *rc) {
	a.caAction(c, func(info *ca.CAInfo) (string, []view.Message, error) {
		return "Limits saved.", nil, a.d.Engine.UpdateCA(c.r.Context(), ca.UpdateRequest{Name: info.Name,
			CRLDays: atoi(c.r.PostFormValue("crl_days")), MaxValidityDays: atoi(c.r.PostFormValue("max_days")), Who: c.who()})
	})
}

func (a *app) caSignCRL(c *rc) {
	a.caAction(c, func(info *ca.CAInfo) (string, []view.Message, error) {
		res, err := a.d.Engine.SignCRL(c.r.Context(), info.ID, info.CurrentGeneration, "ui", c.who())
		if err != nil {
			return "", nil, err
		}
		return "CRL number " + strconv.FormatInt(res.Number, 10) + " signed (" + strconv.Itoa(res.Entries) + " entries).", nil, nil
	})
}

func (a *app) caUploadCRL(c *rc) {
	a.caAction(c, func(info *ca.CAInfo) (string, []view.Message, error) {
		res, warnings, err := a.d.Engine.UploadCRL(c.r.Context(), info.Name, []byte(strings.TrimSpace(c.r.PostFormValue("crl"))+"\n"), c.who())
		if err != nil {
			return "", nil, err
		}
		var more []view.Message
		for _, w := range warnings {
			more = append(more, view.Message{Kind: view.MessageWarning, Text: w})
		}
		return "CRL number " + strconv.FormatInt(res.Number, 10) + " uploaded and served.", more, nil
	})
}

func (a *app) caRenew(c *rc) {
	info, detail, ok := a.caFor(c)
	if !ok {
		return
	}
	res, err := a.d.Engine.RenewCA(c.r.Context(), ca.RenewRequest{Name: info.Name, KeyAlgorithm: c.r.PostFormValue("alg"), ValidityDays: atoi(c.r.PostFormValue("days")), Who: c.who()})
	if err != nil {
		c.refused(err, detail+"/manage")
		return
	}
	if res.Offline != nil {
		c.done(detail+"/offline", "The new generation waits for its signature on the offline root.", notesOf(res)...)
		return
	}
	c.done(detail, "Renewed: generation "+strconv.FormatInt(res.Generation, 10)+" signs from now on.", notesOf(res)...)
}

func (a *app) caRetire(c *rc) {
	a.caAction(c, func(info *ca.CAInfo) (string, []view.Message, error) {
		if !yes(c.r.PostFormValue("confirm")) {
			return "", nil, &ca.DeniedError{Reasons: []string{"Tick the confirmation to retire the CA."}}
		}
		return info.Name + " is retired.", nil, a.d.Engine.RetireCA(c.r.Context(), info.Name, c.who())
	})
}

func (a *app) caRevoke(c *rc) {
	a.caAction(c, func(info *ca.CAInfo) (string, []view.Message, error) {
		if !yes(c.r.PostFormValue("confirm")) {
			return "", nil, &ca.DeniedError{Reasons: []string{"Tick the confirmation – a revocation can't be undone."}}
		}
		res, err := a.d.Engine.RevokeCA(c.r.Context(), ca.RevokeCARequest{Name: info.Name, Reason: c.r.PostFormValue("reason"), Who: c.who()})
		if err != nil {
			return "", nil, err
		}
		var more []view.Message
		for _, w := range res.Warnings {
			more = append(more, view.Message{Kind: view.MessageWarning, Text: w})
		}
		if !res.Published {
			return info.Name + " is revoked; the parent's CRL follows at the unseal.", more, nil
		}
		return info.Name + " is revoked and on the CRL of " + info.Parent + ".", more, nil
	})
}
